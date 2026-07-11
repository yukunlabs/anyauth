package localdev

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/auditlog"
	"github.com/yukunlabs/anyauth/internal/authz"
	"github.com/yukunlabs/anyauth/internal/authzstore"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

func TestSemanticAuthorizationApprovalFlow(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	issuer := "http://127.0.0.1:" + itoa(providerPort)
	registerSemanticAuthorizationFixtures(t, dataDir)

	servers, _, err := Start(Config{ProviderPort: providerPort, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servers.Shutdown(context.Background()) })

	createResponse := createAuthorizationRequestOutput{}
	postAuthorizationJSON(t, issuer+"/api/authorization-requests", createAuthorizationRequestInput{
		AgentID:       "codex",
		ApplicationID: "github",
		Action:        "issue.create",
		ResourceType:  "repository",
		ResourceID:    "yukunlabs/anyauth",
		TaskID:        "task-test",
		TaskName:      "Test semantic authorization",
		TTLSeconds:    1800,
	}, http.StatusCreated, &createResponse)
	if createResponse.Request.Status != authzstore.RequestPending {
		t.Fatalf("unexpected request response: %#v", createResponse)
	}

	body := mustGetBody(t, http.DefaultClient, issuer+"/approvals", http.StatusOK)
	if !strings.Contains(body, "issue.create") || !strings.Contains(body, "yukunlabs/anyauth") {
		t.Fatalf("approval page did not render semantic request: %s", body)
	}
	approveURL := issuer + "/approvals/" + url.PathEscape(createResponse.Request.ID) + "/approve"
	req, err := http.NewRequest(http.MethodPost, approveURL, strings.NewReader(url.Values{}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", issuer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d, body = %s", resp.StatusCode, responseBody)
	}

	evaluation := authz.Request{
		Actor:         authz.Identity{Type: authz.IdentityAgent, ID: "codex"},
		Subject:       authz.Identity{Type: authz.IdentityHuman, ID: "local-user"},
		ApplicationID: "github",
		Action:        authz.Action{Name: "issue.create"},
		Resource:      authz.Resource{Type: "repository", ID: "yukunlabs/anyauth"},
		Context:       authz.RequestContext{TaskID: "task-test"},
	}
	var decision accessEvaluationOutput
	postAuthorizationJSON(t, issuer+"/access/v1/evaluation", evaluation, http.StatusOK, &decision)
	if !decision.Decision || decision.Context.DecisionID == "" || len(decision.Context.GrantIDs) != 1 {
		t.Fatalf("unexpected allow decision: %#v", decision)
	}

	store := authzstore.New(dataDir)
	if _, err := store.RevokeGrant(decision.Context.GrantIDs[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	postAuthorizationJSON(t, issuer+"/access/v1/evaluation", evaluation, http.StatusOK, &decision)
	if decision.Decision || decision.Context.ReasonCode != authz.ReasonGrantRevoked {
		t.Fatalf("unexpected revoked decision: %#v", decision)
	}

	events, err := auditlog.Load(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Type] = true
	}
	for _, eventType := range []string{"authorization.request", "authorization.approve", "authorization.decision"} {
		if !seen[eventType] {
			t.Fatalf("missing %s audit event in %#v", eventType, events)
		}
	}
}

func TestSemanticAuthorizationApprovalRequiresConfiguredPIN(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	issuer := "http://127.0.0.1:" + itoa(providerPort)
	registerSemanticAuthorizationFixtures(t, dataDir)
	if _, err := userstore.SetPIN(dataDir, "654321"); err != nil {
		t.Fatal(err)
	}

	servers, _, err := Start(Config{ProviderPort: providerPort, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servers.Shutdown(context.Background()) })

	var created createAuthorizationRequestOutput
	postAuthorizationJSON(t, issuer+"/api/authorization-requests", createAuthorizationRequestInput{
		AgentID:       "codex",
		ApplicationID: "github",
		Action:        "issue.create",
		ResourceType:  "repository",
		ResourceID:    "yukunlabs/anyauth",
		TTLSeconds:    1800,
	}, http.StatusCreated, &created)

	approveURL := issuer + "/approvals/" + url.PathEscape(created.Request.ID) + "/approve"
	for _, tt := range []struct {
		pin    string
		status int
	}{
		{pin: "wrong-pin", status: http.StatusUnauthorized},
		{pin: "654321", status: http.StatusOK},
	} {
		values := url.Values{"pin": []string{tt.pin}}
		req, err := http.NewRequest(http.MethodPost, approveURL, strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", issuer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tt.status {
			t.Fatalf("pin %q status = %d, want %d, body = %s", tt.pin, resp.StatusCode, tt.status, body)
		}
	}
}

func TestSemanticApprovalRejectsCrossOriginPost(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	issuer := "http://127.0.0.1:" + itoa(providerPort)
	registerSemanticAuthorizationFixtures(t, dataDir)

	servers, _, err := Start(Config{ProviderPort: providerPort, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servers.Shutdown(context.Background()) })

	var created createAuthorizationRequestOutput
	postAuthorizationJSON(t, issuer+"/api/authorization-requests", createAuthorizationRequestInput{
		AgentID:       "codex",
		ApplicationID: "github",
		Action:        "issue.create",
		ResourceType:  "repository",
		ResourceID:    "yukunlabs/anyauth",
		TTLSeconds:    1800,
	}, http.StatusCreated, &created)

	approveURL := issuer + "/approvals/" + url.PathEscape(created.Request.ID) + "/approve"
	req, err := http.NewRequest(http.MethodPost, approveURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://attacker.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin approval status = %d", resp.StatusCode)
	}
}

func TestAccessEvaluationEchoesRequestID(t *testing.T) {
	dataDir := t.TempDir()
	providerPort := freePort(t)
	issuer := "http://127.0.0.1:" + itoa(providerPort)
	registerSemanticAuthorizationFixtures(t, dataDir)

	servers, _, err := Start(Config{ProviderPort: providerPort, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servers.Shutdown(context.Background()) })

	body, err := json.Marshal(authz.Request{
		Actor:         authz.Identity{Type: authz.IdentityAgent, ID: "codex"},
		Subject:       authz.Identity{Type: authz.IdentityHuman, ID: "local-user"},
		ApplicationID: "github",
		Action:        authz.Action{Name: "issue.create"},
		Resource:      authz.Resource{Type: "repository", ID: "yukunlabs/anyauth"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, issuer+"/access/v1/evaluation", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "request-test-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluation status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Request-ID"); got != "request-test-123" {
		t.Fatalf("X-Request-ID = %q", got)
	}
}

func registerSemanticAuthorizationFixtures(t *testing.T, dataDir string) {
	t.Helper()
	if _, err := agentregistry.Add(dataDir, agentregistry.Agent{ID: "codex", Name: "Codex"}); err != nil {
		t.Fatal(err)
	}
	if _, err := authzstore.New(dataDir).AddApplication(authzstore.Application{
		ID:            "github",
		Name:          "GitHub",
		Actions:       []string{"issue.create", "repository.read"},
		ResourceTypes: []string{"repository"},
	}); err != nil {
		t.Fatal(err)
	}
}

func postAuthorizationJSON(t *testing.T, target string, input any, status int, output any) {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(target, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("POST %s status = %d, want %d, body = %s", target, resp.StatusCode, status, responseBody)
	}
	if output != nil {
		if err := json.Unmarshal(responseBody, output); err != nil {
			t.Fatalf("decode POST %s response: %v; body = %s", target, err, responseBody)
		}
	}
}
