package authzstore

import (
	"context"
	"testing"
	"time"

	"github.com/yukunlabs/anyauth/internal/authz"
)

func TestAuthorizationRequestApprovalAndRevocation(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	store := New(t.TempDir())
	_, err := store.AddApplication(Application{
		ID:            "github",
		Name:          "GitHub",
		Actions:       []string{"issue.create"},
		ResourceTypes: []string{"repository"},
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	request, err := store.CreateRequest(testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if request.Status != RequestPending {
		t.Fatalf("status = %q", request.Status)
	}

	request, grant, err := store.DecideRequest(request.ID, true, "grt_test", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if request.Status != RequestApproved || grant == nil || request.GrantID != grant.ID {
		t.Fatalf("unexpected approval result: request=%#v grant=%#v", request, grant)
	}

	grants, err := store.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	decision, err := authz.Evaluate(grants, authz.Request{
		Actor:         request.Actor,
		Subject:       request.Subject,
		ApplicationID: request.ApplicationID,
		Action:        authz.Action{Name: request.Permission.Action},
		Resource:      authz.Resource{Type: request.Permission.Resource.Type, ID: request.Permission.Resource.ID},
		Context:       authz.RequestContext{TaskID: request.TaskID},
	}, authz.EvaluateOptions{Now: now.Add(2 * time.Minute), DecisionID: "dec_test"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("approved grant did not authorize request: %#v", decision)
	}

	if _, err := store.RevokeGrant(grant.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	grants, err = store.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	decision, err = authz.Evaluate(grants, authz.Request{
		Actor:         request.Actor,
		Subject:       request.Subject,
		ApplicationID: request.ApplicationID,
		Action:        authz.Action{Name: request.Permission.Action},
		Resource:      authz.Resource{Type: request.Permission.Resource.Type, ID: request.Permission.Resource.ID},
		Context:       authz.RequestContext{TaskID: request.TaskID},
	}, authz.EvaluateOptions{Now: now.Add(4 * time.Minute), DecisionID: "dec_revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.ReasonCode != authz.ReasonGrantRevoked {
		t.Fatalf("revoked grant decision = %#v", decision)
	}
}

func TestAuthorizationRequestValidatesApplicationCatalog(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	store := New(t.TempDir())
	_, err := store.AddApplication(Application{
		ID:            "github",
		Actions:       []string{"issue.create"},
		ResourceTypes: []string{"repository"},
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := testRequest(now)
	request.Permission.Action = "repository.delete"
	if _, err := store.CreateRequest(request); err == nil {
		t.Fatal("expected undeclared action to be rejected")
	}
	request = testRequest(now)
	request.Permission.Resource.Type = "organization"
	if _, err := store.CreateRequest(request); err == nil {
		t.Fatal("expected undeclared resource type to be rejected")
	}
}

func TestDenyAndExpireAuthorizationRequest(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	store := New(t.TempDir())
	_, err := store.AddApplication(Application{
		ID:            "github",
		Actions:       []string{"issue.create"},
		ResourceTypes: []string{"repository"},
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}

	denied, err := store.CreateRequest(testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	denied, grant, err := store.DecideRequest(denied.ID, false, "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != RequestDenied || grant != nil {
		t.Fatalf("unexpected deny result: request=%#v grant=%#v", denied, grant)
	}

	expiredRequest := testRequest(now)
	expiredRequest.ID = "req_expired"
	expiredRequest.ExpiresAt = now.Add(time.Minute)
	expiredRequest, err = store.CreateRequest(expiredRequest)
	if err != nil {
		t.Fatal(err)
	}
	expiredRequest, _, err = store.DecideRequest(expiredRequest.ID, true, "grt_expired", now.Add(2*time.Minute))
	if err == nil || expiredRequest.Status != RequestExpired {
		t.Fatalf("expected expired request, got request=%#v err=%v", expiredRequest, err)
	}
}

func TestAuthorizationStoreRejectsGrantThatExceedsApproval(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	store := New(t.TempDir())
	_, err := store.AddApplication(Application{
		ID:            "github",
		Actions:       []string{"issue.create", "repository.delete"},
		ResourceTypes: []string{"repository"},
		CreatedAt:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.CreateRequest(testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.DecideRequest(request.ID, true, "grt_test", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.Grants[0].Permissions = append(state.Grants[0].Permissions, authz.Permission{
		Action:   "repository.delete",
		Resource: authz.ResourceSelector{Type: "repository", ID: "yukunlabs/anyauth"},
	})
	if err := validateFile(state); err == nil {
		t.Fatal("expected grant broader than its approval to be rejected")
	}

	state.Grants = nil
	if err := validateFile(state); err == nil {
		t.Fatal("expected approved request with missing grant to be rejected")
	}

	state, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.Requests = nil
	if err := validateFile(state); err == nil {
		t.Fatal("expected root grant without an approval to be rejected")
	}
}

func testRequest(now time.Time) AuthorizationRequest {
	return AuthorizationRequest{
		ID:            "req_test",
		Actor:         authz.Identity{Type: authz.IdentityAgent, ID: "codex"},
		Subject:       authz.Identity{Type: authz.IdentityHuman, ID: "local-user"},
		ApplicationID: "github",
		Permission: authz.Permission{
			Action:   "issue.create",
			Resource: authz.ResourceSelector{Type: "repository", ID: "yukunlabs/anyauth"},
		},
		TaskID:              "task-test",
		TaskName:            "Improve AnyAuth authorization",
		RequestedTTLSeconds: 1800,
		Status:              RequestPending,
		CreatedAt:           now,
		ExpiresAt:           now.Add(15 * time.Minute),
	}
}
