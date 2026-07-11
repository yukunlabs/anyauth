package localdev

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/auditlog"
	"github.com/yukunlabs/anyauth/internal/authz"
	"github.com/yukunlabs/anyauth/internal/authzstore"
	"github.com/yukunlabs/anyauth/internal/jose"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

const (
	defaultAuthorizationTTL = 30 * time.Minute
	maxAuthorizationTTL     = 24 * time.Hour
	requestApprovalWindow   = 15 * time.Minute
)

type createAuthorizationRequestInput struct {
	AgentID       string `json:"agent_id"`
	ApplicationID string `json:"application_id"`
	Action        string `json:"action"`
	ResourceType  string `json:"resource_type"`
	ResourceID    string `json:"resource_id"`
	TaskID        string `json:"task_id,omitempty"`
	TaskName      string `json:"task_name,omitempty"`
	TTLSeconds    int64  `json:"ttl_seconds,omitempty"`
}

type createAuthorizationRequestOutput struct {
	Request     authzstore.AuthorizationRequest `json:"request"`
	ApprovalURL string                          `json:"approval_url"`
}

type accessEvaluationOutput struct {
	Decision bool                    `json:"decision"`
	Context  accessEvaluationContext `json:"context"`
}

type accessEvaluationContext struct {
	DecisionID string           `json:"decision_id"`
	ReasonCode authz.ReasonCode `json:"reason_code"`
	Reason     string           `json:"reason"`
	GrantIDs   []string         `json:"grant_ids,omitempty"`
}

func (a *app) authorizationRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input createAuthorizationRequestInput
	if err := decodeJSONRequest(w, r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	input.AgentID = strings.TrimSpace(input.AgentID)
	input.ApplicationID = strings.TrimSpace(input.ApplicationID)
	input.Action = strings.TrimSpace(input.Action)
	input.ResourceType = strings.TrimSpace(input.ResourceType)
	input.ResourceID = strings.TrimSpace(input.ResourceID)
	input.TaskID = strings.TrimSpace(input.TaskID)
	input.TaskName = strings.TrimSpace(input.TaskName)

	agents, err := agentregistry.Load(a.cfg.DataDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}
	agent, ok := agentregistry.Find(agents, input.AgentID)
	if !ok || agent.Disabled {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "registered active agent is required"})
		return
	}
	ttl := time.Duration(input.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = defaultAuthorizationTTL
	}
	if ttl < time.Minute || ttl > maxAuthorizationTTL {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "ttl must be between 1 minute and 24 hours"})
		return
	}
	requestID, err := randomPrefixedID("req", 16)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}
	if input.TaskID == "" && input.TaskName != "" {
		input.TaskID, err = randomPrefixedID("task", 12)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
			return
		}
	}
	now := time.Now().UTC()
	request, err := a.authorization.CreateRequest(authzstore.AuthorizationRequest{
		ID:            requestID,
		Actor:         authz.Identity{Type: authz.IdentityAgent, ID: agent.ID},
		Subject:       authz.Identity{Type: authz.IdentityHuman, ID: a.profile.Sub},
		ApplicationID: input.ApplicationID,
		Permission: authz.Permission{
			Action:   input.Action,
			Resource: authz.ResourceSelector{Type: input.ResourceType, ID: input.ResourceID},
		},
		TaskID:              input.TaskID,
		TaskName:            input.TaskName,
		RequestedTTLSeconds: int64(ttl / time.Second),
		Status:              authzstore.RequestPending,
		CreatedAt:           now,
		ExpiresAt:           now.Add(requestApprovalWindow),
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if _, err := auditlog.Append(a.cfg.DataDir, auditlog.Event{
		Type:          "authorization.request",
		Decision:      "pending",
		ActorType:     string(request.Actor.Type),
		HumanSub:      request.Subject.ID,
		AgentID:       request.Actor.ID,
		ApplicationID: request.ApplicationID,
		Action:        request.Permission.Action,
		ResourceType:  request.Permission.Resource.Type,
		Resource:      request.Permission.Resource.ID,
		TaskID:        request.TaskID,
		TaskName:      request.TaskName,
	}); err != nil {
		log.Printf("failed to append authorization request audit event: %v", err)
	}
	writeJSON(w, http.StatusCreated, createAuthorizationRequestOutput{
		Request:     request,
		ApprovalURL: a.issuer + "/approvals",
	})
}

func (a *app) approvals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := a.authorization.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	var body strings.Builder
	body.WriteString("<h1>Agent authorization approvals</h1>")
	body.WriteString(`<p class="muted">Review semantic actions requested by registered local agents.</p>`)
	pending := 0
	for _, request := range state.Requests {
		if request.StatusAt(now) != authzstore.RequestPending {
			continue
		}
		pending++
		body.WriteString(`<section style="margin:1.5rem 0;padding:1rem;border:1px solid #ddd;border-radius:.5rem">`)
		body.WriteString("<h2>" + html.EscapeString(request.Permission.Action) + "</h2>")
		body.WriteString("<dl>")
		approvalDetail(&body, "Agent", request.Actor.ID)
		approvalDetail(&body, "Human", request.Subject.ID)
		approvalDetail(&body, "Application", request.ApplicationID)
		approvalDetail(&body, "Resource", request.Permission.Resource.Type+":"+request.Permission.Resource.ID)
		approvalDetail(&body, "Task", request.TaskName)
		approvalDetail(&body, "Task ID", request.TaskID)
		approvalDetail(&body, "Grant duration", (time.Duration(request.RequestedTTLSeconds) * time.Second).String())
		approvalDetail(&body, "Request expires", request.ExpiresAt.Format(time.RFC3339))
		body.WriteString("</dl>")
		pinControl := ""
		if userstore.HasPIN(a.profile) {
			pinControl = `<p><label>PIN<br><input name="pin" type="password" autocomplete="current-password" required></label></p>`
		} else {
			pinControl = `<p class="muted">No local PIN is configured. Approval relies on an explicit local browser action.</p>`
		}
		id := url.PathEscape(request.ID)
		body.WriteString(`<form method="post" action="/approvals/` + id + `/approve">` + pinControl + `<button type="submit">Approve</button></form>`)
		body.WriteString(`<form method="post" action="/approvals/` + id + `/deny" style="margin-top:.5rem">` + pinControl + `<button type="submit">Deny</button></form>`)
		body.WriteString("</section>")
	}
	if pending == 0 {
		body.WriteString(`<p>No pending authorization requests.</p>`)
	}
	writeHTML(w, "AnyAuth Agent Approvals", body.String())
}

func (a *app) approvalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.validateLocalFormOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/approvals/"), "/"), "/")
	if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "deny") {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if userstore.HasPIN(a.profile) {
		ok, err := userstore.VerifyPIN(a.profile, r.Form.Get("pin"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeHTMLStatus(w, http.StatusUnauthorized, "Approval Error", "<h1>PIN verification failed</h1>")
			return
		}
	}
	approve := parts[1] == "approve"
	grantID := ""
	var err error
	if approve {
		grantID, err = randomPrefixedID("grt", 16)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	request, grant, err := a.authorization.DecideRequest(parts[0], approve, grantID, time.Now())
	if err != nil {
		writeHTMLStatus(w, http.StatusConflict, "Approval Error", "<h1>Approval Error</h1><pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	decision := "deny"
	eventType := "authorization.deny"
	if approve {
		decision = "allow"
		eventType = "authorization.approve"
	}
	event := auditlog.Event{
		Type:          eventType,
		Decision:      decision,
		ActorType:     "human",
		HumanSub:      request.Subject.ID,
		AgentID:       request.Actor.ID,
		ApplicationID: request.ApplicationID,
		Action:        request.Permission.Action,
		ResourceType:  request.Permission.Resource.Type,
		Resource:      request.Permission.Resource.ID,
		TaskID:        request.TaskID,
		TaskName:      request.TaskName,
	}
	if grant != nil {
		event.GrantIDs = []string{grant.ID}
	}
	if _, err := auditlog.Append(a.cfg.DataDir, event); err != nil {
		log.Printf("failed to append authorization approval audit event: %v", err)
	}
	writeHTML(w, "Authorization Decision", fmt.Sprintf(`<h1>Request %s</h1><p>Agent <strong>%s</strong> requesting <strong>%s</strong> on <strong>%s:%s</strong>.</p><p><a href="/approvals">Back to approvals</a></p>`,
		html.EscapeString(string(request.Status)),
		html.EscapeString(request.Actor.ID),
		html.EscapeString(request.Permission.Action),
		html.EscapeString(request.Permission.Resource.Type),
		html.EscapeString(request.Permission.Resource.ID),
	))
}

func (a *app) accessEvaluation(w http.ResponseWriter, r *http.Request) {
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-ID")); requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request authz.Request
	if err := decodeJSONRequestLoose(w, r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if !request.Subject.Equal(authz.Identity{Type: authz.IdentityHuman, ID: a.profile.Sub}) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "subject must be the local AnyAuth user"})
		return
	}
	agents, err := agentregistry.Load(a.cfg.DataDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}
	agent, ok := agentregistry.Find(agents, request.Actor.ID)
	if request.Actor.Type != authz.IdentityAgent || !ok || agent.Disabled {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": "actor must be a registered active agent"})
		return
	}
	if err := a.authorization.ValidateEvaluation(request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	authorizer, err := authz.NewAuthorizer(
		a.authorization,
		authzAuditRecorder{dataDir: a.cfg.DataDir},
		time.Now,
		func() (string, error) { return randomPrefixedID("dec", 16) },
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}
	decision, err := authorizer.Check(r.Context(), request)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error", "error_description": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, accessEvaluationOutput{
		Decision: decision.Allowed,
		Context: accessEvaluationContext{
			DecisionID: decision.DecisionID,
			ReasonCode: decision.ReasonCode,
			Reason:     decision.Reason,
			GrantIDs:   decision.GrantIDs,
		},
	})
}

type authzAuditRecorder struct {
	dataDir string
}

func (r authzAuditRecorder) RecordDecision(_ context.Context, request authz.Request, decision authz.Decision) error {
	result := "deny"
	if decision.Allowed {
		result = "allow"
	}
	_, err := auditlog.Append(r.dataDir, auditlog.Event{
		Type:          "authorization.decision",
		Decision:      result,
		DecisionID:    decision.DecisionID,
		ActorType:     string(request.Actor.Type),
		HumanSub:      request.Subject.ID,
		AgentID:       request.Actor.ID,
		ApplicationID: request.ApplicationID,
		Action:        request.Action.Name,
		ResourceType:  request.Resource.Type,
		Resource:      request.Resource.ID,
		TaskID:        request.Context.TaskID,
		GrantIDs:      decision.GrantIDs,
		Reason:        decision.Reason,
	})
	return err
}

func decodeJSONRequest(w http.ResponseWriter, r *http.Request, target any) error {
	return decodeJSONRequestWithMode(w, r, target, true)
}

func decodeJSONRequestLoose(w http.ResponseWriter, r *http.Request, target any) error {
	return decodeJSONRequestWithMode(w, r, target, false)
}

func decodeJSONRequestWithMode(w http.ResponseWriter, r *http.Request, target any, strict bool) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain exactly one JSON object")
	}
	return nil
}

func (a *app) validateLocalFormOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && origin != a.issuer {
		return fmt.Errorf("cross-origin approval request rejected")
	}
	if origin == "" {
		referer := strings.TrimSpace(r.Header.Get("Referer"))
		if referer != "" {
			parsed, err := url.Parse(referer)
			if err != nil || parsed.Scheme+"://"+parsed.Host != a.issuer {
				return fmt.Errorf("cross-origin approval request rejected")
			}
		}
	}
	return nil
}

func approvalDetail(body *strings.Builder, name string, value string) {
	if value == "" {
		return
	}
	body.WriteString("<dt><strong>" + html.EscapeString(name) + "</strong></dt><dd>" + html.EscapeString(value) + "</dd>")
}

func randomPrefixedID(prefix string, size int) (string, error) {
	value, err := jose.RandomURLToken(size)
	if err != nil {
		return "", err
	}
	return prefix + "_" + value, nil
}
