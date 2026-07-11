package authz

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateGrantLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	base := testGrant(now)
	request := testRequest()
	revokedAt := now.Add(-time.Minute)

	tests := []struct {
		name   string
		grants []Grant
		mutate func(*Request)
		allow  bool
		reason ReasonCode
	}{
		{name: "matching active grant", grants: []Grant{base}, allow: true, reason: ReasonMatchingGrant},
		{name: "default deny", allow: false, reason: ReasonNoMatchingGrant},
		{name: "wrong action", grants: []Grant{base}, mutate: func(r *Request) { r.Action.Name = "issue.delete" }, reason: ReasonPermissionNotGranted},
		{name: "wrong resource", grants: []Grant{base}, mutate: func(r *Request) { r.Resource.ID = "yukunlabs/other" }, reason: ReasonPermissionNotGranted},
		{name: "wrong actor", grants: []Grant{base}, mutate: func(r *Request) { r.Actor.ID = "claude" }, reason: ReasonNoMatchingGrant},
		{name: "task mismatch", grants: []Grant{base}, mutate: func(r *Request) { r.Context.TaskID = "different-task" }, reason: ReasonTaskMismatch},
		{name: "not yet valid", grants: []Grant{withGrant(base, func(g *Grant) { g.NotBefore = now.Add(time.Minute) })}, reason: ReasonGrantNotYetValid},
		{name: "expired", grants: []Grant{withGrant(base, func(g *Grant) { g.ExpiresAt = now })}, reason: ReasonGrantExpired},
		{name: "revoked", grants: []Grant{withGrant(base, func(g *Grant) { g.RevokedAt = &revokedAt })}, reason: ReasonGrantRevoked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request
			if tt.mutate != nil {
				tt.mutate(&req)
			}
			decision, err := Evaluate(tt.grants, req, EvaluateOptions{Now: now, DecisionID: "dec_test"})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != tt.allow {
				t.Fatalf("allowed = %v, want %v", decision.Allowed, tt.allow)
			}
			if decision.ReasonCode != tt.reason {
				t.Fatalf("reason = %q, want %q", decision.ReasonCode, tt.reason)
			}
		})
	}
}

func TestEvaluateWildcardResourceSelector(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	grant := testGrant(now)
	grant.Permissions[0].Resource.ID = AllResources
	request := testRequest()
	request.Resource.ID = "yukunlabs/another-repo"

	decision, err := Evaluate([]Grant{grant}, request, EvaluateOptions{Now: now, DecisionID: "dec_test"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatalf("expected wildcard resource grant to allow request: %#v", decision)
	}
}

func TestEvaluateDerivedGrantAndAncestorRevocation(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	parent := testGrant(now)
	parent.ID = "grt_parent"
	parent.Permissions[0].Resource.ID = AllResources
	child := testGrant(now)
	child.ID = "grt_child"
	child.Issuer = parent.Grantee
	child.Grantee = Identity{Type: IdentityAgent, ID: "subagent"}
	child.ParentGrantID = parent.ID
	child.ExpiresAt = now.Add(10 * time.Minute)

	request := testRequest()
	request.Actor = child.Grantee
	decision, err := Evaluate([]Grant{parent, child}, request, EvaluateOptions{Now: now, DecisionID: "dec_child"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || len(decision.GrantIDs) != 2 {
		t.Fatalf("expected derived grant chain to allow: %#v", decision)
	}

	revokedAt := now.Add(-time.Minute)
	parent.RevokedAt = &revokedAt
	decision, err = Evaluate([]Grant{parent, child}, request, EvaluateOptions{Now: now, DecisionID: "dec_revoked"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.ReasonCode != ReasonGrantRevoked {
		t.Fatalf("expected revoked ancestor to deny: %#v", decision)
	}
}

func TestValidateDerivedGrantRejectsPrivilegeEscalation(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	parent := testGrant(now)
	parent.ID = "grt_parent"

	tests := []struct {
		name   string
		mutate func(*Grant)
		want   string
	}{
		{name: "extra action", mutate: func(g *Grant) { g.Permissions[0].Action = "repository.delete" }, want: "exceeds parent authority"},
		{name: "broader resource", mutate: func(g *Grant) { g.Permissions[0].Resource.ID = AllResources }, want: "exceeds parent authority"},
		{name: "longer expiry", mutate: func(g *Grant) { g.ExpiresAt = parent.ExpiresAt.Add(time.Minute) }, want: "must not exceed parent"},
		{name: "created before parent", mutate: func(g *Grant) { g.CreatedAt = parent.CreatedAt.Add(-time.Minute); g.NotBefore = parent.NotBefore }, want: "created_at must not precede parent"},
		{name: "different application", mutate: func(g *Grant) { g.ApplicationID = "cloud" }, want: "application must equal parent"},
		{name: "different subject", mutate: func(g *Grant) { g.Subject.ID = "other-human" }, want: "subject must equal parent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			child := testGrant(now)
			child.ID = "grt_child"
			child.Issuer = parent.Grantee
			child.Grantee = Identity{Type: IdentityAgent, ID: "subagent"}
			child.ParentGrantID = parent.ID
			tt.mutate(&child)
			err := ValidateDerivedGrant(child, parent)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestEvaluateRejectsMalformedState(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	grant := testGrant(now)
	grant.ParentGrantID = "missing"

	_, err := Evaluate([]Grant{grant}, testRequest(), EvaluateOptions{Now: now, DecisionID: "dec_test"})
	if err == nil || !strings.Contains(err.Error(), "missing parent") {
		t.Fatalf("error = %v, want missing parent", err)
	}
}

func testGrant(now time.Time) Grant {
	return Grant{
		ID:            "grt_test",
		Subject:       Identity{Type: IdentityHuman, ID: "local-user"},
		Issuer:        Identity{Type: IdentityHuman, ID: "local-user"},
		Grantee:       Identity{Type: IdentityAgent, ID: "codex"},
		ApplicationID: "github",
		Permissions: []Permission{{
			Action:   "issue.create",
			Resource: ResourceSelector{Type: "repository", ID: "yukunlabs/anyauth"},
		}},
		TaskID:    "improve-anyauth-authorization",
		NotBefore: now.Add(-time.Minute),
		ExpiresAt: now.Add(30 * time.Minute),
		CreatedAt: now.Add(-time.Minute),
	}
}

func testRequest() Request {
	return Request{
		Actor:         Identity{Type: IdentityAgent, ID: "codex"},
		Subject:       Identity{Type: IdentityHuman, ID: "local-user"},
		ApplicationID: "github",
		Action:        Action{Name: "issue.create"},
		Resource:      Resource{Type: "repository", ID: "yukunlabs/anyauth"},
		Context:       RequestContext{TaskID: "improve-anyauth-authorization"},
	}
}

func withGrant(grant Grant, mutate func(*Grant)) Grant {
	mutate(&grant)
	return grant
}
