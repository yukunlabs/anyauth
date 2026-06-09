package policy

import (
	"testing"
	"time"
)

func TestAddLoadAndRemovePolicy(t *testing.T) {
	dataDir := t.TempDir()

	rule, err := Add(dataDir, Rule{
		ID:             "read-private",
		Description:    "Allow read access to private pages.",
		Effect:         EffectAllow,
		Methods:        []string{"get", "GET"},
		PathPrefix:     "private",
		AgentID:        "codex",
		RequiredScopes: []string{"app.read", "app.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rule.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt")
	}
	if rule.PathPrefix != "/private" {
		t.Fatalf("path prefix = %s, want /private", rule.PathPrefix)
	}

	rules, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count = %d, want 1", len(rules))
	}
	if len(rules[0].Methods) != 1 || rules[0].Methods[0] != "GET" {
		t.Fatalf("methods were not normalized: %+v", rules[0].Methods)
	}
	if len(rules[0].RequiredScopes) != 1 || rules[0].RequiredScopes[0] != "app.read" {
		t.Fatalf("scopes were not normalized: %+v", rules[0].RequiredScopes)
	}

	removed, err := Remove(dataDir, "read-private")
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != "read-private" {
		t.Fatalf("removed = %+v", removed)
	}
}

func TestEvaluateAllowsWhenNoPoliciesConfigured(t *testing.T) {
	decision := Evaluate(nil, Request{Method: "GET", Path: "/private", AgentID: "codex"})
	if !decision.Allowed {
		t.Fatalf("expected default allow with no policies, got %+v", decision)
	}
}

func TestEvaluateAllowsMatchingScope(t *testing.T) {
	rules := []Rule{testRule("read-private", EffectAllow, "GET", "/private", "app.read")}
	decision := Evaluate(rules, Request{
		Method:  "GET",
		Path:    "/private/page",
		AgentID: "codex",
		Scopes:  []string{"app.read"},
	})
	if !decision.Allowed || decision.Rule == nil || decision.Rule.ID != "read-private" {
		t.Fatalf("expected allow, got %+v", decision)
	}
}

func TestEvaluateDeniesMissingScope(t *testing.T) {
	rules := []Rule{testRule("read-private", EffectAllow, "GET", "/private", "app.read")}
	decision := Evaluate(rules, Request{
		Method:  "GET",
		Path:    "/private/page",
		AgentID: "codex",
		Scopes:  []string{"app.write"},
	})
	if decision.Allowed || decision.Rule == nil || decision.Rule.ID != "read-private" {
		t.Fatalf("expected missing scope deny, got %+v", decision)
	}
}

func TestEvaluateDeniesWhenNoAllowPolicyMatches(t *testing.T) {
	rules := []Rule{testRule("read-private", EffectAllow, "GET", "/private", "app.read")}
	decision := Evaluate(rules, Request{
		Method:  "GET",
		Path:    "/admin",
		AgentID: "codex",
		Scopes:  []string{"app.read"},
	})
	if decision.Allowed || decision.Rule != nil {
		t.Fatalf("expected default deny with configured policies, got %+v", decision)
	}
}

func TestEvaluateDenyPolicyWins(t *testing.T) {
	rules := []Rule{
		testRule("allow-admin", EffectAllow, "GET", "/admin", "app.read"),
		testRule("deny-admin", EffectDeny, "GET", "/admin", ""),
	}
	decision := Evaluate(rules, Request{
		Method:  "GET",
		Path:    "/admin",
		AgentID: "codex",
		Scopes:  []string{"app.read"},
	})
	if decision.Allowed || decision.Rule == nil || decision.Rule.ID != "deny-admin" {
		t.Fatalf("expected deny policy to win, got %+v", decision)
	}
}

func TestEvaluateHonorsAgentBinding(t *testing.T) {
	rule := testRule("codex-only", EffectAllow, "GET", "/private", "app.read")
	rule.AgentID = "codex"
	decision := Evaluate([]Rule{rule}, Request{
		Method:  "GET",
		Path:    "/private",
		AgentID: "other-agent",
		Scopes:  []string{"app.read"},
	})
	if decision.Allowed {
		t.Fatalf("expected agent mismatch deny, got %+v", decision)
	}
}

func TestValidateRejectsBadRule(t *testing.T) {
	if err := Validate(Rule{Effect: EffectAllow, PathPrefix: "/", CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected missing id to fail")
	}
	if err := Validate(Rule{ID: "bad id", Effect: EffectAllow, PathPrefix: "/", CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected whitespace id to fail")
	}
	if err := Validate(Rule{ID: "bad", Effect: "maybe", PathPrefix: "/", CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected bad effect to fail")
	}
	if err := Validate(Rule{ID: "bad", Effect: EffectAllow, PathPrefix: "relative", CreatedAt: time.Now()}); err == nil {
		t.Fatal("expected bad path to fail")
	}
}

func testRule(id string, effect Effect, method string, pathPrefix string, scope string) Rule {
	rule := Rule{
		ID:         id,
		Effect:     effect,
		Methods:    []string{method},
		PathPrefix: pathPrefix,
		CreatedAt:  time.Now(),
	}
	if scope != "" {
		rule.RequiredScopes = []string{scope}
	}
	return rule
}
