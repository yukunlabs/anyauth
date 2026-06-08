package agentregistry

import (
	"testing"
)

func TestAddLoadAndRemoveAgent(t *testing.T) {
	dataDir := t.TempDir()

	agent, err := Add(dataDir, Agent{
		ID:   "codex",
		Name: "Codex Local Agent",
		Kind: "cli",
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	agents, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("agent count = %d, want 1", len(agents))
	}
	if agents[0].ID != "codex" || agents[0].Name != "Codex Local Agent" || agents[0].Kind != "cli" {
		t.Fatalf("unexpected agent: %+v", agents[0])
	}

	removed, err := Remove(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != "codex" {
		t.Fatalf("removed agent = %+v", removed)
	}

	agents, err = Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Fatalf("agent count after remove = %d, want 0", len(agents))
	}
}

func TestAddAgentRejectsDuplicateID(t *testing.T) {
	dataDir := t.TempDir()

	if _, err := Add(dataDir, Agent{ID: "codex", Name: "Codex"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(dataDir, Agent{ID: "codex", Name: "Codex Again"}); err == nil {
		t.Fatal("expected duplicate agent id to fail")
	}
}

func TestValidateAgentRejectsBadID(t *testing.T) {
	if err := Validate(Agent{Name: "Missing ID"}); err == nil {
		t.Fatal("expected missing id to fail")
	}
	if err := Validate(Agent{ID: "bad id", Name: "Bad ID"}); err == nil {
		t.Fatal("expected whitespace id to fail")
	}
	if err := Validate(Agent{ID: "nameless"}); err == nil {
		t.Fatal("expected missing name to fail")
	}
}
