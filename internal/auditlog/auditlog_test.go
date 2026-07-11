package auditlog

import (
	"strings"
	"testing"
	"time"
)

func TestAppendAndLoadEvents(t *testing.T) {
	dataDir := t.TempDir()
	now := time.Date(2026, 6, 9, 11, 0, 0, 0, time.UTC)

	first, err := Append(dataDir, Event{
		Time:      now,
		Type:      "delegation.create",
		Decision:  "allow",
		ActorType: "human",
		HumanSub:  "local-user",
		AgentID:   "codex",
		Scopes:    []string{"app.read", "app.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" {
		t.Fatal("expected generated id")
	}

	second, err := Append(dataDir, Event{
		Time:          now.Add(time.Minute),
		Type:          "authorization.decision",
		Decision:      "allow",
		DecisionID:    "dec_test",
		ApplicationID: "github",
		Action:        "issue.create",
		ResourceType:  "repository",
		GrantIDs:      []string{"grt_test", "grt_test"},
		AgentID:       "codex",
		Resource:      "yukunlabs/anyauth",
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := Load(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2", len(events))
	}
	if events[0].ID != first.ID || events[1].ID != second.ID {
		t.Fatalf("events out of order: %+v", events)
	}
	if strings.Join(events[0].Scopes, " ") != "app.read" {
		t.Fatalf("scopes were not normalized: %+v", events[0].Scopes)
	}
	if events[1].DecisionID != "dec_test" || events[1].ApplicationID != "github" ||
		events[1].Action != "issue.create" || strings.Join(events[1].GrantIDs, " ") != "grt_test" {
		t.Fatalf("semantic authorization fields were not preserved: %+v", events[1])
	}

	events, err = Load(dataDir, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != second.ID {
		t.Fatalf("limit returned %+v, want second event", events)
	}
}

func TestValidateRejectsIncompleteEvent(t *testing.T) {
	if err := Validate(Event{Type: "proxy.allow", Decision: "allow", Time: time.Now()}); err == nil {
		t.Fatal("expected missing id to fail")
	}
	if err := Validate(Event{ID: "evt_1", Decision: "allow", Time: time.Now()}); err == nil {
		t.Fatal("expected missing type to fail")
	}
	if err := Validate(Event{ID: "evt_1", Type: "proxy.allow", Time: time.Now()}); err == nil {
		t.Fatal("expected missing decision to fail")
	}
}
