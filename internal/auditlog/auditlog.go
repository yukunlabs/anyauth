package auditlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yukunlabs/anyauth/internal/jose"
)

const FileName = "audit.jsonl"

type Event struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Type         string    `json:"type"`
	Decision     string    `json:"decision"`
	ActorType    string    `json:"actor_type,omitempty"`
	HumanSub     string    `json:"human_sub,omitempty"`
	AgentID      string    `json:"agent_id,omitempty"`
	DelegationID string    `json:"delegation_id,omitempty"`
	TokenID      string    `json:"token_id,omitempty"`
	Audience     string    `json:"audience,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	Resource     string    `json:"resource,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Note         string    `json:"note,omitempty"`
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Append(dataDir string, event Event) (Event, error) {
	event = normalize(event)
	if event.ID == "" {
		id, err := randomID()
		if err != nil {
			return Event{}, err
		}
		event.ID = id
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if err := Validate(event); err != nil {
		return Event{}, err
	}

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Event{}, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Event{}, err
	}
	defer file.Close()

	raw, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return Event{}, err
	}
	return event, nil
}

func Load(dataDir string, limit int) ([]Event, error) {
	file, err := os.Open(Path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, err
		}
		event = normalize(event)
		if err := Validate(event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

func Validate(event Event) error {
	if event.ID == "" {
		return fmt.Errorf("audit event id is required")
	}
	if event.Type == "" {
		return fmt.Errorf("audit event type is required")
	}
	if event.Decision == "" {
		return fmt.Errorf("audit event decision is required")
	}
	if event.Time.IsZero() {
		return fmt.Errorf("audit event time is required")
	}
	return nil
}

func normalize(event Event) Event {
	event.ID = strings.TrimSpace(event.ID)
	event.Type = strings.TrimSpace(event.Type)
	event.Decision = strings.TrimSpace(event.Decision)
	event.ActorType = strings.TrimSpace(event.ActorType)
	event.HumanSub = strings.TrimSpace(event.HumanSub)
	event.AgentID = strings.TrimSpace(event.AgentID)
	event.DelegationID = strings.TrimSpace(event.DelegationID)
	event.TokenID = strings.TrimSpace(event.TokenID)
	event.Audience = strings.TrimSpace(event.Audience)
	event.Resource = strings.TrimSpace(event.Resource)
	event.Reason = strings.TrimSpace(event.Reason)
	event.Note = strings.TrimSpace(event.Note)
	event.Scopes = normalizeScopes(event.Scopes)
	if !event.Time.IsZero() {
		event.Time = event.Time.UTC()
	}
	return event
}

func normalizeScopes(scopes []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	return out
}

func randomID() (string, error) {
	value, err := jose.RandomURLToken(16)
	if err != nil {
		return "", err
	}
	return "evt_" + value, nil
}
