package delegation

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/jose"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

func TestCreateAndValidateDelegationToken(t *testing.T) {
	dataDir := t.TempDir()
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{ID: "codex", Name: "Codex Local Agent"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)

	record, token, err := Create(dataDir, CreateRequest{
		Issuer:   "http://127.0.0.1:7100",
		Audience: AudienceForProtectPort(7200),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		TaskName: "Triage local issues",
		Scopes:   []string{"app.read", "app.write"},
		Note:     "test delegation",
		TTL:      30 * time.Minute,
		Now:      now,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected token")
	}
	if record.TokenSHA256 == "" || strings.Contains(record.TokenSHA256, token) {
		t.Fatalf("unexpected token hash: %s", record.TokenSHA256)
	}
	if record.TaskID == "" || record.TaskName != "Triage local issues" {
		t.Fatalf("unexpected task fields: %+v", record)
	}

	ctx, err := ValidateToken(token, ValidateOptions{
		Issuer:    "http://127.0.0.1:7100",
		Audience:  AudienceForProtectPort(7200),
		DataDir:   dataDir,
		Now:       now.Add(time.Minute),
		PublicKey: &key.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Delegation.ID != record.ID {
		t.Fatalf("delegation id = %s, want %s", ctx.Delegation.ID, record.ID)
	}
	if ctx.Agent.ID != "codex" {
		t.Fatalf("agent id = %s, want codex", ctx.Agent.ID)
	}
	if ctx.Delegation.TaskID != record.TaskID || ctx.Delegation.TaskName != "Triage local issues" {
		t.Fatalf("task fields = %+v, want %+v", ctx.Delegation, record)
	}
	if strings.Join(ctx.Scopes, " ") != "app.read app.write" {
		t.Fatalf("scopes = %v", ctx.Scopes)
	}
}

func TestValidateDelegationTokenRejectsWrongAudience(t *testing.T) {
	dataDir := t.TempDir()
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{ID: "codex", Name: "Codex"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	_, token, err := Create(dataDir, CreateRequest{
		Issuer:   "http://127.0.0.1:7100",
		Audience: AudienceForProtectPort(7200),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.read"},
		TTL:      30 * time.Minute,
		Now:      now,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ValidateToken(token, ValidateOptions{
		Issuer:    "http://127.0.0.1:7100",
		Audience:  AudienceForProtectPort(7201),
		DataDir:   dataDir,
		Now:       now.Add(time.Minute),
		PublicKey: &key.PublicKey,
	})
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience failure, got %v", err)
	}
}

func TestValidateDelegationTokenRejectsRevokedToken(t *testing.T) {
	dataDir := t.TempDir()
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{ID: "codex", Name: "Codex"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	record, token, err := Create(dataDir, CreateRequest{
		Issuer:   "http://127.0.0.1:7100",
		Audience: AudienceForProtectPort(7200),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.read"},
		TTL:      30 * time.Minute,
		Now:      now,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(dataDir, record.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	_, err = ValidateToken(token, ValidateOptions{
		Issuer:    "http://127.0.0.1:7100",
		Audience:  AudienceForProtectPort(7200),
		DataDir:   dataDir,
		Now:       now.Add(2 * time.Minute),
		PublicKey: &key.PublicKey,
	})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("expected revoked failure, got %v", err)
	}
}

func TestValidateDelegationTokenRejectsTampering(t *testing.T) {
	dataDir := t.TempDir()
	agent, err := agentregistry.Add(dataDir, agentregistry.Agent{ID: "codex", Name: "Codex"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.LoadOrCreateRSAKey(filepath.Join(dataDir, "dev-private-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	_, token, err := Create(dataDir, CreateRequest{
		Issuer:   "http://127.0.0.1:7100",
		Audience: AudienceForProtectPort(7200),
		Human:    userstore.DefaultProfile(),
		Agent:    agent,
		Scopes:   []string{"app.read"},
		TTL:      30 * time.Minute,
		Now:      now,
		Key:      key,
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := token[:len(token)-1] + "x"

	_, err = ValidateToken(tampered, ValidateOptions{
		Issuer:    "http://127.0.0.1:7100",
		Audience:  AudienceForProtectPort(7200),
		DataDir:   dataDir,
		Now:       now.Add(time.Minute),
		PublicKey: &key.PublicKey,
	})
	if err == nil {
		t.Fatal("expected tampered token to fail")
	}
}
