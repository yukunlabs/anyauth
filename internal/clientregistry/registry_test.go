package clientregistry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddAndLoadClient(t *testing.T) {
	dataDir := t.TempDir()

	client, err := Add(dataDir, Client{
		ID:           "my-app",
		Name:         "My App",
		RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.Secret == "" {
		t.Fatal("generated secret is empty")
	}

	clients, err := Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 {
		t.Fatalf("len(clients) = %d, want 1", len(clients))
	}
	if clients[0].ID != "my-app" {
		t.Fatalf("client id = %q, want my-app", clients[0].ID)
	}
	if clients[0].Secret != client.Secret {
		t.Fatal("loaded secret differs from generated secret")
	}

	raw, err := os.ReadFile(filepath.Join(dataDir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"version": 1`) {
		t.Fatalf("registry file missing version: %s", raw)
	}
}

func TestAddRejectsDuplicateClient(t *testing.T) {
	dataDir := t.TempDir()
	_, err := Add(dataDir, Client{
		ID:           "my-app",
		RedirectURIs: []string{"http://127.0.0.1:3000/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = Add(dataDir, Client{
		ID:           "my-app",
		RedirectURIs: []string{"http://127.0.0.1:4000/callback"},
	})
	if err == nil {
		t.Fatal("expected duplicate client error")
	}
}

func TestValidateRejectsBadRedirectURI(t *testing.T) {
	err := Validate(Client{
		ID:           "my-app",
		Secret:       "secret",
		RedirectURIs: []string{"javascript:alert(1)"},
	})
	if err == nil {
		t.Fatal("expected invalid redirect URI error")
	}
}
