package clientregistry

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const FileName = "clients.json"

type Client struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

type File struct {
	Version int      `json:"version"`
	Clients []Client `json:"clients"`
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Load(dataDir string) ([]Client, error) {
	raw, err := os.ReadFile(Path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var file File
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	clients := append([]Client(nil), file.Clients...)
	if err := validateAll(clients); err != nil {
		return nil, err
	}
	sortClients(clients)
	return clients, nil
}

func Add(dataDir string, client Client) (Client, error) {
	if client.Secret == "" {
		secret, err := GenerateSecret()
		if err != nil {
			return Client{}, err
		}
		client.Secret = secret
	}
	if client.Name == "" {
		client.Name = client.ID
	}
	if err := Validate(client); err != nil {
		return Client{}, err
	}

	clients, err := Load(dataDir)
	if err != nil {
		return Client{}, err
	}
	for _, existing := range clients {
		if existing.ID == client.ID {
			return Client{}, fmt.Errorf("client %q already exists", client.ID)
		}
	}
	clients = append(clients, client)
	sortClients(clients)
	if err := Save(dataDir, clients); err != nil {
		return Client{}, err
	}
	return client, nil
}

func Save(dataDir string, clients []Client) error {
	if err := validateAll(clients); err != nil {
		return err
	}
	sortClients(clients)

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(File{Version: 1, Clients: clients}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Validate(client Client) error {
	if client.ID == "" {
		return fmt.Errorf("client id is required")
	}
	if strings.ContainsAny(client.ID, " \t\r\n") {
		return fmt.Errorf("client id must not contain whitespace")
	}
	if client.Secret == "" {
		return fmt.Errorf("client secret is required")
	}
	if len(client.RedirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}

	seen := map[string]bool{}
	for _, redirectURI := range client.RedirectURIs {
		parsed, err := url.Parse(redirectURI)
		if err != nil {
			return fmt.Errorf("invalid redirect URI %q: %w", redirectURI, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("redirect URI %q must use http or https", redirectURI)
		}
		if parsed.Host == "" {
			return fmt.Errorf("redirect URI %q must include a host", redirectURI)
		}
		if seen[redirectURI] {
			return fmt.Errorf("duplicate redirect URI %q", redirectURI)
		}
		seen[redirectURI] = true
	}
	return nil
}

func GenerateSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validateAll(clients []Client) error {
	seen := map[string]bool{}
	for _, client := range clients {
		if err := Validate(client); err != nil {
			return err
		}
		if seen[client.ID] {
			return fmt.Errorf("duplicate client id %q", client.ID)
		}
		seen[client.ID] = true
	}
	return nil
}

func sortClients(clients []Client) {
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ID < clients[j].ID
	})
}
