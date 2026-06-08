package agentregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const FileName = "agents.json"

type Agent struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Disabled  bool      `json:"disabled,omitempty"`
}

type File struct {
	Version int     `json:"version"`
	Agents  []Agent `json:"agents"`
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Load(dataDir string) ([]Agent, error) {
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
	agents := normalizeAll(file.Agents)
	if err := validateAll(agents); err != nil {
		return nil, err
	}
	sortAgents(agents)
	return agents, nil
}

func Add(dataDir string, agent Agent) (Agent, error) {
	agent = normalize(agent)
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now().UTC()
	}
	if err := Validate(agent); err != nil {
		return Agent{}, err
	}

	agents, err := Load(dataDir)
	if err != nil {
		return Agent{}, err
	}
	for _, existing := range agents {
		if existing.ID == agent.ID {
			return Agent{}, fmt.Errorf("agent %q already exists", agent.ID)
		}
	}
	agents = append(agents, agent)
	sortAgents(agents)
	if err := Save(dataDir, agents); err != nil {
		return Agent{}, err
	}
	return agent, nil
}

func Remove(dataDir string, id string) (Agent, error) {
	agents, err := Load(dataDir)
	if err != nil {
		return Agent{}, err
	}

	kept := make([]Agent, 0, len(agents))
	var removed Agent
	for _, agent := range agents {
		if agent.ID == id {
			removed = agent
			continue
		}
		kept = append(kept, agent)
	}
	if removed.ID == "" {
		return Agent{}, fmt.Errorf("agent %q not found", id)
	}
	if err := Save(dataDir, kept); err != nil {
		return Agent{}, err
	}
	return removed, nil
}

func Save(dataDir string, agents []Agent) error {
	agents = normalizeAll(agents)
	if err := validateAll(agents); err != nil {
		return err
	}
	sortAgents(agents)

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(File{Version: 1, Agents: agents}, "", "  ")
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

func Find(agents []Agent, id string) (Agent, bool) {
	for _, agent := range agents {
		if agent.ID == id {
			return agent, true
		}
	}
	return Agent{}, false
}

func Validate(agent Agent) error {
	if agent.ID == "" {
		return fmt.Errorf("agent id is required")
	}
	if strings.ContainsAny(agent.ID, " \t\r\n") {
		return fmt.Errorf("agent id must not contain whitespace")
	}
	if agent.Name == "" {
		return fmt.Errorf("agent name is required")
	}
	return nil
}

func normalizeAll(agents []Agent) []Agent {
	out := append([]Agent(nil), agents...)
	for i := range out {
		out[i] = normalize(out[i])
	}
	return out
}

func normalize(agent Agent) Agent {
	agent.ID = strings.TrimSpace(agent.ID)
	agent.Name = strings.TrimSpace(agent.Name)
	agent.Kind = strings.TrimSpace(agent.Kind)
	if agent.Name == "" {
		agent.Name = agent.ID
	}
	return agent
}

func validateAll(agents []Agent) error {
	seen := map[string]bool{}
	for _, agent := range agents {
		if err := Validate(agent); err != nil {
			return err
		}
		if seen[agent.ID] {
			return fmt.Errorf("duplicate agent id %q", agent.ID)
		}
		seen[agent.ID] = true
	}
	return nil
}

func sortAgents(agents []Agent) {
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].ID < agents[j].ID
	})
}
