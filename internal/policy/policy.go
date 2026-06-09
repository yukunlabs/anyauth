package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const FileName = "policies.json"

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type Rule struct {
	ID             string    `json:"id"`
	Description    string    `json:"description,omitempty"`
	Effect         Effect    `json:"effect"`
	Methods        []string  `json:"methods,omitempty"`
	PathPrefix     string    `json:"path_prefix"`
	AgentID        string    `json:"agent_id,omitempty"`
	RequiredScopes []string  `json:"required_scopes,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

type File struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type Request struct {
	Method  string
	Path    string
	AgentID string
	Scopes  []string
}

type Decision struct {
	Allowed bool
	Rule    *Rule
	Reason  string
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Load(dataDir string) ([]Rule, error) {
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
	rules := normalizeAll(file.Rules)
	if err := validateAll(rules); err != nil {
		return nil, err
	}
	sortRules(rules)
	return rules, nil
}

func Add(dataDir string, rule Rule) (Rule, error) {
	rule = normalize(rule)
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	if err := Validate(rule); err != nil {
		return Rule{}, err
	}

	rules, err := Load(dataDir)
	if err != nil {
		return Rule{}, err
	}
	for _, existing := range rules {
		if existing.ID == rule.ID {
			return Rule{}, fmt.Errorf("policy %q already exists", rule.ID)
		}
	}
	rules = append(rules, rule)
	if err := Save(dataDir, rules); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func Remove(dataDir string, id string) (Rule, error) {
	rules, err := Load(dataDir)
	if err != nil {
		return Rule{}, err
	}

	kept := make([]Rule, 0, len(rules))
	var removed Rule
	for _, rule := range rules {
		if rule.ID == id {
			removed = rule
			continue
		}
		kept = append(kept, rule)
	}
	if removed.ID == "" {
		return Rule{}, fmt.Errorf("policy %q not found", id)
	}
	if err := Save(dataDir, kept); err != nil {
		return Rule{}, err
	}
	return removed, nil
}

func Save(dataDir string, rules []Rule) error {
	rules = normalizeAll(rules)
	if err := validateAll(rules); err != nil {
		return err
	}
	sortRules(rules)

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(File{Version: 1, Rules: rules}, "", "  ")
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

func Evaluate(rules []Rule, req Request) Decision {
	rules = normalizeAll(rules)
	sortRules(rules)
	if len(rules) == 0 {
		return Decision{Allowed: true, Reason: "no policies configured"}
	}
	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Path = normalizePath(req.Path)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.Scopes = normalizeScopes(req.Scopes)

	var candidateMissingScope *Rule
	for _, rule := range rules {
		if !matchesBase(rule, req) {
			continue
		}
		if rule.Effect == EffectDeny {
			return Decision{Allowed: false, Rule: copyRule(rule), Reason: "matched deny policy " + rule.ID}
		}
		if !hasRequiredScopes(req.Scopes, rule.RequiredScopes) {
			if candidateMissingScope == nil {
				candidateMissingScope = copyRule(rule)
			}
			continue
		}
		return Decision{Allowed: true, Rule: copyRule(rule), Reason: "matched allow policy " + rule.ID}
	}
	if candidateMissingScope != nil {
		return Decision{Allowed: false, Rule: candidateMissingScope, Reason: "missing required scope for policy " + candidateMissingScope.ID}
	}
	return Decision{Allowed: false, Reason: "no matching allow policy"}
}

func Validate(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("policy id is required")
	}
	if strings.ContainsAny(rule.ID, " \t\r\n") {
		return fmt.Errorf("policy id must not contain whitespace")
	}
	if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
		return fmt.Errorf("policy effect must be allow or deny")
	}
	if rule.PathPrefix == "" || !strings.HasPrefix(rule.PathPrefix, "/") || strings.HasPrefix(rule.PathPrefix, "//") {
		return fmt.Errorf("policy path prefix must start with a single /")
	}
	for _, method := range rule.Methods {
		if method == "" {
			return fmt.Errorf("policy method must not be empty")
		}
		if method != "*" && !validHTTPMethod(method) {
			return fmt.Errorf("unsupported policy method %q", method)
		}
	}
	for _, scope := range rule.RequiredScopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("invalid required scope %q", scope)
		}
	}
	if rule.CreatedAt.IsZero() {
		return fmt.Errorf("policy created_at is required")
	}
	return nil
}

func normalizeAll(rules []Rule) []Rule {
	out := append([]Rule(nil), rules...)
	for i := range out {
		out[i] = normalize(out[i])
	}
	return out
}

func normalize(rule Rule) Rule {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Effect = Effect(strings.ToLower(strings.TrimSpace(string(rule.Effect))))
	rule.PathPrefix = normalizePath(rule.PathPrefix)
	rule.AgentID = strings.TrimSpace(rule.AgentID)
	rule.Methods = normalizeMethods(rule.Methods)
	rule.RequiredScopes = normalizeScopes(rule.RequiredScopes)
	if !rule.CreatedAt.IsZero() {
		rule.CreatedAt = rule.CreatedAt.UTC()
	}
	return rule
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func normalizeMethods(methods []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if method == "ANY" {
			method = "*"
		}
		if seen[method] {
			continue
		}
		seen[method] = true
		out = append(out, method)
	}
	sort.Strings(out)
	return out
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
	sort.Strings(out)
	return out
}

func validateAll(rules []Rule) error {
	seen := map[string]bool{}
	for _, rule := range rules {
		if err := Validate(rule); err != nil {
			return err
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate policy id %q", rule.ID)
		}
		seen[rule.ID] = true
	}
	return nil
}

func matchesBase(rule Rule, req Request) bool {
	if rule.AgentID != "" && rule.AgentID != req.AgentID {
		return false
	}
	if !methodMatches(rule.Methods, req.Method) {
		return false
	}
	return pathPrefixMatches(req.Path, rule.PathPrefix)
}

func methodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, candidate := range methods {
		if candidate == "*" || candidate == method {
			return true
		}
	}
	return false
}

func pathPrefixMatches(path string, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/")
}

func hasRequiredScopes(scopes []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := map[string]bool{}
	for _, scope := range scopes {
		have[scope] = true
	}
	for _, scope := range required {
		if !have[scope] {
			return false
		}
	}
	return true
}

func validHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func copyRule(rule Rule) *Rule {
	clone := rule
	clone.Methods = append([]string(nil), rule.Methods...)
	clone.RequiredScopes = append([]string(nil), rule.RequiredScopes...)
	return &clone
}

func sortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Effect != rules[j].Effect {
			return rules[i].Effect == EffectDeny
		}
		if len(rules[i].PathPrefix) != len(rules[j].PathPrefix) {
			return len(rules[i].PathPrefix) > len(rules[j].PathPrefix)
		}
		return rules[i].ID < rules[j].ID
	})
}
