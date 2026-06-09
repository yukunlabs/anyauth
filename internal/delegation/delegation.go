package delegation

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yukunlabs/anyauth/internal/agentregistry"
	"github.com/yukunlabs/anyauth/internal/jose"
	"github.com/yukunlabs/anyauth/internal/userstore"
)

const (
	FileName  = "delegations.json"
	TokenUse  = "delegation"
	SigningID = "anyauth-local-dev-key"
)

type Delegation struct {
	ID          string     `json:"id"`
	TokenID     string     `json:"token_id"`
	TokenSHA256 string     `json:"token_sha256"`
	HumanSub    string     `json:"human_sub"`
	HumanName   string     `json:"human_name"`
	HumanEmail  string     `json:"human_email"`
	AgentID     string     `json:"agent_id"`
	AgentName   string     `json:"agent_name"`
	TaskID      string     `json:"task_id,omitempty"`
	TaskName    string     `json:"task_name,omitempty"`
	Audience    string     `json:"audience"`
	Scopes      []string   `json:"scopes"`
	Note        string     `json:"note,omitempty"`
	IssuedAt    time.Time  `json:"issued_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type File struct {
	Version     int          `json:"version"`
	Delegations []Delegation `json:"delegations"`
}

type CreateRequest struct {
	Issuer   string
	Audience string
	Human    userstore.Profile
	Agent    agentregistry.Agent
	TaskID   string
	TaskName string
	Scopes   []string
	Note     string
	TTL      time.Duration
	Now      time.Time
	Key      *rsa.PrivateKey
}

type ValidateOptions struct {
	Issuer    string
	Audience  string
	DataDir   string
	Now       time.Time
	PublicKey *rsa.PublicKey
}

type Context struct {
	Delegation Delegation
	Agent      agentregistry.Agent
	Claims     map[string]any
	Scopes     []string
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func Load(dataDir string) ([]Delegation, error) {
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
	delegations := normalizeAll(file.Delegations)
	if err := validateAll(delegations); err != nil {
		return nil, err
	}
	sortDelegations(delegations)
	return delegations, nil
}

func Create(dataDir string, req CreateRequest) (Delegation, string, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	req.Scopes = normalizeScopes(req.Scopes)
	if err := validateCreateRequest(req); err != nil {
		return Delegation{}, "", err
	}

	delegationID, err := randomPrefixedID("del", 16)
	if err != nil {
		return Delegation{}, "", err
	}
	tokenID, err := randomPrefixedID("jti", 16)
	if err != nil {
		return Delegation{}, "", err
	}
	taskID := strings.TrimSpace(req.TaskID)
	if taskID == "" && strings.TrimSpace(req.TaskName) != "" {
		taskID, err = randomPrefixedID("task", 12)
		if err != nil {
			return Delegation{}, "", err
		}
	}

	record := Delegation{
		ID:         delegationID,
		TokenID:    tokenID,
		HumanSub:   req.Human.Sub,
		HumanName:  req.Human.Name,
		HumanEmail: req.Human.Email,
		AgentID:    req.Agent.ID,
		AgentName:  req.Agent.Name,
		TaskID:     taskID,
		TaskName:   strings.TrimSpace(req.TaskName),
		Audience:   req.Audience,
		Scopes:     req.Scopes,
		Note:       strings.TrimSpace(req.Note),
		IssuedAt:   now,
		ExpiresAt:  now.Add(req.TTL).UTC(),
	}

	payload := map[string]any{
		"iss":                   req.Issuer,
		"sub":                   record.HumanSub,
		"name":                  record.HumanName,
		"email":                 record.HumanEmail,
		"aud":                   record.Audience,
		"iat":                   record.IssuedAt.Unix(),
		"nbf":                   record.IssuedAt.Unix(),
		"exp":                   record.ExpiresAt.Unix(),
		"jti":                   record.TokenID,
		"token_use":             TokenUse,
		"scope":                 strings.Join(record.Scopes, " "),
		"act":                   map[string]any{"sub": record.AgentID, "name": record.AgentName},
		"anyauth_delegation_id": record.ID,
		"anyauth_agent_id":      record.AgentID,
		"anyauth_agent_name":    record.AgentName,
	}
	if record.TaskID != "" {
		payload["anyauth_task_id"] = record.TaskID
	}
	if record.TaskName != "" {
		payload["anyauth_task_name"] = record.TaskName
	}

	token, err := jose.SignJWT(payload, req.Key, SigningID)
	if err != nil {
		return Delegation{}, "", err
	}
	record.TokenSHA256 = TokenSHA256(token)

	delegations, err := Load(dataDir)
	if err != nil {
		return Delegation{}, "", err
	}
	delegations = append(delegations, record)
	if err := Save(dataDir, delegations); err != nil {
		return Delegation{}, "", err
	}
	return record, token, nil
}

func Save(dataDir string, delegations []Delegation) error {
	delegations = normalizeAll(delegations)
	if err := validateAll(delegations); err != nil {
		return err
	}
	sortDelegations(delegations)

	path := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(File{Version: 1, Delegations: delegations}, "", "  ")
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

func Revoke(dataDir string, id string, now time.Time) (Delegation, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	delegations, err := Load(dataDir)
	if err != nil {
		return Delegation{}, err
	}
	for i := range delegations {
		if delegations[i].ID != id {
			continue
		}
		delegations[i].RevokedAt = &now
		if err := Save(dataDir, delegations); err != nil {
			return Delegation{}, err
		}
		return delegations[i], nil
	}
	return Delegation{}, fmt.Errorf("delegation %q not found", id)
}

func ValidateToken(token string, opts ValidateOptions) (Context, error) {
	if strings.TrimSpace(token) == "" {
		return Context{}, fmt.Errorf("delegation token is required")
	}
	if opts.PublicKey == nil {
		return Context{}, fmt.Errorf("public key is required")
	}
	if opts.Issuer == "" {
		return Context{}, fmt.Errorf("issuer is required")
	}
	if opts.Audience == "" {
		return Context{}, fmt.Errorf("audience is required")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	claims, err := jose.VerifyRS256JWT(token, opts.PublicKey)
	if err != nil {
		return Context{}, err
	}
	if err := validateClaims(claims, opts.Issuer, opts.Audience, now); err != nil {
		return Context{}, err
	}

	delegationID, _ := claimString(claims, "anyauth_delegation_id")
	tokenID, _ := claimString(claims, "jti")
	agentID, _ := claimString(claims, "anyauth_agent_id")
	taskID, _ := optionalClaimString(claims, "anyauth_task_id")
	scope, _ := claimString(claims, "scope")

	delegations, err := Load(opts.DataDir)
	if err != nil {
		return Context{}, err
	}
	record, ok := findDelegation(delegations, delegationID)
	if !ok {
		return Context{}, fmt.Errorf("delegation %q not found", delegationID)
	}
	if record.RevokedAt != nil {
		return Context{}, fmt.Errorf("delegation %q is revoked", record.ID)
	}
	if !now.Before(record.ExpiresAt) {
		return Context{}, fmt.Errorf("delegation %q is expired", record.ID)
	}
	if record.TokenID != tokenID {
		return Context{}, fmt.Errorf("token id mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(record.TokenSHA256), []byte(TokenSHA256(token))) != 1 {
		return Context{}, fmt.Errorf("token hash mismatch")
	}
	if record.AgentID != agentID {
		return Context{}, fmt.Errorf("agent id mismatch")
	}
	if record.TaskID != "" && record.TaskID != taskID {
		return Context{}, fmt.Errorf("task id mismatch")
	}
	if record.Audience != opts.Audience {
		return Context{}, fmt.Errorf("delegation audience mismatch")
	}
	if strings.Join(record.Scopes, " ") != scope {
		return Context{}, fmt.Errorf("delegation scope mismatch")
	}

	agents, err := agentregistry.Load(opts.DataDir)
	if err != nil {
		return Context{}, err
	}
	agent, ok := agentregistry.Find(agents, agentID)
	if !ok {
		return Context{}, fmt.Errorf("agent %q not found", agentID)
	}
	if agent.Disabled {
		return Context{}, fmt.Errorf("agent %q is disabled", agentID)
	}

	return Context{
		Delegation: record,
		Agent:      agent,
		Claims:     claims,
		Scopes:     append([]string(nil), record.Scopes...),
	}, nil
}

func TokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func AudienceForProtectPort(port int) string {
	return fmt.Sprintf("anyauth-protect-%d", port)
}

func IssuerForProviderPort(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func validateCreateRequest(req CreateRequest) error {
	if req.Key == nil {
		return fmt.Errorf("signing key is required")
	}
	if req.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if req.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if req.TTL <= 0 {
		return fmt.Errorf("ttl must be positive")
	}
	if req.Human.Sub == "" {
		return fmt.Errorf("human sub is required")
	}
	if req.Human.Name == "" {
		return fmt.Errorf("human name is required")
	}
	if err := agentregistry.Validate(req.Agent); err != nil {
		return err
	}
	if req.Agent.Disabled {
		return fmt.Errorf("agent %q is disabled", req.Agent.ID)
	}
	if req.TaskID != "" && strings.ContainsAny(req.TaskID, " \t\r\n") {
		return fmt.Errorf("task id must not contain whitespace")
	}
	if len(req.Scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}
	return nil
}

func validateClaims(claims map[string]any, issuer string, audience string, now time.Time) error {
	if got, _ := claimString(claims, "iss"); got != issuer {
		return fmt.Errorf("issuer mismatch")
	}
	if !audienceMatches(claims["aud"], audience) {
		return fmt.Errorf("audience mismatch")
	}
	if got, _ := claimString(claims, "token_use"); got != TokenUse {
		return fmt.Errorf("token_use must be %q", TokenUse)
	}
	if _, err := claimString(claims, "sub"); err != nil {
		return err
	}
	if _, err := claimString(claims, "jti"); err != nil {
		return err
	}
	if _, err := claimString(claims, "anyauth_delegation_id"); err != nil {
		return err
	}
	if _, err := claimString(claims, "anyauth_agent_id"); err != nil {
		return err
	}
	if _, err := claimString(claims, "scope"); err != nil {
		return err
	}
	nbf, err := claimUnix(claims, "nbf")
	if err != nil {
		return err
	}
	if now.Unix() < nbf {
		return fmt.Errorf("token is not valid yet")
	}
	exp, err := claimUnix(claims, "exp")
	if err != nil {
		return err
	}
	if now.Unix() >= exp {
		return fmt.Errorf("token expired")
	}
	return nil
}

func ValidateStored(record Delegation) error {
	if record.ID == "" {
		return fmt.Errorf("delegation id is required")
	}
	if strings.ContainsAny(record.ID, " \t\r\n") {
		return fmt.Errorf("delegation id must not contain whitespace")
	}
	if record.TokenID == "" {
		return fmt.Errorf("delegation token id is required")
	}
	if record.TokenSHA256 == "" {
		return fmt.Errorf("delegation token hash is required")
	}
	if record.HumanSub == "" {
		return fmt.Errorf("delegation human sub is required")
	}
	if record.AgentID == "" {
		return fmt.Errorf("delegation agent id is required")
	}
	if record.AgentName == "" {
		return fmt.Errorf("delegation agent name is required")
	}
	if record.TaskID != "" && strings.ContainsAny(record.TaskID, " \t\r\n") {
		return fmt.Errorf("delegation task id must not contain whitespace")
	}
	if record.Audience == "" {
		return fmt.Errorf("delegation audience is required")
	}
	if len(record.Scopes) == 0 {
		return fmt.Errorf("delegation scopes are required")
	}
	for _, scope := range record.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("invalid delegation scope %q", scope)
		}
	}
	if record.IssuedAt.IsZero() {
		return fmt.Errorf("delegation issued_at is required")
	}
	if record.ExpiresAt.IsZero() {
		return fmt.Errorf("delegation expires_at is required")
	}
	if !record.ExpiresAt.After(record.IssuedAt) {
		return fmt.Errorf("delegation expires_at must be after issued_at")
	}
	return nil
}

func normalizeAll(delegations []Delegation) []Delegation {
	out := append([]Delegation(nil), delegations...)
	for i := range out {
		out[i].ID = strings.TrimSpace(out[i].ID)
		out[i].TokenID = strings.TrimSpace(out[i].TokenID)
		out[i].TokenSHA256 = strings.TrimSpace(out[i].TokenSHA256)
		out[i].HumanSub = strings.TrimSpace(out[i].HumanSub)
		out[i].HumanName = strings.TrimSpace(out[i].HumanName)
		out[i].HumanEmail = strings.TrimSpace(out[i].HumanEmail)
		out[i].AgentID = strings.TrimSpace(out[i].AgentID)
		out[i].AgentName = strings.TrimSpace(out[i].AgentName)
		out[i].TaskID = strings.TrimSpace(out[i].TaskID)
		out[i].TaskName = strings.TrimSpace(out[i].TaskName)
		out[i].Audience = strings.TrimSpace(out[i].Audience)
		out[i].Note = strings.TrimSpace(out[i].Note)
		out[i].Scopes = normalizeScopes(out[i].Scopes)
	}
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
	return out
}

func validateAll(delegations []Delegation) error {
	seenIDs := map[string]bool{}
	seenTokenIDs := map[string]bool{}
	for _, record := range delegations {
		if err := ValidateStored(record); err != nil {
			return err
		}
		if seenIDs[record.ID] {
			return fmt.Errorf("duplicate delegation id %q", record.ID)
		}
		if seenTokenIDs[record.TokenID] {
			return fmt.Errorf("duplicate delegation token id %q", record.TokenID)
		}
		seenIDs[record.ID] = true
		seenTokenIDs[record.TokenID] = true
	}
	return nil
}

func findDelegation(delegations []Delegation, id string) (Delegation, bool) {
	for _, record := range delegations {
		if record.ID == id {
			return record, true
		}
	}
	return Delegation{}, false
}

func sortDelegations(delegations []Delegation) {
	sort.Slice(delegations, func(i, j int) bool {
		return delegations[i].IssuedAt.Before(delegations[j].IssuedAt)
	})
}

func claimString(claims map[string]any, key string) (string, error) {
	raw, ok := claims[key]
	if !ok {
		return "", fmt.Errorf("%s claim missing", key)
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s claim missing or invalid", key)
	}
	return value, nil
}

func optionalClaimString(claims map[string]any, key string) (string, bool) {
	raw, ok := claims[key]
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

func claimUnix(claims map[string]any, key string) (int64, error) {
	raw, ok := claims[key]
	if !ok {
		return 0, fmt.Errorf("%s claim missing", key)
	}
	value, ok := raw.(float64)
	if !ok {
		return 0, fmt.Errorf("%s claim missing or invalid", key)
	}
	return int64(value), nil
}

func audienceMatches(raw any, want string) bool {
	switch value := raw.(type) {
	case string:
		return value == want
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok && text == want {
				return true
			}
		}
	}
	return false
}

func randomPrefixedID(prefix string, bytes int) (string, error) {
	value, err := jose.RandomURLToken(bytes)
	if err != nil {
		return "", err
	}
	return prefix + "_" + value, nil
}
