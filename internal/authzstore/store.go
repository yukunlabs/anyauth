package authzstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yukunlabs/anyauth/internal/authz"
)

const FileName = "authorization.json"

type Application struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Actions       []string  `json:"actions"`
	ResourceTypes []string  `json:"resource_types"`
	CreatedAt     time.Time `json:"created_at"`
}

type RequestStatus string

const (
	RequestPending  RequestStatus = "pending"
	RequestApproved RequestStatus = "approved"
	RequestDenied   RequestStatus = "denied"
	RequestExpired  RequestStatus = "expired"
)

type AuthorizationRequest struct {
	ID                  string           `json:"id"`
	Actor               authz.Identity   `json:"actor"`
	Subject             authz.Identity   `json:"subject"`
	ApplicationID       string           `json:"application_id"`
	Permission          authz.Permission `json:"permission"`
	TaskID              string           `json:"task_id,omitempty"`
	TaskName            string           `json:"task_name,omitempty"`
	RequestedTTLSeconds int64            `json:"requested_ttl_seconds"`
	Status              RequestStatus    `json:"status"`
	CreatedAt           time.Time        `json:"created_at"`
	ExpiresAt           time.Time        `json:"expires_at"`
	DecidedAt           *time.Time       `json:"decided_at,omitempty"`
	GrantID             string           `json:"grant_id,omitempty"`
}

func (r AuthorizationRequest) StatusAt(now time.Time) RequestStatus {
	if r.Status == RequestPending && !now.Before(r.ExpiresAt) {
		return RequestExpired
	}
	return r.Status
}

type File struct {
	Version      int                    `json:"version"`
	Applications []Application          `json:"applications"`
	Requests     []AuthorizationRequest `json:"requests"`
	Grants       []authz.Grant          `json:"grants"`
}

type Store struct {
	dataDir string
	mu      sync.Mutex
}

func New(dataDir string) *Store {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return &Store{dataDir: dataDir}
}

func Path(dataDir string) string {
	if dataDir == "" {
		dataDir = ".anyauth"
	}
	return filepath.Join(dataDir, FileName)
}

func (s *Store) Load() (File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadUnlocked()
}

func (s *Store) AddApplication(application Application) (Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	application = normalizeApplication(application)
	if application.CreatedAt.IsZero() {
		application.CreatedAt = time.Now().UTC()
	}
	if err := validateApplication(application); err != nil {
		return Application{}, err
	}
	state, err := s.loadUnlocked()
	if err != nil {
		return Application{}, err
	}
	for _, existing := range state.Applications {
		if existing.ID == application.ID {
			return Application{}, fmt.Errorf("application %q already exists", application.ID)
		}
	}
	state.Applications = append(state.Applications, application)
	if err := s.saveUnlocked(state); err != nil {
		return Application{}, err
	}
	return application, nil
}

func (s *Store) CreateRequest(request AuthorizationRequest) (AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	request = normalizeRequest(request)
	if err := validateRequest(request); err != nil {
		return AuthorizationRequest{}, err
	}
	state, err := s.loadUnlocked()
	if err != nil {
		return AuthorizationRequest{}, err
	}
	application, ok := findApplication(state.Applications, request.ApplicationID)
	if !ok {
		return AuthorizationRequest{}, fmt.Errorf("application %q not found", request.ApplicationID)
	}
	if !contains(application.Actions, request.Permission.Action) {
		return AuthorizationRequest{}, fmt.Errorf("application %q does not declare action %q", application.ID, request.Permission.Action)
	}
	if !contains(application.ResourceTypes, request.Permission.Resource.Type) {
		return AuthorizationRequest{}, fmt.Errorf("application %q does not declare resource type %q", application.ID, request.Permission.Resource.Type)
	}
	for _, existing := range state.Requests {
		if existing.ID == request.ID {
			return AuthorizationRequest{}, fmt.Errorf("authorization request %q already exists", request.ID)
		}
	}
	state.Requests = append(state.Requests, request)
	if err := s.saveUnlocked(state); err != nil {
		return AuthorizationRequest{}, err
	}
	return request, nil
}

func (s *Store) DecideRequest(id string, approve bool, grantID string, now time.Time) (AuthorizationRequest, *authz.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.IsZero() {
		return AuthorizationRequest{}, nil, fmt.Errorf("decision time is required")
	}
	now = now.UTC()
	state, err := s.loadUnlocked()
	if err != nil {
		return AuthorizationRequest{}, nil, err
	}
	for i := range state.Requests {
		request := &state.Requests[i]
		if request.ID != id {
			continue
		}
		if request.Status != RequestPending {
			return AuthorizationRequest{}, nil, fmt.Errorf("authorization request %q is %s", id, request.Status)
		}
		if !now.Before(request.ExpiresAt) {
			request.Status = RequestExpired
			request.DecidedAt = &now
			if err := s.saveUnlocked(state); err != nil {
				return AuthorizationRequest{}, nil, err
			}
			return *request, nil, fmt.Errorf("authorization request %q is expired", id)
		}

		request.DecidedAt = &now
		if !approve {
			request.Status = RequestDenied
			if err := s.saveUnlocked(state); err != nil {
				return AuthorizationRequest{}, nil, err
			}
			copy := *request
			return copy, nil, nil
		}
		if grantID == "" {
			return AuthorizationRequest{}, nil, fmt.Errorf("grant id is required for approval")
		}
		grant := authz.Grant{
			ID:            grantID,
			Subject:       request.Subject,
			Issuer:        request.Subject,
			Grantee:       request.Actor,
			ApplicationID: request.ApplicationID,
			Permissions:   []authz.Permission{request.Permission},
			TaskID:        request.TaskID,
			NotBefore:     now,
			ExpiresAt:     now.Add(time.Duration(request.RequestedTTLSeconds) * time.Second),
			CreatedAt:     now,
		}
		if err := grant.Validate(); err != nil {
			return AuthorizationRequest{}, nil, err
		}
		for _, existing := range state.Grants {
			if existing.ID == grant.ID {
				return AuthorizationRequest{}, nil, fmt.Errorf("grant %q already exists", grant.ID)
			}
		}
		request.Status = RequestApproved
		request.GrantID = grant.ID
		state.Grants = append(state.Grants, grant)
		if err := s.saveUnlocked(state); err != nil {
			return AuthorizationRequest{}, nil, err
		}
		requestCopy := *request
		grantCopy := grant
		return requestCopy, &grantCopy, nil
	}
	return AuthorizationRequest{}, nil, fmt.Errorf("authorization request %q not found", id)
}

func (s *Store) RevokeGrant(id string, now time.Time) (authz.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if now.IsZero() {
		return authz.Grant{}, fmt.Errorf("revocation time is required")
	}
	now = now.UTC()
	state, err := s.loadUnlocked()
	if err != nil {
		return authz.Grant{}, err
	}
	for i := range state.Grants {
		if state.Grants[i].ID != id {
			continue
		}
		if state.Grants[i].RevokedAt != nil {
			return authz.Grant{}, fmt.Errorf("grant %q is already revoked", id)
		}
		state.Grants[i].RevokedAt = &now
		if err := s.saveUnlocked(state); err != nil {
			return authz.Grant{}, err
		}
		return state.Grants[i], nil
	}
	return authz.Grant{}, fmt.Errorf("grant %q not found", id)
}

func (s *Store) ListGrants(context.Context) ([]authz.Grant, error) {
	state, err := s.Load()
	if err != nil {
		return nil, err
	}
	return append([]authz.Grant(nil), state.Grants...), nil
}

func (s *Store) ValidateEvaluation(request authz.Request) error {
	if err := request.Validate(); err != nil {
		return err
	}
	state, err := s.Load()
	if err != nil {
		return err
	}
	application, ok := findApplication(state.Applications, request.ApplicationID)
	if !ok {
		return fmt.Errorf("application %q not found", request.ApplicationID)
	}
	if !contains(application.Actions, request.Action.Name) {
		return fmt.Errorf("application %q does not declare action %q", application.ID, request.Action.Name)
	}
	if !contains(application.ResourceTypes, request.Resource.Type) {
		return fmt.Errorf("application %q does not declare resource type %q", application.ID, request.Resource.Type)
	}
	return nil
}

func (s *Store) loadUnlocked() (File, error) {
	raw, err := os.ReadFile(Path(s.dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: 1}, nil
	}
	if err != nil {
		return File{}, err
	}
	var state File
	if err := json.Unmarshal(raw, &state); err != nil {
		return File{}, err
	}
	if state.Version == 0 {
		state.Version = 1
	}
	normalizeFile(&state)
	if err := validateFile(state); err != nil {
		return File{}, err
	}
	return state, nil
}

func (s *Store) saveUnlocked(state File) error {
	if state.Version == 0 {
		state.Version = 1
	}
	normalizeFile(&state)
	if err := validateFile(state); err != nil {
		return err
	}
	path := Path(s.dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
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

func validateFile(state File) error {
	if state.Version != 1 {
		return fmt.Errorf("unsupported authorization file version %d", state.Version)
	}
	seenApplications := map[string]bool{}
	applicationsByID := map[string]Application{}
	for _, application := range state.Applications {
		if err := validateApplication(application); err != nil {
			return err
		}
		if seenApplications[application.ID] {
			return fmt.Errorf("duplicate application id %q", application.ID)
		}
		seenApplications[application.ID] = true
		applicationsByID[application.ID] = application
	}
	seenRequests := map[string]bool{}
	for _, request := range state.Requests {
		if err := validateRequest(request); err != nil {
			return err
		}
		if seenRequests[request.ID] {
			return fmt.Errorf("duplicate authorization request id %q", request.ID)
		}
		seenRequests[request.ID] = true
		application, ok := applicationsByID[request.ApplicationID]
		if !ok {
			return fmt.Errorf("authorization request %q references missing application %q", request.ID, request.ApplicationID)
		}
		if err := validatePermissionAgainstApplication(request.Permission, application); err != nil {
			return fmt.Errorf("authorization request %q: %w", request.ID, err)
		}
	}
	if err := authz.ValidateGrants(state.Grants); err != nil {
		return err
	}
	grantsByID := map[string]authz.Grant{}
	for _, grant := range state.Grants {
		application, ok := applicationsByID[grant.ApplicationID]
		if !ok {
			return fmt.Errorf("grant %q references missing application %q", grant.ID, grant.ApplicationID)
		}
		for _, permission := range grant.Permissions {
			if err := validatePermissionAgainstApplication(permission, application); err != nil {
				return fmt.Errorf("grant %q: %w", grant.ID, err)
			}
		}
		grantsByID[grant.ID] = grant
	}
	approvedRootGrants := map[string]bool{}
	for _, request := range state.Requests {
		if request.Status != RequestApproved {
			continue
		}
		grant, ok := grantsByID[request.GrantID]
		if !ok {
			return fmt.Errorf("approved authorization request %q references missing grant %q", request.ID, request.GrantID)
		}
		if len(grant.Permissions) != 1 || !samePermission(grant.Permissions[0], request.Permission) ||
			!grant.Subject.Equal(request.Subject) || !grant.Grantee.Equal(request.Actor) ||
			grant.ApplicationID != request.ApplicationID || grant.TaskID != request.TaskID {
			return fmt.Errorf("grant %q does not exactly represent approved request %q", grant.ID, request.ID)
		}
		if request.DecidedAt == nil || !grant.CreatedAt.Equal(*request.DecidedAt) ||
			!grant.ExpiresAt.Equal(request.DecidedAt.Add(time.Duration(request.RequestedTTLSeconds)*time.Second)) {
			return fmt.Errorf("grant %q lifetime does not match approved request %q", grant.ID, request.ID)
		}
		approvedRootGrants[grant.ID] = true
	}
	for _, grant := range state.Grants {
		if grant.ParentGrantID == "" && !approvedRootGrants[grant.ID] {
			return fmt.Errorf("root grant %q does not reference an approved request", grant.ID)
		}
	}
	return nil
}

func validateApplication(application Application) error {
	if err := validateToken("application id", application.ID); err != nil {
		return err
	}
	if application.Name == "" {
		return fmt.Errorf("application name is required")
	}
	if len(application.Actions) == 0 {
		return fmt.Errorf("application must declare at least one action")
	}
	for _, action := range application.Actions {
		if err := (authz.Action{Name: action}).Validate(); err != nil {
			return err
		}
	}
	if len(application.ResourceTypes) == 0 {
		return fmt.Errorf("application must declare at least one resource type")
	}
	for _, resourceType := range application.ResourceTypes {
		if err := validateToken("resource type", resourceType); err != nil {
			return err
		}
	}
	if application.CreatedAt.IsZero() {
		return fmt.Errorf("application created_at is required")
	}
	return nil
}

func validateRequest(request AuthorizationRequest) error {
	if err := validateToken("authorization request id", request.ID); err != nil {
		return err
	}
	if err := request.Actor.Validate(); err != nil {
		return fmt.Errorf("actor: %w", err)
	}
	if request.Actor.Type != authz.IdentityAgent && request.Actor.Type != authz.IdentityWorkload {
		return fmt.Errorf("authorization request actor must be an agent or workload")
	}
	if err := request.Subject.Validate(); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if request.Subject.Type != authz.IdentityHuman {
		return fmt.Errorf("authorization request subject must be human")
	}
	if err := validateToken("application id", request.ApplicationID); err != nil {
		return err
	}
	if err := request.Permission.Validate(); err != nil {
		return err
	}
	if request.TaskID != "" {
		if err := validateToken("task id", request.TaskID); err != nil {
			return err
		}
	}
	if request.RequestedTTLSeconds < 60 || request.RequestedTTLSeconds > int64((24*time.Hour)/time.Second) {
		return fmt.Errorf("requested ttl must be between 1 minute and 24 hours")
	}
	switch request.Status {
	case RequestPending, RequestApproved, RequestDenied, RequestExpired:
	default:
		return fmt.Errorf("unsupported authorization request status %q", request.Status)
	}
	if request.CreatedAt.IsZero() || request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return fmt.Errorf("authorization request must have a valid creation and expiry window")
	}
	if request.Status == RequestPending && (request.DecidedAt != nil || request.GrantID != "") {
		return fmt.Errorf("pending authorization request must not have decision fields")
	}
	if request.Status != RequestPending && request.DecidedAt == nil {
		return fmt.Errorf("decided authorization request must have decided_at")
	}
	if request.DecidedAt != nil {
		if (request.Status == RequestApproved || request.Status == RequestDenied) && !request.DecidedAt.Before(request.ExpiresAt) {
			return fmt.Errorf("approved or denied authorization request must be decided before expiry")
		}
		if request.Status == RequestExpired && request.DecidedAt.Before(request.ExpiresAt) {
			return fmt.Errorf("expired authorization request must not be decided before expiry")
		}
	}
	if request.Status == RequestApproved && request.GrantID == "" {
		return fmt.Errorf("approved authorization request must reference a grant")
	}
	if request.Status != RequestApproved && request.GrantID != "" {
		return fmt.Errorf("non-approved authorization request must not reference a grant")
	}
	return nil
}

func normalizeFile(state *File) {
	for i := range state.Applications {
		state.Applications[i] = normalizeApplication(state.Applications[i])
	}
	for i := range state.Requests {
		state.Requests[i] = normalizeRequest(state.Requests[i])
	}
	sort.Slice(state.Applications, func(i, j int) bool { return state.Applications[i].ID < state.Applications[j].ID })
	sort.Slice(state.Requests, func(i, j int) bool {
		if state.Requests[i].CreatedAt.Equal(state.Requests[j].CreatedAt) {
			return state.Requests[i].ID < state.Requests[j].ID
		}
		return state.Requests[i].CreatedAt.Before(state.Requests[j].CreatedAt)
	})
	sort.Slice(state.Grants, func(i, j int) bool {
		if state.Grants[i].CreatedAt.Equal(state.Grants[j].CreatedAt) {
			return state.Grants[i].ID < state.Grants[j].ID
		}
		return state.Grants[i].CreatedAt.Before(state.Grants[j].CreatedAt)
	})
}

func normalizeApplication(application Application) Application {
	application.ID = strings.TrimSpace(application.ID)
	application.Name = strings.TrimSpace(application.Name)
	if application.Name == "" {
		application.Name = application.ID
	}
	application.Actions = normalizeTokens(application.Actions)
	application.ResourceTypes = normalizeTokens(application.ResourceTypes)
	return application
}

func normalizeRequest(request AuthorizationRequest) AuthorizationRequest {
	request.ID = strings.TrimSpace(request.ID)
	request.ApplicationID = strings.TrimSpace(request.ApplicationID)
	request.TaskID = strings.TrimSpace(request.TaskID)
	request.TaskName = strings.TrimSpace(request.TaskName)
	request.Permission.Action = strings.TrimSpace(request.Permission.Action)
	request.Permission.Resource.Type = strings.TrimSpace(request.Permission.Resource.Type)
	request.Permission.Resource.ID = strings.TrimSpace(request.Permission.Resource.ID)
	return request
}

func normalizeTokens(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func findApplication(applications []Application, id string) (Application, bool) {
	for _, application := range applications {
		if application.ID == id {
			return application, true
		}
	}
	return Application{}, false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func validatePermissionAgainstApplication(permission authz.Permission, application Application) error {
	if !contains(application.Actions, permission.Action) {
		return fmt.Errorf("application %q does not declare action %q", application.ID, permission.Action)
	}
	if !contains(application.ResourceTypes, permission.Resource.Type) {
		return fmt.Errorf("application %q does not declare resource type %q", application.ID, permission.Resource.Type)
	}
	return nil
}

func samePermission(left authz.Permission, right authz.Permission) bool {
	return left.Action == right.Action && left.Resource == right.Resource
}

func validateToken(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("%s must not contain whitespace", name)
	}
	return nil
}
