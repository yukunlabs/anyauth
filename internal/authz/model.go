// Package authz defines AnyAuth's storage- and protocol-independent
// authorization model.
package authz

import (
	"fmt"
	"strings"
	"time"
)

type IdentityType string

const (
	IdentityHuman    IdentityType = "human"
	IdentityAgent    IdentityType = "agent"
	IdentityWorkload IdentityType = "workload"
	AllResources                  = "*"
)

type Identity struct {
	Type IdentityType `json:"type"`
	ID   string       `json:"id"`
}

func (i Identity) Equal(other Identity) bool {
	return i.Type == other.Type && i.ID == other.ID
}

func (i Identity) Validate() error {
	switch i.Type {
	case IdentityHuman, IdentityAgent, IdentityWorkload:
	default:
		return fmt.Errorf("unsupported identity type %q", i.Type)
	}
	return validateToken("identity id", i.ID)
}

type Action struct {
	Name string `json:"name"`
}

func (a Action) Validate() error {
	return validateToken("action name", a.Name)
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (r Resource) Validate() error {
	if err := validateToken("resource type", r.Type); err != nil {
		return err
	}
	if err := validateResourceID(r.ID); err != nil {
		return err
	}
	if r.ID == AllResources {
		return fmt.Errorf("authorization request resource id must be concrete")
	}
	return nil
}

type ResourceSelector struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (r ResourceSelector) Validate() error {
	if err := validateToken("resource selector type", r.Type); err != nil {
		return err
	}
	return validateResourceID(r.ID)
}

func (r ResourceSelector) Contains(resource Resource) bool {
	return r.Type == resource.Type && (r.ID == AllResources || r.ID == resource.ID)
}

func (r ResourceSelector) ContainsSelector(child ResourceSelector) bool {
	return r.Type == child.Type && (r.ID == AllResources || r.ID == child.ID)
}

type Permission struct {
	Action   string           `json:"action"`
	Resource ResourceSelector `json:"resource"`
}

func (p Permission) Validate() error {
	if err := validateToken("permission action", p.Action); err != nil {
		return err
	}
	return p.Resource.Validate()
}

func (p Permission) Contains(action Action, resource Resource) bool {
	return p.Action == action.Name && p.Resource.Contains(resource)
}

func (p Permission) ContainsPermission(child Permission) bool {
	return p.Action == child.Action && p.Resource.ContainsSelector(child.Resource)
}

type RequestContext struct {
	TaskID string `json:"task_id,omitempty"`
}

func (c RequestContext) Validate() error {
	if c.TaskID == "" {
		return nil
	}
	return validateToken("task id", c.TaskID)
}

type Request struct {
	Actor         Identity       `json:"actor"`
	Subject       Identity       `json:"subject"`
	ApplicationID string         `json:"application_id"`
	Action        Action         `json:"action"`
	Resource      Resource       `json:"resource"`
	Context       RequestContext `json:"context,omitempty"`
}

func (r Request) Validate() error {
	if err := r.Actor.Validate(); err != nil {
		return fmt.Errorf("actor: %w", err)
	}
	if err := r.Subject.Validate(); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if err := validateToken("application id", r.ApplicationID); err != nil {
		return err
	}
	if err := r.Action.Validate(); err != nil {
		return err
	}
	if err := r.Resource.Validate(); err != nil {
		return err
	}
	return r.Context.Validate()
}

type Grant struct {
	ID            string       `json:"id"`
	Subject       Identity     `json:"subject"`
	Issuer        Identity     `json:"issuer"`
	Grantee       Identity     `json:"grantee"`
	ApplicationID string       `json:"application_id"`
	Permissions   []Permission `json:"permissions"`
	TaskID        string       `json:"task_id,omitempty"`
	NotBefore     time.Time    `json:"not_before"`
	ExpiresAt     time.Time    `json:"expires_at"`
	RevokedAt     *time.Time   `json:"revoked_at,omitempty"`
	ParentGrantID string       `json:"parent_grant_id,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
}

func (g Grant) Validate() error {
	if err := validateToken("grant id", g.ID); err != nil {
		return err
	}
	if err := g.Subject.Validate(); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if err := g.Issuer.Validate(); err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	if err := g.Grantee.Validate(); err != nil {
		return fmt.Errorf("grantee: %w", err)
	}
	if err := validateToken("application id", g.ApplicationID); err != nil {
		return err
	}
	if len(g.Permissions) == 0 {
		return fmt.Errorf("grant must contain at least one permission")
	}
	seen := map[string]bool{}
	for _, permission := range g.Permissions {
		if err := permission.Validate(); err != nil {
			return err
		}
		key := permission.Action + "\x00" + permission.Resource.Type + "\x00" + permission.Resource.ID
		if seen[key] {
			return fmt.Errorf("grant contains duplicate permission %q", permission.Action)
		}
		seen[key] = true
	}
	if g.TaskID != "" {
		if err := validateToken("task id", g.TaskID); err != nil {
			return err
		}
	}
	if g.ParentGrantID != "" {
		if err := validateToken("parent grant id", g.ParentGrantID); err != nil {
			return err
		}
	} else if !g.Subject.Equal(g.Issuer) {
		return fmt.Errorf("root grant issuer must equal its subject")
	}
	if g.CreatedAt.IsZero() {
		return fmt.Errorf("grant created_at is required")
	}
	if g.NotBefore.IsZero() {
		return fmt.Errorf("grant not_before is required")
	}
	if g.ExpiresAt.IsZero() {
		return fmt.Errorf("grant expires_at is required")
	}
	if g.NotBefore.Before(g.CreatedAt) {
		return fmt.Errorf("grant not_before must not precede created_at")
	}
	if !g.ExpiresAt.After(g.NotBefore) {
		return fmt.Errorf("grant expires_at must be after not_before")
	}
	if g.RevokedAt != nil && g.RevokedAt.Before(g.CreatedAt) {
		return fmt.Errorf("grant revoked_at must not precede created_at")
	}
	return nil
}

func ValidateDerivedGrant(child Grant, parent Grant) error {
	if err := parent.Validate(); err != nil {
		return fmt.Errorf("parent grant: %w", err)
	}
	if err := child.Validate(); err != nil {
		return fmt.Errorf("child grant: %w", err)
	}
	if child.ParentGrantID != parent.ID {
		return fmt.Errorf("child parent_grant_id must reference parent grant")
	}
	if !child.Subject.Equal(parent.Subject) {
		return fmt.Errorf("child subject must equal parent subject")
	}
	if !child.Issuer.Equal(parent.Grantee) {
		return fmt.Errorf("child issuer must equal parent grantee")
	}
	if child.ApplicationID != parent.ApplicationID {
		return fmt.Errorf("child application must equal parent application")
	}
	if child.NotBefore.Before(parent.NotBefore) {
		return fmt.Errorf("child not_before must not precede parent")
	}
	if child.CreatedAt.Before(parent.CreatedAt) {
		return fmt.Errorf("child created_at must not precede parent")
	}
	if child.ExpiresAt.After(parent.ExpiresAt) {
		return fmt.Errorf("child expires_at must not exceed parent")
	}
	if parent.TaskID != "" && child.TaskID != parent.TaskID {
		return fmt.Errorf("child task must equal a task-bound parent")
	}
	for _, childPermission := range child.Permissions {
		contained := false
		for _, parentPermission := range parent.Permissions {
			if parentPermission.ContainsPermission(childPermission) {
				contained = true
				break
			}
		}
		if !contained {
			return fmt.Errorf("child permission %q exceeds parent authority", childPermission.Action)
		}
	}
	return nil
}

type ReasonCode string

const (
	ReasonMatchingGrant        ReasonCode = "matching_grant"
	ReasonNoMatchingGrant      ReasonCode = "no_matching_grant"
	ReasonPermissionNotGranted ReasonCode = "permission_not_granted"
	ReasonTaskMismatch         ReasonCode = "task_mismatch"
	ReasonGrantNotYetValid     ReasonCode = "grant_not_yet_valid"
	ReasonGrantExpired         ReasonCode = "grant_expired"
	ReasonGrantRevoked         ReasonCode = "grant_revoked"
)

type Decision struct {
	Allowed    bool       `json:"decision"`
	DecisionID string     `json:"decision_id"`
	ReasonCode ReasonCode `json:"reason_code"`
	Reason     string     `json:"reason"`
	GrantIDs   []string   `json:"grant_ids,omitempty"`
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

func validateResourceID(value string) error {
	if value == "" {
		return fmt.Errorf("resource id is required")
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("resource id contains invalid whitespace or control characters")
	}
	return nil
}
