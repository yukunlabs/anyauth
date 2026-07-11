package authz

import (
	"fmt"
	"sort"
	"time"
)

type EvaluateOptions struct {
	Now        time.Time
	DecisionID string
}

func Evaluate(grants []Grant, request Request, opts EvaluateOptions) (Decision, error) {
	if err := request.Validate(); err != nil {
		return Decision{}, fmt.Errorf("authorization request: %w", err)
	}
	if opts.Now.IsZero() {
		return Decision{}, fmt.Errorf("evaluation time is required")
	}
	if opts.DecisionID == "" {
		return Decision{}, fmt.Errorf("decision id is required")
	}

	grantByID, err := validateGrantSet(grants)
	if err != nil {
		return Decision{}, err
	}

	ordered := append([]Grant(nil), grants...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	var candidate *Grant
	var permissionCandidate *Grant
	var taskCandidate *Grant
	var inactiveReason ReasonCode
	var inactiveGrantID string

	for i := range ordered {
		grant := &ordered[i]
		if !grant.Subject.Equal(request.Subject) || !grant.Grantee.Equal(request.Actor) || grant.ApplicationID != request.ApplicationID {
			continue
		}
		if candidate == nil {
			candidate = grant
		}
		if !grantAllowsPermission(*grant, request.Action, request.Resource) {
			continue
		}
		if permissionCandidate == nil {
			permissionCandidate = grant
		}
		if grant.TaskID != "" && grant.TaskID != request.Context.TaskID {
			continue
		}
		if taskCandidate == nil {
			taskCandidate = grant
		}

		active, code, blockingID := activeGrantChain(*grant, grantByID, opts.Now)
		if !active {
			if inactiveReason == "" {
				inactiveReason = code
				inactiveGrantID = blockingID
			}
			continue
		}
		return Decision{
			Allowed:    true,
			DecisionID: opts.DecisionID,
			ReasonCode: ReasonMatchingGrant,
			Reason:     fmt.Sprintf("matched active grant %s", grant.ID),
			GrantIDs:   grantChainIDs(*grant, grantByID),
		}, nil
	}

	decision := Decision{Allowed: false, DecisionID: opts.DecisionID}
	switch {
	case taskCandidate != nil && inactiveReason != "":
		decision.ReasonCode = inactiveReason
		decision.Reason = fmt.Sprintf("grant %s is not active", inactiveGrantID)
		decision.GrantIDs = []string{inactiveGrantID}
	case permissionCandidate != nil:
		decision.ReasonCode = ReasonTaskMismatch
		decision.Reason = fmt.Sprintf("request task does not match grant %s", permissionCandidate.ID)
		decision.GrantIDs = []string{permissionCandidate.ID}
	case candidate != nil:
		decision.ReasonCode = ReasonPermissionNotGranted
		decision.Reason = "no candidate grant contains the requested action and resource"
	case len(grants) > 0:
		decision.ReasonCode = ReasonNoMatchingGrant
		decision.Reason = "no grant matches the actor, subject, and application"
	default:
		decision.ReasonCode = ReasonNoMatchingGrant
		decision.Reason = "no grants are configured"
	}
	return decision, nil
}

func validateGrantSet(grants []Grant) (map[string]Grant, error) {
	byID := make(map[string]Grant, len(grants))
	for _, grant := range grants {
		if err := grant.Validate(); err != nil {
			return nil, fmt.Errorf("grant %q: %w", grant.ID, err)
		}
		if _, exists := byID[grant.ID]; exists {
			return nil, fmt.Errorf("duplicate grant id %q", grant.ID)
		}
		byID[grant.ID] = grant
	}
	for _, grant := range grants {
		if grant.ParentGrantID == "" {
			continue
		}
		parent, ok := byID[grant.ParentGrantID]
		if !ok {
			return nil, fmt.Errorf("grant %q references missing parent %q", grant.ID, grant.ParentGrantID)
		}
		if err := ValidateDerivedGrant(grant, parent); err != nil {
			return nil, fmt.Errorf("grant %q: %w", grant.ID, err)
		}
	}
	for _, grant := range grants {
		seen := map[string]bool{}
		current := grant
		for current.ParentGrantID != "" {
			if seen[current.ID] {
				return nil, fmt.Errorf("grant ancestry cycle contains %q", current.ID)
			}
			seen[current.ID] = true
			current = byID[current.ParentGrantID]
		}
	}
	return byID, nil
}

func ValidateGrants(grants []Grant) error {
	_, err := validateGrantSet(grants)
	return err
}

func grantAllowsPermission(grant Grant, action Action, resource Resource) bool {
	for _, permission := range grant.Permissions {
		if permission.Contains(action, resource) {
			return true
		}
	}
	return false
}

func activeGrantChain(grant Grant, grantByID map[string]Grant, now time.Time) (bool, ReasonCode, string) {
	current := grant
	for {
		if current.RevokedAt != nil && !now.Before(*current.RevokedAt) {
			return false, ReasonGrantRevoked, current.ID
		}
		if now.Before(current.NotBefore) {
			return false, ReasonGrantNotYetValid, current.ID
		}
		if !now.Before(current.ExpiresAt) {
			return false, ReasonGrantExpired, current.ID
		}
		if current.ParentGrantID == "" {
			return true, "", ""
		}
		current = grantByID[current.ParentGrantID]
	}
}

func grantChainIDs(grant Grant, grantByID map[string]Grant) []string {
	ids := []string{grant.ID}
	for grant.ParentGrantID != "" {
		grant = grantByID[grant.ParentGrantID]
		ids = append(ids, grant.ID)
	}
	return ids
}
