package authz

import (
	"context"
	"fmt"
	"time"
)

type GrantSource interface {
	ListGrants(context.Context) ([]Grant, error)
}

type DecisionRecorder interface {
	RecordDecision(context.Context, Request, Decision) error
}

type DecisionIDGenerator func() (string, error)

type Authorizer struct {
	grants GrantSource
	record DecisionRecorder
	now    func() time.Time
	newID  DecisionIDGenerator
}

func NewAuthorizer(grants GrantSource, record DecisionRecorder, now func() time.Time, newID DecisionIDGenerator) (*Authorizer, error) {
	if grants == nil {
		return nil, fmt.Errorf("grant source is required")
	}
	if record == nil {
		return nil, fmt.Errorf("decision recorder is required")
	}
	if now == nil {
		return nil, fmt.Errorf("clock is required")
	}
	if newID == nil {
		return nil, fmt.Errorf("decision id generator is required")
	}
	return &Authorizer{grants: grants, record: record, now: now, newID: newID}, nil
}

func (a *Authorizer) Check(ctx context.Context, request Request) (Decision, error) {
	if err := request.Validate(); err != nil {
		return Decision{}, fmt.Errorf("authorization request: %w", err)
	}
	grants, err := a.grants.ListGrants(ctx)
	if err != nil {
		return Decision{}, fmt.Errorf("load grants: %w", err)
	}
	decisionID, err := a.newID()
	if err != nil {
		return Decision{}, fmt.Errorf("create decision id: %w", err)
	}
	decision, err := Evaluate(grants, request, EvaluateOptions{
		Now:        a.now(),
		DecisionID: decisionID,
	})
	if err != nil {
		return Decision{}, err
	}
	if err := a.record.RecordDecision(ctx, request, decision); err != nil {
		return Decision{}, fmt.Errorf("record decision: %w", err)
	}
	return decision, nil
}
