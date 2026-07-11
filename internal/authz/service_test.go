package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAuthorizerCheckRecordsDecision(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	source := &stubGrantSource{grants: []Grant{testGrant(now)}}
	recorder := &stubDecisionRecorder{}
	authorizer, err := NewAuthorizer(source, recorder, func() time.Time { return now }, func() (string, error) { return "dec_service", nil })
	if err != nil {
		t.Fatal(err)
	}

	decision, err := authorizer.Check(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.DecisionID != "dec_service" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if len(recorder.decisions) != 1 || recorder.decisions[0].DecisionID != decision.DecisionID {
		t.Fatalf("recorded decisions = %#v", recorder.decisions)
	}
}

func TestAuthorizerFailsClosedOnDependencies(t *testing.T) {
	now := time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC)
	dependencyError := errors.New("dependency unavailable")

	tests := []struct {
		name     string
		source   *stubGrantSource
		recorder *stubDecisionRecorder
		newID    DecisionIDGenerator
		want     string
	}{
		{
			name:     "grant source failure",
			source:   &stubGrantSource{err: dependencyError},
			recorder: &stubDecisionRecorder{},
			newID:    func() (string, error) { return "dec_test", nil },
			want:     "load grants",
		},
		{
			name:     "id generator failure",
			source:   &stubGrantSource{},
			recorder: &stubDecisionRecorder{},
			newID:    func() (string, error) { return "", dependencyError },
			want:     "create decision id",
		},
		{
			name:     "decision recorder failure",
			source:   &stubGrantSource{},
			recorder: &stubDecisionRecorder{err: dependencyError},
			newID:    func() (string, error) { return "dec_test", nil },
			want:     "record decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorizer, err := NewAuthorizer(tt.source, tt.recorder, func() time.Time { return now }, tt.newID)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := authorizer.Check(context.Background(), testRequest())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
			if decision.Allowed {
				t.Fatalf("dependency failure returned an allow decision: %#v", decision)
			}
		})
	}
}

type stubGrantSource struct {
	grants []Grant
	err    error
}

func (s *stubGrantSource) ListGrants(context.Context) ([]Grant, error) {
	return append([]Grant(nil), s.grants...), s.err
}

type stubDecisionRecorder struct {
	decisions []Decision
	err       error
}

func (s *stubDecisionRecorder) RecordDecision(_ context.Context, _ Request, decision Decision) error {
	if s.err != nil {
		return s.err
	}
	s.decisions = append(s.decisions, decision)
	return nil
}
