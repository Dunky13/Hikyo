// Package audit is the audit-model ADR's event vocabulary: the envelope,
// the closed category.action registry, retention classes, outcome licensing,
// and the free-text hygiene applied to every attacker-influencable string
// before it lands in a durable surveillance record. It is a leaf package
// (imports only internal/domain) so the authorization package, the store and
// the service layer can all speak it without cycles.
//
// The package validates; it does not persist. Persistence is the store's
// audit repositories (tenant trail, instance trail), and the denial writer
// in the authorization package's enumerated surface — both of which refuse
// an event this package's Validate rejects (fail-closed: an operation
// without its durable audit record does not complete).
package audit

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Dunky13/wenv/internal/domain"
)

// Trail names one of the two append-only tables. The two trails are two
// independent seq sequences; no cross-trail order exists (audit-model ADR
// § Storage).
type Trail string

const (
	// TrailTenant is audit_tenant_events: org-owned, chain-scoped rows.
	TrailTenant Trail = "tenant"
	// TrailInstance is audit_instance_events: instance-, system- and
	// unauthenticated-class events, unresolvable denials included.
	TrailInstance Trail = "instance"
)

// Outcome is the envelope's single outcome enum — no payload
// shadow-outcomes. Which values a type may carry is registry data
// (CI invariant 12).
type Outcome string

const (
	OutcomeIntent       Outcome = "intent"
	OutcomeSuccess      Outcome = "success"
	OutcomeDenied       Outcome = "denied"
	OutcomeFailure      Outcome = "failure"
	OutcomeUnknown      Outcome = "unknown"
	OutcomeDisconnected Outcome = "disconnected"
)

// RetentionClass is one of the two classes (audit-model ADR § Retention).
// Class membership is fixed per event type in the registry, not
// configurable.
type RetentionClass string

const (
	// RetentionAccess: the unbounded machine-traffic stream — fetch
	// envelopes, per-key delivery, conditional-fetch access records, denial
	// events.
	RetentionAccess RetentionClass = "access"
	// RetentionSecurity: everything else; longer default.
	RetentionSecurity RetentionClass = "security"
)

// ActorClass is the envelope's principal classification. Nullable actor ids
// are a structured fact — an unknown-account login failure has no principal
// — never a dummy principal.
type ActorClass string

const (
	ActorHuman           ActorClass = "human"
	ActorMachine         ActorClass = "machine"
	ActorSystem          ActorClass = "system"
	ActorBreakGlass      ActorClass = "break-glass"
	ActorUnauthenticated ActorClass = "unauthenticated"
)

// Origin is the envelope's origin enum.
type Origin string

const (
	OriginWeb           Origin = "web"
	OriginCLI           Origin = "cli"
	OriginAPI           Origin = "api"
	OriginOperatorFetch Origin = "operator-fetch"
	OriginAdapterJob    Origin = "adapter-job"
	OriginOfflineRecon  Origin = "offline-reconciled"
	OriginSystem        Origin = "system"
)

// Actor is the envelope's acting-principal triple. IDs are nullable as
// structured facts (class ActorUnauthenticated with empty ids), never dummy
// principals.
type Actor struct {
	ID           string // principal id, "" when structurally absent
	Class        ActorClass
	CredentialID string // authenticating artifact id, "" when absent
}

// Object is the acted-on type + immutable id; the zero value means the event
// has no object (an admission-threshold crossing).
type Object struct {
	Type string
	ID   string
}

// Event is the envelope every audit row carries (audit-model ADR § The event
// envelope). seq and recorded_at are storage-assigned at durable insert and
// therefore absent here; occurred_at is caller-supplied and flagged when
// client-asserted (offline reconciliation).
//
// Deliberately ABSENT: the scope chain. The chain a tenant event carries is
// the proof's resolved chain (or, for the denial writer, the chain
// authorize() itself resolved) — passed alongside the event by the trusted
// layer that binds it, never a field a caller could populate. This keeps
// the proof-signature analyzer's rule intact: no tenant-identifier-typed
// value travels a store-method parameter.
type Event struct {
	ID               string // UUIDv7, prefixed — NewEventID
	Type             EventType
	SchemaVersion    int
	OccurredAt       time.Time
	OccurredAsserted bool // client-asserted occurred_at (offline-reconciled)
	Actor            Actor
	AuthorityID      string // recorded authority principal, "" when direct
	Object           Object
	Outcome          Outcome
	CorrelationID    string
	SourceIP         string // "" only where structurally absent
	UserAgent        string
	Origin           Origin
	Payload          Payload
}

// NewEventID mints the project-pattern UUIDv7 id for an event.
func NewEventID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("audit: generate event id: %w", err)
	}
	return "evt_" + id.String(), nil
}

// Validate checks the event against the closed registry: registered type,
// licensed outcome, schema-valid payload, trail-consistent scope, and the
// envelope's own free-text hygiene already applied (bounded, sanitized —
// Validate refuses rather than silently re-sanitizes: an unsanitized event
// at the write boundary is a bug in the emitter). A failure here MUST fail
// the emitting operation (fail-closed, CI invariant 1). scope is the
// trusted-layer-bound chain: proof-resolved for tenant events, empty for
// instance events.
func Validate(e Event, trail Trail, scope domain.Scope) error {
	spec, ok := Registry[e.Type]
	if !ok {
		return fmt.Errorf("audit: event type %q is not in the closed registry", e.Type)
	}
	if e.ID == "" {
		return fmt.Errorf("audit: %s: event without an id", e.Type)
	}
	if e.SchemaVersion != spec.SchemaVersion {
		return fmt.Errorf("audit: %s: schema version %d, registry declares %d", e.Type, e.SchemaVersion, spec.SchemaVersion)
	}
	if !spec.Outcomes[e.Outcome] {
		return fmt.Errorf("audit: %s: outcome %q is not licensed for this type (CI invariant 12)", e.Type, e.Outcome)
	}
	if !spec.Trails[trail] {
		return fmt.Errorf("audit: %s: not registered for the %s trail", e.Type, trail)
	}
	if e.OccurredAt.IsZero() {
		return fmt.Errorf("audit: %s: zero occurred_at", e.Type)
	}
	switch e.Actor.Class {
	case ActorHuman, ActorMachine, ActorSystem, ActorBreakGlass:
	case ActorUnauthenticated:
		if e.Actor.ID != "" || e.Actor.CredentialID != "" {
			return fmt.Errorf("audit: %s: unauthenticated actor with principal or credential id", e.Type)
		}
	default:
		return fmt.Errorf("audit: %s: unknown actor class %q", e.Type, e.Actor.Class)
	}
	switch e.Origin {
	case OriginWeb, OriginCLI, OriginAPI, OriginOperatorFetch, OriginAdapterJob, OriginOfflineRecon, OriginSystem:
	default:
		return fmt.Errorf("audit: %s: unknown origin %q", e.Type, e.Origin)
	}
	switch trail {
	case TrailTenant:
		if _, err := scope.Level(); err != nil {
			return fmt.Errorf("audit: %s: tenant event scope: %w", e.Type, err)
		}
		if scope.Org == "" {
			return fmt.Errorf("audit: %s: tenant event without an org chain", e.Type)
		}
	case TrailInstance:
		if scope != (domain.Scope{}) {
			return fmt.Errorf("audit: %s: instance event carries a tenant chain", e.Type)
		}
	default:
		return fmt.Errorf("audit: unknown trail %q", trail)
	}
	for _, field := range []struct{ name, v string }{
		{"user_agent", e.UserAgent}, {"source_ip", e.SourceIP},
	} {
		if err := checkSanitized(field.v); err != nil {
			return fmt.Errorf("audit: %s: envelope field %s: %w", e.Type, field.name, err)
		}
	}
	if err := spec.Schema.validate(e.Type, e.Payload); err != nil {
		return err
	}
	return nil
}

// ScopeClass returns the audit row's declared scope class string for a
// tenant event ("org" | "project" | "env") or "instance" for the instance
// trail, matching the per-class row shapes.
func ScopeClass(trail Trail, s domain.Scope) (string, error) {
	if trail == TrailInstance {
		return "instance", nil
	}
	level, err := s.Level()
	if err != nil {
		return "", err
	}
	switch level {
	case domain.LevelOrg:
		return "org", nil
	case domain.LevelProject:
		return "project", nil
	case domain.LevelEnv:
		return "env", nil
	default:
		return "", fmt.Errorf("audit: tenant event with empty scope")
	}
}
