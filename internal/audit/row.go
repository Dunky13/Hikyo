package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// TimeFormat is the fixed-width UTC microsecond text form audit timestamps
// take on sqlite: unlike RFC3339Nano's trailing-zero truncation, every value
// is the same width, so lexicographic order is time order and range
// predicates compare correctly. Postgres stores timestamptz natively.
const TimeFormat = "2006-01-02T15:04:05.000000Z07:00"

// FormatTime renders a timestamp in the audit text form (UTC, microsecond).
func FormatTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(TimeFormat)
}

// ParseTime reads the audit text form back.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(TimeFormat, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit: timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// Row is the canonical storage shape of one validated event — the single
// place envelope-to-column mapping lives, shared by the store's audit
// repositories and the authorization package's denial writer so the two
// writers cannot drift. Nullable columns are pointers; times stay time.Time
// (each engine's binding formats them).
type Row struct {
	ID                string
	Type              string
	SchemaVersion     int64
	OccurredAt        time.Time
	OccurredAsserted  bool
	RecordedAt        time.Time
	ActorID           *string
	ActorClass        string
	ActorCredentialID *string
	AuthorityID       *string
	ScopeClass        string // "instance" on the instance trail
	OrgID             string // tenant trail only
	ProjectID         *string
	EnvID             *string
	ObjectType        *string
	ObjectID          *string
	Outcome           string
	CorrelationID     *string
	SourceIP          *string
	UserAgent         *string
	Origin            string
	Payload           string // schema-validated JSON
}

// BuildRow validates e for the trail and renders it into its storage shape.
// scope is the trusted-layer-bound chain (see Event). sqlite supplies its
// durable-insert timestamp as recordedAt; postgres passes zero because its
// BEFORE INSERT trigger owns recorded_at. A validation failure MUST fail the
// emitting operation.
func BuildRow(e Event, trail Trail, scope domain.Scope, recordedAt time.Time) (Row, error) {
	if err := Validate(e, trail, scope); err != nil {
		return Row{}, err
	}
	scopeClass, err := ScopeClass(trail, scope)
	if err != nil {
		return Row{}, err
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return Row{}, fmt.Errorf("audit: %s: marshal payload: %w", e.Type, err)
	}
	return Row{
		ID:                e.ID,
		Type:              string(e.Type),
		SchemaVersion:     int64(e.SchemaVersion),
		OccurredAt:        e.OccurredAt.UTC().Truncate(time.Microsecond),
		OccurredAsserted:  e.OccurredAsserted,
		RecordedAt:        recordedAt.UTC().Truncate(time.Microsecond),
		ActorID:           optional(e.Actor.ID),
		ActorClass:        string(e.Actor.Class),
		ActorCredentialID: optional(e.Actor.CredentialID),
		AuthorityID:       optional(e.AuthorityID),
		ScopeClass:        scopeClass,
		OrgID:             string(scope.Org),
		ProjectID:         optional(string(scope.Project)),
		EnvID:             optional(string(scope.Env)),
		ObjectType:        optional(e.Object.Type),
		ObjectID:          optional(e.Object.ID),
		Outcome:           string(e.Outcome),
		CorrelationID:     optional(e.CorrelationID),
		SourceIP:          optional(e.SourceIP),
		UserAgent:         optional(e.UserAgent),
		Origin:            string(e.Origin),
		Payload:           string(payload),
	}, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Context is the per-request wire metadata every event records: recorded on
// every event, null only where structurally absent (audit-model ADR:
// absence is a structural fact, never a redaction). The HTTP and CLI layers
// (#47/#48) attach it via WithContext; free text is sanitized at capture.
type Context struct {
	SourceIP  string
	UserAgent string
	Origin    Origin
	// RequestOrigin is the HTTP `Origin` HEADER the request presented, not the
	// audit Origin enum beside it — the two are different facts with the same
	// English name. It is empty for every non-browser caller, and it exists so
	// the workspace authentication leg can compare a bearer's BOUND origin
	// against the origin actually presenting it: a `ws` bearer issued to
	// origin A must not authenticate from allowlisted origin B.
	RequestOrigin string
}

type ctxKey struct{}

// WithContext attaches sanitized wire metadata to the request context.
func WithContext(ctx context.Context, c Context) context.Context {
	c.SourceIP = SanitizeFreeText(c.SourceIP)
	c.UserAgent = SanitizeFreeText(c.UserAgent)
	c.RequestOrigin = SanitizeFreeText(c.RequestOrigin)
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns the attached wire metadata. Absent metadata means an
// in-process caller with no wire origin: OriginSystem, no addresses — the
// structural-absence case, not a default that fakes a request.
func FromContext(ctx context.Context) Context {
	if c, ok := ctx.Value(ctxKey{}).(Context); ok {
		return c
	}
	return Context{Origin: OriginSystem}
}
