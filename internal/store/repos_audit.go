package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// Audit trail repositories (#45, audit-model ADR § Storage and export). The
// application layer holds INSERT and SELECT only on both audit tables — the
// append-only invariant scans the query files; these are the only proof-
// carrying doors to them (the denial writer is the authorization package's
// own enumerated path and does not pass through here).
//
// Chain binding follows the store's universal rule: a tenant event's chain
// is the proof's resolved chain — the caller's Event.Scope is deliberately
// ignored and overwritten, so caller arguments structurally cannot reach a
// chain column. Page reads bind their chain predicates the same way.

// AuditFilter is the normalized filter structure for trail reads. Zero From
// means the epoch; zero To means unbounded (bound to MaxTime at the query).
// AfterSeq is the page cursor; Limit is the page size and must be positive
// (the caller's bound — ops spec owns defaults).
type AuditFilter struct {
	From     time.Time
	To       time.Time
	AfterSeq int64
	Limit    int
}

// auditMaxTime bounds an open-ended To (year 9999 is inside both engines'
// ranges and lexicographically last in the fixed-width text form).
var auditMaxTime = time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)

func (f AuditFilter) bounds() (from, to time.Time, err error) {
	if f.Limit <= 0 {
		return time.Time{}, time.Time{}, errors.New("store: audit page limit must be positive")
	}
	from = f.From.UTC()
	to = f.To.UTC()
	if f.To.IsZero() {
		to = auditMaxTime
	}
	return from, to, nil
}

// Normalized renders the filter as the audit.query event's payload fields —
// the parsed, normalized filter structure, never a raw query string.
func (f AuditFilter) Normalized() audit.Payload {
	p := audit.Payload{"filter_limit": f.Limit}
	if !f.From.IsZero() {
		p["filter_from"] = audit.FormatTime(f.From)
	}
	if !f.To.IsZero() {
		p["filter_to"] = audit.FormatTime(f.To)
	}
	if f.AfterSeq > 0 {
		p["filter_after_seq"] = f.AfterSeq
	}
	return p
}

// AuditEvent is one stored trail row: the envelope plus its storage-assigned
// seq and recorded_at, and the chain columns as plain strings (read-side
// output — the analyzer's tenant-typed-parameter rule concerns inputs).
type AuditEvent struct {
	audit.Event
	Seq        int64
	RecordedAt time.Time
	ScopeClass string
	OrgID      string
	ProjectID  string
	EnvID      string
	RawPayload string // schema-versioned JSON as stored; export emits it verbatim
}

// AuditReader is the read side of the trails.
type AuditReader interface {
	// PageTenant returns one bounded page of the tenant trail addressed by
	// the proof's resolved chain (org proofs read the whole org, deeper
	// proofs read their refinement), ordered by seq.
	PageTenant(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error)
	// PageInstance returns one bounded page of the instance trail.
	PageInstance(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error)
}

// AuditRepo adds the two insert doors. Insertion validates against the
// closed registry and fails the surrounding operation on refusal
// (fail-closed — an operation without its durable audit record does not
// complete).
type AuditRepo interface {
	AuditReader
	// InsertTenant writes one tenant-trail event. The event's chain is the
	// proof's resolved chain; recorded_at is assigned here.
	InsertTenant(ctx context.Context, p authz.Proof, e audit.Event) error
	// InsertInstance writes one instance-trail event.
	InsertInstance(ctx context.Context, p authz.Proof, e audit.Event) error
}

// --- sqlite ---

type sqliteAudit struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteRepos) Audit() AuditRepo { return sqliteAudit{q: sqlitegen.New(r.db), tok: r.tok} }

func (a sqliteAudit) InsertTenant(ctx context.Context, p authz.Proof, e audit.Event) error {
	chain, err := authz.Verify(p, authz.StoreAuditTenantInsert, a.tok)
	if err != nil {
		return err
	}
	e.Actor = resolveActorClass(ctx, e.Actor, func(id string) (string, error) {
		return a.q.GetPrincipalKind(ctx, id)
	})
	// Chain columns: proof-bound, never caller input.
	row, err := audit.BuildRow(e, audit.TrailTenant, chain, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertTenantAuditEvent(ctx, sqlitegen.InsertTenantAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: row.SchemaVersion,
		OccurredAt:       audit.FormatTime(row.OccurredAt),
		OccurredAsserted: boolToInt(row.OccurredAsserted),
		RecordedAt:       audit.FormatTime(row.RecordedAt),
		ActorID:          nullString(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: nullString(row.ActorCredentialID), AuthorityID: nullString(row.AuthorityID),
		ScopeClass: row.ScopeClass, OrgID: row.OrgID,
		ProjectID: nullString(row.ProjectID), EnvID: nullString(row.EnvID),
		ObjectType: nullString(row.ObjectType), ObjectID: nullString(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: nullString(row.CorrelationID),
		SourceIp: nullString(row.SourceIP), UserAgent: nullString(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func (a sqliteAudit) InsertInstance(ctx context.Context, p authz.Proof, e audit.Event) error {
	if _, err := authz.Verify(p, authz.StoreAuditInstanceInsert, a.tok); err != nil {
		return err
	}
	e.Actor = resolveActorClass(ctx, e.Actor, func(id string) (string, error) {
		return a.q.GetPrincipalKind(ctx, id)
	})
	row, err := audit.BuildRow(e, audit.TrailInstance, domain.Scope{}, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertInstanceAuditEvent(ctx, sqlitegen.InsertInstanceAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: row.SchemaVersion,
		OccurredAt:       audit.FormatTime(row.OccurredAt),
		OccurredAsserted: boolToInt(row.OccurredAsserted),
		RecordedAt:       audit.FormatTime(row.RecordedAt),
		ActorID:          nullString(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: nullString(row.ActorCredentialID), AuthorityID: nullString(row.AuthorityID),
		ObjectType: nullString(row.ObjectType), ObjectID: nullString(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: nullString(row.CorrelationID),
		SourceIp: nullString(row.SourceIP), UserAgent: nullString(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func (a sqliteAudit) PageTenant(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error) {
	chain, err := authz.Verify(p, authz.StoreAuditTenantPage, a.tok)
	if err != nil {
		return nil, err
	}
	from, to, err := f.bounds()
	if err != nil {
		return nil, err
	}
	level, err := chain.Level()
	if err != nil {
		return nil, err
	}
	var rows []sqlitegen.AuditTenantEvent
	switch level {
	case domain.LevelOrg:
		rows, err = a.q.PageTenantAuditOrg(ctx, sqlitegen.PageTenantAuditOrgParams{
			OrgID: string(chain.Org), Seq: f.AfterSeq,
			RecordedAt: audit.FormatTime(from), RecordedAt_2: audit.FormatTime(to),
			Limit: int64(f.Limit),
		})
	case domain.LevelProject:
		rows, err = a.q.PageTenantAuditProject(ctx, sqlitegen.PageTenantAuditProjectParams{
			OrgID: string(chain.Org), ProjectID: nullString(strPtr(string(chain.Project))), Seq: f.AfterSeq,
			RecordedAt: audit.FormatTime(from), RecordedAt_2: audit.FormatTime(to),
			Limit: int64(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditEnv(ctx, sqlitegen.PageTenantAuditEnvParams{
			OrgID: string(chain.Org), ProjectID: nullString(strPtr(string(chain.Project))),
			EnvID: nullString(strPtr(string(chain.Env))), Seq: f.AfterSeq,
			RecordedAt: audit.FormatTime(from), RecordedAt_2: audit.FormatTime(to),
			Limit: int64(f.Limit),
		})
	default:
		return nil, errors.New("store: tenant audit page with an empty chain")
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditEventFromSQLiteTenant(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (a sqliteAudit) PageInstance(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error) {
	if _, err := authz.Verify(p, authz.StoreAuditInstancePage, a.tok); err != nil {
		return nil, err
	}
	from, to, err := f.bounds()
	if err != nil {
		return nil, err
	}
	rows, err := a.q.PageInstanceAudit(ctx, sqlitegen.PageInstanceAuditParams{
		Seq:        f.AfterSeq,
		RecordedAt: audit.FormatTime(from), RecordedAt_2: audit.FormatTime(to),
		Limit: int64(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditEventFromSQLiteInstance(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

// --- postgres ---

type pgAudit struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgRepos) Audit() AuditRepo { return pgAudit{q: pggen.New(r.db), tok: r.tok} }

func (a pgAudit) InsertTenant(ctx context.Context, p authz.Proof, e audit.Event) error {
	chain, err := authz.Verify(p, authz.StoreAuditTenantInsert, a.tok)
	if err != nil {
		return err
	}
	e.Actor = resolveActorClass(ctx, e.Actor, func(id string) (string, error) {
		return a.q.GetPrincipalKind(ctx, id)
	})
	// Chain columns: proof-bound, never caller input.
	row, err := audit.BuildRow(e, audit.TrailTenant, chain, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertTenantAuditEvent(ctx, pggen.InsertTenantAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: int32(row.SchemaVersion),
		OccurredAt:       pgtype.Timestamptz{Time: row.OccurredAt, Valid: true},
		OccurredAsserted: row.OccurredAsserted,
		RecordedAt:       pgtype.Timestamptz{Time: row.RecordedAt, Valid: true},
		ActorID:          pgText(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: pgText(row.ActorCredentialID), AuthorityID: pgText(row.AuthorityID),
		ScopeClass: row.ScopeClass, ChainOrgID: row.OrgID,
		ProjectID: pgText(row.ProjectID), EnvID: pgText(row.EnvID),
		ObjectType: pgText(row.ObjectType), ObjectID: pgText(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: pgText(row.CorrelationID),
		SourceIp: pgText(row.SourceIP), UserAgent: pgText(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func (a pgAudit) InsertInstance(ctx context.Context, p authz.Proof, e audit.Event) error {
	if _, err := authz.Verify(p, authz.StoreAuditInstanceInsert, a.tok); err != nil {
		return err
	}
	e.Actor = resolveActorClass(ctx, e.Actor, func(id string) (string, error) {
		return a.q.GetPrincipalKind(ctx, id)
	})
	row, err := audit.BuildRow(e, audit.TrailInstance, domain.Scope{}, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertInstanceAuditEvent(ctx, pggen.InsertInstanceAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: int32(row.SchemaVersion),
		OccurredAt:       pgtype.Timestamptz{Time: row.OccurredAt, Valid: true},
		OccurredAsserted: row.OccurredAsserted,
		RecordedAt:       pgtype.Timestamptz{Time: row.RecordedAt, Valid: true},
		ActorID:          pgText(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: pgText(row.ActorCredentialID), AuthorityID: pgText(row.AuthorityID),
		ObjectType: pgText(row.ObjectType), ObjectID: pgText(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: pgText(row.CorrelationID),
		SourceIp: pgText(row.SourceIP), UserAgent: pgText(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func (a pgAudit) PageTenant(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error) {
	chain, err := authz.Verify(p, authz.StoreAuditTenantPage, a.tok)
	if err != nil {
		return nil, err
	}
	from, to, err := f.bounds()
	if err != nil {
		return nil, err
	}
	level, err := chain.Level()
	if err != nil {
		return nil, err
	}
	fromTz := pgtype.Timestamptz{Time: from, Valid: true}
	toTz := pgtype.Timestamptz{Time: to, Valid: true}
	var rows []pggen.AuditTenantEvent
	switch level {
	case domain.LevelOrg:
		rows, err = a.q.PageTenantAuditOrg(ctx, pggen.PageTenantAuditOrgParams{
			ChainOrgID: string(chain.Org), AfterSeq: f.AfterSeq,
			FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	case domain.LevelProject:
		rows, err = a.q.PageTenantAuditProject(ctx, pggen.PageTenantAuditProjectParams{
			ChainOrgID: string(chain.Org), ChainProjectID: pgText(strPtr(string(chain.Project))),
			AfterSeq: f.AfterSeq, FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditEnv(ctx, pggen.PageTenantAuditEnvParams{
			ChainOrgID: string(chain.Org), ChainProjectID: pgText(strPtr(string(chain.Project))),
			ChainEnvID: pgText(strPtr(string(chain.Env))),
			AfterSeq:   f.AfterSeq, FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	default:
		return nil, errors.New("store: tenant audit page with an empty chain")
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditEventFromPGTenant(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (a pgAudit) PageInstance(ctx context.Context, p authz.Proof, f AuditFilter) ([]AuditEvent, error) {
	if _, err := authz.Verify(p, authz.StoreAuditInstancePage, a.tok); err != nil {
		return nil, err
	}
	from, to, err := f.bounds()
	if err != nil {
		return nil, err
	}
	rows, err := a.q.PageInstanceAudit(ctx, pggen.PageInstanceAuditParams{
		AfterSeq: f.AfterSeq,
		FromTime: pgtype.Timestamptz{Time: from, Valid: true},
		ToTime:   pgtype.Timestamptz{Time: to, Valid: true},
		PageLimit: int32(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, r := range rows {
		ev, err := auditEventFromPGInstance(r)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

// --- shared mapping helpers ---

// resolveActorClass fills a principal actor's class from principals.kind
// when the emitter left it empty — the server-side truth, not a caller
// claim. An explicitly set class (system, break-glass, unauthenticated)
// passes through untouched.
func resolveActorClass(_ context.Context, a audit.Actor, kindOf func(string) (string, error)) audit.Actor {
	if a.Class != "" || a.ID == "" {
		return a
	}
	kind, err := kindOf(a.ID)
	switch {
	case err == nil && kind == "human":
		a.Class = audit.ActorHuman
	case err == nil && kind == "machine":
		a.Class = audit.ActorMachine
	default:
		// Unknown principal or lookup failure: structured absence. BuildRow
		// validation keeps the enum closed either way.
		return audit.Actor{Class: audit.ActorUnauthenticated}
	}
	return a
}

func nullString(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func pgText(p *string) pgtype.Text {
	if p == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *p, Valid: true}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func auditEventFromSQLiteTenant(r sqlitegen.AuditTenantEvent) (AuditEvent, error) {
	occurred, err := audit.ParseTime(r.OccurredAt)
	if err != nil {
		return AuditEvent{}, err
	}
	recorded, err := audit.ParseTime(r.RecordedAt)
	if err != nil {
		return AuditEvent{}, err
	}
	if r.OccurredAsserted != 0 && r.OccurredAsserted != 1 {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: occurred_asserted = %d, not a boolean", r.ID, r.OccurredAsserted)
	}
	return AuditEvent{
		Event: audit.Event{
			ID: r.ID, Type: audit.EventType(r.Type), SchemaVersion: int(r.SchemaVersion),
			OccurredAt: occurred, OccurredAsserted: r.OccurredAsserted == 1,
			Actor: audit.Actor{
				ID: r.ActorID.String, Class: audit.ActorClass(r.ActorClass),
				CredentialID: r.ActorCredentialID.String,
			},
			AuthorityID:   r.AuthorityID.String,
			Object:        audit.Object{Type: r.ObjectType.String, ID: r.ObjectID.String},
			Outcome:       audit.Outcome(r.Outcome),
			CorrelationID: r.CorrelationID.String,
			SourceIP:      r.SourceIp.String, UserAgent: r.UserAgent.String,
			Origin: audit.Origin(r.Origin),
		},
		Seq: r.Seq, RecordedAt: recorded, ScopeClass: r.ScopeClass,
		OrgID: r.OrgID, ProjectID: r.ProjectID.String, EnvID: r.EnvID.String,
		RawPayload: r.Payload,
	}, nil
}

func auditEventFromSQLiteInstance(r sqlitegen.AuditInstanceEvent) (AuditEvent, error) {
	occurred, err := audit.ParseTime(r.OccurredAt)
	if err != nil {
		return AuditEvent{}, err
	}
	recorded, err := audit.ParseTime(r.RecordedAt)
	if err != nil {
		return AuditEvent{}, err
	}
	if r.OccurredAsserted != 0 && r.OccurredAsserted != 1 {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: occurred_asserted = %d, not a boolean", r.ID, r.OccurredAsserted)
	}
	return AuditEvent{
		Event: audit.Event{
			ID: r.ID, Type: audit.EventType(r.Type), SchemaVersion: int(r.SchemaVersion),
			OccurredAt: occurred, OccurredAsserted: r.OccurredAsserted == 1,
			Actor: audit.Actor{
				ID: r.ActorID.String, Class: audit.ActorClass(r.ActorClass),
				CredentialID: r.ActorCredentialID.String,
			},
			AuthorityID:   r.AuthorityID.String,
			Object:        audit.Object{Type: r.ObjectType.String, ID: r.ObjectID.String},
			Outcome:       audit.Outcome(r.Outcome),
			CorrelationID: r.CorrelationID.String,
			SourceIP:      r.SourceIp.String, UserAgent: r.UserAgent.String,
			Origin: audit.Origin(r.Origin),
		},
		Seq: r.Seq, RecordedAt: recorded, ScopeClass: "instance", RawPayload: r.Payload,
	}, nil
}

func auditEventFromPGTenant(r pggen.AuditTenantEvent) (AuditEvent, error) {
	if !r.OccurredAt.Valid || !r.RecordedAt.Valid {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: null timestamp", r.ID)
	}
	return AuditEvent{
		Event: audit.Event{
			ID: r.ID, Type: audit.EventType(r.Type), SchemaVersion: int(r.SchemaVersion),
			OccurredAt: r.OccurredAt.Time.UTC(), OccurredAsserted: r.OccurredAsserted,
			Actor: audit.Actor{
				ID: r.ActorID.String, Class: audit.ActorClass(r.ActorClass),
				CredentialID: r.ActorCredentialID.String,
			},
			AuthorityID:   r.AuthorityID.String,
			Object:        audit.Object{Type: r.ObjectType.String, ID: r.ObjectID.String},
			Outcome:       audit.Outcome(r.Outcome),
			CorrelationID: r.CorrelationID.String,
			SourceIP:      r.SourceIp.String, UserAgent: r.UserAgent.String,
			Origin: audit.Origin(r.Origin),
		},
		Seq: r.Seq, RecordedAt: r.RecordedAt.Time.UTC(), ScopeClass: r.ScopeClass,
		OrgID: r.OrgID, ProjectID: r.ProjectID.String, EnvID: r.EnvID.String,
		RawPayload: r.Payload,
	}, nil
}

func auditEventFromPGInstance(r pggen.AuditInstanceEvent) (AuditEvent, error) {
	if !r.OccurredAt.Valid || !r.RecordedAt.Valid {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: null timestamp", r.ID)
	}
	return AuditEvent{
		Event: audit.Event{
			ID: r.ID, Type: audit.EventType(r.Type), SchemaVersion: int(r.SchemaVersion),
			OccurredAt: r.OccurredAt.Time.UTC(), OccurredAsserted: r.OccurredAsserted,
			Actor: audit.Actor{
				ID: r.ActorID.String, Class: audit.ActorClass(r.ActorClass),
				CredentialID: r.ActorCredentialID.String,
			},
			AuthorityID:   r.AuthorityID.String,
			Object:        audit.Object{Type: r.ObjectType.String, ID: r.ObjectID.String},
			Outcome:       audit.Outcome(r.Outcome),
			CorrelationID: r.CorrelationID.String,
			SourceIP:      r.SourceIp.String, UserAgent: r.UserAgent.String,
			Origin: audit.Origin(r.Origin),
		},
		Seq: r.Seq, RecordedAt: r.RecordedAt.Time.UTC(), ScopeClass: "instance", RawPayload: r.Payload,
	}, nil
}
