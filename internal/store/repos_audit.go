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
	"github.com/Dunky13/wenv/internal/store/auditrow"
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
// AfterSeq is the public allocation-order lower bound; Limit is the page size
// and must be positive (the caller's bound — ops spec owns defaults). Export
// mode adds an internal commit-order cursor without changing AfterSeq.
type AuditFilter struct {
	From           time.Time
	To             time.Time
	AfterSeq       int64
	Limit          int
	Order          AuditPageOrder // internal page mode; excluded from Normalized
	AfterCommitSeq AuditCommitSeq // internal export cursor; excluded from Normalized
}

// AuditPageOrder names the storage order for an audit page.
type AuditPageOrder uint8

const (
	AuditPageBySeq AuditPageOrder = iota
	AuditPageByCommit
)

// AuditCommitSeq is postgres's database-owned export position.
type AuditCommitSeq int64

// auditMaxTime bounds an open-ended To (year 9999 is inside both engines'
// ranges and lexicographically last in the fixed-width text form).
var auditMaxTime = time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)

func (f AuditFilter) bounds() (from, to time.Time, err error) {
	if f.Limit <= 0 {
		return time.Time{}, time.Time{}, errors.New("store: audit page limit must be positive")
	}
	if f.Order != AuditPageBySeq && f.Order != AuditPageByCommit {
		return time.Time{}, time.Time{}, fmt.Errorf("store: unknown audit page order %d", f.Order)
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
	CommitSeq  AuditCommitSeq // postgres export cursor; equals Seq on sqlite
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
	// proofs read their refinement), in the filter's validated order.
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
	chain, err := authz.VerifyEvent(p, authz.StoreAuditTenantInsert, a.tok, e.Type)
	if err != nil {
		return err
	}
	e.Actor, err = auditrow.ResolveActorClass(ctx, a.q.GetPrincipalKind, e.Actor, authz.IsSystemProof(p))
	if err != nil {
		return err
	}
	// Chain columns: proof-bound, never caller input.
	row, err := audit.BuildRow(e, audit.TrailTenant, chain, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertTenantAuditEvent(ctx, auditrow.SQLiteTenant(row))
}

func (a sqliteAudit) InsertInstance(ctx context.Context, p authz.Proof, e audit.Event) error {
	if _, err := authz.VerifyEvent(p, authz.StoreAuditInstanceInsert, a.tok, e.Type); err != nil {
		return err
	}
	var err error
	e.Actor, err = auditrow.ResolveActorClass(ctx, a.q.GetPrincipalKind, e.Actor, authz.IsSystemProof(p))
	if err != nil {
		return err
	}
	row, err := audit.BuildRow(e, audit.TrailInstance, domain.Scope{}, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertInstanceAuditEvent(ctx, auditrow.SQLiteInstance(row))
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
	if f.Order == AuditPageByCommit {
		return a.pageTenantExport(ctx, chain, level, f, from, to)
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
			OrgID: string(chain.Org), ProjectID: sql.NullString{String: string(chain.Project), Valid: true},
			Seq:        f.AfterSeq,
			RecordedAt: audit.FormatTime(from), RecordedAt_2: audit.FormatTime(to),
			Limit: int64(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditEnv(ctx, sqlitegen.PageTenantAuditEnvParams{
			OrgID: string(chain.Org), ProjectID: sql.NullString{String: string(chain.Project), Valid: true},
			EnvID: sql.NullString{String: string(chain.Env), Valid: true}, Seq: f.AfterSeq,
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
	if f.Order == AuditPageByCommit {
		return a.pageInstanceExport(ctx, f, from, to)
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

func (a sqliteAudit) pageTenantExport(ctx context.Context, chain domain.Scope, level domain.Level, f AuditFilter, from, to time.Time) ([]AuditEvent, error) {
	var err error
	var rows []sqlitegen.AuditTenantEvent
	switch level {
	case domain.LevelOrg:
		rows, err = a.q.PageTenantAuditExportOrg(ctx, sqlitegen.PageTenantAuditExportOrgParams{
			ChainOrgID: string(chain.Org), AfterSeq: f.AfterSeq, AfterCommitSeq: int64(f.AfterCommitSeq),
			FromTime: audit.FormatTime(from), ToTime: audit.FormatTime(to), PageLimit: int64(f.Limit),
		})
	case domain.LevelProject:
		rows, err = a.q.PageTenantAuditExportProject(ctx, sqlitegen.PageTenantAuditExportProjectParams{
			ChainOrgID: string(chain.Org), ChainProjectID: sql.NullString{String: string(chain.Project), Valid: true},
			AfterSeq: f.AfterSeq, AfterCommitSeq: int64(f.AfterCommitSeq),
			FromTime: audit.FormatTime(from), ToTime: audit.FormatTime(to), PageLimit: int64(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditExportEnv(ctx, sqlitegen.PageTenantAuditExportEnvParams{
			ChainOrgID: string(chain.Org), ChainProjectID: sql.NullString{String: string(chain.Project), Valid: true},
			ChainEnvID: sql.NullString{String: string(chain.Env), Valid: true},
			AfterSeq:   f.AfterSeq, AfterCommitSeq: int64(f.AfterCommitSeq),
			FromTime: audit.FormatTime(from), ToTime: audit.FormatTime(to), PageLimit: int64(f.Limit),
		})
	default:
		return nil, errors.New("store: tenant audit export page with an empty chain")
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		event, err := auditEventFromSQLiteTenant(row)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

func (a sqliteAudit) pageInstanceExport(ctx context.Context, f AuditFilter, from, to time.Time) ([]AuditEvent, error) {
	rows, err := a.q.PageInstanceAuditExport(ctx, sqlitegen.PageInstanceAuditExportParams{
		AfterSeq:       f.AfterSeq,
		AfterCommitSeq: int64(f.AfterCommitSeq),
		FromTime:       audit.FormatTime(from),
		ToTime:         audit.FormatTime(to),
		PageLimit:      int64(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		event, err := auditEventFromSQLiteInstance(row)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
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
	chain, err := authz.VerifyEvent(p, authz.StoreAuditTenantInsert, a.tok, e.Type)
	if err != nil {
		return err
	}
	e.Actor, err = auditrow.ResolveActorClass(ctx, a.q.GetPrincipalKind, e.Actor, authz.IsSystemProof(p))
	if err != nil {
		return err
	}
	// Chain columns: proof-bound, never caller input.
	row, err := audit.BuildRow(e, audit.TrailTenant, chain, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertTenantAuditEvent(ctx, auditrow.PGTenant(row))
}

func (a pgAudit) InsertInstance(ctx context.Context, p authz.Proof, e audit.Event) error {
	if _, err := authz.VerifyEvent(p, authz.StoreAuditInstanceInsert, a.tok, e.Type); err != nil {
		return err
	}
	var err error
	e.Actor, err = auditrow.ResolveActorClass(ctx, a.q.GetPrincipalKind, e.Actor, authz.IsSystemProof(p))
	if err != nil {
		return err
	}
	row, err := audit.BuildRow(e, audit.TrailInstance, domain.Scope{}, time.Now())
	if err != nil {
		return err
	}
	return a.q.InsertInstanceAuditEvent(ctx, auditrow.PGInstance(row))
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
	if f.Order == AuditPageByCommit {
		return a.pageTenantExport(ctx, chain, level, f, from, to)
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
			ChainOrgID: string(chain.Org), ChainProjectID: pgtype.Text{String: string(chain.Project), Valid: true},
			AfterSeq: f.AfterSeq,
			FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditEnv(ctx, pggen.PageTenantAuditEnvParams{
			ChainOrgID: string(chain.Org), ChainProjectID: pgtype.Text{String: string(chain.Project), Valid: true},
			ChainEnvID: pgtype.Text{String: string(chain.Env), Valid: true},
			AfterSeq:   f.AfterSeq,
			FromTime:   fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
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
	if f.Order == AuditPageByCommit {
		return a.pageInstanceExport(ctx, f, from, to)
	}
	rows, err := a.q.PageInstanceAudit(ctx, pggen.PageInstanceAuditParams{
		AfterSeq:  f.AfterSeq,
		FromTime:  pgtype.Timestamptz{Time: from, Valid: true},
		ToTime:    pgtype.Timestamptz{Time: to, Valid: true},
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

func (a pgAudit) pageTenantExport(ctx context.Context, chain domain.Scope, level domain.Level, f AuditFilter, from, to time.Time) ([]AuditEvent, error) {
	var err error
	fromTz := pgtype.Timestamptz{Time: from, Valid: true}
	toTz := pgtype.Timestamptz{Time: to, Valid: true}
	commitCursor := pgtype.Int8{Int64: int64(f.AfterCommitSeq), Valid: true}
	var rows []pggen.AuditTenantEvent
	switch level {
	case domain.LevelOrg:
		rows, err = a.q.PageTenantAuditExportOrg(ctx, pggen.PageTenantAuditExportOrgParams{
			ChainOrgID: string(chain.Org), AfterSeq: f.AfterSeq, AfterCommitSeq: commitCursor,
			FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	case domain.LevelProject:
		rows, err = a.q.PageTenantAuditExportProject(ctx, pggen.PageTenantAuditExportProjectParams{
			ChainOrgID: string(chain.Org), ChainProjectID: pgtype.Text{String: string(chain.Project), Valid: true},
			AfterSeq: f.AfterSeq, AfterCommitSeq: commitCursor,
			FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	case domain.LevelEnv:
		rows, err = a.q.PageTenantAuditExportEnv(ctx, pggen.PageTenantAuditExportEnvParams{
			ChainOrgID: string(chain.Org), ChainProjectID: pgtype.Text{String: string(chain.Project), Valid: true},
			ChainEnvID: pgtype.Text{String: string(chain.Env), Valid: true},
			AfterSeq:   f.AfterSeq, AfterCommitSeq: commitCursor,
			FromTime: fromTz, ToTime: toTz, PageLimit: int32(f.Limit),
		})
	default:
		return nil, errors.New("store: tenant audit export page with an empty chain")
	}
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		event, err := auditEventFromPGTenant(row)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
}

func (a pgAudit) pageInstanceExport(ctx context.Context, f AuditFilter, from, to time.Time) ([]AuditEvent, error) {
	rows, err := a.q.PageInstanceAuditExport(ctx, pggen.PageInstanceAuditExportParams{
		AfterSeq:       f.AfterSeq,
		AfterCommitSeq: pgtype.Int8{Int64: int64(f.AfterCommitSeq), Valid: true},
		FromTime:       pgtype.Timestamptz{Time: from, Valid: true},
		ToTime:         pgtype.Timestamptz{Time: to, Valid: true},
		PageLimit:      int32(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(rows))
	for _, row := range rows {
		event, err := auditEventFromPGInstance(row)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, nil
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
		Seq: r.Seq, CommitSeq: AuditCommitSeq(r.Seq), RecordedAt: recorded, ScopeClass: r.ScopeClass,
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
		Seq: r.Seq, CommitSeq: AuditCommitSeq(r.Seq), RecordedAt: recorded, ScopeClass: "instance", RawPayload: r.Payload,
	}, nil
}

func auditEventFromPGTenant(r pggen.AuditTenantEvent) (AuditEvent, error) {
	if !r.OccurredAt.Valid || !r.RecordedAt.Valid || !r.CommitSeq.Valid {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: null timestamp or commit order", r.ID)
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
		Seq: r.Seq, CommitSeq: AuditCommitSeq(r.CommitSeq.Int64), RecordedAt: r.RecordedAt.Time.UTC(), ScopeClass: r.ScopeClass,
		OrgID: r.OrgID, ProjectID: r.ProjectID.String, EnvID: r.EnvID.String,
		RawPayload: r.Payload,
	}, nil
}

func auditEventFromPGInstance(r pggen.AuditInstanceEvent) (AuditEvent, error) {
	if !r.OccurredAt.Valid || !r.RecordedAt.Valid || !r.CommitSeq.Valid {
		return AuditEvent{}, fmt.Errorf("store: audit event %s: null timestamp or commit order", r.ID)
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
		Seq: r.Seq, CommitSeq: AuditCommitSeq(r.CommitSeq.Int64), RecordedAt: r.RecordedAt.Time.UTC(), ScopeClass: "instance", RawPayload: r.Payload,
	}, nil
}
