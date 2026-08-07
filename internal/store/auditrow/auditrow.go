// Package auditrow is the single audit Row → engine-parameter mapping,
// shared by the store's audit repositories and the authorization package's
// denial writer so the two writers cannot drift (audit-model ADR: one
// envelope-to-column mapping). It also owns the server-side actor-class
// resolution both writers perform. It holds no authority of its own: it
// maps an already-validated Row and answers a kind lookup through whichever
// generated query set the caller's transaction is bound to.
package auditrow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// KindLookup answers principals.kind inside the caller's transaction. Both
// generated query sets satisfy it.
type KindLookup func(ctx context.Context, id string) (string, error)

// ResolveActorClass fills a principal actor's class from principals.kind
// when the emitter left it empty — the server-side truth, not a caller
// claim. An explicitly set class (system, break-glass, unauthenticated)
// passes through untouched. A missing row is structured absence
// (unauthenticated, null ids); a transient lookup failure or an unknown
// kind value is a loud error — recording a real, identified principal as a
// dummy `unauthenticated` is exactly what the envelope rule forbids, so the
// write must fail instead (fail-closed).
func ResolveActorClass(ctx context.Context, kindOf KindLookup, a audit.Actor) (audit.Actor, error) {
	switch a.Class {
	case "":
		// Resolve below.
	case audit.ActorSystem, audit.ActorBreakGlass, audit.ActorUnauthenticated:
		// Principal-less classes are the emitter's to assert: no row exists
		// to check them against.
		return a, nil
	default:
		// human/machine is server-side truth, never an emitter claim — an
		// emitter that could assert it could attribute an event to any
		// principal id it names.
		return audit.Actor{}, fmt.Errorf("auditrow: actor class %q is resolved from principals.kind, not asserted by the emitter", a.Class)
	}
	if a.ID == "" {
		a.Class = audit.ActorUnauthenticated
		return a, nil
	}
	kind, err := kindOf(ctx, a.ID)
	switch {
	case err == nil && kind == "human":
		a.Class = audit.ActorHuman
		return a, nil
	case err == nil && kind == "machine":
		a.Class = audit.ActorMachine
		return a, nil
	case errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows):
		return audit.Actor{Class: audit.ActorUnauthenticated}, nil
	case err != nil:
		return audit.Actor{}, fmt.Errorf("auditrow: principal %s kind lookup: %w", a.ID, err)
	default:
		return audit.Actor{}, fmt.Errorf("auditrow: principal %s has unknown kind %q", a.ID, kind)
	}
}

// SQLiteTenant maps a validated Row to the tenant-trail insert parameters.
func SQLiteTenant(row audit.Row) sqlitegen.InsertTenantAuditEventParams {
	return sqlitegen.InsertTenantAuditEventParams{
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
	}
}

// SQLiteInstance maps a validated Row to the instance-trail insert
// parameters.
func SQLiteInstance(row audit.Row) sqlitegen.InsertInstanceAuditEventParams {
	return sqlitegen.InsertInstanceAuditEventParams{
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
	}
}

// PGTenant maps a validated Row to the tenant-trail insert parameters.
func PGTenant(row audit.Row) pggen.InsertTenantAuditEventParams {
	return pggen.InsertTenantAuditEventParams{
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
	}
}

// PGInstance maps a validated Row to the instance-trail insert parameters.
func PGInstance(row audit.Row) pggen.InsertInstanceAuditEventParams {
	return pggen.InsertInstanceAuditEventParams{
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
	}
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

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
