package authn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// WriteDenial is the resolution surface's SINGLE write path (audit-model ADR
// amendment part 4: the tenant-isolation ADR's enumerated read-only
// interface gains exactly one write, the denial writer — a failed
// authorize() mints no proof, so the denial event cannot travel the
// proof-carrying store surface). The transaction package calls it inside a
// dedicated flush transaction after rolling back the denied attempt; the
// event is durable at that transaction's commit, before the error response.
//
// The denied principal's kind is resolved here (not on the probe-visible
// attempt, whose query count is pinned by the isolation invariants). A
// principal with no row is recorded as class unauthenticated with null ids —
// the structured-absence rule, never a dummy principal.
func (r *Resolver) WriteDenial(ctx context.Context, e audit.Event, trail audit.Trail, scope domain.Scope) error {
	e.Actor = r.resolveActor(ctx, e.Actor)
	row, err := audit.BuildRow(e, trail, scope, time.Now())
	if err != nil {
		return fmt.Errorf("authn: denial event refused at the write boundary: %w", err)
	}
	if r.sq != nil {
		return writeDenialSQLite(ctx, r.sq, row, trail)
	}
	return writeDenialPG(ctx, r.pg, row, trail)
}

func (r *Resolver) resolveActor(ctx context.Context, a audit.Actor) audit.Actor {
	if a.ID == "" {
		a.Class = audit.ActorUnauthenticated
		return a
	}
	var kind string
	var err error
	if r.sq != nil {
		kind, err = r.sq.GetPrincipalKind(ctx, a.ID)
	} else {
		kind, err = r.pg.GetPrincipalKind(ctx, a.ID)
	}
	switch {
	case err == nil && kind == "human":
		a.Class = audit.ActorHuman
	case err == nil && kind == "machine":
		a.Class = audit.ActorMachine
	case errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows):
		// No such principal: structured absence, not a dummy class.
		return audit.Actor{Class: audit.ActorUnauthenticated}
	default:
		// Lookup failure or an unknown kind value: fail toward the honest
		// unknown rather than inventing a class; BuildRow's validation keeps
		// the enum closed.
		return audit.Actor{Class: audit.ActorUnauthenticated}
	}
	return a
}

func writeDenialSQLite(ctx context.Context, q *sqlitegen.Queries, row audit.Row, trail audit.Trail) error {
	if trail == audit.TrailTenant {
		return q.InsertTenantAuditEvent(ctx, sqlitegen.InsertTenantAuditEventParams{
			ID: row.ID, Type: row.Type, SchemaVersion: row.SchemaVersion,
			OccurredAt:       audit.FormatTime(row.OccurredAt),
			OccurredAsserted: boolInt(row.OccurredAsserted),
			RecordedAt:       audit.FormatTime(row.RecordedAt),
			ActorID:          nullStr(row.ActorID), ActorClass: row.ActorClass,
			ActorCredentialID: nullStr(row.ActorCredentialID), AuthorityID: nullStr(row.AuthorityID),
			ScopeClass: row.ScopeClass, OrgID: row.OrgID,
			ProjectID: nullStr(row.ProjectID), EnvID: nullStr(row.EnvID),
			ObjectType: nullStr(row.ObjectType), ObjectID: nullStr(row.ObjectID),
			Outcome: row.Outcome, CorrelationID: nullStr(row.CorrelationID),
			SourceIp: nullStr(row.SourceIP), UserAgent: nullStr(row.UserAgent),
			Origin: row.Origin, Payload: row.Payload,
		})
	}
	return q.InsertInstanceAuditEvent(ctx, sqlitegen.InsertInstanceAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: row.SchemaVersion,
		OccurredAt:       audit.FormatTime(row.OccurredAt),
		OccurredAsserted: boolInt(row.OccurredAsserted),
		RecordedAt:       audit.FormatTime(row.RecordedAt),
		ActorID:          nullStr(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: nullStr(row.ActorCredentialID), AuthorityID: nullStr(row.AuthorityID),
		ObjectType: nullStr(row.ObjectType), ObjectID: nullStr(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: nullStr(row.CorrelationID),
		SourceIp: nullStr(row.SourceIP), UserAgent: nullStr(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func writeDenialPG(ctx context.Context, q *pggen.Queries, row audit.Row, trail audit.Trail) error {
	if trail == audit.TrailTenant {
		return q.InsertTenantAuditEvent(ctx, pggen.InsertTenantAuditEventParams{
			ID: row.ID, Type: row.Type, SchemaVersion: int32(row.SchemaVersion),
			OccurredAt:       pgtype.Timestamptz{Time: row.OccurredAt, Valid: true},
			OccurredAsserted: row.OccurredAsserted,
			RecordedAt:       pgtype.Timestamptz{Time: row.RecordedAt, Valid: true},
			ActorID:          pgStr(row.ActorID), ActorClass: row.ActorClass,
			ActorCredentialID: pgStr(row.ActorCredentialID), AuthorityID: pgStr(row.AuthorityID),
			ScopeClass: row.ScopeClass, ChainOrgID: row.OrgID,
			ProjectID: pgStr(row.ProjectID), EnvID: pgStr(row.EnvID),
			ObjectType: pgStr(row.ObjectType), ObjectID: pgStr(row.ObjectID),
			Outcome: row.Outcome, CorrelationID: pgStr(row.CorrelationID),
			SourceIp: pgStr(row.SourceIP), UserAgent: pgStr(row.UserAgent),
			Origin: row.Origin, Payload: row.Payload,
		})
	}
	return q.InsertInstanceAuditEvent(ctx, pggen.InsertInstanceAuditEventParams{
		ID: row.ID, Type: row.Type, SchemaVersion: int32(row.SchemaVersion),
		OccurredAt:       pgtype.Timestamptz{Time: row.OccurredAt, Valid: true},
		OccurredAsserted: row.OccurredAsserted,
		RecordedAt:       pgtype.Timestamptz{Time: row.RecordedAt, Valid: true},
		ActorID:          pgStr(row.ActorID), ActorClass: row.ActorClass,
		ActorCredentialID: pgStr(row.ActorCredentialID), AuthorityID: pgStr(row.AuthorityID),
		ObjectType: pgStr(row.ObjectType), ObjectID: pgStr(row.ObjectID),
		Outcome: row.Outcome, CorrelationID: pgStr(row.CorrelationID),
		SourceIp: pgStr(row.SourceIP), UserAgent: pgStr(row.UserAgent),
		Origin: row.Origin, Payload: row.Payload,
	})
}

func nullStr(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func pgStr(p *string) pgtype.Text {
	if p == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *p, Valid: true}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
