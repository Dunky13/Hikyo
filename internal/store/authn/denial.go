package authn

import (
	"context"
	"fmt"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/auditrow"
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
// the structured-absence rule; a lookup FAILURE fails the flush loudly (the
// transaction package then refuses the uniform denial), because recording a
// real, identified prober as a dummy `unauthenticated` actor is exactly
// what the envelope rule forbids.
func (r *Resolver) WriteDenial(ctx context.Context, e audit.Event, trail audit.Trail, scope domain.Scope) error {
	actor, err := auditrow.ResolveActorClass(ctx, r.principalKind, e.Actor)
	if err != nil {
		return fmt.Errorf("authn: denial actor resolution: %w", err)
	}
	e.Actor = actor
	row, err := audit.BuildRow(e, trail, scope, time.Now())
	if err != nil {
		return fmt.Errorf("authn: denial event refused at the write boundary: %w", err)
	}
	if r.sq != nil {
		if trail == audit.TrailTenant {
			return r.sq.InsertTenantAuditEvent(ctx, auditrow.SQLiteTenant(row))
		}
		return r.sq.InsertInstanceAuditEvent(ctx, auditrow.SQLiteInstance(row))
	}
	if trail == audit.TrailTenant {
		return r.pg.InsertTenantAuditEvent(ctx, auditrow.PGTenant(row))
	}
	return r.pg.InsertInstanceAuditEvent(ctx, auditrow.PGInstance(row))
}

func (r *Resolver) principalKind(ctx context.Context, id string) (string, error) {
	if r.sq != nil {
		return r.sq.GetPrincipalKind(ctx, id)
	}
	return r.pg.GetPrincipalKind(ctx, id)
}
