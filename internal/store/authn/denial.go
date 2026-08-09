package authn

import (
	"context"
	"fmt"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/auditrow"
)

// WriteDenial is the resolution surface's FIRST proof-free write path
// (audit-model ADR amendment part 4: the tenant-isolation ADR's enumerated
// read-only interface gains a write, the denial writer — a failed
// authorize() mints no proof, so the denial event cannot travel the
// proof-carrying store surface).
//
// The ADR said "exactly one". Human authentication (#47) added twelve more
// for the same structural reason, and the "exactly one" is now a PINNED
// ENUMERATED LIST in internal/lint.ResolutionSurfaceWriters rather than a
// count — see the deviation recorded in docs/handoff/47-first-slice.md.
//
// The transaction package calls it inside a
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
	return r.writeProofFreeEvent(ctx, e, trail, scope, "denial")
}

// WriteAuthEvent is the second proof-free audit path, and it exists for the
// same reason the first does. A login, a logout and a credential
// establishment all have to record what happened, and none of them can hold a
// proof: the first two are what produce the principal a proof would need, and
// the third deliberately produces no session at all. Routing them through the
// proof-carrying store surface is not merely awkward, it is impossible.
//
// It shares the denial writer's machinery so the two cannot drift, and it is
// named in the pinned enumerated write list (internal/lint) like every other
// writer here.
func (r *Resolver) WriteAuthEvent(ctx context.Context, e audit.Event, trail audit.Trail) error {
	return r.writeProofFreeEvent(ctx, e, trail, domain.Scope{}, "auth")
}

func (r *Resolver) writeProofFreeEvent(ctx context.Context, e audit.Event, trail audit.Trail, scope domain.Scope, what string) error {
	// No proof exists at all on these paths. The emitter never asserts an
	// actor class, and the absent-principal case resolves to unauthenticated
	// inside ResolveActorClass.
	actor, err := auditrow.ResolveActorClass(ctx, r.principalKind, e.Actor, true)
	if err != nil {
		return fmt.Errorf("authn: %s actor resolution: %w", what, err)
	}
	e.Actor = actor
	recordedAt := time.Time{}
	if r.sq != nil {
		recordedAt = time.Now()
	}
	row, err := audit.BuildRow(e, trail, scope, recordedAt)
	if err != nil {
		return fmt.Errorf("authn: %s event refused at the write boundary: %w", what, err)
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
