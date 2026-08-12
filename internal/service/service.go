// Package service is the domain layer. Handlers cannot reach the datastore
// directly: internal/store is importable only by this package (and its own
// subpackages) — enforced by the import-boundary test. Every data-touching
// method takes the acting principal, opens a transaction, authorizes inside
// it (single chokepoint, no cache), and only then calls the store with the
// minted proof. Middleware extracts artifacts only; there is no
// authenticated principal outside a transaction.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/migrate"
)

// newAuditEvent is the one event constructor for every service emitter —
// domain events (committed in-transaction with their write, per the
// audit-model ADR's durability discipline), the audit.query event, and the
// export INTENT/OUTCOME pair. It mints the id, stamps occurred_at, and
// carries the request's wire metadata; the actor class is resolved
// server-side at the store boundary.
func newAuditEvent(ctx context.Context, typ audit.EventType, principal domain.PrincipalID, obj audit.Object, outcome audit.Outcome, correlationID string, payload audit.Payload) (audit.Event, error) {
	id, err := audit.NewEventID()
	if err != nil {
		return audit.Event{}, err
	}
	wire := audit.FromContext(ctx)
	return audit.Event{
		ID: id, Type: typ, SchemaVersion: 1,
		OccurredAt:    time.Now().UTC(),
		Actor:         audit.Actor{ID: string(principal)},
		Object:        obj,
		Outcome:       outcome,
		CorrelationID: correlationID,
		SourceIP:      wire.SourceIP, UserAgent: wire.UserAgent, Origin: wire.Origin,
		Payload: payload,
	}, nil
}

// domainEvent is newAuditEvent for the common success-outcome domain event.
func domainEvent(ctx context.Context, typ audit.EventType, principal domain.PrincipalID, obj audit.Object, payload audit.Payload) (audit.Event, error) {
	return newAuditEvent(ctx, typ, principal, obj, audit.OutcomeSuccess, "", payload)
}

// System answers operational questions for the HTTP layer.
type System struct {
	DB    *store.DB
	Store store.Config
}

// Ready reports whether a request would actually work: the datastore is
// reachable and the schema matches this binary exactly. Boot already refuses
// to serve on a mismatch, but the live check also catches the cross-process
// race the ADR names — an old server still running after a newer
// `hikyo migrate` applied DDL (behind or ahead).
func (s *System) Ready(ctx context.Context) error {
	if err := s.DB.Ping(ctx); err != nil {
		return err
	}
	return migrate.Check(ctx, s.Store)
}

// Actor is who is asking, resolved INSIDE the operation's own transaction.
//
// This type exists because of a real defect two reviewers found
// independently: the transport used to resolve the session in one
// transaction and then hand a bare principal id to a service that opened
// another. Between them a session could be revoked, expire, have its
// generation advanced or its credential epoch bumped — and the operation
// would still authorize against the principal that resolution had already
// decided on. A principal id crossing a transaction boundary IS the
// cross-request authorization cache the permission model forbids; it just
// looks like an argument.
//
// The zero value resolves to nothing, so a caller that forgets to set one
// gets a refusal rather than an anonymous success.
type Actor struct {
	bearer    string
	principal domain.PrincipalID
}

// Bearer is the network path: a presented session artifact, resolved at the
// chokepoint inside whichever transaction the operation opens.
func Bearer(artifact string) Actor { return Actor{bearer: artifact} }

// LocalPrincipal is the below-the-network path: a principal the caller
// already established by other means — the isolation harness, and local
// authority verbs that run on the server's own host.
//
// It bypasses session resolution by construction, which is exactly why the
// import-boundary test refuses internal/server the right to name it. A
// transport that could build one could authorize as anybody.
func LocalPrincipal(p domain.PrincipalID) Actor { return Actor{principal: p} }

// resolve returns the caller's live Identity. A LocalPrincipal actor is local
// host authority: it carries no session, so its Identity has an empty SessionID
// and is exempt from the MFA-mandatory assurance check at authorize(). A bearer
// actor resolves to the full session assurance the chokepoint enforces.
func (a Actor) resolve(ctx context.Context, az *authz.TxAuthorizer, now time.Time) (authz.Identity, error) {
	if a.principal != "" {
		return authz.Identity{Principal: a.principal}, nil
	}
	if a.bearer == "" {
		return authz.Identity{}, domain.ErrUnauthenticated
	}
	return az.Authenticate(ctx, a.bearer, now)
}

func newID(prefix string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("service: generate %s id: %w", prefix, err)
	}
	return prefix + "_" + id.String(), nil
}
