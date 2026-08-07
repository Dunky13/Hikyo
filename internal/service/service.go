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
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/migrate"
	"github.com/Dunky13/wenv/internal/store/tx"
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
// `wenv migrate` applied DDL (behind or ahead).
func (s *System) Ready(ctx context.Context) error {
	if err := s.DB.Ping(ctx); err != nil {
		return err
	}
	return migrate.Check(ctx, s.Store)
}

func newID(prefix string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("service: generate %s id: %w", prefix, err)
	}
	return prefix + "_" + id.String(), nil
}

// Orgs is the demonstration aggregate's service. Org administration is
// instance-scoped scaffolding (see the authz operation registry); the real
// hierarchy surface lands with #48.
type Orgs struct {
	DB *store.DB
}

// Create publishes a new org through the transactional boundary.
func (s *Orgs) Create(ctx context.Context, principal domain.PrincipalID, name string, active bool, metadata json.RawMessage) (store.Org, error) {
	id, err := newID("org")
	if err != nil {
		return store.Org{}, err
	}
	org := store.Org{
		ID:        id,
		Name:      name,
		Active:    active,
		Metadata:  metadata,
		CreatedAt: store.CanonTime(time.Now()),
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpOrgCreate, domain.Scope{})
		if err != nil {
			return err
		}
		if err := r.Orgs().Create(ctx, p, org); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgCreated, principal,
			audit.Object{Type: "org", ID: org.ID},
			audit.Payload{"org_id": org.ID, "org_name": audit.SanitizeFreeText(org.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if err != nil {
		return store.Org{}, err
	}
	return org, nil
}

// Org reads are instance-scoped operator reads of cross-tenant metadata, so
// they are audited (the audit-model ADR's default-deny rule refuses
// `audited: none` to instance-class operations). The event commits with the
// read, which is why these run in a write transaction: an operator read
// without its durable record does not complete.
func (s *Orgs) Get(ctx context.Context, principal domain.PrincipalID, id string) (store.Org, error) {
	var out store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpOrgGet, domain.Scope{})
		if err != nil {
			return err
		}
		out, err = r.Orgs().Get(ctx, p, id)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRead, principal,
			audit.Object{Type: "org", ID: out.ID},
			audit.Payload{"query": "get", "row_count": 1})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	return out, err
}

func (s *Orgs) List(ctx context.Context, principal domain.PrincipalID) ([]store.Org, error) {
	var out []store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpOrgList, domain.Scope{})
		if err != nil {
			return err
		}
		out, err = r.Orgs().List(ctx, p)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRead, principal, audit.Object{},
			audit.Payload{"query": "list", "row_count": len(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	return out, err
}

func (s *Orgs) Count(ctx context.Context, principal domain.PrincipalID) (int64, error) {
	var out int64
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpOrgList, domain.Scope{})
		if err != nil {
			return err
		}
		out, err = r.Orgs().Count(ctx, p)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRead, principal, audit.Object{},
			audit.Payload{"query": "count", "row_count": int(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	return out, err
}

// Projects is the org-level tenant-scoped demonstration service.
type Projects struct {
	DB *store.DB
}

// Create makes a project inside org. The service addresses the scope; the
// chain the store writes comes from the proof authorize() minted after
// resolving that scope — never from these arguments.
func (s *Projects) Create(ctx context.Context, principal domain.PrincipalID, org domain.OrgID, name string) (store.Project, error) {
	id, err := newID("prj")
	if err != nil {
		return store.Project{}, err
	}
	proj := store.NewProject{ID: id, Name: name, CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpProjectCreate, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		if err := r.Projects().Create(ctx, p, proj); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventProjectCreated, principal,
			audit.Object{Type: "project", ID: proj.ID},
			audit.Payload{"name": audit.SanitizeFreeText(proj.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return store.Project{}, err
	}
	return store.Project{ID: proj.ID, OrgID: string(org), Name: proj.Name, CreatedAt: proj.CreatedAt}, nil
}

// Environments is the project/env-level tenant-scoped demonstration service.
type Environments struct {
	DB *store.DB
}

// Environment methods address scope as a domain.Scope — the same shape
// authorize() takes; a wrong-depth scope is refused there (loud error).
// Create addresses the parent project (Org+Project); Get/UpdateNote address
// the environment (full chain).

func (s *Environments) Create(ctx context.Context, principal domain.PrincipalID, scope domain.Scope, name string) (store.Environment, error) {
	id, err := newID("env")
	if err != nil {
		return store.Environment{}, err
	}
	env := store.NewEnvironment{ID: id, Name: name, Note: "", CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpEnvCreate, scope)
		if err != nil {
			return err
		}
		if err := r.Environments().Create(ctx, p, env); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventEnvCreated, principal,
			audit.Object{Type: "environment", ID: env.ID},
			audit.Payload{"name": audit.SanitizeFreeText(env.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return store.Environment{}, err
	}
	return store.Environment{
		ID: env.ID, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		Name: env.Name, Note: env.Note, CreatedAt: env.CreatedAt,
	}, nil
}

func (s *Environments) Get(ctx context.Context, principal domain.PrincipalID, scope domain.Scope) (store.Environment, error) {
	var out store.Environment
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpEnvRead, scope)
		if err != nil {
			return err
		}
		out, err = r.Environments().Get(ctx, p)
		return err
	})
	return out, err
}

func (s *Environments) UpdateNote(ctx context.Context, principal domain.PrincipalID, scope domain.Scope, note string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := az.Authorize(ctx, principal, authz.OpEnvUpdateNote, scope)
		if err != nil {
			return err
		}
		if err := r.Environments().UpdateNote(ctx, p, note); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventEnvNoteChanged, principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}
