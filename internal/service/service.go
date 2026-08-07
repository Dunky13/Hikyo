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

// resolve turns an Actor into a principal, inside the caller's transaction.
func (a Actor) resolve(ctx context.Context, az *authz.TxAuthorizer, now time.Time) (domain.PrincipalID, error) {
	if a.principal != "" {
		return a.principal, nil
	}
	if a.bearer == "" {
		return "", domain.ErrUnauthenticated
	}
	id, err := az.Authenticate(ctx, a.bearer, now)
	if err != nil {
		return "", err
	}
	return id.Principal, nil
}

func newID(prefix string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("service: generate %s id: %w", prefix, err)
	}
	return prefix + "_" + id.String(), nil
}

// Org is the service layer's organisation. It is a distinct type from the
// store row on purpose: internal/store is importable only by this package, so
// a transport that returned store rows would either violate that boundary or
// force it open. Field names match the store row, which keeps the conversion
// a copy rather than a translation.
type Org struct {
	ID        string
	Name      string
	Active    bool
	Metadata  json.RawMessage
	CreatedAt time.Time
}

func orgOf(o store.Org) Org {
	return Org{ID: o.ID, Name: o.Name, Active: o.Active, Metadata: o.Metadata, CreatedAt: o.CreatedAt}
}

// Orgs is the demonstration aggregate's service. Org administration is
// instance-scoped scaffolding (see the authz operation registry); the real
// hierarchy surface lands with #48.
type Orgs struct {
	DB *store.DB
}

// Create publishes a new org through the transactional boundary.
func (s *Orgs) Create(ctx context.Context, actor Actor, name string, active bool, metadata json.RawMessage) (Org, error) {
	id, err := newID("org")
	if err != nil {
		return Org{}, err
	}
	org := store.Org{
		ID:        id,
		Name:      name,
		Active:    active,
		Metadata:  metadata,
		CreatedAt: store.CanonTime(time.Now()),
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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
		return Org{}, err
	}
	return orgOf(org), nil
}

// Org reads are instance-scoped operator reads of cross-tenant metadata, so
// they are audited (the audit-model ADR's default-deny rule refuses
// `audited: none` to instance-class operations). The event commits with the
// read, which is why these run in a write transaction: an operator read
// without its durable record does not complete.
func (s *Orgs) Get(ctx context.Context, actor Actor, id string) (Org, error) {
	var out store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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
	return orgOf(out), err
}

func (s *Orgs) List(ctx context.Context, actor Actor) ([]Org, error) {
	var out []store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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
	if err != nil {
		return nil, err
	}
	list := make([]Org, 0, len(out))
	for _, o := range out {
		list = append(list, orgOf(o))
	}
	return list, nil
}

func (s *Orgs) Count(ctx context.Context, actor Actor) (int64, error) {
	var out int64
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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
func (s *Projects) Create(ctx context.Context, actor Actor, org domain.OrgID, name string) (store.Project, error) {
	id, err := newID("prj")
	if err != nil {
		return store.Project{}, err
	}
	proj := store.NewProject{ID: id, Name: name, CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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

func (s *Environments) Create(ctx context.Context, actor Actor, scope domain.Scope, name string) (store.Environment, error) {
	id, err := newID("env")
	if err != nil {
		return store.Environment{}, err
	}
	env := store.NewEnvironment{ID: id, Name: name, Note: "", CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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

func (s *Environments) Get(ctx context.Context, actor Actor, scope domain.Scope) (store.Environment, error) {
	var out store.Environment
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, principal, authz.OpEnvRead, scope)
		if err != nil {
			return err
		}
		out, err = r.Environments().Get(ctx, p)
		return err
	})
	return out, err
}

func (s *Environments) UpdateNote(ctx context.Context, actor Actor, scope domain.Scope, note string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		principal, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
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
