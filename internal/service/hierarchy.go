package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The hierarchy surface (#48): Instance → Organization → Project →
// Environment → Folder, as the domain model stands after the flat-model ADR.
//
// What is deliberately absent, at every layer down to the column: no `base`
// pointer on Environment, no project-defaults layer, no masked state, no value
// row of any kind. The flat-model ADR's own reason — "a structure that must
// not be used is a bug that hasn't happened yet" — forbids the dormant
// version as much as the live one, so there is nothing here to grep for later.
//
// Every method takes the acting principal, opens one transaction, authorizes
// inside it, and only then calls the store with the minted proof. Identity is
// always the immutable prefixed id: a rename changes a label, never a
// reference.

// MaxEnvironmentsPerProject is the ops spec's environment-count cap. It is
// enforced inside the creating transaction, against a count read under the
// same proof — a check made anywhere else is a check a concurrent create can
// walk past.
const MaxEnvironmentsPerProject = 50

// Name and path bounds. No ADR fixes a display-name length for org, project,
// environment or folder; 128 bytes is the bound the org contract already
// carried since #47, adopted here for every entity so there is one number
// rather than four. The key-name grammar (uppercase, env-var-safe) governs
// KEYS and is deliberately not applied to entity names.
const (
	maxNameBytes      = 128
	maxFolderPathLen  = 256
	maxFolderPathSegs = 32
)

// checkName is the entity-name grammar, enforced in the domain rather than
// only at the contract boundary: internal callers (the isolation harness,
// future jobs) do not pass through request validation, and a name that reaches
// the database unbounded is a bound that existed only on paper.
//
// `what` names the thing being checked in full ("organisation name", "folder
// path segment"), so the message reads as a sentence at every call site rather
// than gaining a stray "name" where the caller's subject is not one.
func checkName(what, name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: %s must not be empty", domain.ErrInvalid, what)
	case len(name) > maxNameBytes:
		return fmt.Errorf("%w: %s exceeds %d bytes", domain.ErrInvalid, what, maxNameBytes)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: %s is not valid UTF-8", domain.ErrInvalid, what)
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("%w: %s has leading or trailing whitespace", domain.ErrInvalid, what)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains a control character", domain.ErrInvalid, what)
		}
	}
	return nil
}

// checkFolderPath is the folder namespace grammar. A folder is display
// grouping only, so its path is a plain slash-separated namespace: no leading
// or trailing separator, no empty segment, no `.`/`..`, bounded in depth to
// match the import spec's tree-depth bound.
//
// The empty-path and empty-segment cases are one case: splitting "" or "a//b"
// yields an empty segment either way, and checkName rejects it with the right
// sentence. There is no separate test for it, because a second test of the same
// thing is a second thing to keep in agreement.
func checkFolderPath(path string) error {
	if len(path) > maxFolderPathLen {
		return fmt.Errorf("%w: folder path exceeds %d bytes", domain.ErrInvalid, maxFolderPathLen)
	}
	segments := strings.Split(path, "/")
	if len(segments) > maxFolderPathSegs {
		return fmt.Errorf("%w: folder path exceeds %d segments", domain.ErrInvalid, maxFolderPathSegs)
	}
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: folder path segment %q is reserved", domain.ErrInvalid, segment)
		}
		if err := checkName("folder path segment", segment); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Organization
// ---------------------------------------------------------------------------

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

// Orgs is the organisation surface. Creation and enumeration are
// instance-scoped operator work; every by-id operation is tenant-scoped at org
// depth, so an org the caller may not reach is indistinguishable from one that
// does not exist.
type Orgs struct {
	DB *store.DB
	// Keyring and Scan are the secret-scanning Surface-2 seam (#74): org
	// create/rename are declaration ingresses, so their author-controlled names
	// and metadata are scanned before any state persists, and the block's
	// acknowledgement tokens are minted under the instance key. Nil disables the
	// scan (tests that predate #74); a booted server always wires both.
	Keyring *crypto.Keyring
	Scan    *scanning.Ruleset
}

// Create publishes a new org through the transactional boundary.
func (s *Orgs) Create(ctx context.Context, actor Actor, name string, active bool, metadata json.RawMessage, acks []string) (Org, error) {
	if err := checkName("organisation name", name); err != nil {
		return Org{}, err
	}
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
	leaves := nonEmptyLeaf(locOrgName, name)
	if len(metadata) > 0 {
		leaves = append(leaves, scanLeaf{Locator: locOrgMetadata, Content: metadata})
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgCreate, domain.Scope{})
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the org name and metadata are scanned before the
		// row persists. The block events carry the new org as their chain.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			domain.Scope{Org: domain.OrgID(id)}, leaves, newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Orgs().Create(ctx, p, org); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgCreated, caller.Principal,
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

// Get reads one org. It is a proof-scoped pure read at org depth, so it emits
// no event of its own: the trail would only duplicate what the read returned,
// which is the exact shape the audit model's default-deny permit accepts.
func (s *Orgs) Get(ctx context.Context, actor Actor, org domain.OrgID) (Org, error) {
	var out store.Org
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgGet, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		out, err = r.Orgs().Get(ctx, p)
		return err
	})
	if err != nil {
		return Org{}, err
	}
	return orgOf(out), nil
}

// MyOrg is an organisation as a navigation destination — identity only. The
// rail needs a name and a route; `metadata` and `active` are operator-set
// state and belong to Get, which authorizes.
type MyOrg struct {
	ID   string
	Name string
}

// ListMine is the navigation surface: exactly the organisations the caller's
// own grants name, at org scope or below.
//
// It is NOT List with a filter, and the difference is the whole point. List
// enumerates every org on the instance under `instance-config`, which the
// human-auth ADR makes MFA-mandatory — correct for operator work, absurd in
// front of a sidebar. This projects the caller's own grant rows, so there is
// no capability to require (holding a grant IS the predicate, and requiring
// one would be circular) and nothing to leak: every row it can return names an
// org the caller already holds authority in.
//
// It therefore emits no audit event, for the same reason `whoami` and
// `listIdentities` emit none. The audit model's default-deny governs
// REGISTRY OPERATIONS — `audited: none` is a permit an operation must earn.
// This is not an operation: it reaches no chokepoint, mutates nothing, and
// reads only the caller's own grant projection. Recording "a principal looked
// at their own sidebar" on every page load would add a row per boot that no
// investigation could ever act on, which is noise the trail has to carry
// forever.
//
// Runs in a read transaction: nothing here writes.
func (s *Orgs) ListMine(ctx context.Context, actor Actor) ([]MyOrg, error) {
	var rows []authz.OrgIdentity
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		// resolveSelf, not resolve. This route calls NO OPERATION — that is the
		// point of it, and the reason it needs no capability — so the
		// artifact-eligibility chokepoint never sees it and cannot confine an
		// instance-connection credential presented here. The admitting set is
		// the confinement instead: the three SESSION artifacts and no machine.
		//
		// A workspace bearer IS admitted, deliberately. It is a session of this
		// instance in every locked mechanical respect, it holds exactly the
		// human's own grants, and the ADR's stated blast radius for it is "the
		// compromised human's grants per remote" — which is precisely what this
		// projection reports. A foreign installation's directory credential is
		// not, and never was, entitled to it.
		caller, err := actor.resolveSelf(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		rows, err = az.OrgsForPrincipal(ctx, caller.Principal)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]MyOrg, 0, len(rows))
	for _, r := range rows {
		out = append(out, MyOrg{ID: string(r.ID), Name: r.Name})
	}
	return out, nil
}

// List is the instance-scoped enumeration of every org, and therefore itself
// audited (the audit model's default-deny rule refuses `audited: none` to
// instance-class operations). The event commits with the read, which is why
// this runs in a write transaction: an operator read without its durable
// record does not complete.
func (s *Orgs) List(ctx context.Context, actor Actor) ([]Org, error) {
	var out []store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgList, domain.Scope{})
		if err != nil {
			return err
		}
		out, err = r.Orgs().List(ctx, p)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRead, caller.Principal, audit.Object{},
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
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgList, domain.Scope{})
		if err != nil {
			return err
		}
		out, err = r.Orgs().Count(ctx, p)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgRead, caller.Principal, audit.Object{},
			audit.Payload{"query": "count", "row_count": int(out)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	return out, err
}

// Rename changes the org's mutable name. The read that produces the previous
// name for the trail runs inside the same transaction as the write, so the
// recorded transition is the one that actually happened.
func (s *Orgs) Rename(ctx context.Context, actor Actor, org domain.OrgID, name string, acks []string) (Org, error) {
	if err := checkName("organisation name", name); err != nil {
		return Org{}, err
	}
	var out store.Org
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgRename, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		before, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the new org name is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			domain.Scope{Org: org}, nonEmptyLeaf(locOrgName, name), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Orgs().Rename(ctx, p, name); err != nil {
			return err
		}
		out = before
		out.Name = name
		ev, err := domainEvent(ctx, audit.EventOrgRenamed, caller.Principal,
			audit.Object{Type: "org", ID: before.ID}, audit.Payload{
				"previous_name": audit.SanitizeFreeText(before.Name),
				"name":          audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Org{}, err
	}
	return orgOf(out), nil
}

// Delete removes an org. It never cascades: an org that still has projects (or
// grants pointing into it) is refused by the ancestry constraints, which
// surface as a conflict. Deleting a tenant's contents out from under it is a
// different, auditable operation and not one this ticket invents.
func (s *Orgs) Delete(ctx context.Context, actor Actor, org domain.OrgID) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpOrgDelete, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		before, err := r.Orgs().Get(ctx, p)
		if err != nil {
			return err
		}
		if err := r.Orgs().Delete(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventOrgDeleted, caller.Principal,
			audit.Object{Type: "org", ID: before.ID},
			audit.Payload{"name": audit.SanitizeFreeText(before.Name)})
		if err != nil {
			return err
		}
		// The trail outlives its subject by design: the audit tables carry the
		// chain as denormalized ids with no ancestry FK, which is the one
		// declared exception to the composite-FK rule and exactly why this
		// insert can follow the delete in the same transaction.
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

// Project is the service layer's project.
type Project struct {
	ID        string
	OrgID     string
	Name      string
	CreatedAt time.Time
}

func projectOf(p store.Project) Project {
	return Project{ID: p.ID, OrgID: p.OrgID, Name: p.Name, CreatedAt: p.CreatedAt}
}

// Projects owns the project surface.
type Projects struct {
	DB *store.DB
	// Keyring and Scan: secret-scanning Surface-2 seam (#74). Project
	// create/rename names are declaration ingresses.
	Keyring *crypto.Keyring
	Scan    *scanning.Ruleset
}

// Create makes a project inside org. The service addresses the scope; the
// chain the store writes comes from the proof authorize() minted after
// resolving that scope — never from these arguments.
func (s *Projects) Create(ctx context.Context, actor Actor, org domain.OrgID, name string, acks []string) (Project, error) {
	if err := checkName("project name", name); err != nil {
		return Project{}, err
	}
	id, err := newID("prj")
	if err != nil {
		return Project{}, err
	}
	proj := store.NewProject{ID: id, Name: name, CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectCreate, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the project name is scanned before the row
		// persists; the block events carry org→(new project) as their chain.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			domain.Scope{Org: org, Project: domain.ProjectID(id)}, nonEmptyLeaf(locProjectName, name), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Projects().Create(ctx, p, proj); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventProjectCreated, caller.Principal,
			audit.Object{Type: "project", ID: proj.ID},
			audit.Payload{"name": audit.SanitizeFreeText(proj.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Project{}, err
	}
	return Project{ID: proj.ID, OrgID: string(org), Name: proj.Name, CreatedAt: proj.CreatedAt}, nil
}

func (s *Projects) Get(ctx context.Context, actor Actor, scope domain.Scope) (Project, error) {
	var out store.Project
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectGet, scope)
		if err != nil {
			return err
		}
		out, err = r.Projects().Get(ctx, p)
		return err
	})
	if err != nil {
		return Project{}, err
	}
	return projectOf(out), nil
}

func (s *Projects) List(ctx context.Context, actor Actor, org domain.OrgID) ([]Project, error) {
	var out []store.Project
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectList, domain.Scope{Org: org})
		if err != nil {
			return err
		}
		out, err = r.Projects().List(ctx, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	list := make([]Project, 0, len(out))
	for _, row := range out {
		list = append(list, projectOf(row))
	}
	return list, nil
}

func (s *Projects) Rename(ctx context.Context, actor Actor, scope domain.Scope, name string, acks []string) (Project, error) {
	if err := checkName("project name", name); err != nil {
		return Project{}, err
	}
	var out store.Project
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectRename, scope)
		if err != nil {
			return err
		}
		before, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the new project name is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locProjectName, name), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Projects().Rename(ctx, p, name); err != nil {
			return err
		}
		out = before
		out.Name = name
		ev, err := domainEvent(ctx, audit.EventProjectRenamed, caller.Principal,
			audit.Object{Type: "project", ID: before.ID}, audit.Payload{
				"previous_name": audit.SanitizeFreeText(before.Name),
				"name":          audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Project{}, err
	}
	return projectOf(out), nil
}

// Delete removes a project. Like every delete on this surface it refuses
// rather than cascading: a project holding environments or folders is refused
// by the ancestry constraints as a conflict.
func (s *Projects) Delete(ctx context.Context, actor Actor, scope domain.Scope) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpProjectDelete, scope)
		if err != nil {
			return err
		}
		before, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		if err := r.Projects().Delete(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventProjectDeleted, caller.Principal,
			audit.Object{Type: "project", ID: before.ID},
			audit.Payload{"name": audit.SanitizeFreeText(before.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// Environment is the service layer's environment. DisplayOrder is its
// user-defined position within the project. There is no base pointer and no
// defaults layer to expose, because neither exists.
type Environment struct {
	ID           string
	OrgID        string
	ProjectID    string
	Name         string
	Note         string
	DisplayOrder int64
	CreatedAt    time.Time
}

func environmentOf(e store.Environment) Environment {
	return Environment{
		ID: e.ID, OrgID: e.OrgID, ProjectID: e.ProjectID,
		Name: e.Name, Note: e.Note, DisplayOrder: e.DisplayOrder, CreatedAt: e.CreatedAt,
	}
}

// Environments owns the environment surface.
//
// The Keyring is here only for clone-at-creation (#50): cloning re-seals every
// copied value under the destination row's own AAD, and that has to happen in
// the same transaction that creates the environment. A build without one can
// still create environments; it refuses to clone, loudly.
type Environments struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// Auth supplies the reveal guard for clone-at-creation (#58): a clone
	// duplicates stored `secret` material, which is a disclosure by proxy, so
	// its source side takes the same enumerated-key ceremony a cell reveal
	// does. Nil refuses a clone that would open secrets, loudly.
	Auth *Auth
	// Advisory announces the new environment's revision 1, after commit.
	Advisory *Advisory
	// Scan: secret-scanning Surface-2 seam (#74). Environment names and notes
	// are author-controlled declaration text.
	Scan *scanning.Ruleset
}

// Environment methods address scope as a domain.Scope — the same shape
// authorize() takes; a wrong-depth scope is refused there (loud error).
// Create/List/Reorder address the parent project (Org+Project); the rest
// address the environment (full chain).

// Create appends an environment at the end of the project's display order.
// The count that bounds it is read under the same proof in the same
// transaction as the insert, so the cap cannot be walked past by two
// concurrent creates.
func (s *Environments) Create(ctx context.Context, actor Actor, scope domain.Scope, name string, acks []string) (Environment, error) {
	env, _, err := s.create(ctx, actor, scope, name, "", acks)
	return env, err
}

// Clone is create-with-clone-at-creation (#50, flat-model ADR § Ergonomics):
// the new environment is born holding a copy of another environment's values.
//
// It is ONE act. The environment row, every copied value and the audit records
// for both commit together or not at all — the atomicity rule admits no
// partially-valid creation, and a clone that aborted after creating the
// environment would leave exactly that.
//
// The copy is preflighted, and the preflight can ABORT the creation: see
// cloneInto. What could not be copied comes back enumerated by name, never
// silently absent.
func (s *Environments) Clone(ctx context.Context, actor Actor, scope domain.Scope, name, sourceEnvID string, acks []string) (Environment, CloneResult, error) {
	if sourceEnvID == "" {
		return Environment{}, CloneResult{}, fmt.Errorf("%w: clone names a source environment", domain.ErrInvalid)
	}
	return s.create(ctx, actor, scope, name, sourceEnvID, acks)
}

func (s *Environments) create(ctx context.Context, actor Actor, scope domain.Scope, name, sourceEnvID string, acks []string) (Environment, CloneResult, error) {
	if err := checkName("environment name", name); err != nil {
		return Environment{}, CloneResult{}, err
	}
	id, err := newID("env")
	if err != nil {
		return Environment{}, CloneResult{}, err
	}
	// The sealer is resolved before the transaction opens: the keyring's store
	// adapter runs transactions of its own, and sqlite serves writes on a
	// single connection, so resolving it inside would wait on the connection
	// this transaction holds. A plain create needs none.
	//
	// After authorization, never before: resolving a sealer MINTS the project
	// data key on first use, and an unauthorized caller must not leave a
	// wrapped-key row behind (see service.sealerFor). Every create needs one
	// now, clone or not: an environment is VALIDATED AND MATERIALIZED against
	// the current schema revision before it becomes fetchable, and a
	// materialization seals what it publishes.
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpEnvCreate, scope)
	if err != nil {
		return Environment{}, CloneResult{}, err
	}
	var created store.NewEnvironment
	var clone CloneResult
	var published PublishedEnvironment
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		clone = CloneResult{}
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvCreate, scope)
		if err != nil {
			return err
		}
		// Take the project row first. Both reads below are read-then-write, and
		// on postgres two transactions at cap-1 would otherwise both see the
		// same count and both insert. sqlite serializes writes on its single
		// _txlock=immediate connection, so there the lock is a plain read.
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		n, err := r.Environments().Count(ctx, p)
		if err != nil {
			return err
		}
		if n >= MaxEnvironmentsPerProject {
			return fmt.Errorf("%w: a project holds at most %d environments",
				domain.ErrLimitExceeded, MaxEnvironmentsPerProject)
		}
		// Surface-2 block (#74): the environment name is scanned before the row
		// persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locEnvironmentName, name), newAckSet(acks)); err != nil {
			return err
		}
		// Append past the highest position in use, NOT at the row count: a
		// delete leaves its gap behind on purpose, so [0,1,2] minus the middle
		// is a count of 2 and a next position of 3. Using the count there would
		// hand the new row position 2, which the last row already holds.
		next, err := r.Environments().NextOrder(ctx, p)
		if err != nil {
			return err
		}
		created = store.NewEnvironment{
			ID: id, Name: name, Note: "",
			// Reorder is what moves an environment; creation does not guess
			// where the operator wanted it.
			DisplayOrder: next,
			CreatedAt:    store.CanonTime(time.Now()),
		}
		if err := r.Environments().Create(ctx, p, created); err != nil {
			return err
		}
		// The environment list is definitions-bundle desired state, so its change
		// advances the definitions revision (#70). Bumped BEFORE the new
		// environment's initial materialization so that snapshot pins the fresh
		// revision. Existing environments are not re-materialized: adding an
		// environment changes no key, declaration or presence rule they deliver.
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventEnvCreated, caller.Principal,
			audit.Object{Type: "environment", ID: created.ID},
			audit.Payload{"name": audit.SanitizeFreeText(created.Name)})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		if sourceEnvID != "" {
			// The row exists now, so the destination half of the copy formula
			// can be evaluated against the environment being created — which
			// is what the ADR requires it to be evaluated against.
			clone, err = cloneInto(ctx, r, az, caller, sealer, s.Keyring, s.Scan, scope, sourceEnvID, created.ID,
				ceremonyGate(ctx, s.Auth, az, caller, PurposeCopy, sourceEnvID))
			if err != nil {
				return err
			}
		}
		// MATERIALIZE REVISION 1 before the environment becomes fetchable
		// (schema-model ADR § Presence): an environment is never deliverable in a
		// state no schema check has seen, and delivery reads only committed
		// snapshots. A `mode: all` required key with nothing to satisfy it
		// therefore refuses the creation here rather than producing an
		// environment born invalid.
		newScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(created.ID)}
		published, err = republish(ctx, r, az, caller, sealer, s.Keyring, newScope,
			store.CanonTime(time.Now()), "environment-create")
		return err
	})
	if err != nil {
		return Environment{}, CloneResult{}, err
	}
	s.Advisory.published(scope, []PublishedEnvironment{published})
	return Environment{
		ID: created.ID, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		Name: created.Name, Note: created.Note,
		DisplayOrder: created.DisplayOrder, CreatedAt: created.CreatedAt,
	}, clone, nil
}

func (s *Environments) Get(ctx context.Context, actor Actor, scope domain.Scope) (Environment, error) {
	var out store.Environment
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvRead, scope)
		if err != nil {
			return err
		}
		out, err = r.Environments().Get(ctx, p)
		return err
	})
	if err != nil {
		return Environment{}, err
	}
	return environmentOf(out), nil
}

// List returns the project's environments in display order.
func (s *Environments) List(ctx context.Context, actor Actor, scope domain.Scope) ([]Environment, error) {
	var out []store.Environment
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvList, scope)
		if err != nil {
			return err
		}
		out, err = r.Environments().List(ctx, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	list := make([]Environment, 0, len(out))
	for _, row := range out {
		list = append(list, environmentOf(row))
	}
	return list, nil
}

func (s *Environments) Rename(ctx context.Context, actor Actor, scope domain.Scope, name string, acks []string) (Environment, error) {
	if err := checkName("environment name", name); err != nil {
		return Environment{}, err
	}
	var out store.Environment
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvRename, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		before, err := r.Environments().Get(ctx, p)
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the new environment name is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locEnvironmentName, name), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Environments().Rename(ctx, p, name); err != nil {
			return err
		}
		// The environment name is definitions-bundle desired state, so a rename
		// advances the definitions revision (#70). It materializes nothing — a
		// rename moves a label nothing is delivered under.
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		out = before
		out.Name = name
		ev, err := domainEvent(ctx, audit.EventEnvRenamed, caller.Principal,
			audit.Object{Type: "environment", ID: before.ID}, audit.Payload{
				"previous_name": audit.SanitizeFreeText(before.Name),
				"name":          audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Environment{}, err
	}
	return environmentOf(out), nil
}

// Reorder rewrites the project's whole display order from an ordered id list.
//
// It takes the WHOLE set rather than one position per call for two reasons: a
// single transaction cannot then leave two environments sharing a position or
// a gap in the sequence, and a concurrent reorder serializes behind it instead
// of interleaving with it. The list must name exactly the project's
// environments, once each; anything else is refused with one fixed message,
// which is also why a foreign id discloses nothing — the refusal is the same
// whether it exists or not.
func (s *Environments) Reorder(ctx context.Context, actor Actor, scope domain.Scope, ordered []string) ([]Environment, error) {
	var out []store.Environment
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvReorder, scope)
		if err != nil {
			return err
		}
		// Same lock as create, for the same reason one level up: two reorders
		// interleaving their per-row writes could commit a blended permutation
		// with duplicate positions, and a reorder racing a create would race its
		// append position.
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		live, err := r.Environments().List(ctx, p)
		if err != nil {
			return err
		}
		known := make(map[string]store.Environment, len(live))
		for _, e := range live {
			known[e.ID] = e
		}
		// A project with no environments has the empty list as its exact whole
		// set, and reordering it is a legal no-op. The contract's minItems
		// matches (0), so the two layers agree rather than the schema rejecting
		// what the service would accept.
		seen := make(map[string]bool, len(ordered))
		if len(ordered) != len(live) {
			return fmt.Errorf("%w: the order must name each of the project's environments exactly once", domain.ErrInvalid)
		}
		out = make([]store.Environment, 0, len(ordered))
		for i, id := range ordered {
			env, ok := known[id]
			if !ok || seen[id] {
				return fmt.Errorf("%w: the order must name each of the project's environments exactly once", domain.ErrInvalid)
			}
			seen[id] = true
			if err := r.Environments().SetOrder(ctx, p, id, int64(i)); err != nil {
				return err
			}
			env.DisplayOrder = int64(i)
			out = append(out, env)
		}
		// The resulting order itself, not only how many rows it covered:
		// swapping production and staging must not produce the same record as
		// any other permutation of the same three environments. Ids are trusted
		// vocabulary (server-minted, grammar-checked), so they are a schema
		// string rather than free text.
		ev, err := domainEvent(ctx, audit.EventEnvReordered, caller.Principal,
			audit.Object{Type: "project", ID: string(scope.Project)},
			audit.Payload{
				"environment_count": len(ordered),
				"environment_order": strings.Join(ordered, ","),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return nil, err
	}
	list := make([]Environment, 0, len(out))
	for _, row := range out {
		list = append(list, environmentOf(row))
	}
	return list, nil
}

// Delete removes an environment. The remaining environments keep their
// positions: display order is a property of each row, not an invariant over
// the set, so a gap is not a defect and closing it would be an unrequested
// write to rows the operator did not name.
func (s *Environments) Delete(ctx context.Context, actor Actor, scope domain.Scope) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvDelete, scope)
		if err != nil {
			return err
		}
		// Environment lifecycle and presence rules are ONE serialization domain
		// per project (#49, schema-model ADR): without the project row, this
		// delete and a concurrent `required_in` edit naming this environment
		// each read a consistent world and commit into an inconsistent one —
		// a dangling reference, or a lost cascade.
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		before, err := r.Environments().Get(ctx, p)
		if err != nil {
			return err
		}
		// The cascade runs BEFORE the delete and in the same transaction: the
		// presence rows carry a composite foreign key to this environment, so
		// the order is not a preference — the delete would be refused
		// otherwise. It also collapses any explicit set it empties and moves
		// the catalogue revision; see cascadeEnvironmentPresence.
		if err := cascadeEnvironmentPresence(ctx, r, p, string(scope.Env)); err != nil {
			return err
		}
		// The environment's values go with it (#50), in the same transaction
		// and for the same structural reason: they attach to this environment
		// and to nothing else, the composite foreign key would refuse the
		// delete while they existed, and the flat model gives them nowhere
		// else to live. Deleting an environment IS deleting its values; the
		// alternative — refusing the delete until every cell is cleared by
		// hand — makes an environment undeletable in proportion to how much it
		// was used.
		if err := r.Values().ClearEnvironment(ctx, p); err != nil {
			return err
		}
		// The drafts and the published history go with it too, for the same
		// composite-foreign-key reason. History is never rewritten, but an
		// environment's lineage is not history once the environment is gone:
		// there is nothing left for it to explain, and the row it hangs off no
		// longer exists.
		if err := r.Pending().DiscardEnvironment(ctx, p); err != nil {
			return err
		}
		if err := r.Pins().DeleteEnvironment(ctx, p); err != nil {
			return err
		}
		if err := r.Snapshots().DeleteEnvironment(ctx, p); err != nil {
			return err
		}
		if err := r.Environments().Delete(ctx, p); err != nil {
			return err
		}
		// The environment list is definitions-bundle desired state, so its
		// deletion advances the definitions revision unconditionally (#70) — even
		// when the environment carried no presence rows for the cascade to rewrite.
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventEnvDeleted, caller.Principal,
			audit.Object{Type: "environment", ID: before.ID},
			audit.Payload{"name": audit.SanitizeFreeText(before.Name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}

// UpdateNote mutates an environment's operator note. It is the edit-authority
// demonstration operation from #44 and has no HTTP route of its own; it stays
// because the isolation probes ride on it to prove that `edit(E)` and
// `definitions-edit(project)` are enforced as different authorities.
func (s *Environments) UpdateNote(ctx context.Context, actor Actor, scope domain.Scope, note string, acks []string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvUpdateNote, scope)
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the note is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locEnvironmentNote, note), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Environments().UpdateNote(ctx, p, note); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventEnvNoteChanged, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}

// ---------------------------------------------------------------------------
// Folder
// ---------------------------------------------------------------------------

// Folder is the service layer's folder: a project-scoped namespace and display
// grouping, and nothing else in v1.
type Folder struct {
	ID        string
	OrgID     string
	ProjectID string
	Path      string
	CreatedAt time.Time
}

func folderOf(f store.Folder) Folder {
	return Folder{ID: f.ID, OrgID: f.OrgID, ProjectID: f.ProjectID, Path: f.Path, CreatedAt: f.CreatedAt}
}

// Folders owns the folder surface. Every method addresses PROJECT depth: the
// scope lattice has no folder level (the permission-model ADR forbids folder-scoped
// grants outright), so the folder id is an ordinary argument that can only
// resolve inside the project the proof already authorized.
type Folders struct {
	DB *store.DB
	// Keyring and Scan: secret-scanning Surface-2 seam (#74). Folder path
	// segments are author-controlled declaration text.
	Keyring *crypto.Keyring
	Scan    *scanning.Ruleset
}

func (s *Folders) Create(ctx context.Context, actor Actor, scope domain.Scope, path string, acks []string) (Folder, error) {
	if err := checkFolderPath(path); err != nil {
		return Folder{}, err
	}
	id, err := newID("fld")
	if err != nil {
		return Folder{}, err
	}
	folder := store.NewFolder{ID: id, Path: path, CreatedAt: store.CanonTime(time.Now())}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFolderCreate, scope)
		if err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		// Surface-2 block (#74): the folder path is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locFolderPath, path), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Folders().Create(ctx, p, folder); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventFolderCreated, caller.Principal,
			audit.Object{Type: "folder", ID: folder.ID},
			audit.Payload{"namespace": audit.SanitizeFreeText(folder.Path)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Folder{}, err
	}
	return Folder{
		ID: folder.ID, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		Path: folder.Path, CreatedAt: folder.CreatedAt,
	}, nil
}

func (s *Folders) Get(ctx context.Context, actor Actor, scope domain.Scope, id string) (Folder, error) {
	var out store.Folder
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFolderGet, scope)
		if err != nil {
			return err
		}
		out, err = r.Folders().Get(ctx, p, id)
		return err
	})
	if err != nil {
		return Folder{}, err
	}
	return folderOf(out), nil
}

func (s *Folders) List(ctx context.Context, actor Actor, scope domain.Scope) ([]Folder, error) {
	var out []store.Folder
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFolderList, scope)
		if err != nil {
			return err
		}
		out, err = r.Folders().List(ctx, p)
		return err
	})
	if err != nil {
		return nil, err
	}
	list := make([]Folder, 0, len(out))
	for _, row := range out {
		list = append(list, folderOf(row))
	}
	return list, nil
}

// Rename moves a folder to a new path. It renames exactly the row named: a
// folder is a flat namespace label in v1, not a tree node with children to
// carry along, so there is no cascade to get wrong.
func (s *Folders) Rename(ctx context.Context, actor Actor, scope domain.Scope, id, path string, acks []string) (Folder, error) {
	if err := checkFolderPath(path); err != nil {
		return Folder{}, err
	}
	var out store.Folder
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFolderRename, scope)
		if err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		before, err := r.Folders().Get(ctx, p, id)
		if err != nil {
			return err
		}
		// Surface-2 block (#74): the new folder path is scanned before it persists.
		if err := applyDeclarationScan(ctx, r, p, az, s.Keyring, s.Scan, caller.Principal,
			scope, nonEmptyLeaf(locFolderPath, path), newAckSet(acks)); err != nil {
			return err
		}
		if err := r.Folders().Rename(ctx, p, id, path); err != nil {
			return err
		}
		out = before
		out.Path = path
		ev, err := domainEvent(ctx, audit.EventFolderRenamed, caller.Principal,
			audit.Object{Type: "folder", ID: before.ID}, audit.Payload{
				"previous_namespace": audit.SanitizeFreeText(before.Path),
				"namespace":          audit.SanitizeFreeText(path),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return Folder{}, err
	}
	return folderOf(out), nil
}

func (s *Folders) Delete(ctx context.Context, actor Actor, scope domain.Scope, id string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpFolderDelete, scope)
		if err != nil {
			return err
		}
		if err := requireDBManagedDefinitions(ctx, r, p); err != nil {
			return err
		}
		before, err := r.Folders().Get(ctx, p, id)
		if err != nil {
			return err
		}
		if err := r.Folders().Delete(ctx, p, id); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventFolderDeleted, caller.Principal,
			audit.Object{Type: "folder", ID: before.ID},
			audit.Payload{"namespace": audit.SanitizeFreeText(before.Path)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
}
