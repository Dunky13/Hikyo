package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Revisions, drafts and publishing (#51, revision-model ADR as amended by the
// flat-model ADR; schema-model ADR for validation timing and key groups).
//
// THE SHAPE OF THE SLICE, stated once because everything below follows from it:
//
//	value_entries   is the PUBLISHED state. Only this pipeline writes it.
//	pending_changes is per-user WORKING state. `values set` writes it, and
//	                nothing reads another owner's material.
//	snapshots       is the immutable per-environment materialization that
//	                delivery reads. Publish is the only thing that creates one.
//
// PUBLISH IS THE AUTHORITY. Saving is free -- a draft may hold a type-invalid
// value, may clear a `required_in` key, may sit against a stale baseline. Every
// one of those is refused at publish, loud, naming what failed. That is the
// schema ADR's "advisory on save, authoritative at publish" made structural:
// there is exactly one place where validation decides anything.

// The AAD field tags and owner tables for the two sealed columns this slice
// adds. Both ride the project-field envelope kind and bind row, environment,
// and key; snapshots bind their parent snapshot too.
const (
	snapshotFieldTag = "snapshot_value"
	pendingFieldTag  = "pending_value"
	snapshotTable    = "snapshot_entries"
	pendingTable     = "pending_changes"
)

// Revisions owns the publish pipeline, the revision history, and the matrix
// signals derived from both.
type Revisions struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// Advisory receives the metadata-only live-update events, AFTER commit.
	// Nil disables the channel entirely, which is safe by construction:
	// correctness never depends on delivery (revision ADR, Live updates).
	Advisory *Advisory
	// Auth supplies the reveal guard for the one disclosing method here,
	// Export. Nil refuses every disclosure loudly.
	Auth *Auth
	Now  func() time.Time
	// PublishProbe is the service-layer conformance seam for forcing two real
	// publish transactions to overlap around the project lock. Production
	// leaves it nil; it decides no behavior and sees no material.
	PublishProbe PublishConformanceProbe
}

// PublishConformanceProbe exposes only the two checkpoints needed to prove
// publish serialization against both real engines.
type PublishConformanceProbe interface {
	BeforeProjectLock(versionIDs []string)
	AfterBaselineRead(versionIDs []string)
}

func (s *Revisions) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// PublishedEnvironment is one environment a materialization advanced.
type PublishedEnvironment struct {
	EnvironmentID string
	Revision      int64
	// ChangeToken is derived from the CURRENT root token key over this
	// snapshot's delivery manifest, never stored -- see the migration.
	ChangeToken string
	// SchemaRevision is the pinned input this snapshot was validated at.
	SchemaRevision int64
	ChangedKeys    []ChangedKey
}

// ChangedKey is one lineage row as reported. It carries no value in any form --
// not the plaintext, not a length, not a digest, not a changed-from marker.
type ChangedKey struct {
	KeyID  string
	Name   string
	Change string
}

// PublishResult is one publish.
type PublishResult struct {
	// Published names every version id that committed, INCLUDING the ones
	// key-group closure pulled in; ClosedIn names just the latter, so a caller
	// can tell what it asked for from what the coupling required.
	Published    []string
	ClosedIn     []string
	Environments []PublishedEnvironment
}

// ErrStalePending reports the optimistic freshness check failing: the
// environment advanced after the draft was staged, or the named version was
// superseded by a newer edit from its owner. Loud, never a silent rebase --
// binding to version ids rather than to entry identity is what stops a
// publisher committing a value they never previewed.
// It wraps domain.ErrConflict so the wire answers 409, the code the contract
// declares for it -- an unmapped sentinel here answered 500 and read as a
// server fault rather than the caller's stale selection.
var ErrStalePending = fmt.Errorf("%w: service: pending change is stale", domain.ErrConflict)

// pendingApply is one draft's effect on one cell during a materialization.
type pendingApply struct {
	versionID  string
	keyID      string
	set        bool
	value      string
	sealed     []byte
	stagedFrom int64
	// stagedFromEntry is the published value-entry id the cell held when the
	// draft was staged, "" for a cell that was absent. The freshness check
	// compares exactly this.
	stagedFromEntry string
	source          store.PendingSource
}

// resolvedCell is one key's outcome in one environment after the selected
// drafts are applied to the published state.
type resolvedCell struct {
	key   store.CatalogueKey
	set   bool
	value string
	// entryID is the published value-entry row this outcome materialized from
	// -- the snapshot's pinned value-entry revision. Filled after the writes.
	entryID string
}

// Publish commits a selection of the caller's own pending changes.
//
// The whole operation runs in ONE serializable transaction that also holds the
// per-project lock: conflict checking, closure, validation, snapshot
// construction, revision allocation and the latest-pointer advance are all
// inside it. Without that, two publishes computed from the same baseline can
// both commit and the later materialization silently reverts the other's key --
// unique revision numbers alone do not linearize the outcome.
//
// SELECTION ISOLATION: each affected environment's snapshot is computed from
// the last published state plus the SELECTED versions only. The publisher's
// unselected drafts and every other principal's are invisible to it, so the
// materialized snapshot always corresponds to a state the publisher previewed.
func (s *Revisions) Publish(ctx context.Context, actor Actor, scope domain.Scope, versionIDs []string) (PublishResult, error) {
	if scope.Env == "" {
		return PublishResult{}, fmt.Errorf("%w: a publish addresses an environment", domain.ErrInvalid)
	}
	if len(versionIDs) == 0 {
		return PublishResult{}, fmt.Errorf("%w: a publish names the pending changes it commits", domain.ErrInvalid)
	}
	if dup, ok := firstDuplicate(versionIDs); ok {
		return PublishResult{}, invalidDetail("pending change %q is named more than once", dup)
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpValuePublish, scope)
	if err != nil {
		return PublishResult{}, err
	}

	var out PublishResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out = PublishResult{}
		// The clock is read INSIDE the transaction: the sealer preflight can
		// take real time, and a credential expiring during it must be refused
		// by the authentication this publish actually rides.
		now := s.now()
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		// The addressed environment is authorized FIRST: a caller who may not
		// publish here learns nothing from the selection read, and the uniform
		// nonexistent answer is the only thing they see.
		p, err := az.Authorize(ctx, caller, authz.OpValuePublish, scope)
		if err != nil {
			return err
		}
		if s.PublishProbe != nil {
			s.PublishProbe.BeforeProjectLock(slices.Clone(versionIDs))
		}
		// One serialization domain per project, acquired BEFORE the freshness
		// and authorization re-checks (schema ADR).
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}

		selected, byID, err := resolveVersions(ctx, r, p, caller.Principal, versionIDs)
		if err != nil {
			return err
		}

		// Authorize EVERY explicitly selected environment before group closure
		// reads catalogue membership or another owner's write-presence. Closure
		// is environment-local and therefore cannot add an environment.
		envs := make([]string, 0, len(selected))
		for _, change := range selected {
			if !slices.Contains(envs, change.EnvironmentID) {
				envs = append(envs, change.EnvironmentID)
			}
		}
		sort.Strings(envs)
		proofs := make(map[string]authz.Proof, len(envs))
		for _, envID := range envs {
			envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
			ep := p
			if envID != string(scope.Env) {
				if ep, err = az.Authorize(ctx, caller, authz.OpValuePublish, envScope); err != nil {
					return err
				}
			}
			proofs[envID] = ep
		}

		selection, closed, err := selectVersions(ctx, r, p, caller.Principal, selected, byID)
		if err != nil {
			return err
		}
		for envID := range selection {
			if _, authorized := proofs[envID]; !authorized {
				return fmt.Errorf("service: key-group closure added environment %s", envID)
			}
		}

		// A stable environment order, so a multi-environment publish writes its
		// rows the same way every time.
		envs = envs[:0]
		for envID := range selection {
			envs = append(envs, envID)
		}
		sort.Strings(envs)

		for _, envID := range envs {
			envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
			ep := proofs[envID]
			applies := selection[envID]
			if err := checkFreshness(ctx, r, ep, applies); err != nil {
				return err
			}
			if s.PublishProbe != nil {
				s.PublishProbe.AfterBaselineRead(slices.Clone(versionIDs))
			}
			for i := range applies {
				if !applies[i].set {
					continue
				}
				plain, err := sealer.OpenField(pendingAAD(
					string(scope.Org), string(scope.Project), envID, applies[i].keyID, applies[i].versionID), applies[i].sealed)
				if err != nil {
					return fmt.Errorf("service: pending change %s: %w", applies[i].versionID, err)
				}
				applies[i].value = string(plain)
			}
			published, err := materialize(ctx, r, ep, sealer, s.Keyring, envScope,
				caller.Principal, now, applies)
			if err != nil {
				return err
			}
			for _, apply := range applies {
				existed, err := r.Pending().Discard(ctx, ep, apply.versionID)
				if err != nil {
					return err
				}
				if !existed {
					return fmt.Errorf("%w: version %s vanished mid-publish", ErrStalePending, apply.versionID)
				}
				out.Published = append(out.Published, apply.versionID)
			}
			trigger := "values"
			for _, apply := range applies {
				if apply.source == store.PendingSourceRestore {
					trigger = "restore"
					break
				}
			}
			if err := recordPublish(ctx, r, ep, caller.Principal, envID, published, len(applies), trigger); err != nil {
				return err
			}
			out.Environments = append(out.Environments, published)
		}
		out.ClosedIn = closed
		slices.Sort(out.Published)
		return nil
	})
	if err != nil {
		return PublishResult{}, err
	}
	// Post-commit, never inside: no external effect may escape before commit,
	// and an advisory about a publish that rolled back would be a claim clients
	// cannot correct.
	s.Advisory.published(scope, out.Environments)
	return out, nil
}

// recordPublish writes the publish audit event. Every materialization goes
// through it -- a value publish, a schema fan-out, an environment creation --
// so there is one event shape for "this environment advanced to revision N"
// and `trigger` says which act produced it.
func recordPublish(ctx context.Context, r store.Repos, p authz.Proof, principal domain.PrincipalID,
	envID string, published PublishedEnvironment, selected int, trigger string) error {
	ev, err := domainEvent(ctx, audit.EventRevisionPublished, principal,
		audit.Object{Type: "environment", ID: envID}, audit.Payload{
			"revision":        published.Revision,
			"schema_revision": published.SchemaRevision,
			"changed_keys":    len(published.ChangedKeys),
			"pending_count":   selected,
			"trigger":         trigger,
		})
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, p, ev)
}

// republish re-materializes one environment from its CURRENT published state,
// with no drafts applied.
//
// Every path that writes published cells outside the draft pipeline ends here
// -- declare-into-environments, import, copy / bulk-apply, clone-at-creation,
// an environment's own creation, and a semantic schema change's fan-out. That is
// what makes "delivery reads only committed, valid snapshots" true of all of
// them rather than of the publish verb alone, and it is why validation and
// lineage have exactly one implementation.
//
// The `publish` authorization is evaluated here even where the caller's own
// operation already carried a `publish(destination)` conjunct: the ADR requires
// per-affected-environment publish authorization IMMEDIATELY BEFORE COMMIT, and
// a check performed earlier in the same transaction is not that.
func republish(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	sealer *crypto.ProjectSealer, kr *crypto.Keyring, scope domain.Scope,
	now time.Time, trigger string) (PublishedEnvironment, error) {
	p, err := az.Authorize(ctx, caller, authz.OpValuePublish, scope)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	published, err := materialize(ctx, r, p, sealer, kr, scope, caller.Principal, now, nil)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	if err := recordPublish(ctx, r, p, caller.Principal, string(scope.Env), published, 0, trigger); err != nil {
		return PublishedEnvironment{}, err
	}
	return published, nil
}

// fanOutSchemaPublish materializes EVERY environment in the project.
//
// A semantic schema change -- a key created, renamed, deleted, reclassified,
// retyped, re-scoped by presence, or moved between groups -- does NOT narrow to
// a touched set the way a value publish does. The schema ADR's locked unit
// stands exactly: such a change validates, requires publish authorization on,
// and materializes a new snapshot for every environment in the project, even
// where no value and no verdict changes, because its PINNED SCHEMA REVISION
// changes and that is a pinned input.
//
// The change token is computed over the delivery manifest, so an environment
// whose delivered content did not move produces an unchanged token and fires no
// rollout: the new revision records that the validation guarantee moved,
// without disturbing anything.
//
// It also carries the authorization the schema ADR demands and #49 could not
// yet evaluate: `publish` on every affected environment, immediately before
// commit. A principal holding `definitions-edit` alone can no longer loosen
// production's validation, drop a presence protection or dissolve a key group
// without production authority.
// The environment list is read under the CALLER'S OWN project proof -- the one
// the schema mutation already minted -- rather than under a second operation:
// enumerating the project's environments is something `definitions-edit`
// already reaches, and a synthetic operation whose only job is to widen a
// store-op set is exactly the kind of registry row that stops meaning anything.
//
// The sealer arrives from OUTSIDE the transaction (prepareSchemaPublish) for the
// reason every sealing path in this package shares: resolving one mints the
// project data key on first use, and minting opens a write transaction that
// would wait forever on sqlite's single write connection for the transaction
// that asked for it.
func fanOutSchemaPublish(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, sealer *crypto.ProjectSealer, kr *crypto.Keyring, scope domain.Scope,
	now time.Time, trigger string) ([]PublishedEnvironment, error) {
	environments, err := r.Environments().List(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]PublishedEnvironment, 0, len(environments))
	for _, env := range environments {
		envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(env.ID)}
		published, err := republish(ctx, r, az, caller, sealer, kr, envScope, now, trigger)
		if err != nil {
			return nil, err
		}
		out = append(out, published)
	}
	return out, nil
}

// selectVersions resolves the named version ids against the caller's own live
// working state and runs key-group closure. It returns the per-environment
// apply set (material still sealed) and the version ids closure pulled in.
func resolveVersions(ctx context.Context, r store.Repos, p authz.Proof,
	principal domain.PrincipalID, versionIDs []string) (map[string]store.PendingChange, map[string]store.PendingChange, error) {
	mine, err := r.Pending().ListForOwner(ctx, p, string(principal))
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]store.PendingChange, len(mine))
	for _, change := range mine {
		byID[change.ID] = change
	}

	selected := make(map[string]store.PendingChange, len(versionIDs))
	for _, id := range versionIDs {
		change, ok := byID[id]
		if !ok {
			// Superseded, already published, discarded with its key, or simply
			// somebody else's. All four are the same answer: this publisher has
			// no live version by that id. Distinguishing them would either leak
			// another principal's draft or silently publish something the
			// caller never previewed.
			return nil, nil, fmt.Errorf("%w: no live pending change %q is owned by this principal",
				ErrStalePending, id)
		}
		selected[id] = change
	}
	return selected, byID, nil
}

func selectVersions(ctx context.Context, r store.Repos, p authz.Proof,
	principal domain.PrincipalID, selected, byID map[string]store.PendingChange) (map[string][]pendingApply, []string, error) {
	keys, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	keyByID := make(map[string]store.CatalogueKey, len(keys))
	groupMembers := map[string][]store.CatalogueKey{}
	for _, k := range keys {
		keyByID[k.ID] = k
		if k.GroupID != "" {
			groupMembers[k.GroupID] = append(groupMembers[k.GroupID], k)
		}
	}
	markers, err := r.Pending().ListMarkers(ctx, p)
	if err != nil {
		return nil, nil, err
	}

	// KEY-GROUP CLOSURE over (group, environment) pairs, to a fixed point.
	//
	// Selecting a change to any member pulls the owner's changes to the other
	// members of the same group IN THE SAME ENVIRONMENT into the publish.
	// Groups couple entries, and a pending change targets a specific
	// (key, environment), so each environment closes independently.
	//
	// A member with no pending change from anyone is NOT an error: the
	// guarantee is that a publisher cannot publish a SUBSET of the pending
	// changes to a group, not that every member must be touched every time.
	var closed []string
	for grew := true; grew; {
		grew = false
		for _, change := range sortedChanges(selected) {
			key, ok := keyByID[change.KeyID]
			if !ok {
				return nil, nil, fmt.Errorf("%w: pending change %s names key %s, which is no longer declared",
					ErrStalePending, change.ID, change.KeyID)
			}
			if key.GroupID == "" {
				continue
			}
			for _, member := range groupMembers[key.GroupID] {
				for _, marker := range markers {
					if marker.KeyID != member.ID || marker.EnvironmentID != change.EnvironmentID {
						continue
					}
					if marker.OwnerID != string(principal) {
						// Never silently split, and never a cross-user hand-off:
						// v1 has no mechanism to publish another principal's
						// staged edit, so a group whose pending members span two
						// owners is refused by name.
						return nil, nil, invalidDetail(
							"key group %s couples key %q, whose pending change in environment %s is owned by another principal: publish is refused rather than split",
							key.GroupID, member.Name, change.EnvironmentID)
					}
					if _, already := selected[marker.ID]; already {
						continue
					}
					pull, ok := byID[marker.ID]
					if !ok {
						return nil, nil, fmt.Errorf("%w: group member version %s is no longer live",
							ErrStalePending, marker.ID)
					}
					selected[marker.ID] = pull
					closed = append(closed, marker.ID)
					grew = true
				}
			}
		}
	}

	out := map[string][]pendingApply{}
	for _, change := range sortedChanges(selected) {
		out[change.EnvironmentID] = append(out[change.EnvironmentID], pendingApply{
			versionID:       change.ID,
			keyID:           change.KeyID,
			set:             change.Operation == store.PendingSet,
			sealed:          change.Ciphertext,
			stagedFrom:      change.StagedFromRevision,
			stagedFromEntry: change.StagedFromEntry,
			source:          change.Source,
		})
	}
	slices.Sort(closed)
	return out, closed, nil
}

// sortedChanges iterates a selection deterministically. Map order would make
// the closure's refusal message depend on Go's hash seed, and a refusal that
// names a different key on every run is not a refusal an operator can act on.
func sortedChanges(selected map[string]store.PendingChange) []store.PendingChange {
	out := make([]store.PendingChange, 0, len(selected))
	for _, change := range selected {
		out = append(out, change)
	}
	slices.SortFunc(out, func(a, b store.PendingChange) int {
		if a.EnvironmentID != b.EnvironmentID {
			if a.EnvironmentID < b.EnvironmentID {
				return -1
			}
			return 1
		}
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	return out
}

// checkFreshness is the optimistic check, PER SELECTED ENTRY: the published
// cell each named version targets must still be the one it was staged against.
//
// Per entry rather than per environment, because that is what the ADR states
// and because the environment-wide reading is unusable -- publishing one key
// would invalidate every outstanding draft in that environment, including
// drafts to keys nothing touched.
//
// The superseded half of the rule needs no code here: a superseded version is
// collected the moment its successor is staged, so it has no id left to name
// and the selection lookup already refused it.
func checkFreshness(ctx context.Context, r store.Repos, p authz.Proof, applies []pendingApply) error {
	entries, err := r.Values().List(ctx, p)
	if err != nil {
		return err
	}
	published := make(map[string]string, len(entries))
	for _, entry := range entries {
		published[entry.KeyID] = entry.ID
	}
	keys, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return err
	}
	names := make(map[string]string, len(keys))
	for _, key := range keys {
		names[key.ID] = key.Name
	}
	for _, apply := range applies {
		if published[apply.keyID] == apply.stagedFromEntry {
			continue
		}
		return fmt.Errorf("%w: version %s targets key %q, whose published value has changed since the draft was staged at revision %d: restage the edit against the current state",
			ErrStalePending, apply.versionID, names[apply.keyID], apply.stagedFrom)
	}
	return nil
}

// currentRevision reads the proof's environment's published revision number,
// 0 when it has never been materialized.
func currentRevision(ctx context.Context, r store.Repos, p authz.Proof) (int64, error) {
	latest, err := r.Snapshots().Latest(ctx, p)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return latest.Revision, nil
}

// materialize is THE publish primitive: it computes one environment's resolved
// state, validates it at the current schema revision, writes the published
// cells, and allocates the immutable snapshot and revision that delivery reads.
//
// Every path that advances an environment goes through it -- a value publish,
// import, a semantic schema publish's fan-out, and an environment's own creation -- so
// there is exactly one implementation of "what does this environment deliver,
// and is that legal".
func materialize(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	kr *crypto.Keyring, scope domain.Scope, publisher domain.PrincipalID, now time.Time,
	applies []pendingApply) (PublishedEnvironment, error) {
	keys, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	presence, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	schemaRevision, err := r.Catalogue().SchemaRevision(ctx, p)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	entries, err := r.Values().List(ctx, p)
	if err != nil {
		return PublishedEnvironment{}, err
	}
	entryByKey := make(map[string]store.ValueEntry, len(entries))
	for _, entry := range entries {
		entryByKey[entry.KeyID] = entry
	}
	applyByKey := make(map[string]pendingApply, len(applies))
	for _, apply := range applies {
		applyByKey[apply.keyID] = apply
	}

	// The resolved state: published cells, overridden by the selection only.
	cells := make([]resolvedCell, 0, len(keys))
	for _, key := range keys {
		cell := resolvedCell{key: key}
		if entry, ok := entryByKey[key.ID]; ok {
			plain, err := openCell(sealer, entry)
			if err != nil {
				return PublishedEnvironment{}, err
			}
			cell.set, cell.value, cell.entryID = true, plain, entry.ID
		}
		if apply, ok := applyByKey[key.ID]; ok {
			cell.set, cell.value = apply.set, apply.value
			if !apply.set {
				cell.entryID = ""
			}
		}
		cells = append(cells, cell)
	}

	if err := validateResolved(cells, presence, string(scope.Env)); err != nil {
		return PublishedEnvironment{}, err
	}

	// Only now do the published cells move. Validation ran on the resolved
	// state first so an abort leaves the transaction with nothing to undo
	// beyond what the engine rolls back anyway.
	for i := range cells {
		apply, ok := applyByKey[cells[i].key.ID]
		if !ok {
			continue
		}
		// The per-key delivery events are emitted HERE, because this is where
		// delivery actually starts and stops now. They are emitted only for
		// cells a PENDING APPLY moved -- material the publisher supplied -- so
		// a schema fan-out, which moves no content, emits none, and copy/clone
		// keep emitting their own disclosure.value_copied instead.
		event := audit.EventValueSet
		if !apply.set {
			if _, err := r.Values().Clear(ctx, p, cells[i].key.ID); err != nil {
				return PublishedEnvironment{}, err
			}
			event = audit.EventValueCleared
		} else {
			id, err := putCell(ctx, r, p, sealer, scope, cells[i].key, publisher, cells[i].value, now)
			if err != nil {
				return PublishedEnvironment{}, err
			}
			cells[i].entryID = id
		}
		ev, err := domainEvent(ctx, event, publisher,
			audit.Object{Type: "key", ID: cells[i].key.ID}, audit.Payload{
				"key_id":         cells[i].key.ID,
				"name":           audit.SanitizeFreeText(cells[i].key.Name),
				"classification": cells[i].key.Classification,
			})
		if err != nil {
			return PublishedEnvironment{}, err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return PublishedEnvironment{}, err
		}
	}

	previous, changes, err := lineage(ctx, r, p, scope, cells)
	if err != nil {
		return PublishedEnvironment{}, err
	}

	revision := previous + 1
	snapshotID, err := newID("snp")
	if err != nil {
		return PublishedEnvironment{}, err
	}
	if err := r.Snapshots().Insert(ctx, p, store.NewSnapshot{
		ID: snapshotID, Revision: revision, SchemaRevision: schemaRevision,
		PublishedBy: string(publisher), PublishedAt: now,
	}); err != nil {
		return PublishedEnvironment{}, err
	}

	rows := make([]delivery.Row, 0, len(cells))
	for _, cell := range cells {
		if !cell.set {
			continue
		}
		entryID, err := newID("sne")
		if err != nil {
			return PublishedEnvironment{}, err
		}
		sealed, err := sealer.SealField(snapshotAAD(
			string(scope.Org), string(scope.Project), string(scope.Env), cell.key.ID, snapshotID, entryID), []byte(cell.value))
		if err != nil {
			return PublishedEnvironment{}, err
		}
		if err := r.Snapshots().InsertEntry(ctx, p, store.NewSnapshotEntry{
			ID: entryID, SnapshotID: snapshotID, KeyID: cell.key.ID,
			KeyName: cell.key.Name, Classification: cell.key.Classification,
			Ciphertext: sealed, ValueEntryID: cell.entryID,
		}); err != nil {
			return PublishedEnvironment{}, err
		}
		rows = append(rows, delivery.Row{
			Key: cell.key.Name, Classification: cell.key.Classification, Value: cell.value,
		})
	}

	for _, change := range changes {
		if err := r.Snapshots().InsertChange(ctx, p, revision,
			change.KeyID, change.Name, store.RevisionChange(change.Change)); err != nil {
			return PublishedEnvironment{}, err
		}
	}

	token, err := kr.ChangeToken(string(scope.Org), string(scope.Project), string(scope.Env),
		delivery.Manifest(rows))
	if err != nil {
		return PublishedEnvironment{}, err
	}
	return PublishedEnvironment{
		EnvironmentID: string(scope.Env), Revision: revision, ChangeToken: token,
		SchemaRevision: schemaRevision, ChangedKeys: changes,
	}, nil
}

// validateResolved is publish's authority, run on the RESOLVED values at the
// current schema revision regardless of any stored draft verdict.
func validateResolved(cells []resolvedCell, presence []store.KeyPresence, envID string) error {
	groups := map[string][]resolvedCell{}
	for _, cell := range cells {
		rules := presenceOfKey(cell.key, presence)
		switch {
		case rules.Required.Covers(envID) && !cell.set:
			// mvp-boundary C2, verbatim: a `required_in` key left `absent`
			// vetoes the publish, naming key AND environment.
			return invalidDetail("key %q is `required_in` environment %s and resolves to absent: publish is vetoed",
				cell.key.Name, envID)
		case rules.Forbidden.Covers(envID) && cell.set:
			return invalidDetail("key %q is `forbidden_in` environment %s and resolves to set: publish is vetoed",
				cell.key.Name, envID)
		}
		if cell.set {
			if err := validateValue(cell.key, cell.value); err != nil {
				return err
			}
		}
		if cell.key.GroupID != "" {
			groups[cell.key.GroupID] = append(groups[cell.key.GroupID], cell)
		}
	}
	// ALL-OR-NONE RESOLVED PRESENCE per environment, always on, no flag: in
	// each environment either every member of a group resolves to `set` or none
	// do. Co-publish closure closes the timing hole; this closes the state one.
	// The message names groups and key names only, never values.
	for groupID, members := range groups {
		set, absent := []string{}, []string{}
		for _, member := range members {
			if member.set {
				set = append(set, member.key.Name)
			} else {
				absent = append(absent, member.key.Name)
			}
		}
		if len(set) > 0 && len(absent) > 0 {
			slices.Sort(set)
			slices.Sort(absent)
			return invalidDetail("key group %s resolves partially in environment %s: set %v, absent %v: a group's presence is all-or-none",
				groupID, envID, set, absent)
		}
	}
	return nil
}

// lineage reads the previous snapshot and diffs it against the state about to
// be published, returning the previous revision number and the changed-key
// rows. The diff is over (key name, pinned value-entry id) -- METADATA, never
// plaintext. The pinned id moves on every real write (a cell is
// delete-then-insert), so a publish that wrote a cell records `edited` even
// when the bytes it wrote equal the bytes that were there: lineage is
// write-presence, and per the revision ADR write-presence must carry no
// information about the plaintext. A value diff here would hand any
// edit+publish holder a guessing oracle -- stage a guess, publish it, read
// "no lineage row" as `unchanged` -- which is exactly the oracle the ADR
// closes on the diff surface. A rename still records `edited`, and a schema
// publish that moves no content still produces no lineage rows at all: the
// new revision records that the validation guarantee moved, without claiming
// anything changed.
func lineage(ctx context.Context, r store.Repos, p authz.Proof,
	scope domain.Scope, cells []resolvedCell) (int64, []ChangedKey, error) {
	type materialized struct{ name, valueEntryID string }
	previousRevision := int64(0)
	before := map[string]materialized{}

	latest, err := r.Snapshots().Latest(ctx, p)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return 0, nil, err
	default:
		previousRevision = latest.Revision
		entries, err := r.Snapshots().Entries(ctx, p, latest.ID)
		if err != nil {
			return 0, nil, err
		}
		for _, entry := range entries {
			before[entry.KeyID] = materialized{name: entry.KeyName, valueEntryID: entry.ValueEntryID}
		}
	}

	var changes []ChangedKey
	seen := map[string]bool{}
	for _, cell := range cells {
		if !cell.set {
			continue
		}
		seen[cell.key.ID] = true
		prior, existed := before[cell.key.ID]
		switch {
		case !existed:
			changes = append(changes, ChangedKey{KeyID: cell.key.ID, Name: cell.key.Name, Change: string(store.RevisionChangeAdded)})
		case prior.name != cell.key.Name || prior.valueEntryID != cell.entryID:
			changes = append(changes, ChangedKey{KeyID: cell.key.ID, Name: cell.key.Name, Change: string(store.RevisionChangeEdited)})
		}
	}
	for keyID, prior := range before {
		if !seen[keyID] {
			changes = append(changes, ChangedKey{KeyID: keyID, Name: prior.name, Change: string(store.RevisionChangeRemoved)})
		}
	}
	slices.SortFunc(changes, func(a, b ChangedKey) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return previousRevision, changes, nil
}

// putCell seals one published value and writes it, returning the row id it
// minted -- which is the snapshot's pinned value-entry revision.
func putCell(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	scope domain.Scope, key store.CatalogueKey, principal domain.PrincipalID,
	value string, now time.Time) (string, error) {
	id, err := newID("val")
	if err != nil {
		return "", err
	}
	entry := store.ValueEntry{
		ID: id, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		EnvironmentID: string(scope.Env), KeyID: key.ID,
	}
	sealed, err := sealer.SealValue(valueAAD(entry), []byte(schema.Normalize(value)))
	if err != nil {
		return "", err
	}
	return id, r.Values().Put(ctx, p, store.NewValueEntry{
		ID: id, KeyID: key.ID, Ciphertext: sealed,
		UpdatedAt: store.CanonTime(now), UpdatedBy: string(principal),
	})
}

// snapshotAAD and pendingAAD bind a ciphertext to exactly one owner coordinate
// in one project. Environment and key prevent same-row metadata relocation;
// snapshot id additionally prevents moving an entry between snapshots.
func snapshotAAD(orgID, projectID, environmentID, keyID, snapshotID, rowID string) crypto.ProjectFieldAAD {
	return crypto.ProjectFieldAAD{
		OrgID: orgID, ProjectID: projectID,
		OwnerTable: snapshotTable, OwnerRowID: rowID, FieldTag: snapshotFieldTag,
		EnvironmentID: environmentID, KeyID: keyID, SnapshotID: snapshotID,
	}
}

func pendingAAD(orgID, projectID, environmentID, keyID, rowID string) crypto.ProjectFieldAAD {
	return crypto.ProjectFieldAAD{
		OrgID: orgID, ProjectID: projectID,
		OwnerTable: pendingTable, OwnerRowID: rowID, FieldTag: pendingFieldTag,
		EnvironmentID: environmentID, KeyID: keyID,
	}
}
