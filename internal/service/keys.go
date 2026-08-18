package service

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The key catalogue (#49, schema-model ADR as amended by the flat-model ADR).
//
// This file is the DECLARATION AUTHORITY's home: internal/schema owns what a
// well-formed rule is and what a value satisfying it looks like, and this
// layer owns everything that needs the database — uniqueness among live keys,
// the per-project cap, presence sets naming real environments, key-group
// conflicts across members, the schema revision, and the two reveal gates.
//
// The contract carries only SHAPE. Every rule below is enforced here because
// an internal caller — the isolation harness, a future import, a job — never
// passes through request validation, and a bound that exists only at the
// transport is a bound that exists only on paper.

// Key is the service layer's declared key. Declaration and Presence are the
// parsed forms: the store holds the canonical JSON, and exactly one place
// (this one) turns it back into rules, so there is no second interpreter to
// disagree with the first.
type Key struct {
	ID              string
	OrgID           string
	ProjectID       string
	Name            string
	FolderPath      string
	Classification  string
	Description     string
	Deprecated      bool
	DeprecationNote string
	Declaration     schema.Declaration
	Presence        schema.PresenceRules
	GroupID         string
	CreatedAt       time.Time
}

// KeySpec is a key creation. It carries no id (server-minted, immutable) and
// no schema revision (the project's, not the key's).
type KeySpec struct {
	Name            string
	FolderPath      string
	Classification  string
	Description     string
	Deprecated      bool
	DeprecationNote string
	Declaration     schema.Declaration
	Presence        schema.PresenceRules
	GroupID         string
}

// KeyMetadataUpdate is the NON-semantic update. It deliberately has no
// classification field and no rule field: the schema ADR exempts exactly these
// four from per-environment publish authorization because they cannot change
// what any environment delivers, and a fifth field here would silently widen
// that exemption.
//
// Every field is a POINTER because this is a PATCH: nil means "leave it
// alone", and the update is merged over the stored row inside the transaction.
// With plain values an absent `folder_path` would arrive as "" and silently
// move the key to the catalogue root — a caller who set only `--description`
// would lose the folder, the deprecation flag and the note in one request.
// That is the silent fallback this project refuses, and a PATCH whose contract
// declares its members optional is exactly where it hides.
type KeyMetadataUpdate struct {
	FolderPath      *string
	Description     *string
	Deprecated      *bool
	DeprecationNote *string
}

// KeyDeclarationUpdate is the semantic update: the value-dependent rules and
// the presence rules, replaced together.
type KeyDeclarationUpdate struct {
	Declaration schema.Declaration
	Presence    schema.PresenceRules
}

// KeyGroupView is a group with the two derived facts a reader needs: who is in
// it, and whether it is inert. A group left with fewer than two members
// couples nothing — the ADR calls that state inert and requires it flagged,
// rather than deleted behind the operator's back.
type KeyGroupView struct {
	ID        string
	OrgID     string
	ProjectID string
	Name      string
	Members   []string // key names, sorted
	Inert     bool
	CreatedAt time.Time
}

// Keys owns the key surface. Every method addresses PROJECT depth: a key is
// declared once per project, and the scope lattice has no key level.
type Keys struct {
	DB *store.DB
	// Keyring materializes the semantic schema fan-out's snapshots. Nil
	// refuses any semantic change in a project that has environments, which is
	// the fail-closed answer: a schema change that cannot materialize is a
	// schema change whose environments would keep delivering under a revision
	// they were never validated at.
	Keyring  *crypto.Keyring
	Advisory *Advisory
}

// KeyGroups owns the group surface, likewise at project depth.
type KeyGroups struct {
	DB       *store.DB
	Keyring  *crypto.Keyring
	Advisory *Advisory
}

type schemaPublisher struct {
	sealer   *crypto.ProjectSealer
	keyring  *crypto.Keyring
	advisory *Advisory
	advanced []PublishedEnvironment
}

// prepareSchemaPublish resolves the project sealer a semantic schema change
// needs to materialize with, BEFORE the transaction opens.
//
// The placement is not a style choice. Resolving a sealer MINTS the project
// data key on first use, and minting opens a write transaction of its own —
// which, on sqlite's single write connection, would wait forever on the
// transaction that asked for it. It is resolved after authorization for the
// reason #50 recorded: an unauthorized caller must not leave a wrapped-key row
// behind for an arbitrary (org, project).
func prepareSchemaPublish(ctx context.Context, db *store.DB, keyring *crypto.Keyring, advisory *Advisory,
	actor Actor, op authz.Operation, scope domain.Scope) (*schemaPublisher, error) {
	sealer, err := sealerFor(ctx, db, keyring, actor, op, scope)
	if err != nil {
		return nil, err
	}
	return &schemaPublisher{sealer: sealer, keyring: keyring, advisory: advisory}, nil
}

// fanOut is the single semantic-schema publish path: every environment gets a
// new pinned-schema revision, each publish authorization is re-evaluated in
// the transaction, and the committed results are retained for post-commit SSE.
func (p *schemaPublisher) fanOut(ctx context.Context, r store.Repos, az *authz.TxAuthorizer,
	caller authz.Identity, proof authz.Proof, scope domain.Scope, trigger string) error {
	advanced, err := fanOutSchemaPublish(ctx, r, az, caller, proof, p.sealer, p.keyring, scope,
		store.CanonTime(time.Now()), trigger)
	if err != nil {
		return err
	}
	p.advanced = advanced
	return nil
}

func (p *schemaPublisher) announce(scope domain.Scope) {
	p.advisory.published(scope, p.advanced)
}

// checkKeyFolderPath allows the empty path — a key at the catalogue root is
// the ordinary case — and otherwise applies the same namespace grammar
// folders take. Keys carry a folder PATH, not a folder id (domain model), so
// nothing here consults the folders table: a key may name a path no folder row
// exists for, and a folder rename does not move the keys that named its old
// path. That divergence is accepted in v1 and recorded in the handoff.
func checkKeyFolderPath(path string) error {
	if path == "" {
		return nil
	}
	return checkFolderPath(path)
}

// checkKeySpec is the declaration-shape authority for everything that does not
// need the database.
func checkKeySpec(spec KeySpec) error {
	if err := schema.CheckKeyName(spec.Name); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	if !schema.Classification(spec.Classification).Valid() {
		return fmt.Errorf("%w: classification must be `secret` or `config`", domain.ErrInvalid)
	}
	if err := checkKeyFolderPath(spec.FolderPath); err != nil {
		return err
	}
	if err := schema.CheckDescription("description", spec.Description); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	if err := schema.CheckDescription("deprecation note", spec.DeprecationNote); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	return nil
}

// checkDeclaration runs the two declaration authorities together: the rules
// must compile, and the presence rules must be well-formed and free of the
// statically decidable required∧forbidden conflict.
func checkDeclaration(d schema.Declaration, p schema.PresenceRules) error {
	if _, err := schema.Compile(d); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	if err := schema.CheckPresence(p.Required, p.Forbidden); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	return nil
}

// keyOf converts a store row plus its presence rows into the service key.
func keyOf(row store.CatalogueKey, presence []store.KeyPresence) (Key, error) {
	decl, err := schema.ParseDeclaration([]byte(row.Declaration))
	if err != nil {
		// A stored declaration that no longer parses is a defect in this
		// package or a hand-edited database, never a caller's problem — so it
		// is a loud error rather than a validation failure.
		return Key{}, fmt.Errorf("service: key %s: stored declaration unreadable: %w", row.ID, err)
	}
	return Key{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, FolderPath: row.FolderPath,
		Classification: row.Classification, Description: row.Description,
		Deprecated: row.Deprecated, DeprecationNote: row.DeprecationNote,
		Declaration: decl,
		Presence:    presenceOf(row.ID, row.RequiredMode, row.ForbiddenMode, presence),
		GroupID:     row.GroupID, CreatedAt: row.CreatedAt,
	}, nil
}

// presenceOf rebuilds one key's presence rules from the row's modes and the
// project's explicit rows. `all` and `none` carry no ids by construction, so
// only `explicit` reads the rows.
func presenceOf(keyID, requiredMode, forbiddenMode string, rows []store.KeyPresence) schema.PresenceRules {
	out := schema.PresenceRules{
		Required:  schema.Presence{Mode: schema.PresenceMode(requiredMode)},
		Forbidden: schema.Presence{Mode: schema.PresenceMode(forbiddenMode)},
	}
	for _, row := range rows {
		if row.KeyID != keyID {
			continue
		}
		switch {
		case row.Rule == store.PresenceRuleRequired && out.Required.Mode == schema.PresenceExplicit:
			out.Required.Environments = append(out.Required.Environments, row.EnvironmentID)
		case row.Rule == store.PresenceRuleForbidden && out.Forbidden.Mode == schema.PresenceExplicit:
			out.Forbidden.Environments = append(out.Forbidden.Environments, row.EnvironmentID)
		}
	}
	return out
}

// presenceRows renders the explicit halves for storage. Nothing is written for
// `all` or `none`: `all` must keep covering environments created later, so
// expanding it here would silently exempt them.
func presenceRows(p schema.PresenceRules) []store.KeyPresence {
	var out []store.KeyPresence
	if p.Required.Mode == schema.PresenceExplicit {
		for _, id := range p.Required.Environments {
			out = append(out, store.KeyPresence{EnvironmentID: id, Rule: store.PresenceRuleRequired})
		}
	}
	if p.Forbidden.Mode == schema.PresenceExplicit {
		for _, id := range p.Forbidden.Environments {
			out = append(out, store.KeyPresence{EnvironmentID: id, Rule: store.PresenceRuleForbidden})
		}
	}
	return out
}

// presenceEqual answers whether the presence rules moved. Order is not
// meaningful in an environment set, so both sides are compared sorted.
func presenceEqual(a, b schema.PresenceRules) bool {
	same := func(x, y schema.Presence) bool {
		if x.Mode != y.Mode {
			return false
		}
		xs := slices.Clone(x.Environments)
		ys := slices.Clone(y.Environments)
		slices.Sort(xs)
		slices.Sort(ys)
		return slices.Equal(xs, ys)
	}
	return same(a.Required, b.Required) && same(a.Forbidden, b.Forbidden)
}

// checkGroupPresence enforces the group's all-or-none presence STATICALLY:
// one member required where another is forbidden can never hold, so the pair
// is refused at declaration rather than discovered at publish. It runs on both
// a presence change and a membership change, because either side can create
// the pair.
//
// The closure algorithm and the runtime all-or-none evaluation are publish's
// (#51); this is only the half that is decidable without any value.
func checkGroupPresence(groupID, selfID string, self schema.PresenceRules, members []store.CatalogueKey, presence []store.KeyPresence) error {
	if groupID == "" {
		return nil
	}
	for _, member := range members {
		if member.ID == selfID || member.GroupID != groupID {
			continue
		}
		other := presenceOf(member.ID, member.RequiredMode, member.ForbiddenMode, presence)
		if err := schema.CheckGroupPresence(self, other); err != nil {
			// Rejection messages name groups and key names only, never values.
			return fmt.Errorf("%w: %s (with key %q)", domain.ErrInvalid, err, member.Name)
		}
	}
	return nil
}

// cascadeEnvironmentPresence removes a deleted environment's id from every
// explicit presence set, in the caller's transaction (schema-model ADR
// § Presence: environment lifecycle and presence rules are one serialized
// domain). It lives here rather than in the hierarchy service because it is
// catalogue content, and it does three things the FK alone does not:
//
//   - The foreign key protects referential integrity, nothing more. It would
//     refuse the delete; it would not decide what the surviving declaration
//     should say.
//   - An explicit set emptied by the cascade would leave `mode: explicit` with
//     ZERO environments — a state CheckPresence itself refuses, so the stored
//     declaration could not be round-tripped back through UpdateDeclaration.
//     The mode collapses to `none`, which is what "cascades its id out" means
//     once the last id is gone.
//   - The catalogue changed, so the CATALOGUE REVISION moves. Two distinct
//     catalogue states under one revision would break "one artifact to pin,
//     one to diff" and the byte-stable export built on it.
//
// It bumps only when it actually touched something: deleting an environment no
// key referenced is not a semantic schema change.
func cascadeEnvironmentPresence(ctx context.Context, r store.Repos, p authz.Proof, envID string) error {
	presence, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return err
	}
	touched := map[string]bool{}
	for _, row := range presence {
		if row.EnvironmentID == envID {
			touched[row.KeyID] = true
		}
	}
	if len(touched) == 0 {
		return nil
	}
	if err := r.Catalogue().DeletePresenceForEnvironment(ctx, p); err != nil {
		return err
	}
	// What survives per (key, rule) after the cascade.
	remaining := map[string]int{}
	for _, row := range presence {
		if row.EnvironmentID != envID {
			remaining[row.KeyID+":"+row.Rule]++
		}
	}
	keys, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if !touched[key.ID] {
			continue
		}
		declaration := store.KeyDeclaration{
			Declaration:   key.Declaration,
			RequiredMode:  emptiedMode(key.RequiredMode, remaining[key.ID+":"+store.PresenceRuleRequired]),
			ForbiddenMode: emptiedMode(key.ForbiddenMode, remaining[key.ID+":"+store.PresenceRuleForbidden]),
		}
		if declaration.RequiredMode == key.RequiredMode && declaration.ForbiddenMode == key.ForbiddenMode {
			continue
		}
		if err := r.Catalogue().UpdateDeclaration(ctx, p, key.ID, declaration); err != nil {
			return err
		}
	}
	return r.Catalogue().BumpSchemaRevision(ctx, p)
}

// emptiedMode collapses an `explicit` set the cascade emptied to `none`.
// `all` and `none` never carried ids, so they never move.
func emptiedMode(mode string, remaining int) string {
	if mode == string(schema.PresenceExplicit) && remaining == 0 {
		return string(schema.PresenceNone)
	}
	return mode
}

// ---------------------------------------------------------------------------
// Reveal-gate attempt limiting
// ---------------------------------------------------------------------------

// The schema ADR requires every reveal-gated attempt to be "audited and
// rate-limited, per key and per principal". Rate limiting is DEFENCE IN DEPTH,
// never the control — the control is that no predicate result reaches a
// non-revealer, which is the gate itself. This bounds how fast a holder of
// `definitions-edit` can hammer the gate for timing signal.
const (
	// GateAttemptsPerMinute is the sliding per-(principal, key) allowance for
	// reveal-gated acts. A human tightening a rule does it once; twenty a
	// minute is already automation. Concrete value is this slice's; the ops
	// spec owns it (disposition item).
	GateAttemptsPerMinute = 20
	// maxTrackedGateSubjects bounds the bucket map. Its keys are AUTHENTICATED
	// principals paired with server-minted key ids, so it is not the
	// attacker-chosen key space admission's per-IP map is — but an unbounded
	// map is still an unbounded map.
	maxTrackedGateSubjects = 4096
)

// gateAttempts is the sliding-window bucket, in memory and process-local for
// the same reason internal/admission is: v1's deployment envelope is a single
// node, and a durable throttle table would add a write per refused attempt —
// amplifying the flood it bounds. A multi-node build must replace it.
type gateAttempts struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

var gateLimiter = &gateAttempts{hits: map[string][]time.Time{}}

// allow charges one attempt. The key is length-prefixed, not concatenated:
// (principal "ab", key "c") and (principal "a", key "bc") must not collide.
//
// The map is HARD bounded. When it is full and every entry is still live, a new
// subject is REFUSED rather than admitted: an unbounded map is the
// memory-exhaustion vector the limiter exists to prevent, and availability
// loses to a bound under the threat model. The refusal is only ever visible to
// a caller who has already passed the gate (see revealGate), so it discloses
// nothing.
func (g *gateAttempts) allow(principal domain.PrincipalID, keyID string, now time.Time) bool {
	subject := strconv.Itoa(len(principal)) + ":" + string(principal) + ":" + keyID
	cutoff := now.Add(-time.Minute)
	g.mu.Lock()
	defer g.mu.Unlock()
	kept := g.hits[subject][:0]
	for _, t := range g.hits[subject] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= GateAttemptsPerMinute {
		g.hits[subject] = kept
		return false
	}
	if len(kept) == 0 && len(g.hits) >= maxTrackedGateSubjects {
		for other, times := range g.hits {
			if len(times) == 0 || !times[len(times)-1].After(cutoff) {
				delete(g.hits, other)
			}
		}
		if len(g.hits) >= maxTrackedGateSubjects {
			return false
		}
	}
	g.hits[subject] = append(kept, now)
	return true
}

// revealGate is the one door to both reveal-gated acts.
//
// THE ORDER HERE IS THE SECURITY PROPERTY, and it is not the obvious one.
// Authorization runs FIRST and its refusal is returned unchanged, so a caller
// without `reveal` sees the uniform nonexistent outcome on the first attempt
// and on the thousandth — identical sentinel, identical bytes. Charging the
// limiter first made the response vary with attempt count, which is an
// existence-and-classification oracle: only a `secret` key that EXISTS ever
// reaches this function, so "the answer changed at attempt 21" answered exactly
// the question the gate refuses. Only a caller who has already PASSED the gate
// — who therefore holds `reveal` — can observe the limit.
//
// Every attempt is recorded through the settlement path, which survives the
// rollback the denied and limited outcomes cause.
func revealGate(ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity,
	scope domain.Scope, op authz.Operation, key store.CatalogueKey, gate string) error {
	// Per-key granularity for the REFUSED attempt: the grant.denied payload is
	// a closed schema shared by every operation and must not grow a key field,
	// while the envelope's object is exactly where an acted-on object belongs.
	az.AttributeDenials(audit.Object{Type: "key", ID: key.ID})
	_, authErr := az.Authorize(ctx, caller, op, scope)
	// Charged whatever the outcome — a denied burst is what it exists to bound
	// — but it never changes what a denied caller is told.
	within := gateLimiter.allow(caller.Principal, key.ID, time.Now())

	outcome := audit.OutcomeDenied
	switch {
	case authErr == nil && within:
		outcome = audit.OutcomeSuccess
	case authErr == nil:
		outcome = audit.OutcomeFailure
	}
	ev, err := newAuditEvent(ctx, audit.EventKeyRevealGateAttempt, caller.Principal,
		audit.Object{Type: "key", ID: key.ID}, outcome, "", audit.Payload{
			"key_id": key.ID,
			"name":   audit.SanitizeFreeText(key.Name),
			"gate":   gate,
		})
	if err != nil {
		return err
	}
	az.CaptureAudit(audit.TrailTenant, domain.Scope{Org: scope.Org, Project: scope.Project}, ev)

	if authErr != nil {
		return authErr
	}
	if !within {
		return fmt.Errorf("%w: a principal attempts at most %d reveal-gated changes per key per minute",
			domain.ErrLimitExceeded, GateAttemptsPerMinute)
	}
	return nil
}

// Create declares a key. Typing a key name that does not exist is a key
// CREATION — an explicit act, never a silent value write (ADR § Closed schema):
// that is the whole reason a typo'd `DATBASE_URL` is answerable at all.
func (s *Keys) Create(ctx context.Context, actor Actor, scope domain.Scope, spec KeySpec) (Key, error) {
	if err := checkKeySpec(spec); err != nil {
		return Key{}, err
	}
	if err := checkDeclaration(spec.Declaration, spec.Presence); err != nil {
		return Key{}, err
	}
	canonical, err := schema.Canonical(spec.Declaration)
	if err != nil {
		return Key{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	// The response echoes the STORED form, never the caller's input. What is
	// written is the canonical declaration — members trimmed, schemes lowered,
	// the JSON Schema re-encoded — so echoing the request would hand back a
	// declaration that differs from the one a later read returns, byte for
	// byte, on exactly the values the canonicalization exists to normalize.
	stored, err := schema.ParseDeclaration(canonical)
	if err != nil {
		return Key{}, fmt.Errorf("service: canonical declaration unreadable: %w", err)
	}
	id, err := newID("key")
	if err != nil {
		return Key{}, err
	}
	row := store.NewCatalogueKey{
		ID: id, Name: spec.Name, FolderPath: spec.FolderPath,
		Classification: spec.Classification, Description: spec.Description,
		Deprecated: spec.Deprecated, DeprecationNote: spec.DeprecationNote,
		Declaration:   string(canonical),
		RequiredMode:  string(spec.Presence.Required.Mode),
		ForbiddenMode: string(spec.Presence.Forbidden.Mode),
		GroupID:       spec.GroupID,
		CreatedAt:     store.CanonTime(time.Now()),
	}
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyCreate, scope)
	if err != nil {
		return Key{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyCreate, scope)
		if err != nil {
			return err
		}
		// One serialization domain per project: the cap check is
		// read-then-write, and the presence rows reference environments another
		// transaction may be deleting.
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		n, err := r.Catalogue().Count(ctx, p)
		if err != nil {
			return err
		}
		if n >= schema.MaxKeysPerProject {
			return fmt.Errorf("%w: a project declares at most %d keys",
				domain.ErrLimitExceeded, schema.MaxKeysPerProject)
		}
		if err := checkGroupMembership(ctx, r, p, spec.GroupID, id, spec.Presence); err != nil {
			return err
		}
		// Name uniqueness among LIVE keys is the table's constraint, not a
		// read-then-write here: a pre-check would be a race, and the UNIQUE
		// index is the only answer that cannot be interleaved past.
		if err := r.Catalogue().Create(ctx, p, row); err != nil {
			return err
		}
		if err := r.Catalogue().ReplacePresence(ctx, p, id, presenceRows(spec.Presence)); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyCreated, caller.Principal,
			audit.Object{Type: "key", ID: id}, audit.Payload{
				"name":           audit.SanitizeFreeText(spec.Name),
				"classification": spec.Classification,
				"namespace":      audit.SanitizeFreeText(spec.FolderPath),
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-create")
	})
	if err != nil {
		return Key{}, err
	}
	publisher.announce(scope)
	return Key{
		ID: id, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		Name: spec.Name, FolderPath: spec.FolderPath,
		Classification: spec.Classification, Description: spec.Description,
		Deprecated: spec.Deprecated, DeprecationNote: spec.DeprecationNote,
		Declaration: stored, Presence: spec.Presence,
		GroupID: spec.GroupID, CreatedAt: row.CreatedAt,
	}, nil
}

// checkGroupMembership resolves the named group and runs the static
// all-or-none check against its other members. An unknown group id is the
// uniform nonexistent outcome, because a group id from another project is
// exactly as unreachable as one that does not exist.
func checkGroupMembership(ctx context.Context, r store.Repos, p authz.Proof, groupID, selfID string, presence schema.PresenceRules) error {
	if groupID == "" {
		return nil
	}
	if _, err := r.Catalogue().GetGroup(ctx, p, groupID); err != nil {
		return err
	}
	members, err := r.Catalogue().List(ctx, p)
	if err != nil {
		return err
	}
	rows, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return err
	}
	return checkGroupPresence(groupID, selfID, presence, members, rows)
}

// Get reads one key with its presence rules.
func (s *Keys) Get(ctx context.Context, actor Actor, scope domain.Scope, id string) (Key, error) {
	var out Key
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGet, scope)
		if err != nil {
			return err
		}
		row, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		rows, err := r.Catalogue().ListPresence(ctx, p)
		if err != nil {
			return err
		}
		out, err = keyOf(row, rows)
		return err
	})
	return out, err
}

// List returns the project's key catalogue and the revision it is at. The
// revision rides along because it is the thing #50 and #51 pin, so a reader
// that acted on this list can say which schema it saw.
func (s *Keys) List(ctx context.Context, actor Actor, scope domain.Scope) ([]Key, int64, error) {
	var out []Key
	var revision int64
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyList, scope)
		if err != nil {
			return err
		}
		rows, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		presence, err := r.Catalogue().ListPresence(ctx, p)
		if err != nil {
			return err
		}
		revision, err = r.Catalogue().SchemaRevision(ctx, p)
		if err != nil {
			return err
		}
		out = make([]Key, 0, len(rows))
		for _, row := range rows {
			key, err := keyOf(row, presence)
			if err != nil {
				return err
			}
			out = append(out, key)
		}
		return nil
	})
	return out, revision, err
}

// Rename changes the key's mutable label. It IS a content-affecting schema
// change — the delivered payload's key set moves — so it advances the schema
// revision, unlike the hierarchy renames, which move a label nothing is
// delivered under.
func (s *Keys) Rename(ctx context.Context, actor Actor, scope domain.Scope, id, name string) (Key, error) {
	if err := schema.CheckKeyName(name); err != nil {
		return Key{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	var out Key
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyRename, scope)
	if err != nil {
		return Key{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyRename, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		if err := refuseAdapterPinnedKey(ctx, r.Catalogue(), p, before); err != nil {
			return err
		}
		if err := r.Catalogue().Rename(ctx, p, id, name); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		after := before
		after.Name = name
		if out, err = readKey(ctx, r, p, after); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyRenamed, caller.Principal,
			audit.Object{Type: "key", ID: before.ID}, audit.Payload{
				"previous_name": audit.SanitizeFreeText(before.Name),
				"name":          audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-rename")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return out, err
}

// UpdateMetadata writes the non-semantic fields. No reveal gate and no
// revision bump: these cannot change what any environment delivers or whether
// it validates, so there is nothing to re-materialize and nothing to disclose.
func (s *Keys) UpdateMetadata(ctx context.Context, actor Actor, scope domain.Scope, id string, m KeyMetadataUpdate) (Key, error) {
	if m.FolderPath != nil {
		if err := checkKeyFolderPath(*m.FolderPath); err != nil {
			return Key{}, err
		}
	}
	if m.Description != nil {
		if err := schema.CheckDescription("description", *m.Description); err != nil {
			return Key{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
	}
	if m.DeprecationNote != nil {
		if err := schema.CheckDescription("deprecation note", *m.DeprecationNote); err != nil {
			return Key{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
	}
	var out Key
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyUpdateMetadata, scope)
		if err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		// Merge over the stored row: an absent member leaves its column alone.
		merged := store.KeyMetadata{
			FolderPath:      pick(m.FolderPath, before.FolderPath),
			Description:     pick(m.Description, before.Description),
			Deprecated:      pickBool(m.Deprecated, before.Deprecated),
			DeprecationNote: pick(m.DeprecationNote, before.DeprecationNote),
		}
		if err := r.Catalogue().UpdateMetadata(ctx, p, id, merged); err != nil {
			return err
		}
		after := before
		after.FolderPath = merged.FolderPath
		after.Description = merged.Description
		after.Deprecated = merged.Deprecated
		after.DeprecationNote = merged.DeprecationNote
		if out, err = readKey(ctx, r, p, after); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyMetadataChanged, caller.Principal,
			audit.Object{Type: "key", ID: before.ID}, audit.Payload{
				"name":      audit.SanitizeFreeText(before.Name),
				"namespace": audit.SanitizeFreeText(merged.FolderPath),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

func refuseAdapterPinnedKey(ctx context.Context, catalogue store.CatalogueRepo, p authz.Proof, key store.CatalogueKey) error {
	pins, err := catalogue.AdapterPins(ctx, p, key.ID)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		return nil
	}
	parts := make([]string, 0, len(pins))
	for _, pin := range pins {
		parts = append(parts, "adapter "+pin.AdapterID+" target "+pin.TargetID)
	}
	return fmt.Errorf("%w: key %s is pinned by %s; remove it from those targets, make this edit, then re-add it through the adapter widening ceremony", domain.ErrConflict, key.Name, strings.Join(parts, ", "))
}

// pick and pickBool are the PATCH merge: an absent member keeps the stored
// value. They exist so the merge reads as one rule rather than four ifs.
func pick(update *string, stored string) string {
	if update == nil {
		return stored
	}
	return *update
}

func pickBool(update *bool, stored bool) bool {
	if update == nil {
		return stored
	}
	return *update
}

// readKey composes the response INSIDE the mutating transaction, from the row
// the mutation produced plus the project's presence rows.
//
// It exists because the obvious alternative — mutate, commit, then call Get —
// authorizes `read@project` in a SECOND transaction. The permission model has
// no prerequisite chaining between capabilities, so `definitions-edit` without
// `read` is a legal, supported state: such a principal would see their write
// COMMIT and then be told the key does not exist. It is also a cross-
// transaction window through which another writer's state could leak into
// "your" response.
func readKey(ctx context.Context, r store.Repos, p authz.Proof, row store.CatalogueKey) (Key, error) {
	presence, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return Key{}, err
	}
	return keyOf(row, presence)
}

// UpdateDeclaration replaces the value-dependent rules and the presence rules.
//
// THE ORDER IN THIS METHOD IS THE SECURITY PROPERTY. The schema ADR's
// load-bearing rule: changing a value-dependent rule on a `secret` key is a
// disclosure, because the result bit itself is the leak — a principal holding
// definitions-edit but not `reveal` can set `pattern: "^A"`, watch the publish
// abort, and bisect the plaintext one predicate at a time. So the gate runs
// BEFORE the new declaration is compiled or evaluated in any way: the
// operation is rejected without evaluating, because timing and abort/success
// are themselves the channel.
//
// The gate is unconditional on whether any value exists. Conditioning it on
// stored values would add a query and a time-of-check/time-of-use window for
// no gain — and this slice has no value rows at all, so a conditional gate
// would be dead until #50 and then wrong.
func (s *Keys) UpdateDeclaration(ctx context.Context, actor Actor, scope domain.Scope, id string, u KeyDeclarationUpdate) (Key, error) {
	var out Key
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyUpdateDeclaration, scope)
	if err != nil {
		return Key{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyUpdateDeclaration, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		beforeDecl, err := schema.ParseDeclaration([]byte(before.Declaration))
		if err != nil {
			return fmt.Errorf("service: key %s: stored declaration unreadable: %w", id, err)
		}
		// Canonical-byte comparison, so a constraint field added later cannot
		// escape the gate by being forgotten in a field list. An unrenderable
		// declaration counts as a change: fail-closed is the only safe default
		// for a gate.
		rulesChanged := schema.ValueDependentChange(beforeDecl, u.Declaration)

		if rulesChanged && before.Classification == string(schema.Secret) {
			if err := revealGate(ctx, az, caller, scope,
				authz.OpKeySecretRuleChange, before, "value-dependent-rule-change"); err != nil {
				return err
			}
		}

		// Only now is the new declaration examined at all.
		if err := checkDeclaration(u.Declaration, u.Presence); err != nil {
			return err
		}
		canonical, err := schema.Canonical(u.Declaration)
		if err != nil {
			return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
		presence, err := r.Catalogue().ListPresence(ctx, p)
		if err != nil {
			return err
		}
		beforePresence := presenceOf(id, before.RequiredMode, before.ForbiddenMode, presence)
		presenceChanged := !presenceEqual(beforePresence, u.Presence)

		members, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		if err := checkGroupPresence(before.GroupID, id, u.Presence, members, presence); err != nil {
			return err
		}
		// Re-saving a canonically identical declaration writes NOTHING: it is a
		// no-op, and a no-op that touched rows would rewrite the presence set
		// and advance the revision — invalidating every pin for nothing.
		if !rulesChanged && !presenceChanged {
			out, err = keyOf(before, presence)
			return err
		}
		if err := r.Catalogue().UpdateDeclaration(ctx, p, id, store.KeyDeclaration{
			Declaration:   string(canonical),
			RequiredMode:  string(u.Presence.Required.Mode),
			ForbiddenMode: string(u.Presence.Forbidden.Mode),
		}); err != nil {
			return err
		}
		// A foreign or deleted environment id lands here as a foreign-key
		// violation, which surfaces as the uniform conflict — the same answer
		// whether the environment belongs to another project or to none.
		if err := r.Catalogue().ReplacePresence(ctx, p, id, presenceRows(u.Presence)); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		after := before
		after.Declaration = string(canonical)
		after.RequiredMode = string(u.Presence.Required.Mode)
		after.ForbiddenMode = string(u.Presence.Forbidden.Mode)
		if out, err = keyOf(after, presenceRowsFor(id, u.Presence)); err != nil {
			return err
		}
		revision, err := r.Catalogue().SchemaRevision(ctx, p)
		if err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyDeclarationChanged, caller.Principal,
			audit.Object{Type: "key", ID: before.ID}, audit.Payload{
				"name":             audit.SanitizeFreeText(before.Name),
				"schema_revision":  revision,
				"rules_changed":    rulesChanged,
				"presence_changed": presenceChanged,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-declaration")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return out, err
}

// presenceRowsFor renders one key's explicit sets as store rows keyed to it,
// so a response can be composed from the rules just written without a re-read
// of a table this transaction is the sole writer of.
func presenceRowsFor(keyID string, p schema.PresenceRules) []store.KeyPresence {
	rows := presenceRows(p)
	for i := range rows {
		rows[i].KeyID = keyID
	}
	return rows
}

// Reclassify is the reclassification CEREMONY (mvp-boundary C1). It is a
// distinct operation and the only path that writes the classification column:
// an ordinary update carries no classification field, so there is no way to
// change one without meeting the gates and the audit below.
//
// Declassification (`secret` → `config`) requires current `reveal`, because
// after it the value is readable under ordinary environment read — you must be
// able to see a secret in order to stop it being one. Tightening
// (`config` → `secret`) does not, and cannot un-disclose what was already
// served as config; the advisory belongs to the UI (#56+).
func (s *Keys) Reclassify(ctx context.Context, actor Actor, scope domain.Scope, id, classification string) (Key, error) {
	if !schema.Classification(classification).Valid() {
		return Key{}, fmt.Errorf("%w: classification must be `secret` or `config`", domain.ErrInvalid)
	}
	var out Key
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyReclassify, scope)
	if err != nil {
		return Key{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyReclassify, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		if err := refuseAdapterPinnedKey(ctx, r.Catalogue(), p, before); err != nil {
			return err
		}
		if before.Classification == classification {
			// A ceremony that changes nothing is a mistake, not a no-op: it
			// would write a disclosure-class audit record for an act that never
			// happened.
			return fmt.Errorf("%w: the key is already classified %q", domain.ErrInvalid, classification)
		}
		if classification == string(schema.Config) {
			// The ATTEMPT record rides the rollback-surviving settlement path;
			// the before-commit disclosure record the ADR requires is
			// settings.key_reclassified below, written inside this transaction
			// ahead of the classification write.
			if err := revealGate(ctx, az, caller, scope,
				authz.OpKeyDeclassify, before, "declassification"); err != nil {
				return err
			}
		}
		if err := r.Catalogue().SetClassification(ctx, p, id, classification); err != nil {
			return err
		}
		// Classification moves what is delivered and, where an adapter routes
		// by it, where — so it is a semantic schema change and advances the
		// revision like any other.
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		after := before
		after.Classification = classification
		if out, err = readKey(ctx, r, p, after); err != nil {
			return err
		}
		// Recorded under the stricter of the pre- and post-change
		// classification: the payload names both and carries no value or
		// instance-derived text at all, so neither direction lands under the
		// laxer regime.
		ev, err := domainEvent(ctx, audit.EventKeyReclassified, caller.Principal,
			audit.Object{Type: "key", ID: before.ID}, audit.Payload{
				"name":                    audit.SanitizeFreeText(before.Name),
				"previous_classification": before.Classification,
				"classification":          classification,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-reclassify")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return out, err
}

// SetGroup moves a key into a group, or out of every group when groupID is "".
// A key belongs to at most one group, so this is a set rather than an append —
// multi-membership would make co-publish closure transitive across groups, and
// selecting one pending change could then drag in a chain the publisher never
// previewed.
func (s *Keys) SetGroup(ctx context.Context, actor Actor, scope domain.Scope, id, groupID string) (Key, error) {
	var out Key
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeySetGroup, scope)
	if err != nil {
		return Key{}, err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeySetGroup, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		presence, err := r.Catalogue().ListPresence(ctx, p)
		if err != nil {
			return err
		}
		// Setting the membership a key already has is an IDEMPOTENT SUCCESS,
		// not a refusal: it writes nothing, moves no revision and emits no
		// event, exactly as re-saving an identical declaration does. The one
		// operation that refuses its no-op is the reclassification ceremony,
		// and only because a ceremony that changed nothing would still write a
		// disclosure-class audit record.
		if before.GroupID == groupID {
			out, err = keyOf(before, presence)
			return err
		}
		self := presenceOf(id, before.RequiredMode, before.ForbiddenMode, presence)
		if err := checkGroupMembership(ctx, r, p, groupID, id, self); err != nil {
			return err
		}
		if err := r.Catalogue().SetGroup(ctx, p, id, groupID); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		after := before
		after.GroupID = groupID
		if out, err = keyOf(after, presence); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyGroupMembershipChanged, caller.Principal,
			audit.Object{Type: "key", ID: before.ID}, audit.Payload{
				"name":              audit.SanitizeFreeText(before.Name),
				"previous_group_id": before.GroupID,
				"group_id":          groupID,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-group-membership")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return out, err
}

// Delete removes a key from the catalogue. Its explicit presence rows go with
// it and it drops out of its group; the group itself survives, possibly inert.
func (s *Keys) Delete(ctx context.Context, actor Actor, scope domain.Scope, id string) error {
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyDelete, scope)
	if err != nil {
		return err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyDelete, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().Get(ctx, p, id)
		if err != nil {
			return err
		}
		// A key any environment still holds a value for is REFUSED, naming
		// those environments (#50). Deleting the declaration would destroy
		// delivered material in every one of them, and the authority for that
		// is per-affected-environment `publish` — which is the publish
		// pipeline's to evaluate (#51), not this operation's to assume. The
		// operator clears the values first, which is an act they can already
		// authorize per environment.
		envs, err := r.Values().EnvironmentsWithValue(ctx, p, id)
		if err != nil {
			return err
		}
		if len(envs) > 0 {
			return fmt.Errorf("%w: key %q still holds values in environment(s) %s — clear them first",
				domain.ErrConflict, before.Name, strings.Join(envs, ", "))
		}
		// The presence rows reference this key, so they go first: the composite
		// foreign key would otherwise refuse the delete, which is the correct
		// refusal for an unhandled case and the wrong one for a handled one.
		if err := r.Catalogue().ReplacePresence(ctx, p, id, nil); err != nil {
			return err
		}
		// Deleting a key INVALIDATES every pending change referencing it
		// (schema ADR § Key identity). Without this, Alice's staged edit to K
		// stays publishable after Bob deletes K, and the publish resurrects a
		// key the schema no longer declares. The rows are collected here and a
		// publish naming one of those version ids is refused loudly by name.
		if _, err := r.Pending().DiscardKey(ctx, p, id); err != nil {
			return err
		}
		if err := r.Catalogue().Delete(ctx, p, id); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyDeleted, caller.Principal,
			audit.Object{Type: "key", ID: before.ID},
			audit.Payload{"name": audit.SanitizeFreeText(before.Name)})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-delete")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return err
}

// ---------------------------------------------------------------------------
// Key groups
// ---------------------------------------------------------------------------

// Create declares a key group. Groups exist as vocabulary here; the co-publish
// closure and the all-or-none presence evaluation that give them teeth are
// publish-time (#51).
func (s *KeyGroups) Create(ctx context.Context, actor Actor, scope domain.Scope, name string) (KeyGroupView, error) {
	if err := schema.CheckGroupName(name); err != nil {
		return KeyGroupView{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	id, err := newID("kgr")
	if err != nil {
		return KeyGroupView{}, err
	}
	created := store.CanonTime(time.Now())
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGroupCreate, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		n, err := r.Catalogue().CountGroups(ctx, p)
		if err != nil {
			return err
		}
		if n >= schema.MaxKeyGroupsPerProject {
			return fmt.Errorf("%w: a project declares at most %d key groups",
				domain.ErrLimitExceeded, schema.MaxKeyGroupsPerProject)
		}
		if err := r.Catalogue().CreateGroup(ctx, p, store.NewCatalogueGroup{
			ID: id, Name: name, CreatedAt: created,
		}); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyGroupCreated, caller.Principal,
			audit.Object{Type: "key_group", ID: id},
			audit.Payload{"name": audit.SanitizeFreeText(name)})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return KeyGroupView{}, err
	}
	return KeyGroupView{
		ID: id, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		Name: name, Inert: true, CreatedAt: created,
	}, nil
}

func (s *KeyGroups) Get(ctx context.Context, actor Actor, scope domain.Scope, id string) (KeyGroupView, error) {
	var out KeyGroupView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGroupGet, scope)
		if err != nil {
			return err
		}
		group, err := r.Catalogue().GetGroup(ctx, p, id)
		if err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		out = groupView(group, keys)
		return nil
	})
	return out, err
}

func (s *KeyGroups) List(ctx context.Context, actor Actor, scope domain.Scope) ([]KeyGroupView, error) {
	var out []KeyGroupView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGroupList, scope)
		if err != nil {
			return err
		}
		groups, err := r.Catalogue().ListGroups(ctx, p)
		if err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		out = make([]KeyGroupView, 0, len(groups))
		for _, group := range groups {
			out = append(out, groupView(group, keys))
		}
		return nil
	})
	return out, err
}

// groupView derives the membership and the inert flag. A group with fewer than
// two members couples nothing; the ADR requires that surfaced rather than
// silently repaired, because the operator is mid-way through building it.
func groupView(group store.CatalogueGroup, keys []store.CatalogueKey) KeyGroupView {
	var members []string
	for _, key := range keys {
		if key.GroupID == group.ID {
			members = append(members, key.Name)
		}
	}
	slices.Sort(members)
	return KeyGroupView{
		ID: group.ID, OrgID: group.OrgID, ProjectID: group.ProjectID,
		Name: group.Name, Members: members, Inert: len(members) < 2,
		CreatedAt: group.CreatedAt,
	}
}

// Rename changes a group's label. A group name is never delivered and never
// validated against, so — unlike a KEY rename — it moves no revision.
func (s *KeyGroups) Rename(ctx context.Context, actor Actor, scope domain.Scope, id, name string) (KeyGroupView, error) {
	if err := schema.CheckGroupName(name); err != nil {
		return KeyGroupView{}, fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	var out KeyGroupView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGroupRename, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().GetGroup(ctx, p, id)
		if err != nil {
			return err
		}
		if err := r.Catalogue().RenameGroup(ctx, p, id, name); err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		after := before
		after.Name = name
		out = groupView(after, keys)
		ev, err := domainEvent(ctx, audit.EventKeyGroupRenamed, caller.Principal,
			audit.Object{Type: "key_group", ID: before.ID}, audit.Payload{
				"previous_name": audit.SanitizeFreeText(before.Name),
				"name":          audit.SanitizeFreeText(name),
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	return out, err
}

// Delete dissolves a group and releases its members. It never deletes the keys
// it coupled: a group is a coupling, and removing a coupling is not removing
// what it coupled.
func (s *KeyGroups) Delete(ctx context.Context, actor Actor, scope domain.Scope, id string) error {
	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, actor, authz.OpKeyGroupDelete, scope)
	if err != nil {
		return err
	}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpKeyGroupDelete, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		before, err := r.Catalogue().GetGroup(ctx, p, id)
		if err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		released := 0
		for _, key := range keys {
			if key.GroupID == id {
				released++
			}
		}
		if err := r.Catalogue().ClearGroupMembers(ctx, p, id); err != nil {
			return err
		}
		if err := r.Catalogue().DeleteGroup(ctx, p, id); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventKeyGroupDeleted, caller.Principal,
			audit.Object{Type: "key_group", ID: before.ID}, audit.Payload{
				"name":             audit.SanitizeFreeText(before.Name),
				"members_released": released,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		return publisher.fanOut(ctx, r, az, caller, p, scope, "key-group-delete")
	})
	if err == nil {
		publisher.announce(scope)
	}
	return err
}

// ErrClassificationInUpdate is the ordinary-update refusal (mvp-boundary C1:
// "classification changes only via the reclassification ceremony"), returned
// by the transport when an ordinary key update carries a classification field
// at all — equal to the current value or not. Refusing the FIELD rather than
// the CHANGE keeps the refusal free of a read, and keeps a caller from
// discovering the current classification by probing which values are accepted.
var ErrClassificationInUpdate = fmt.Errorf(
	"%w: classification changes only through the reclassification ceremony, never an ordinary update",
	domain.ErrInvalid)
