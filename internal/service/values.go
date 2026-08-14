package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The flat value model (#50, flat-model ADR + encryption ADR + the locked
// permission-model formula table).
//
// A Value attaches to a `(key, environment)`. There are no other layers, so
// RESOLUTION IS A LOOKUP: a key in an environment is that environment's `set`
// entry, or it is unresolved. Nothing is inherited, nothing defaults, and
// there is no third presence state — `masked` was deleted with the graph it
// existed to explain, and it has no representation in this file, the store,
// the API or the CLI.
//
// The ergonomics inheritance used to provide are three EXPLICIT operations,
// each independent and each producing values with no ongoing relationship to
// their source:
//
//   - Declare-into-environments (Declare) — the caller SUPPLIES one plaintext
//     and it lands in several environments at once.
//   - Copy-to / bulk-apply (Copy) — the server duplicates STORED material into
//     chosen destinations. One key or many, one destination or many; the ADR's
//     "copy-to" and "bulk apply" are the same operation over different sized
//     inputs, so they are one method.
//   - Clone-at-creation (Environments.Clone) — the same duplication, with the
//     destination being an environment that does not exist yet.
//
// The difference that MATTERS is not how many cells move: it is whether the
// actor supplied the plaintext. Supplied material needs no `reveal` (they
// already have it — they typed it). Server-side duplication is "authorized
// duplication, never supply" and carries the locked formula in full:
// `reveal(source)` ∧ `reveal(destination)` ∧ `publish(destination)`.

// valueFieldTag is the AAD's field tag for the value column. One column, one
// tag; a second sealed column on this row would take its own.
const valueFieldTag = "value"

// The copy-operation labels for the audit trail: which ergonomic operation a
// duplication was. The three share one authorization story and must still be
// distinguishable in the record. They are plain strings — the audit payload's
// `operation` field is an open string, so a named type would buy only a
// conversion at every use.
const (
	copyOpCopy      = "copy"
	copyOpBulkApply = "bulk-apply"
	copyOpClone     = "clone"
)

// Values owns the value surface. Every method addresses an environment or the
// project that holds several of them.
//
// The Keyring is here rather than in the store because the store never sees
// plaintext: this layer seals before writing and opens after reading, and the
// AAD it builds names exactly the row the ciphertext is allowed to live on.
type Values struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// Advisory receives the metadata-only staging events, AFTER commit. Nil
	// disables the channel; correctness never depends on delivery.
	Advisory *Advisory
	// Auth supplies the reveal guard (#58): every route in the formula table
	// that carries a `reveal` conjunct consumes this session's reauthentication
	// window over the environment it discloses in, for exactly the keys it
	// discloses. Nil is a wiring fault and refuses every disclosure loudly
	// (ErrNoCeremonySeam) rather than disclosing without a ceremony.
	Auth *Auth
}

// ValueCell is one `(key, environment)` cell as reported to a reader.
//
// Presence is the single boolean `Set`. That is the whole presence model —
// there is no mode, no enum with a third member, and no "masked" anything. A
// cell that is not `Set` carries no value from any source, which is what "no
// fallback source exists" means once inheritance is gone.
//
// Value carries plaintext ONLY where the reader was authorized to see it:
// `config` under `read`, `secret` under `read ∧ reveal`. Revealed says which
// happened, so a caller can tell "" (an empty value the operator set) from ""
// (a secret they may not read) without guessing.
type ValueCell struct {
	KeyID          string
	Name           string
	Classification string
	Set            bool
	Value          string
	Revealed       bool
	UpdatedAt      time.Time
	UpdatedBy      string
}

// DiffRow is one key's two-sided comparison. Same disclosure rules as
// ValueCell, applied per side: without the reveal gate a `secret` row reports
// write-presence only, and Equal is left unanswered — whether two secrets match
// is itself material a non-revealer may not have.
type DiffRow struct {
	KeyID          string
	Name           string
	Classification string
	Left           ValueCell
	Right          ValueCell
	// Equal is nil where the comparison could not be made without disclosing
	// something the caller may not see.
	Equal *bool
}

// CopyRequest is one copy-to / bulk-apply. Keys and destinations are both
// explicit: "copy everything" is what clone-at-creation is for, and an empty
// list quietly meaning "all" is how a mistyped bulk apply becomes an incident.
type CopyRequest struct {
	SourceEnvironmentID       string
	KeyNames                  []string
	DestinationEnvironmentIDs []string
	// ConfirmProtected is the protected-environment confirmation. A protected
	// destination refuses the copy without it, by name.
	ConfirmProtected bool
}

// CopyResult enumerates what moved, one entry per (key, destination).
type CopyResult struct {
	Copied []CopiedValue
}

// CopiedValue is one cell that landed.
type CopiedValue struct {
	KeyName                string
	DestinationEnvironment string
}

// CloneResult is what a clone-at-creation produced. UncopiedSecrets names,
// BY NAME, every `secret` the source held that this actor's authority could
// not duplicate: the ADR requires them enumerated in the creation result
// rather than left for the operator to discover as an empty cell.
type CloneResult struct {
	Copied          []string
	UncopiedSecrets []string
}

// ErrProtectedDestination refuses a copy into a protected environment that
// carries no confirmation. It is a distinct sentinel because the caller CAN
// see the environment — the refusal is a ceremony, not an authorization
// answer, so masking it as nonexistent would be a lie.
//
// It wraps domain.ErrConflict: a protected destination is a POST-authorization
// state refusal (the caller passed the destination formula, the environment's
// protection flag then refused the act), which is exactly what conflict is —
// "the current state of this resource refuses the request". Wrapping no
// sentinel would classify() it as an internal fault and answer 500 for a
// documented refusal. The conflict message is uniform on the wire, but the
// refusal carries the destination environment id as a SafeDetail (see
// ProtectedDestinationRefusal): the id came from the caller's OWN request and
// the refusal is post-authorization, so naming it discloses nothing.
var ErrProtectedDestination = fmt.Errorf("%w: destination environment is protected", domain.ErrConflict)

// ProtectedDestinationRefusal builds the protected-destination refusal for a
// destination environment. It wraps ErrProtectedDestination (so errors.Is and
// classify() see the conflict sentinel) and rides the destination id on the
// SafeDetail channel the uniform writer honours for conflict — the id is
// caller-supplied and the refusal is post-authorization, so it identifies the
// destination without disclosing anything the caller could not already see.
func ProtectedDestinationRefusal(envID domain.EnvID) error {
	return &detailErr{
		detail: string(envID),
		err: fmt.Errorf("%w: %s — confirm the protected destination explicitly",
			ErrProtectedDestination, envID),
	}
}

// detailErr wraps a domain sentinel with a caller-safe detail string. The
// transport's uniform writer honours the detail only for `bad_request` and
// `conflict`, and every detail it carries is caller-supplied text that discloses
// nothing tenancy-scoped: key or environment names the caller already named, or
// the destination id of a protected-destination refusal — never anything the
// caller could not already see. classify() routes it by the wrapped sentinel.
type detailErr struct {
	detail string
	err    error
}

func (e *detailErr) Error() string      { return e.err.Error() }
func (e *detailErr) Unwrap() error      { return e.err }
func (e *detailErr) SafeDetail() string { return e.detail }

// invalidDetail is a domain.ErrInvalid whose message is safe to return on the
// wire verbatim (see detailErr): a refusal naming keys or environments the
// caller already holds.
func invalidDetail(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return &detailErr{detail: msg, err: fmt.Errorf("%w: %s", domain.ErrInvalid, msg)}
}

// firstDuplicate reports the first value that appears more than once. A
// duplicate in an environment or key list is a request for the same logical
// cell twice — repeated writes, repeated events and a doubled response row for
// one intent — so the value surface refuses it rather than silently applying
// the write more than once.
func firstDuplicate(names []string) (string, bool) {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if seen[name] {
			return name, true
		}
		seen[name] = true
	}
	return "", false
}

// sealerFor resolves the project's DEK sealer, AFTER the caller has been
// authorized for the operation they are asking for.
//
// Two constraints meet here and neither is negotiable.
//
// It must run OUTSIDE the transaction: the keyring's store adapter opens
// transactions of its own, and sqlite serves writes on a single connection, so
// resolving a sealer inside a write transaction would wait on the connection
// that transaction holds. Every other sealer user in this package resolves its
// sealer before opening its transaction, for the same reason.
//
// And it must not run before authorization: ForProject MINTS the project data
// key on first use, so an unauthorized caller naming an arbitrary
// (org, project) pair would otherwise leave a wrapped-key row behind — an
// authenticated principal writing rows for tenants that need not exist. The
// pre-flight is therefore a bare read transaction that evaluates the
// operation's own formula against the addressed scope and touches no store
// operation at all: its refusal is the uniform nonexistent, identical to the
// one the real transaction would produce, and nothing is minted behind it.
//
// The window between the two transactions carries no STATE — only a key
// handle — and the real transaction re-authorizes and re-reads everything, so
// this is not the cross-transaction composition #49 argued against.
func sealerFor(ctx context.Context, db *store.DB, kr *crypto.Keyring, actor Actor,
	op authz.Operation, scope domain.Scope) (*crypto.ProjectSealer, error) {
	if kr == nil {
		return nil, errors.New("service: value operations require a keyring")
	}
	err := tx.Read(ctx, db, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = az.Authorize(ctx, caller, op, scope)
		return err
	})
	if err != nil {
		return nil, err
	}
	return kr.ForProject(ctx, string(scope.Org), string(scope.Project))
}

// sealer is sealerFor bound to this service's datastore and keyring.
func (s *Values) sealer(ctx context.Context, actor Actor, op authz.Operation, scope domain.Scope) (*crypto.ProjectSealer, error) {
	return sealerFor(ctx, s.DB, s.Keyring, actor, op, scope)
}

// valueAAD binds a ciphertext to exactly one row: org, project, environment,
// key, THIS row id, and the column. Every component is a column on the row
// being decrypted, so a ciphertext lifted anywhere else stops opening.
func valueAAD(e store.ValueEntry) crypto.ValueAAD {
	return crypto.ValueAAD{
		OrgID: e.OrgID, ProjectID: e.ProjectID, EnvID: e.EnvironmentID,
		KeyID: e.KeyID, RowID: e.ID, FieldTag: valueFieldTag,
	}
}

// findKey resolves a key by NAME within the proof's project. The CLI and API
// address values by key name (`values set DATABASE_URL`) because the name is
// what an operator has; the id is server vocabulary that only ever appears in
// responses and audit records.
func findKey(ctx context.Context, cat store.CatalogueReader, p authz.Proof, name string) (store.CatalogueKey, error) {
	keys, err := cat.List(ctx, p)
	if err != nil {
		return store.CatalogueKey{}, err
	}
	return keyByName(keys, name)
}

// keyByName resolves a key by NAME in an already-listed catalogue — findKey
// without the second List, for a caller that holds the list already.
//
// A key that is not declared is NOT a value write — typing a name that does not
// exist is a key creation, an explicit act elsewhere (schema ADR § Closed
// schema). Never auto-declare.
func keyByName(keys []store.CatalogueKey, name string) (store.CatalogueKey, error) {
	for _, k := range keys {
		if k.Name == name {
			return k, nil
		}
	}
	return store.CatalogueKey{}, fmt.Errorf("%w: no key %q is declared in this project", domain.ErrNotFound, name)
}

// presenceOfKey rebuilds one key's presence rules from the project's rows.
func presenceOfKey(key store.CatalogueKey, rows []store.KeyPresence) schema.PresenceRules {
	return presenceOf(key.ID, key.RequiredMode, key.ForbiddenMode, rows)
}

// validateValue runs the declaration against the value. The write path is a
// delivering path in this slice — what commits is what an environment
// delivers — so an invalid value is refused HERE, not deferred to a publish
// that does not exist yet.
func validateValue(key store.CatalogueKey, value string) error {
	decl, err := schema.ParseDeclaration([]byte(key.Declaration))
	if err != nil {
		return fmt.Errorf("service: key %s: stored declaration unreadable: %w", key.ID, err)
	}
	compiled, err := schema.Compile(decl)
	if err != nil {
		return fmt.Errorf("service: key %s: stored declaration does not compile: %w", key.ID, err)
	}
	verdict := compiled.Validate(value, schema.Classification(key.Classification))
	if verdict.Valid {
		return nil
	}
	// Failure text is schema-derived; for a `secret` key the engine never puts
	// instance data in it in the first place, so this carries nothing the
	// caller may not see.
	parts := make([]string, 0, len(verdict.Errors))
	for _, f := range verdict.Errors {
		parts = append(parts, f.Keyword+": "+f.Message)
	}
	return fmt.Errorf("%w: value for %q is invalid (%s)",
		domain.ErrInvalid, key.Name, strings.Join(parts, "; "))
}

// checkNotForbidden refuses a write where the schema says the key must never
// exist. `forbidden_in` is the flat model's ONLY "this key must not be here"
// mechanism — it changes under schema authority, not per-environment publish
// authority, which is precisely why it survived and `masked` did not.
func checkNotForbidden(key store.CatalogueKey, rules schema.PresenceRules, envID string) error {
	if rules.Forbidden.Covers(envID) {
		return fmt.Errorf("%w: key %q is `forbidden_in` environment %s",
			domain.ErrInvalid, key.Name, envID)
	}
	return nil
}

// writeCell seals one value under the project DEK and writes it, replacing
// whatever the cell held. The row id is minted here and bound into the AAD, so
// every occurrence gets its own id and no id is ever reused. It returns the
// timestamp it stored, so a caller reports the same instant the row carries
// rather than a second, slightly-later time.Now().
//
// The environment is scope.Env: a value addresses exactly the environment its
// scope resolved to, and there is no second environment a cell could be written
// into.
func writeCell(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	scope domain.Scope, key store.CatalogueKey, principal domain.PrincipalID, value string) (time.Time, error) {
	id, err := newID("val")
	if err != nil {
		return time.Time{}, err
	}
	entry := store.ValueEntry{
		ID: id, OrgID: string(scope.Org), ProjectID: string(scope.Project),
		EnvironmentID: string(scope.Env), KeyID: key.ID,
	}
	sealed, err := sealer.SealValue(valueAAD(entry), []byte(schema.Normalize(value)))
	if err != nil {
		return time.Time{}, err
	}
	updatedAt := store.CanonTime(time.Now())
	if err := r.Values().Put(ctx, p, store.NewValueEntry{
		ID: id, KeyID: key.ID, Ciphertext: sealed,
		UpdatedAt: updatedAt, UpdatedBy: string(principal),
	}); err != nil {
		return time.Time{}, err
	}
	return updatedAt, nil
}

// openCell decrypts one stored cell. It is an internal server operation and is
// never itself a disclosure: whether the caller may SEE the result was decided
// by the operation's formula before this was reached.
func openCell(sealer *crypto.ProjectSealer, entry store.ValueEntry) (string, error) {
	plain, err := sealer.OpenValue(valueAAD(entry), entry.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("service: value %s: %w", entry.ID, err)
	}
	return string(plain), nil
}

// StagedChange is one draft as reported to its owner.
type StagedChange struct {
	// VersionID is the immutable version id a selective publish names.
	VersionID          string
	KeyID              string
	Name               string
	Classification     string
	Operation          string
	StagedFromRevision int64
	CreatedAt          time.Time
}

// Set stages one edit into the caller's own working state.
//
// IT PUBLISHES NOTHING. An edit to a `(key, environment)` is saved immediately
// as a pending change owned by the caller, recorded against the published
// revision it was staged from, and delivery does not move until a publish names
// its version id. The formula is therefore `edit` ALONE -- `edit` confers no
// delivery power, and edit-without-publish IS the propose-and-review flow the
// permission ADR says it is.
//
// SAVING IS FREE. The value is not validated here and a `required_in` key may
// be cleared here: a draft is the user's scratchpad, and blocking a save pushes
// work in progress into external notepads, which for secrets is exactly where
// it must not go. Every one of those refusals lives at publish instead.
func (s *Values) Set(ctx context.Context, actor Actor, scope domain.Scope, keyName, value string) (StagedChange, error) {
	return s.stage(ctx, actor, scope, keyName, store.PendingSet, value)
}

// Unset stages a clear: the cell goes to `absent` when the draft is published.
func (s *Values) Unset(ctx context.Context, actor Actor, scope domain.Scope, keyName string) (StagedChange, error) {
	return s.stage(ctx, actor, scope, keyName, store.PendingUnset, "")
}

func (s *Values) stage(ctx context.Context, actor Actor, scope domain.Scope, keyName string,
	operation store.PendingOperation, value string) (StagedChange, error) {
	if scope.Env == "" {
		return StagedChange{}, fmt.Errorf("%w: a value addresses an environment", domain.ErrInvalid)
	}
	sealer, err := s.sealer(ctx, actor, authz.OpValueStage, scope)
	if err != nil {
		return StagedChange{}, err
	}
	var out StagedChange
	var keyID, keyNameOut string
	var owner domain.PrincipalID
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out = StagedChange{}
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpValueStage, scope)
		if err != nil {
			return err
		}
		// One serialization domain per project: the draft records the published
		// entry it was staged against, and a concurrent publish must not slip
		// between reading that entry and writing the row that pins it.
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		key, err := findKey(ctx, r.Catalogue(), p, keyName)
		if err != nil {
			return err
		}
		revision, err := currentRevision(ctx, r, p)
		if err != nil {
			return err
		}
		baseline := ""
		switch entry, err := r.Values().Get(ctx, p, key.ID); {
		case errors.Is(err, domain.ErrNotFound):
			// `absent` at staging time. The empty string is the baseline, and it
			// is a real value here rather than a missing one: a cell that gains
			// a published value after this point makes the draft stale.
		case err != nil:
			return err
		default:
			baseline = entry.ID
		}
		versionID, err := newID("pcv")
		if err != nil {
			return err
		}
		var sealed []byte
		if operation == store.PendingSet {
			if sealed, err = sealer.SealField(
				pendingAAD(string(scope.Org), string(scope.Project), string(scope.Env), key.ID, versionID),
				[]byte(schema.Normalize(value))); err != nil {
				return err
			}
		}
		now := store.CanonTime(time.Now())
		if err := r.Pending().Stage(ctx, p, store.NewPendingChange{
			ID: versionID, KeyID: key.ID, OwnerID: string(caller.Principal),
			Operation: operation, Ciphertext: sealed,
			StagedFromRevision: revision, StagedFromEntry: baseline, CreatedAt: now,
		}); err != nil {
			return err
		}
		ev, err := domainEvent(ctx, audit.EventValueStaged, caller.Principal,
			audit.Object{Type: "key", ID: key.ID}, audit.Payload{
				"key_id":         key.ID,
				"name":           audit.SanitizeFreeText(key.Name),
				"classification": key.Classification,
				"operation":      string(operation),
				"version_id":     versionID,
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		keyID, keyNameOut, owner = key.ID, key.Name, caller.Principal
		out = StagedChange{
			VersionID: versionID, KeyID: key.ID, Name: key.Name,
			Classification: key.Classification, Operation: string(operation),
			StagedFromRevision: revision, CreatedAt: now,
		}
		return nil
	})
	if err != nil {
		return StagedChange{}, err
	}
	// Post-commit: the matrix's quieter "another user has a pending change here"
	// marker is exactly this fact, and it must not be announced for a draft
	// whose transaction rolled back.
	s.Advisory.staged(scope, keyID, keyNameOut, owner)
	return out, nil
}

// Declare is declare-into-environments: ONE supplied plaintext into several
// environments in one transaction. It is the flat model's answer to "I don't
// want to type this 4 times", and it creates no relationship between the
// copies — each is an independent value, and editing one later changes nothing
// elsewhere, by design.
//
// It is authorized per DESTINATION, exactly as a single write is: holding
// `edit ∧ publish` on two of three environments does not buy the third, and
// the whole call is refused rather than partially applied.
func (s *Values) Declare(ctx context.Context, actor Actor, scope domain.Scope, envIDs []string, keyName, value string) ([]ValueCell, error) {
	// The empty/blank/duplicate checks live in declare (below), which Set shares:
	// stating them twice invites the two spellings to drift.
	return s.declare(ctx, actor, scope, envIDs, keyName, value)
}

func (s *Values) declare(ctx context.Context, actor Actor, scope domain.Scope, envIDs []string, keyName, value string) ([]ValueCell, error) {
	if len(envIDs) == 0 {
		return nil, fmt.Errorf("%w: a value addresses an environment", domain.ErrInvalid)
	}
	if slices.Contains(envIDs, "") {
		return nil, fmt.Errorf("%w: a value addresses an environment", domain.ErrInvalid)
	}
	if dup, ok := firstDuplicate(envIDs); ok {
		return nil, invalidDetail("environment %q is named more than once", dup)
	}
	// Gated on the FIRST destination: a caller who cannot write there cannot
	// write anywhere in this call, because the whole declare is all-or-nothing.
	first := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envIDs[0])}
	sealer, err := s.sealer(ctx, actor, authz.OpValueSet, first)
	if err != nil {
		return nil, err
	}
	var out []ValueCell
	var advanced []PublishedEnvironment
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out, advanced = nil, nil
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		for _, envID := range envIDs {
			envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
			p, err := az.Authorize(ctx, caller, authz.OpValueSet, envScope)
			if err != nil {
				return err
			}
			// One serialization domain per project: the value is validated
			// against the key's declaration, and a concurrent declaration
			// change must not slip between the read and the write.
			if err := r.Projects().Lock(ctx, p); err != nil {
				return err
			}
			key, err := findKey(ctx, r.Catalogue(), p, keyName)
			if err != nil {
				return err
			}
			rows, err := r.Catalogue().ListPresence(ctx, p)
			if err != nil {
				return err
			}
			if err := checkNotForbidden(key, presenceOfKey(key, rows), envID); err != nil {
				return err
			}
			if err := validateValue(key, value); err != nil {
				return err
			}
			updatedAt, err := writeCell(ctx, r, p, sealer, envScope, key, caller.Principal, value)
			if err != nil {
				return err
			}
			ev, err := domainEvent(ctx, audit.EventValueSet, caller.Principal,
				audit.Object{Type: "key", ID: key.ID}, audit.Payload{
					"key_id":         key.ID,
					"name":           audit.SanitizeFreeText(key.Name),
					"classification": key.Classification,
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
			// Declare is a supplied-plaintext write that DELIVERS -- its locked
			// formula carries `publish` on every destination, and #50 shipped it
			// as an immediate write. It therefore materializes each destination
			// rather than staging: a value that is authorized as delivered and
			// then does not deliver would be a third state nobody asked for.
			env, err := republish(ctx, r, az, caller, sealer, s.Keyring, envScope, time.Now().UTC(), "declare")
			if err != nil {
				return err
			}
			advanced = append(advanced, env)
			out = append(out, ValueCell{
				KeyID: key.ID, Name: key.Name, Classification: key.Classification,
				Set: true, UpdatedAt: updatedAt, UpdatedBy: string(caller.Principal),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.Advisory.published(scope, advanced)
	return out, nil
}

// Get reads one cell. reveal asks for `secret` plaintext and carries the
// locked disclosure formula plus one audit event; without it a `secret` cell
// reports write-presence only, and a `config` cell reports its value under
// plain `read` because classification IS the sensitivity boundary.
func (s *Values) Get(ctx context.Context, actor Actor, scope domain.Scope, keyName string, reveal bool) (ValueCell, error) {
	cells, err := s.read(ctx, actor, scope, keyName, reveal)
	if err != nil {
		return ValueCell{}, err
	}
	return cells[0], nil
}

// List reads the environment's whole resolved set: one row per DECLARED key,
// each `set` or `absent`. In the flat model this IS the resolution — a lookup
// per key with nothing underneath — so an absent row carries no value from
// anywhere, which is the property C2 asks to see.
func (s *Values) List(ctx context.Context, actor Actor, scope domain.Scope, reveal bool) ([]ValueCell, error) {
	return s.read(ctx, actor, scope, "", reveal)
}

// read is Get and List: keyName "" means every declared key. The disclosure
// surface these emit is always "cell" — the copy, clone and diff surfaces write
// their disclosure events on their own paths — so it is a constant here rather
// than a parameter both call sites pass identically.
//
// A revealing read runs in a WRITE transaction, because it writes its
// disclosure events: the record must be durable before the plaintext leaves
// the server, never after.
func (s *Values) read(ctx context.Context, actor Actor, scope domain.Scope, keyName string, reveal bool) ([]ValueCell, error) {
	op := authz.OpValueList
	switch {
	case reveal:
		op = authz.OpValueReveal
	case keyName != "":
		op = authz.OpValueRead
	}
	sealer, err := s.sealer(ctx, actor, op, scope)
	if err != nil {
		return nil, err
	}
	var out []ValueCell
	if reveal {
		err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, time.Now().UTC())
			if err != nil {
				return err
			}
			p, err := az.Authorize(ctx, caller, op, scope)
			if err != nil {
				return err
			}
			out, err = readCells(ctx, r.Catalogue(), r.Values(), p, sealer, keyName, true,
				ceremonyGate(ctx, s.Auth, az, caller, PurposeReveal, string(scope.Env)))
			if err != nil {
				return err
			}
			return auditDisclosures(ctx, r.Audit(), p, caller.Principal, out, "cell")
		})
	} else {
		err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, time.Now().UTC())
			if err != nil {
				return err
			}
			p, err := az.Authorize(ctx, caller, op, scope)
			if err != nil {
				return err
			}
			out, err = readCells(ctx, r.Catalogue(), r.Values(), p, sealer, keyName, false, nil)
			return err
		})
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// readCells assembles the resolved view for one environment.
// gate is the reveal ceremony's insertion point (#58). It is called with the
// enumerated unit — the `secret` keys that are `set`, and therefore exactly the
// keys this act will decrypt and emit a disclosure event for — BEFORE the first
// ciphertext is opened. Nil on a non-revealing read, where there is no unit and
// nothing to gate.
//
// It takes the key ids rather than being folded into the decrypt loop because
// the ceremony is ONE decision over the whole unit: a per-key gate inside the
// loop would let a bulk reveal open half its keys and then refuse, which is
// neither the prototype's "one decision over exactly the keys below" nor a
// trail anyone can read.
type discloseGate func(keyIDs []string) error

func readCells(ctx context.Context, cat store.CatalogueReader, vals store.ValueReader, p authz.Proof,
	sealer *crypto.ProjectSealer, keyName string, reveal bool, gate discloseGate) ([]ValueCell, error) {
	keys, err := cat.List(ctx, p)
	if err != nil {
		return nil, err
	}
	if keyName != "" {
		// The catalogue is already listed; resolve within it rather than listing
		// it a second time.
		key, err := keyByName(keys, keyName)
		if err != nil {
			return nil, err
		}
		keys = []store.CatalogueKey{key}
	}
	entries := map[string]store.ValueEntry{}
	if keyName == "" {
		rows, err := vals.List(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			entries[row.KeyID] = row
		}
	} else {
		row, err := vals.Get(ctx, p, keys[0].ID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			// `absent`. Not an error, not a fallback, not a lookup elsewhere.
		case err != nil:
			return nil, err
		default:
			entries[row.KeyID] = row
		}
	}
	// The ceremony runs here: after the catalogue and the rows are resolved (so
	// the unit is known exactly) and before any cell is opened (so a refusal
	// discloses nothing and writes no disclosure event).
	if reveal && gate != nil {
		unit := make([]string, 0, len(keys))
		for _, key := range keys {
			if key.Classification != string(schema.Secret) {
				continue
			}
			if _, ok := entries[key.ID]; ok {
				unit = append(unit, key.ID)
			}
		}
		if err := gate(unit); err != nil {
			return nil, err
		}
	}
	out := make([]ValueCell, 0, len(keys))
	for _, key := range keys {
		cell := ValueCell{
			KeyID: key.ID, Name: key.Name, Classification: key.Classification,
		}
		entry, ok := entries[key.ID]
		if ok {
			cell.Set = true
			cell.UpdatedAt = entry.UpdatedAt
			cell.UpdatedBy = entry.UpdatedBy
			// `config` plaintext rides `read`; `secret` plaintext needs the
			// gate the caller either passed or did not ask for.
			if key.Classification == string(schema.Config) || reveal {
				plain, err := openCell(sealer, entry)
				if err != nil {
					return nil, err
				}
				cell.Value = plain
				cell.Revealed = true
			}
		}
		out = append(out, cell)
	}
	return out, nil
}

// auditDisclosures writes one event per key whose `secret` plaintext was
// rendered. Never one event for a bulk reveal: "revealed 40 secrets" as a
// single row is exactly what the audit ADR forbids.
func auditDisclosures(ctx context.Context, trail store.AuditRepo, p authz.Proof,
	principal domain.PrincipalID, cells []ValueCell, surface string) error {
	for _, cell := range cells {
		if cell.Classification != string(schema.Secret) || !cell.Set {
			continue
		}
		ev, err := domainEvent(ctx, audit.EventValueRevealed, principal,
			audit.Object{Type: "key", ID: cell.KeyID}, audit.Payload{
				"key_id":  cell.KeyID,
				"name":    audit.SanitizeFreeText(cell.Name),
				"surface": surface,
			})
		if err != nil {
			return err
		}
		if err := trail.InsertTenant(ctx, p, ev); err != nil {
			return err
		}
	}
	return nil
}

// Diff compares two environments on demand.
//
// This is NOT the ambient drift signal the flat model deleted: divergence
// between environments is the point of the model, so equality is not a health
// signal and nothing watches it. This is an explicit, authorized, per-
// invocation comparison, under the oracle rules — write-presence without the
// reveal gate, plaintext only with it, and one disclosure event per key per
// side that was actually disclosed.
func (s *Values) Diff(ctx context.Context, actor Actor, scope domain.Scope, leftEnv, rightEnv string, reveal bool) ([]DiffRow, error) {
	if leftEnv == "" || rightEnv == "" {
		return nil, fmt.Errorf("%w: diff names two environments", domain.ErrInvalid)
	}
	if leftEnv == rightEnv {
		return nil, fmt.Errorf("%w: diff names two DIFFERENT environments", domain.ErrInvalid)
	}
	// Gated on the LEFT side's read: a caller who cannot read it gets the
	// uniform nonexistent before any key material is touched.
	leftScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(leftEnv)}
	gate := authz.OpValueList
	if reveal {
		gate = authz.OpValueReveal
	}
	sealer, err := s.sealer(ctx, actor, gate, leftScope)
	if err != nil {
		return nil, err
	}
	var out []DiffRow
	// Like a revealing read, a revealing diff writes one disclosure event per
	// key per side, so it takes a write transaction; the presence-only diff
	// stays on the read pool.
	sides := func(ctx context.Context, cat store.CatalogueReader, vals store.ValueReader, trail store.AuditRepo,
		az *authz.TxAuthorizer, caller authz.Identity) error {
		read := func(envID string) ([]ValueCell, error) {
			envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
			op := authz.OpValueList
			if reveal {
				op = authz.OpValueReveal
			}
			// Authorized PER SIDE: `read` on staging says nothing about prod,
			// and a diff that showed one side under the other side's grant
			// would be exactly the oracle the formula table exists to close.
			p, err := az.Authorize(ctx, caller, op, envScope)
			if err != nil {
				return nil, err
			}
			// One ceremony PER SIDE, over that side's own unit. A diff
			// discloses in two environments, and the reveal guard is
			// per-environment: a window open on staging authorizes nothing in
			// production, which is the whole point of capping production at 0.
			cells, err := readCells(ctx, cat, vals, p, sealer, "", reveal,
				ceremonyGate(ctx, s.Auth, az, caller, PurposeReveal, envID))
			if err != nil {
				return nil, err
			}
			if reveal {
				if err := auditDisclosures(ctx, trail, p, caller.Principal, cells, "diff"); err != nil {
					return nil, err
				}
			}
			return cells, nil
		}
		left, err := read(leftEnv)
		if err != nil {
			return err
		}
		right, err := read(rightEnv)
		if err != nil {
			return err
		}
		out = diffRows(left, right)
		return nil
	}
	if reveal {
		err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, time.Now().UTC())
			if err != nil {
				return err
			}
			return sides(ctx, r.Catalogue(), r.Values(), r.Audit(), az, caller)
		})
	} else {
		err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
			caller, err := actor.resolve(ctx, az, time.Now().UTC())
			if err != nil {
				return err
			}
			return sides(ctx, r.Catalogue(), r.Values(), nil, az, caller)
		})
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// diffRows pairs two resolved views. Both sides list every declared key, so
// the pairing is positional by key id and no row can be missing from one side.
func diffRows(left, right []ValueCell) []DiffRow {
	byKey := map[string]ValueCell{}
	for _, cell := range right {
		byKey[cell.KeyID] = cell
	}
	out := make([]DiffRow, 0, len(left))
	for _, l := range left {
		r := byKey[l.KeyID]
		row := DiffRow{
			KeyID: l.KeyID, Name: l.Name, Classification: l.Classification,
			Left: l, Right: r,
		}
		switch {
		case !l.Set && !r.Set:
			// Both absent: equal, and saying so discloses nothing.
			equal := true
			row.Equal = &equal
		case l.Set != r.Set:
			// Presence differs. Write-presence is readable under `read`, so
			// this answer is available to every reader.
			equal := false
			row.Equal = &equal
		case l.Revealed && r.Revealed:
			equal := l.Value == r.Value
			row.Equal = &equal
			// Otherwise: both set, at least one side unreadable. Equal stays
			// nil — "are these two secrets the same?" is material, and a
			// caller without the gate does not get it as a yes/no either.
		}
		out = append(out, row)
	}
	return out
}

// Copy is copy-to and bulk-apply: server-side duplication of STORED material
// into one or more destinations. Every copy produces an INDEPENDENT value —
// the ciphertext is never carried over, the plaintext is re-sealed under the
// destination row's own AAD, and no ongoing relationship is created, so
// editing the source later changes nothing downstream.
//
// The locked formula, split across the scopes and the classifications it
// names (see materialSet):
//
//	secret material: reveal(source) ∧ reveal(destination) ∧ publish(destination)
//	config material:   read(source) ∧                       publish(destination)
//
// A named `secret` the caller cannot read out of the source REFUSES the copy.
// Only clone-at-creation tolerates a failed source gate, because only clone is
// specified to proceed with what it could take and enumerate the rest.
func (s *Values) Copy(ctx context.Context, actor Actor, scope domain.Scope, req CopyRequest) (CopyResult, error) {
	switch {
	case req.SourceEnvironmentID == "":
		return CopyResult{}, fmt.Errorf("%w: copy names a source environment", domain.ErrInvalid)
	case len(req.KeyNames) == 0:
		return CopyResult{}, fmt.Errorf("%w: copy names at least one key", domain.ErrInvalid)
	case len(req.DestinationEnvironmentIDs) == 0:
		return CopyResult{}, fmt.Errorf("%w: copy names at least one destination environment", domain.ErrInvalid)
	case slices.Contains(req.DestinationEnvironmentIDs, req.SourceEnvironmentID):
		return CopyResult{}, fmt.Errorf("%w: an environment cannot be its own copy destination", domain.ErrInvalid)
	}
	if dup, ok := firstDuplicate(req.KeyNames); ok {
		return CopyResult{}, invalidDetail("key %q is named more than once", dup)
	}
	if dup, ok := firstDuplicate(req.DestinationEnvironmentIDs); ok {
		return CopyResult{}, invalidDetail("destination environment %q is named more than once", dup)
	}
	operation := copyOpCopy
	if len(req.KeyNames) > 1 || len(req.DestinationEnvironmentIDs) > 1 {
		operation = copyOpBulkApply
	}
	// Gated on the source read, which every copy needs whatever it carries.
	sourceScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(req.SourceEnvironmentID)}
	sealer, err := s.sealer(ctx, actor, authz.OpValueList, sourceScope)
	if err != nil {
		return CopyResult{}, err
	}
	var out CopyResult
	var advanced []PublishedEnvironment
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out = CopyResult{}
		advanced = nil
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		// Classify the named keys under the source read — nothing is opened here.
		// This decides which destination legs the copy will need, and supplies
		// the units the two ceremonies enumerate.
		hasConfig, secretKeyIDs, allKeyIDs, err := classifyCopyKeys(ctx, r, az, caller, sourceScope, req.KeyNames)
		if err != nil {
			return err
		}
		// PREFLIGHT every destination — the copy formula and the protected-
		// destination ceremony — BEFORE any source secret is opened. A
		// destination refused here lands ahead of readSourceMaterial's reveal
		// gate, so a refused copy opens no material and writes no disclosure
		// record: the trail records what was genuinely read, and a rollback can no
		// longer erase a disclosure that should have stood. Past this loop every
		// open and write is on a path all destinations have cleared, so a later
		// failure is a real fault where rolling the disclosure back is correct.
		for _, destID := range req.DestinationEnvironmentIDs {
			destScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(destID)}
			if err := authorizeDestination(ctx, r, az, caller, destScope,
				req.ConfirmProtected, hasConfig, len(secretKeyIDs) > 0, allKeyIDs,
				ceremonyGate(ctx, s.Auth, az, caller, PurposePublish, destID)); err != nil {
				return err
			}
		}
		// The SOURCE ceremony. A copy carries `reveal(source E)` in the locked
		// formula, so it takes the same enumerated-key ceremony a cell reveal
		// does — including copy-without-display, which discloses to a
		// destination rather than to a screen and is a disclosure either way.
		material, _, err := readSourceMaterial(ctx, r, az, caller, sealer, scope,
			req.SourceEnvironmentID, req.KeyNames, false, copyOpCopy,
			ceremonyGate(ctx, s.Auth, az, caller, PurposeCopy, req.SourceEnvironmentID))
		if err != nil {
			return err
		}
		for _, destID := range req.DestinationEnvironmentIDs {
			destScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(destID)}
			copied, err := applyMaterial(ctx, r, az, caller, sealer, destScope,
				req.SourceEnvironmentID, material, operation)
			out.Copied = append(out.Copied, copied...)
			if err != nil {
				return err
			}
			published, err := republish(ctx, r, az, caller, sealer, s.Keyring, destScope,
				store.CanonTime(time.Now()), operation)
			if err != nil {
				return err
			}
			advanced = append(advanced, published)
		}
		return nil
	})
	if err != nil {
		return CopyResult{}, err
	}
	s.Advisory.published(scope, advanced)
	return out, nil
}

// classifyCopyKeys resolves the named keys under the source read and reports
// which classifications the copy carries, opening NO material. It is the copy
// preflight's input: which destination legs to authorize before a single secret
// is decrypted. An absent named key is a refusal here just as it is in
// readSourceMaterial, so the two agree on what a copy names.
func classifyCopyKeys(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	sourceScope domain.Scope, keyNames []string) (hasConfig bool, secretKeyIDs, allKeyIDs []string, err error) {
	readProof, err := az.Authorize(ctx, caller, authz.OpValueList, sourceScope)
	if err != nil {
		return false, nil, nil, err
	}
	for _, name := range keyNames {
		key, err := findKey(ctx, r.Catalogue(), readProof, name)
		if err != nil {
			return false, nil, nil, err
		}
		// allKeyIDs is what the DESTINATION ceremony enumerates: every key the
		// decision carries, `config` included. The human is agreeing to deliver
		// this batch into a protected environment, and a modal that listed only
		// the secret half would be asking them to approve something narrower
		// than what happens.
		allKeyIDs = append(allKeyIDs, key.ID)
		if key.Classification == string(schema.Secret) {
			secretKeyIDs = append(secretKeyIDs, key.ID)
		} else {
			hasConfig = true
		}
	}
	return hasConfig, secretKeyIDs, allKeyIDs, nil
}

// authorizeDestination clears one copy destination up front: the destination
// legs the material requires (config, secret, or both) and the protected-
// environment ceremony, writing NOTHING. Running it for every destination
// before readSourceMaterial is what keeps the disclosure trail truthful — a
// destination refusal lands before any secret is opened. Each leg is authorized
// only where its classification is present, preserving the non-empty-batch rule
// the copy formula split depends on.
func authorizeDestination(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	destScope domain.Scope, confirmProtected, hasConfig, hasSecret bool, allKeyIDs []string,
	protectedGate discloseGate) error {
	var legs []authz.Operation
	if hasConfig {
		legs = append(legs, authz.OpValueCopyDestinationConfig)
	}
	if hasSecret {
		legs = append(legs, authz.OpValueCopyDestination)
	}
	var protected bool
	for i, op := range legs {
		if err := withDestination(ctx, r, az, caller, op, destScope, func(_ authz.Proof, isProtected bool) error {
			if i == 0 {
				protected = isProtected
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if !protected {
		return nil
	}
	// THE PROTECTED-DESTINATION DECISION, made exactly once per destination and
	// over EVERY key the copy carries — `config` included.
	//
	// A machine gets the ADR's explicit plan field: "an explicit field in the
	// immutable plan… never an interactive prompt". A HUMAN gets the ceremony,
	// and the boolean is not an alternative for them — a caller-supplied `true`
	// is the one thing that must never satisfy protection, or the UI can delete
	// the guard by sending a constant. That was the hole: the ceremony hung on
	// the secret leg, so a config-only copy into a protected environment went
	// through on the flag alone.
	if skipsCeremony(caller) {
		if !confirmProtected {
			return ProtectedDestinationRefusal(destScope.Env)
		}
		return nil
	}
	if protectedGate == nil {
		return ProtectedDestinationRefusal(destScope.Env)
	}
	return protectedGate(allKeyIDs)
}

// sourceValue is one piece of source material, carried in memory between the
// source read and the destination write. The PLAINTEXT is here because the
// ciphertext cannot be reused: the destination row has a different id, a
// different environment and therefore a different AAD, so duplication is
// always decrypt-and-reseal.
type sourceValue struct {
	key       store.CatalogueKey
	plaintext string
}

// materialSet splits what is being duplicated by classification, because the
// two halves carry different authorization stories end to end.
//
// THE SPLIT IS FORCED, not chosen. Grants inherit DOWNWARD only, so `reveal`
// on an environment that does not exist yet can come only from a
// project-or-wider grant — which necessarily covers every source environment
// in that project. Were `config` material to need destination `reveal` too, a
// clone's source gate could never fail while its destination gate passed, and
// the flat-model ADR's "otherwise creation proceeds and the uncopied secrets
// land `absent`, enumerated by name" — with mvp-boundary C2's clone abort —
// would be text describing an unreachable state. The gate is classification-
// scoped in its own wording ("begin delivering a **`secret`** value occurrence
// the publisher did not supply"), and the permission ADR files `config` values
// under `read`.
type materialSet struct {
	config []sourceValue
	secret []sourceValue
}

func (m materialSet) empty() bool { return len(m.config) == 0 && len(m.secret) == 0 }

// sourceCell is one resolved-but-unopened piece of source material: the key and
// its ciphertext row, carried from a preflight to the open WITHOUT decrypting.
// Splitting resolution from the open is what lets clone run its born-invalid
// abort (cloneInto) before any plaintext is touched or any disclosure event
// written — an aborted clone then rolls back nothing it opened, honouring the
// OpValueCopySource promise of one durable disclosure event per secret OPENED.
type sourceCell struct {
	key   store.CatalogueKey
	entry store.ValueEntry
}

// sourcePlan is what planSourceMaterial resolved: which cells will be opened,
// split by classification, the secrets it could not take (skipped), and the
// reveal proof under which the planned secrets are opened and their disclosure
// records written. Nothing here has been decrypted.
type sourcePlan struct {
	config      []sourceCell
	secret      []sourceCell
	skipped     []string
	revealProof authz.Proof // non-nil iff at least one secret cell is planned
}

// planSourceMaterial authorizes the source legs and resolves what a duplication
// will move, opening NOTHING: it reads ciphertext rows and evaluates the
// source-material gate, but decrypts no plaintext and writes no disclosure
// event. The open is openSourceMaterial's, run only once the caller has
// confirmed the preflight will not abort (clone), or immediately (copy).
//
// `config` rides the ordinary environment read; `secret` rides the reveal-gated
// copy-source operation, authorized ONLY when secret material is actually named
// — an unused leg that could fail is a refusal nobody asked for.
//
// tolerateGateFailure is clone's preflight behaviour: a clone plans what it can
// and enumerates the rest, while an explicit copy of a named secret the caller
// cannot read out of the source is a refusal.
func planSourceMaterial(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	scope domain.Scope, sourceEnvID string, keyNames []string, tolerateGateFailure bool) (sourcePlan, error) {
	var plan sourcePlan
	sourceScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(sourceEnvID)}
	readProof, err := az.Authorize(ctx, caller, authz.OpValueList, sourceScope)
	if err != nil {
		return plan, err
	}
	var secretKeys []store.CatalogueKey
	for _, name := range keyNames {
		key, err := findKey(ctx, r.Catalogue(), readProof, name)
		if err != nil {
			return plan, err
		}
		if key.Classification == string(schema.Secret) {
			secretKeys = append(secretKeys, key)
			continue
		}
		entry, err := r.Values().Get(ctx, readProof, key.ID)
		if errors.Is(err, domain.ErrNotFound) {
			if tolerateGateFailure {
				continue
			}
			return plan, fmt.Errorf("%w: key %q is absent in the source environment",
				domain.ErrNotFound, name)
		}
		if err != nil {
			return plan, err
		}
		plan.config = append(plan.config, sourceCell{key: key, entry: entry})
	}
	if len(secretKeys) == 0 {
		return plan, nil
	}
	// The source-material gate, evaluated only because secret material is in
	// play. Its refusal is the whole operation's refusal for an explicit copy,
	// and a narrowing for a clone.
	revealProof, gateErr := az.Authorize(ctx, caller, authz.OpValueCopySource, sourceScope)
	if gateErr != nil {
		if !tolerateGateFailure {
			return plan, gateErr
		}
		plan.skipped = make([]string, 0, len(secretKeys))
		for _, key := range secretKeys {
			plan.skipped = append(plan.skipped, key.Name)
		}
		return plan, nil
	}
	plan.revealProof = revealProof
	for _, key := range secretKeys {
		entry, err := r.Values().Get(ctx, revealProof, key.ID)
		if errors.Is(err, domain.ErrNotFound) {
			// A secret named by the clone's key list but absent at source (gate
			// passed): neither copied nor skipped. It lands nowhere, and the
			// stranded computation in cloneInto is what decides whether that is
			// fatal — this plan just declines to open a cell that holds nothing.
			if tolerateGateFailure {
				continue
			}
			return plan, fmt.Errorf("%w: key %q is absent in the source environment",
				domain.ErrNotFound, key.Name)
		}
		if err != nil {
			return plan, err
		}
		plan.secret = append(plan.secret, sourceCell{key: key, entry: entry})
	}
	return plan, nil
}

// openSourceMaterial decrypts a preflight's planned cells into a materialSet and
// records the source-side disclosure — one EventValueRevealed per `secret` cell
// it opens. This is the ONLY place plaintext leaves the sealer and the only
// place the source disclosure trail is written, so a caller that must abort does
// so against the plan (before calling this), never against opened material: a
// rollback past this point is a real fault, never an abort erasing a disclosure
// it should have stood behind. `config` opens no event — reading it discloses
// nothing beyond the `read` the caller already holds.
// The ceremony runs between the plan and the open, on EVERY caller of this
// pair: `gate` is handed the planned `secret` unit, and a refusal lands before
// the first ciphertext is touched — so a copy or clone whose source ceremony is
// missing opens nothing and writes no disclosure event, which is the same
// ordering the destination preflight already establishes.
func openSourceMaterial(ctx context.Context, r store.Repos, sealer *crypto.ProjectSealer,
	principal domain.PrincipalID, plan sourcePlan, surface string, gate discloseGate) (materialSet, error) {
	var out materialSet
	if gate != nil && len(plan.secret) > 0 {
		unit := make([]string, 0, len(plan.secret))
		for _, c := range plan.secret {
			unit = append(unit, c.key.ID)
		}
		if err := gate(unit); err != nil {
			return out, err
		}
	}
	for _, c := range plan.config {
		plain, err := openCell(sealer, c.entry)
		if err != nil {
			return out, err
		}
		out.config = append(out.config, sourceValue{key: c.key, plaintext: plain})
	}
	for _, c := range plan.secret {
		plain, err := openCell(sealer, c.entry)
		if err != nil {
			return out, err
		}
		out.secret = append(out.secret, sourceValue{key: c.key, plaintext: plain})
	}
	if len(plan.secret) > 0 {
		if err := auditSourceDisclosures(ctx, r.Audit(), plan.revealProof, principal, out.secret, surface); err != nil {
			return out, err
		}
	}
	return out, nil
}

// readSourceMaterial is the plan-then-open path an explicit copy takes: it
// resolves and immediately opens, because Copy has already authorized every
// destination before it is called (see Copy), so no abort can intervene between
// the plan and the open. Clone runs the two halves separately (cloneInto) to fit
// its born-invalid abort between them, so it never opens material an abort would
// roll back.
func readSourceMaterial(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	sealer *crypto.ProjectSealer, scope domain.Scope, sourceEnvID string, keyNames []string,
	tolerateGateFailure bool, surface string, gate discloseGate) (materialSet, []string, error) {
	plan, err := planSourceMaterial(ctx, r, az, caller, scope, sourceEnvID, keyNames, tolerateGateFailure)
	if err != nil {
		return materialSet{}, nil, err
	}
	material, err := openSourceMaterial(ctx, r, sealer, caller.Principal, plan, surface, gate)
	if err != nil {
		return materialSet{}, nil, err
	}
	return material, plan.skipped, nil
}

// auditSourceDisclosures records the source half of a duplication.
func auditSourceDisclosures(ctx context.Context, trail store.AuditRepo, p authz.Proof,
	principal domain.PrincipalID, material []sourceValue, surface string) error {
	cells := make([]ValueCell, 0, len(material))
	for _, m := range material {
		cells = append(cells, ValueCell{
			KeyID: m.key.ID, Name: m.key.Name,
			Classification: m.key.Classification, Set: true,
		})
	}
	return auditDisclosures(ctx, trail, p, principal, cells, surface)
}

// withDestination runs one destination leg — the protected-environment
// ceremony included — and hands the resulting proof to fn.
//
// It takes a callback rather than returning the proof because a helper that
// returns a proof has to return SOMETHING on the error path, and the only
// value available is a nil Proof — the one forgeable value the proof guard
// refuses outright. Handing the proof to a callback never constructs one.
// It reports the destination's PROTECTED flag to the callback rather than
// deciding on it: the decision is one per destination and belongs where the
// whole batch is known (authorizeDestination), not once per classification
// leg. The project row is locked for the rest of the transaction here, so the
// flag this reports cannot move underneath a later step — which is why the
// write path re-checks nothing.
func withDestination(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	op authz.Operation, destScope domain.Scope, fn func(authz.Proof, bool) error) error {
	p, err := az.Authorize(ctx, caller, op, destScope)
	if err != nil {
		return err
	}
	if err := r.Projects().Lock(ctx, p); err != nil {
		return err
	}
	settings, err := r.Environments().Settings(ctx, p)
	if err != nil {
		return err
	}
	return fn(p, settings.Protected)
}

// applyMaterial writes one destination's share, one leg per classification and
// each leg authorized ONLY where it carries something: a config-only copy must
// never evaluate the reveal-gated destination operation, or the unreachability
// the split exists to avoid comes straight back.
func applyMaterial(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	sealer *crypto.ProjectSealer, destScope domain.Scope, sourceEnvID string,
	material materialSet, operation string) ([]CopiedValue, error) {
	var out []CopiedValue
	legs := []struct {
		op       authz.Operation
		material []sourceValue
	}{
		{authz.OpValueCopyDestinationConfig, material.config},
		{authz.OpValueCopyDestination, material.secret},
	}
	for _, leg := range legs {
		if len(leg.material) == 0 {
			continue
		}
		// The protected decision was made and CONSUMED in the preflight, under
		// the project lock this call re-takes; a protected window authorises
		// exactly one decision, so re-deciding here would be a double-spend.
		err := withDestination(ctx, r, az, caller, leg.op, destScope, func(p authz.Proof, _ bool) error {
			copied, err := writeMaterial(ctx, r, p, sealer, caller, destScope, sourceEnvID, leg.material, operation)
			out = append(out, copied...)
			return err
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// writeMaterial re-seals every piece of material into one destination and
// records one event per key. The ciphertext is never carried over: the
// destination row has its own id, its own environment and therefore its own
// AAD, so duplication is always decrypt-and-reseal (encryption ADR).
func writeMaterial(ctx context.Context, r store.Repos, p authz.Proof, sealer *crypto.ProjectSealer,
	caller authz.Identity, destScope domain.Scope, sourceEnvID string,
	material []sourceValue, operation string) ([]CopiedValue, error) {
	destID := string(destScope.Env)
	presence, err := r.Catalogue().ListPresence(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]CopiedValue, 0, len(material))
	for _, m := range material {
		if err := checkNotForbidden(m.key, presenceOfKey(m.key, presence), destID); err != nil {
			return nil, err
		}
		if err := validateValue(m.key, m.plaintext); err != nil {
			return nil, err
		}
		if _, err := writeCell(ctx, r, p, sealer, destScope, m.key, caller.Principal, m.plaintext); err != nil {
			return nil, err
		}
		ev, err := domainEvent(ctx, audit.EventValueCopied, caller.Principal,
			audit.Object{Type: "key", ID: m.key.ID}, audit.Payload{
				"key_id":                m.key.ID,
				"name":                  audit.SanitizeFreeText(m.key.Name),
				"classification":        m.key.Classification,
				"source_environment_id": sourceEnvID,
				"operation":             operation,
			})
		if err != nil {
			return nil, err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return nil, err
		}
		out = append(out, CopiedValue{KeyName: m.key.Name, DestinationEnvironment: destID})
	}
	return out, nil
}

// cloneInto is clone-at-creation's value half, running in the transaction that
// created the destination environment (hierarchy.go's Environments.Clone).
//
// The preflight the ADR requires, in order. Steps 1–3 resolve and abort against
// a PLAN (planSourceMaterial) that opens no plaintext and writes no disclosure
// event; only step 4, reached once no abort can fire, opens the material and
// records the disclosures — so an aborted clone rolls back nothing it opened:
//
//  1. `config` values copy FREELY — freely meaning without the reveal gate on
//     either side, not without authorization: reading them needs `read(source)`
//     and writing them needs `publish(destination)`.
//  2. `secret` values copy only where the source-material gate passes. A caller
//     without `reveal(source)` is not refused the creation — the gate is
//     evaluated and its failure narrows what moves, which is the ADR's
//     "otherwise creation proceeds and the uncopied secrets land absent,
//     enumerated by name".
//  3. A `secret` that would be ABSENT in the new environment and is
//     `required_in` it ABORTS the creation, naming the keys — whether the
//     source-material gate blocked it OR the source never held it. Only a
//     `mode: all` rule can reach a brand-new environment (an explicit list could
//     not have named an id that did not exist), and an environment born invalid
//     is the partially-valid creation the atomicity rule forbids.
//  4. The planned material is opened and its source disclosures written, then
//     each destination leg copies its share.
func cloneInto(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	sealer *crypto.ProjectSealer, scope domain.Scope, sourceEnvID, destEnvID string,
	gate discloseGate) (CloneResult, error) {
	var out CloneResult
	sourceScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(sourceEnvID)}
	destScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(destEnvID)}

	// Everything the source environment holds, named: a clone copies the whole
	// environment, so its key list IS the source's `set` cells.
	readProof, err := az.Authorize(ctx, caller, authz.OpValueList, sourceScope)
	if err != nil {
		return out, err
	}
	present, err := r.Values().List(ctx, readProof)
	if err != nil {
		return out, err
	}
	keys, err := r.Catalogue().List(ctx, readProof)
	if err != nil {
		return out, err
	}
	nameByID := map[string]store.CatalogueKey{}
	for _, k := range keys {
		nameByID[k.ID] = k
	}
	names := make([]string, 0, len(present))
	for _, entry := range present {
		if key, ok := nameByID[entry.KeyID]; ok {
			names = append(names, key.Name)
		}
	}
	slices.Sort(names)

	// PREFLIGHT ONLY — resolve the gate and what would land WITHOUT decrypting
	// anything or writing a disclosure event. The born-invalid abort below runs
	// against this plan, so an aborted clone rolls back nothing it opened: the
	// OpValueCopySource promise is one durable disclosure event per secret
	// OPENED, and a secret the abort strands is never opened.
	plan, err := planSourceMaterial(ctx, r, az, caller, scope, sourceEnvID, names, true)
	if err != nil {
		return out, err
	}
	slices.Sort(plan.skipped)
	out.UncopiedSecrets = plan.skipped

	// The abort, BEFORE anything is opened or written: a `mode: all` required
	// SECRET that would be absent in the new environment leaves it born invalid,
	// which the atomicity rule forbids. "Absent" is the superset the ADR names,
	// reached two ways and BOTH must abort: the source-material gate blocked the
	// secret (it is in `plan.skipped`), OR the source never held it at all (it is
	// not among the source's `set` cells, so the plan never saw it and it is
	// neither planned nor skipped). Deciding on what will actually LAND — the
	// secret cells about to be opened — catches both without enumerating the causes.
	landed := make(map[string]bool, len(plan.secret))
	for _, c := range plan.secret {
		landed[c.key.Name] = true
	}
	presence, err := r.Catalogue().ListPresence(ctx, readProof)
	if err != nil {
		return out, err
	}
	var stranded []string
	for _, key := range keys {
		if key.Classification != string(schema.Secret) || landed[key.Name] {
			continue
		}
		if presenceOfKey(key, presence).Required.Covers(destEnvID) {
			stranded = append(stranded, key.Name)
		}
	}
	slices.Sort(stranded)
	if len(stranded) > 0 {
		return CloneResult{}, invalidDetail(
			"cloning %s would leave required secret(s) absent in the new environment: %s",
			sourceEnvID, strings.Join(stranded, ", "))
	}

	// Preflight passed — NOW open the planned material and write the source-side
	// disclosure events. Any failure past here is a genuine fault where rollback
	// is correct, not an abort erasing a disclosure it had already written.
	material, err := openSourceMaterial(ctx, r, sealer, caller.Principal, plan, copyOpClone, gate)
	if err != nil {
		return out, err
	}
	if material.empty() {
		return out, nil
	}
	// A brand-new environment cannot be protected — the flag is set after
	// creation — so the ceremony has nothing to confirm here.
	copied, err := applyMaterial(ctx, r, az, caller, sealer, destScope, sourceEnvID, material, copyOpClone)
	if err != nil {
		return CloneResult{}, err
	}
	for _, c := range copied {
		out.Copied = append(out.Copied, c.KeyName)
	}
	return out, nil
}
