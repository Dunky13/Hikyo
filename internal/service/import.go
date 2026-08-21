package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
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

// The import path's server side (#68, import-paths ADR § Binding phase 1 to
// phase 2). Two methods, one per phase, and nothing between them:
//
//   - Occurrences is phase 1's ONLY server contact. Read-only: declared keys,
//     the two-state presence in one environment, the definitions revision, and
//     per (key, environment) a SERVER-MINTED OPAQUE OCCURRENCE TOKEN naming the
//     exact resolved state. It never requires `reveal`, never compares values
//     and never writes.
//   - Import is phase 2. Strict closed schema, human-only, per environment, and
//     — when a manifest is supplied — a PRECONDITION verified inside the
//     import's own authorized transaction.
//
// The token is what makes skip-by-default true rather than hopeful. A bucket
// label cannot do the job: `set` → `set` with a changed value preserves the
// bucket, so a bucket-checked "reviewed overwrite" would still clobber the
// newer value. The token is computed over the value ROW ID, which is minted per
// write and never reused, so an edit advances it and the match fails.

// ImportOccurrence is one key's phase-1 observation. It covers keys the project
// does NOT declare as well: an import proposes those, and phase 2 must be able
// to check they did not move either, so they carry a token binding the
// reviewed undeclared-to-declared class/type transition rather than no token.
type ImportOccurrence struct {
	KeyID          string
	Name           string
	Declared       bool
	Classification string
	Type           string
	// Set is the whole presence model: `set` or `absent`.
	Set bool
	// Token is the server-minted opaque occurrence token. Opaque means opaque:
	// a client copies it into the run manifest and never interprets it.
	Token string
}

// ImportPresence is what phase 1 learned about one environment.
type ImportPresence struct {
	Project             string
	Environment         string
	DefinitionsRevision int64
	Keys                []ImportOccurrence
}

// ImportCandidate is one key phase 1 may declare. For an undeclared name the
// intended fields are bound into its token; for an existing name the current
// catalogue declaration remains authoritative.
type ImportCandidate struct {
	Name                   string
	IntendedClassification string
	IntendedType           string
}

// ImportEntry is one key's imported plaintext.
type ImportEntry struct {
	Key   string
	Value string
}

// ImportPrecondition is the run manifest's expected-state half, the one
// declared additive input `values import` gained.
type ImportPrecondition struct {
	DefinitionsRevision int64
	// Environments are every environment the manifest names. read(E) is
	// re-evaluated for each of them inside the import's own transaction, ON TOP
	// of the verb's own formula: a caller lacking it receives the plain
	// authorization failure and no precondition result.
	Environments []string
	// Occurrences are the reviewed (key, environment) tokens.
	Occurrences []ImportOccurrenceRef
}

// ImportOccurrenceRef is one reviewed occurrence from the manifest.
type ImportOccurrenceRef struct {
	Key         string
	Environment string
	Token       string
}

// ImportRequest is one `values import` invocation against one environment.
type ImportRequest struct {
	Entries []ImportEntry
	// Overwrite is the enumerated `set`-bucket consent. Skip-by-default
	// otherwise, which is what makes a re-run idempotent.
	Overwrite []string
	// Precondition is nil without `--manifest`, in which case `values import`
	// behaves exactly as locked.
	Precondition *ImportPrecondition
}

// ImportResult is what landed.
type ImportResult struct {
	Imported []string
	// Skipped are keys already `set` in the target environment that no
	// enumerated overwrite named. Listed by name, never silently dropped.
	Skipped []string
	// Findings are the Surface-1 warnings the imported CONFIG values produced
	// (#74, surface import_value), warn-not-block: the import succeeds and each
	// finding names its rule and key locator. No dismissal token here.
	Findings []Finding
}

// movedTokenRefusal is the ONE wording every precondition mismatch produces.
//
// It is one wording deliberately. The tokens are server-minted and opaque, so
// an edited or fabricated manifest must not be able to phrase a question about
// someone else's state that the server answers differently — an unrecognized
// token has to be exactly as informative as a stale one. Two messages would be
// a one-bit oracle on whether a guessed token was ever real.
const movedTokenRefusal = "the reviewed state moved before this import ran"

// MaxImportCandidates bounds how many undeclared names one presence read may
// ask about. It is the import framework's record cap: a caller cannot make the
// server mint more tokens than an import could ever plan.
const MaxImportCandidates = 5000

// Occurrences is phase 1's read. Candidates are the key declarations the run
// intends to propose; every one gets a token, declared or not.
func (s *Values) Occurrences(ctx context.Context, actor Actor, scope domain.Scope, candidates []ImportCandidate) (ImportPresence, error) {
	if s.Keyring == nil {
		return ImportPresence{}, errors.New("service: import presence requires a keyring")
	}
	if len(candidates) > MaxImportCandidates {
		return ImportPresence{}, fmt.Errorf("%w: an import presence read names at most %d keys, got %d",
			domain.ErrLimitExceeded, MaxImportCandidates, len(candidates))
	}
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.Name)
	}
	if dup, ok := firstDuplicate(names); ok {
		return ImportPresence{}, invalidDetail("key %q is named more than once", dup)
	}
	var out ImportPresence
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpImportPresence, scope)
		if err != nil {
			return err
		}
		out, err = readOccurrences(ctx, r.Catalogue(), r.Values(), s.Keyring, p, scope, candidates)
		return err
	})
	if err != nil {
		return ImportPresence{}, err
	}
	return out, nil
}

// readOccurrences assembles one environment's occurrence view. Shared by phase
// 1's read and phase 2's precondition, so the two cannot compute the token
// differently — which would make every manifest stale.
func readOccurrences(ctx context.Context, cat store.CatalogueReader, vals store.ValueReader,
	kr *crypto.Keyring, p authz.Proof, scope domain.Scope, candidates []ImportCandidate) (ImportPresence, error) {
	keys, err := cat.List(ctx, p)
	if err != nil {
		return ImportPresence{}, err
	}
	entries, err := vals.List(ctx, p)
	if err != nil {
		return ImportPresence{}, err
	}
	revision, err := cat.SchemaRevision(ctx, p)
	if err != nil {
		return ImportPresence{}, err
	}
	byKey := make(map[string]store.ValueEntry, len(entries))
	for _, e := range entries {
		byKey[e.KeyID] = e
	}
	out := ImportPresence{
		Project: string(scope.Project), Environment: string(scope.Env), DefinitionsRevision: revision,
	}
	declared := make(map[string]bool, len(keys))
	for _, k := range keys {
		declared[k.Name] = true
		entry, set := byKey[k.ID]
		token, err := mintOccurrence(kr, scope, k, entry.ID)
		if err != nil {
			return ImportPresence{}, err
		}
		out.Keys = append(out.Keys, ImportOccurrence{
			KeyID: k.ID, Name: k.Name, Declared: true, Classification: k.Classification,
			Type: declaredType(k), Set: set, Token: token,
		})
	}
	// The candidates the project does not declare. Their token names the
	// reviewed transition from undeclared and absent to the exact intended
	// classification and type. Applying that bundle line is expected; a
	// different declaration or a value appearing is movement.
	for _, candidate := range candidates {
		if declared[candidate.Name] {
			continue
		}
		if !schema.Classification(candidate.IntendedClassification).Valid() ||
			!importPrimitive(schema.Type(candidate.IntendedType)) {
			return ImportPresence{}, invalidDetail(
				"key %q must name an intended `secret|config` classification and primitive type", candidate.Name)
		}
		token, err := kr.OccurrenceToken(string(scope.Org), string(scope.Project), string(scope.Env),
			delivery.EncodeOccurrence(delivery.Occurrence{
				Name: candidate.Name, IntendedClassification: candidate.IntendedClassification,
				IntendedType: candidate.IntendedType,
			}))
		if err != nil {
			return ImportPresence{}, err
		}
		out.Keys = append(out.Keys, ImportOccurrence{Name: candidate.Name, Token: token})
	}
	sort.Slice(out.Keys, func(i, j int) bool { return out.Keys[i].Name < out.Keys[j].Name })
	return out, nil
}

// mintOccurrence keys the canonical occurrence encoding. entryID is "" for
// `absent`, which is a state the token names as precisely as it names a value:
// a key that was absent at review and is set now must reject.
func mintOccurrence(kr *crypto.Keyring, scope domain.Scope, k store.CatalogueKey, entryID string) (string, error) {
	digest := sha256.Sum256([]byte(k.Declaration))
	return kr.OccurrenceToken(string(scope.Org), string(scope.Project), string(scope.Env),
		delivery.EncodeOccurrence(delivery.Occurrence{
			Declared:       true,
			Name:           k.Name,
			KeyID:          k.ID,
			EntryID:        entryID,
			Classification: k.Classification,
			Declaration:    hex.EncodeToString(digest[:]),
		}))
}

// declaredType reports the same canonical textual expression `keys show`
// renders: a primitive, or any_of(branch|branch). The import client uses the
// full expression to check whether its effective primitive is a branch.
func declaredType(k store.CatalogueKey) string {
	decl, err := schema.ParseDeclaration([]byte(k.Declaration))
	if err != nil {
		return ""
	}
	if decl.Rule != nil {
		return schema.TypeExpression([]schema.Type{decl.Rule.Type})
	}
	types := make([]schema.Type, 0, len(decl.AnyOf))
	for _, alt := range decl.AnyOf {
		types = append(types, alt.Type)
	}
	return schema.TypeExpression(types)
}

func importPrimitive(typ schema.Type) bool {
	switch typ {
	case schema.TypeString, schema.TypeInteger, schema.TypeBoolean,
		schema.TypeEnum, schema.TypeURL, schema.TypeJSON:
		return true
	default:
		return false
	}
}

// Import is phase 2: `values import` against one environment, in ONE
// transaction.
//
// The order is load-bearing and is the ADR's own:
//
//  1. authorize the import itself (`edit ∧ publish` on this environment);
//  2. re-evaluate phase 1's read formula — read@project AND read@environment
//     for the union of the manifest's environments AND this import's target — in the same
//     transaction, on top of the verb's formula. A caller lacking it gets the
//     plain authorization failure and no precondition result: the precondition
//     is not an oracle, and the union is what keeps that true when the caller
//     chooses the manifest's list;
//  3. only then verify the occurrence tokens, per key.
//
// Any movement rejects, naming the keys, and NOTHING is written: the whole run
// is one transaction, and a partially applied migration whose manifest no
// longer describes it is worse than one the human re-runs.
func (s *Values) Import(ctx context.Context, actor Actor, scope domain.Scope, req ImportRequest) (ImportResult, error) {
	switch {
	case len(req.Entries) == 0:
		return ImportResult{}, fmt.Errorf("%w: an import carries at least one value", domain.ErrInvalid)
	case scope.Env == "":
		return ImportResult{}, fmt.Errorf("%w: `values import` is per environment", domain.ErrInvalid)
	}
	names := make([]string, 0, len(req.Entries))
	for _, e := range req.Entries {
		if e.Key == "" {
			return ImportResult{}, fmt.Errorf("%w: an import entry names a key", domain.ErrInvalid)
		}
		// Bound supplied plaintext before declaration parsing, validation, or
		// sealing. The schema engine enforces the same byte budget later, but
		// import must not accept an oversized request merely because this entry
		// would have been skipped or rejected for another reason first.
		if len(e.Value) > schema.MaxValueBytes {
			return ImportResult{}, fmt.Errorf("%w: value for %q exceeds the %d-byte validation budget",
				domain.ErrInvalid, e.Key, schema.MaxValueBytes)
		}
		names = append(names, e.Key)
	}
	if dup, ok := firstDuplicate(names); ok {
		return ImportResult{}, invalidDetail("key %q is named more than once", dup)
	}
	if dup, ok := firstDuplicate(req.Overwrite); ok {
		return ImportResult{}, invalidDetail("--overwrite names key %q more than once", dup)
	}
	// An overwrite consent for a key the run does not import is a mistake worth
	// hearing about: it usually means a typo, and a typo in a consent list is
	// the one place a silent no-op is dangerous.
	for _, name := range req.Overwrite {
		if !slices.Contains(names, name) {
			return ImportResult{}, invalidDetail("--overwrite names key %q, which this import does not carry", name)
		}
	}

	sealer, err := s.sealer(ctx, actor, authz.OpValueImport, scope)
	if err != nil {
		return ImportResult{}, err
	}
	// §179 fail-closed default: a bulk value fan-out with no named category.
	// Concurrency (8/org) at entry, per-principal rate (60/min) in-tx.
	release, err := s.Budget.acquire(budgetDefaultConc, budgetKeys{Org: scope.Org})
	if err != nil {
		return ImportResult{}, err
	}
	defer release()
	overwrite := make(map[string]bool, len(req.Overwrite))
	for _, name := range req.Overwrite {
		overwrite[name] = true
	}

	var result ImportResult
	var published PublishedEnvironment
	advanced := false
	var rateCharged bool
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		result = ImportResult{}
		published = PublishedEnvironment{}
		advanced = false
		total := 0
		caller, err := actor.resolve(ctx, az, time.Now().UTC())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpValueImport, scope)
		if err != nil {
			return err
		}
		if err := s.Budget.chargeOnce(&rateCharged, budgetDefaultRate, budgetKeys{Principal: caller.Principal}); err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}

		// The closed schema is NOT conceded on the import path. The largest
		// imports are precisely the accumulated-typo case it exists to catch,
		// so an undeclared key rejects the run by name rather than being
		// created or skipped.
		var undeclared []string
		for _, name := range names {
			if _, err := keyByName(keys, name); err != nil {
				undeclared = append(undeclared, name)
			}
		}
		if len(undeclared) > 0 {
			sort.Strings(undeclared)
			return fmt.Errorf("%w: %d key(s) are not declared in this project: %s — "+
				"apply the definitions bundle first",
				domain.ErrInvalid, len(undeclared), strings.Join(undeclared, ", "))
		}

		if err := s.checkPrecondition(ctx, r, az, caller, p, scope, req, names); err != nil {
			return err
		}

		entries, err := r.Values().List(ctx, p)
		if err != nil {
			return err
		}
		set := make(map[string]bool, len(entries))
		for _, e := range entries {
			set[e.KeyID] = true
		}
		presence, err := r.Catalogue().ListPresence(ctx, p)
		if err != nil {
			return err
		}

		for _, entry := range req.Entries {
			key, err := keyByName(keys, entry.Key)
			if err != nil {
				return err
			}
			// Skip-by-default on the `set` bucket. Listed by name: a skipped
			// key the operator expected to land is a fact they must be told.
			if set[key.ID] && !overwrite[entry.Key] {
				result.Skipped = append(result.Skipped, entry.Key)
				continue
			}
			if err := checkNotForbidden(key, presenceOfKey(key, presence), string(scope.Env)); err != nil {
				return err
			}
			if err := validateValue(key, entry.Value); err != nil {
				return err
			}
			if _, err := writeCell(ctx, r, p, sealer, scope, key, caller.Principal, entry.Value); err != nil {
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
			// Surface-1 warn (#74), warn-only: an imported CONFIG value is scanned
			// and its findings ride the import response. OpValueImport licenses
			// finding_warned; a secret key is a no-op (Surface 3).
			f, err := scanConfigValue(ctx, r, p, s.Keyring, s.Scan, scope, key.ID,
				key.Classification, []byte(schema.Normalize(entry.Value)), surfaceImportValue,
				caller.Principal, nil, false, &total)
			if err != nil {
				return err
			}
			result.Findings = append(result.Findings, f...)
			result.Imported = append(result.Imported, entry.Key)
		}
		sort.Strings(result.Imported)
		sort.Strings(result.Skipped)
		// Import is an immediate, publish-authorized bulk write, like declare and
		// copy. Materialize its final state once, after every cell has landed, so
		// delivery and revision history advance atomically with the import rather
		// than exposing value_entries that no committed snapshot contains.
		if len(result.Imported) > 0 {
			published, err = republish(ctx, r, az, caller, sealer, s.Keyring, scope,
				store.CanonTime(time.Now()), "import")
			if err != nil {
				return err
			}
			advanced = true
		}

		run, err := domainEvent(ctx, audit.EventValueImported, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, audit.Payload{
				"imported_count": len(result.Imported),
				"skipped_count":  len(result.Skipped),
				"manifest_bound": req.Precondition != nil,
			})
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, run)
	})
	if err != nil {
		return ImportResult{}, err
	}
	if advanced {
		s.Advisory.published(scope, []PublishedEnvironment{published})
	}
	return result, nil
}

// checkPrecondition is the manifest's half, run inside the import's own
// transaction and BEFORE anything is written.
func (s *Values) checkPrecondition(ctx context.Context, r store.Repos, az *authz.TxAuthorizer,
	caller authz.Identity, p authz.Proof, scope domain.Scope, req ImportRequest, names []string) error {
	pre := req.Precondition
	if pre == nil {
		// Without a manifest, `values import` behaves exactly as locked. The
		// precondition is what makes import's skip-by-default TRUE, not a new
		// default for the verb.
		return nil
	}
	// Phase 1's read formula, re-evaluated for every environment the manifest
	// names AND ALWAYS FOR THE TARGET. The union is the whole point: the
	// manifest's environment list is caller-supplied, so authorizing only what
	// it names lets a caller omit the environment they are actually importing
	// into, present a captured token, and read the token-match answer as an
	// oracle on state they cannot read. The target is authorized because it is
	// the target, not because a manifest mentioned it.
	//
	// This runs BEFORE any token is checked: a caller lacking either read atom receives
	// the plain authorization failure and learns nothing about state.
	authorized := append([]string{string(scope.Env)}, pre.Environments...)
	slices.Sort(authorized)
	for _, envID := range slices.Compact(authorized) {
		if envID == "" {
			return fmt.Errorf("%w: the manifest names an empty environment", domain.ErrInvalid)
		}
		named := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
		if _, err := az.Authorize(ctx, caller, authz.OpImportPresence, named); err != nil {
			return err
		}
	}

	// The definitions revision is RECORDED, not compared. Comparing it would
	// refuse every run that followed the documented flow: applying this run's
	// own definitions bundle bumps the revision, so a global equality check
	// makes "plan, apply, import" a guaranteed conflict. Staleness detection is
	// per key, and it is already inside the token — the declaration digest and
	// the classification are two of its four fields, so a declaration that
	// moved under a key rejects THAT key by name.

	candidates := make([]ImportCandidate, 0, len(names))
	for _, name := range names {
		candidates = append(candidates, ImportCandidate{Name: name})
	}
	current, err := readOccurrences(ctx, r.Catalogue(), r.Values(), s.Keyring, p, scope, candidates)
	if err != nil {
		return err
	}
	live := make(map[string]ImportOccurrence, len(current.Keys))
	for _, k := range current.Keys {
		live[k.Name] = k
	}
	reviewed := make(map[string]string, len(pre.Occurrences))
	for _, o := range pre.Occurrences {
		if o.Environment != string(scope.Env) {
			// A token minted for another environment is scoped to a different
			// key and cannot match here. Ignoring it is correct: one manifest
			// covers a whole run, and this call imports one environment.
			continue
		}
		reviewed[o.Key] = o.Token
	}

	// Every key this run WRITES must carry a reviewed token that still holds.
	// Two ways it can hold, and the second is what makes the documented flow
	// work at all:
	//
	//   - the key was DECLARED at review: the token still recomputes to the
	//     same value, which covers the value occurrence, the classification and
	//     the declaration digest in one comparison;
	//   - the key was UNDECLARED at review: the token is the "undeclared and
	//     absent" one, and the check is that the key is STILL ABSENT. A
	//     declaration having appeared is the expected effect of applying this
	//     run's own bundle — it is the flow, not movement. A VALUE having
	//     appeared is movement, and rejects that key by name.
	//
	// A key the manifest never reviewed is movement too — it is a key the human
	// did not see — so its absence from the list rejects in the same wording.
	var moved []string
	for _, name := range names {
		token, ok := reviewed[name]
		if !ok {
			moved = append(moved, name)
			continue
		}
		observed := live[name]
		switch {
		case tokenMatches(token, observed.Token):
			// Declared at review and unmoved, or undeclared at review and still
			// undeclared: either way the recomputation agrees.
		case observed.Declared && !observed.Set && tokenMatches(token, undeclaredToken(
			s.Keyring, scope, name, observed.Classification, observed.Type)):
			// Declared since review, still absent: the bundle landed.
		default:
			moved = append(moved, name)
		}
	}
	if len(moved) > 0 {
		sort.Strings(moved)
		return fmt.Errorf("%w: %s — %d key(s) rejected by name: %s; re-run `hikyo import` and review again",
			domain.ErrConflict, movedTokenRefusal, len(moved), strings.Join(moved, ", "))
	}
	return nil
}

// tokenMatches compares two tokens without leaking which byte differed. Both
// sides are server-minted, so this is belt-and-braces rather than the only
// thing standing between a caller and a forgery — but a timing-distinguishable
// compare on a value a caller supplies is never the right call.
func tokenMatches(presented, computed string) bool {
	return computed != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(computed)) == 1
}

// undeclaredToken recomputes the reviewed undeclared-to-declared transition
// for one name. A keyring failure yields "", which tokenMatches refuses —
// failing toward rejection is the only safe direction here.
func undeclaredToken(kr *crypto.Keyring, scope domain.Scope, name, classification, typ string) string {
	token, err := kr.OccurrenceToken(string(scope.Org), string(scope.Project), string(scope.Env),
		delivery.EncodeOccurrence(delivery.Occurrence{
			Name: name, IntendedClassification: classification, IntendedType: typ,
		}))
	if err != nil {
		return ""
	}
	return token
}
