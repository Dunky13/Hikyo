package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// PlanTTL is the immutable-plan lifetime (#70, ops-spec). An unapplied plan
// expires 24h after creation; the hourly GC prunes it.
const PlanTTL = 24 * time.Hour

// MaxOpenPlansPerProject is the open-plan quota: at most this many unapplied,
// unexpired plans per project (#70, ops-spec).
const MaxOpenPlansPerProject = 20

// MaxProvenanceBytes bounds each provenance label (#70, ADR § Provenance).
const MaxProvenanceBytes = 256

// Definitions is the definitions Git-flow service: export / check / plan /
// apply / settings (#70, source-of-truth ADR). It owns no policy of its own —
// the pure diff lives in internal/definitions, the publish pipeline in
// publish.go — and stitches them to the store under one authorized transaction
// each.
type Definitions struct {
	DB       *store.DB
	Keyring  *crypto.Keyring
	Advisory *Advisory
	// Budget applies the § 151 schema-revision rate limit (60/h per project) to
	// the definitions-apply path, via prepareSchemaPublish. Nil disables it.
	Budget *Budget
	// Scan is the secret-scanning Surface-2 seam (#74 SS3, ADR §7 (b)/(c)): the
	// plan/apply chokepoints scan every author-controlled bundle leaf before an
	// immutable plan persists (plan) and re-scan on ruleset-snapshot skew (apply),
	// and `check` surfaces findings non-persisting. A nil ruleset is scanning-off
	// (a pre-#74 test); a booted server always wires it.
	Scan *scanning.Ruleset
	Now  func() time.Time
}

func (s *Definitions) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// scanSnapshot is the ruleset snapshot version a plan is scanned under, recorded
// so apply can detect skew (#74 SS3). Empty when scanning is off (a pre-#74 test).
func (s *Definitions) scanSnapshot() string {
	if s.Scan == nil {
		return ""
	}
	return s.Scan.SnapshotVersion()
}

// CheckResult is the drift diagnostic (#70 § Drift). Findings carries the
// non-blocking secret-scanning results of the submitted bundle (#74 SS3): a
// read-only dry-run that surfaces credential-shaped leaves without persisting or
// minting a token, so an operator sees a plan would be refused before running it.
type CheckResult struct {
	State           string
	BaseRevision    *int64
	CurrentRevision int64
	Differences     definitions.Diff
	Findings        []Finding
}

// KeyDeletion is one deleted key with the environments that still hold a live
// value for it — the concrete impact the plan preview renders.
type KeyDeletion struct {
	Name   string   `json:"name"`
	LiveIn []string `json:"live_in"`
}

// EnvDeletion is one deleted environment with its live-occurrence count.
type EnvDeletion struct {
	Name        string `json:"name"`
	Occurrences int64  `json:"occurrences"`
}

// PlanDiff is the rendered plan preview: the structural diff plus the concrete
// deletion impact.
type PlanDiff struct {
	Environments   definitions.KindDiff `json:"environments"`
	KeyGroups      definitions.KindDiff `json:"key_groups"`
	Keys           definitions.KindDiff `json:"keys"`
	KeyDeletions   []KeyDeletion        `json:"key_deletions"`
	EnvDeletions   []EnvDeletion        `json:"env_deletions"`
	RevealRequired []string             `json:"reveal_required"`
}

// PlanView is the plan response — the impact preview a plan IS.
type PlanView struct {
	ID                    string
	Digest                string
	BaseRevision          *int64
	CurrentRevision       int64
	Additive              bool
	ExpiresAt             time.Time
	ProtectedEnvironments []string
	Diff                  PlanDiff
	DeletionsPresent      bool
	RevealRequired        []string
}

// ApplyOptions carries the apply request fields.
type ApplyOptions struct {
	AllowDelete bool
	Digest      string
	Commit      string
	Ref         string
	Actor       string
	// Acknowledgements are the secret-scanning override tokens a skew re-scan
	// honors (#74 SS3, ADR §7 (c)). They are consumed only when apply re-scans —
	// i.e. the running ruleset snapshot differs from the plan's; a same-version
	// apply runs no scan and ignores them.
	Acknowledgements []string
}

// ApplyResult is the apply response.
type ApplyResult struct {
	Revision  int64
	Published []string
	PlanID    string
}

// LastApply is the last-applied provenance record the settings view surfaces.
type LastApply struct {
	PlanID    string
	AppliedAt time.Time
	AppliedBy string
	Commit    string
	Ref       string
	Actor     string
	Revision  int64
}

// DefinitionsSettings is the settings view.
type DefinitionsSettings struct {
	Source    string
	LastApply *LastApply
}

// Export renders the project's canonical definitions bundle. --portable strips
// the server-owned ids and the base revision, producing a template that applies
// cleanly to a fresh instance.
func (s *Definitions) Export(ctx context.Context, actor Actor, scope domain.Scope, portable bool) ([]byte, error) {
	// §179 fail-closed default: a whole-project bundle materialization with no
	// named category. Authorized-then-acquired at entry (rate + concurrency), so
	// an unauthorized caller cannot occupy the org's slots by guessing its id.
	release, err := chargeDefaultAtEntry(ctx, s.DB, s.Budget, actor, authz.OpDefinitionsExport, scope, s.now)
	if err != nil {
		return nil, err
	}
	defer release()
	var out []byte
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsExport, scope)
		if err != nil {
			return err
		}
		cur, err := buildCurrentState(ctx, r.Catalogue(), r.Environments(), p)
		if err != nil {
			return err
		}
		bundle := bundleFromState(cur, !portable)
		bundle, err = definitions.Normalize(bundle)
		if err != nil {
			return err
		}
		out, err = definitions.Encode(bundle)
		return err
	})
	return out, err
}

// Check classifies drift between a submitted bundle and current state, with no
// persistence. It is the diagnostic; plan is the gate.
func (s *Definitions) Check(ctx context.Context, actor Actor, scope domain.Scope, raw []byte) (CheckResult, error) {
	// §179 fail-closed default: Check materializes the whole project state, lists
	// every key/presence/group/environment and parses every declaration, plus
	// scans the submitted bundle — the same fan-out Export is, so it takes the
	// same default budget (authorized-then-acquired at entry).
	release, err := chargeDefaultAtEntry(ctx, s.DB, s.Budget, actor, authz.OpDefinitionsCheck, scope, s.now)
	if err != nil {
		return CheckResult{}, err
	}
	defer release()
	var res CheckResult
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsCheck, scope)
		if err != nil {
			return err
		}
		bundle, err := definitions.Parse(raw)
		if err != nil {
			return err
		}
		cur, err := buildCurrentState(ctx, r.Catalogue(), r.Environments(), p)
		if err != nil {
			return err
		}
		state, diff, err := definitions.Compare(bundle, cur)
		if err != nil {
			return err
		}
		findings, err := scanBundleForCheck(ctx, s.Scan, bundle)
		if err != nil {
			return err
		}
		res = CheckResult{
			State:           string(state),
			BaseRevision:    bundle.BaseRevision,
			CurrentRevision: cur.SchemaRevision,
			Differences:     diff,
			Findings:        findings,
		}
		return nil
	})
	return res, err
}

// GetSettings reads the project's definitions source and last-apply provenance.
func (s *Definitions) GetSettings(ctx context.Context, actor Actor, scope domain.Scope) (DefinitionsSettings, error) {
	var out DefinitionsSettings
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsSettingsGet, scope)
		if err != nil {
			return err
		}
		proj, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		out.Source = proj.DefinitionsSource
		last, err := r.Definitions().LatestAppliedPlan(ctx, p)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out.LastApply = lastApplyOf(last)
		return nil
	})
	return out, err
}

// SetSettings writes the project's definitions source. It rides
// `project-settings`, off the definitions-edit path (permission ADR §84).
func (s *Definitions) SetSettings(ctx context.Context, actor Actor, scope domain.Scope, source string) (DefinitionsSettings, error) {
	if source != "db" && source != "git" {
		return DefinitionsSettings{}, fmt.Errorf("%w: definitions_source must be `db` or `git`", domain.ErrInvalid)
	}
	var out DefinitionsSettings
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsSettingsSet, scope)
		if err != nil {
			return err
		}
		proj, err := r.Projects().Get(ctx, p)
		if err != nil {
			return err
		}
		previous := proj.DefinitionsSource
		if previous != source {
			if err := r.Projects().SetDefinitionsSource(ctx, p, source); err != nil {
				return err
			}
			ev, err := domainEvent(ctx, audit.EventSettingsDefinitionsSourceChanged, caller.Principal,
				audit.Object{Type: "project", ID: string(scope.Project)}, audit.Payload{
					"previous_source": previous,
					"source":          source,
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
		}
		out.Source = source
		last, err := r.Definitions().LatestAppliedPlan(ctx, p)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		out.LastApply = lastApplyOf(last)
		return nil
	})
	return out, err
}

// buildCurrentState reads the project's live definitions into the pure diff
// engine's snapshot type.
func buildCurrentState(ctx context.Context, cat store.CatalogueReader, envs store.EnvironmentReader, p authz.Proof) (definitions.CurrentState, error) {
	keys, err := cat.List(ctx, p)
	if err != nil {
		return definitions.CurrentState{}, err
	}
	presence, err := cat.ListPresence(ctx, p)
	if err != nil {
		return definitions.CurrentState{}, err
	}
	groups, err := cat.ListGroups(ctx, p)
	if err != nil {
		return definitions.CurrentState{}, err
	}
	envList, err := envs.List(ctx, p)
	if err != nil {
		return definitions.CurrentState{}, err
	}
	revision, err := cat.SchemaRevision(ctx, p)
	if err != nil {
		return definitions.CurrentState{}, err
	}
	cur := definitions.CurrentState{SchemaRevision: revision}
	for _, e := range envList {
		cur.Environments = append(cur.Environments, definitions.Environment{ID: e.ID, Name: e.Name})
	}
	for _, g := range groups {
		cur.KeyGroups = append(cur.KeyGroups, definitions.KeyGroup{ID: g.ID, Name: g.Name})
	}
	for _, row := range keys {
		decl, err := schema.ParseDeclaration([]byte(row.Declaration))
		if err != nil {
			return definitions.CurrentState{}, fmt.Errorf("service: key %s: stored declaration unreadable: %w", row.ID, err)
		}
		rules := presenceOf(row.ID, row.RequiredMode, row.ForbiddenMode, presence)
		cur.Keys = append(cur.Keys, definitions.CurrentKey{
			ID: row.ID, Name: row.Name, FolderPath: row.FolderPath,
			Classification: row.Classification, Description: row.Description,
			Deprecated: row.Deprecated, DeprecationNote: row.DeprecationNote,
			GroupID: row.GroupID, Declaration: decl,
			Required: rules.Required, Forbidden: rules.Forbidden,
		})
	}
	return cur, nil
}

// bundleFromState renders current state as a bundle. withIDs stamps the
// server-owned ids and the base revision (export); a portable export omits both.
func bundleFromState(cur definitions.CurrentState, withIDs bool) definitions.Bundle {
	envNameByID := make(map[string]string, len(cur.Environments))
	for _, e := range cur.Environments {
		envNameByID[e.ID] = e.Name
	}
	groupNameByID := make(map[string]string, len(cur.KeyGroups))
	for _, g := range cur.KeyGroups {
		groupNameByID[g.ID] = g.Name
	}
	b := definitions.Bundle{FormatVersion: definitions.FormatVersion}
	if withIDs {
		rev := cur.SchemaRevision
		b.BaseRevision = &rev
	}
	for _, e := range cur.Environments {
		env := definitions.Environment{Name: e.Name}
		if withIDs {
			env.ID = e.ID
		}
		b.Environments = append(b.Environments, env)
	}
	for _, g := range cur.KeyGroups {
		kg := definitions.KeyGroup{Name: g.Name}
		if withIDs {
			kg.ID = g.ID
		}
		b.KeyGroups = append(b.KeyGroups, kg)
	}
	for _, k := range cur.Keys {
		key := definitions.Key{
			Name: k.Name, FolderPath: k.FolderPath, Classification: k.Classification,
			Description: k.Description, Deprecated: k.Deprecated, DeprecationNote: k.DeprecationNote,
			Group:       groupNameByID[k.GroupID],
			Declaration: k.Declaration,
			RequiredIn:  bundlePresence(k.Required, envNameByID),
			ForbiddenIn: bundlePresence(k.Forbidden, envNameByID),
		}
		if withIDs {
			key.ID = k.ID
		}
		b.Keys = append(b.Keys, key)
	}
	return b
}

// bundlePresence converts a stored presence rule (env ids) to the bundle form
// (env names).
func bundlePresence(p schema.Presence, envNameByID map[string]string) definitions.Presence {
	out := definitions.Presence{Mode: string(p.Mode), Environments: []string{}}
	for _, id := range p.Environments {
		out.Environments = append(out.Environments, envNameByID[id])
	}
	return out
}

func lastApplyOf(plan store.DefinitionsPlan) *LastApply {
	return &LastApply{
		PlanID: plan.ID, AppliedAt: plan.AppliedAt, AppliedBy: plan.AppliedBy,
		Commit: plan.ProvenanceCommit, Ref: plan.ProvenanceRef, Actor: plan.ProvenanceActor,
		// Apply refuses unless the current revision equals the plan's base, then
		// bumps exactly once — so the revision an applied plan produced is
		// provably its base + 1. Deriving it needs no extra stored column.
		Revision: plan.BaseSchemaRevision + 1,
	}
}

// protectedEnvironmentPin keeps identity for stale-set checks and the plan-time
// name for stable preview rendering. A later rename must not look like a newly
// protected environment, while GetPlan must return the same names Plan did.
type protectedEnvironmentPin struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func protectedPins(prot []store.EnvironmentProtection, names map[string]string) []protectedEnvironmentPin {
	var pins []protectedEnvironmentPin
	for _, e := range prot {
		if e.Protected {
			pins = append(pins, protectedEnvironmentPin{ID: e.ID, Name: names[e.ID]})
		}
	}
	sort.Slice(pins, func(i, j int) bool { return pins[i].ID < pins[j].ID })
	return pins
}

func protectedPinNames(pins []protectedEnvironmentPin) []string {
	names := make([]string, 0, len(pins))
	for _, pin := range pins {
		names = append(names, pin.Name)
	}
	sort.Strings(names)
	return names
}

func protectedPinIDs(pins []protectedEnvironmentPin) []string {
	ids := make([]string, 0, len(pins))
	for _, pin := range pins {
		ids = append(ids, pin.ID)
	}
	sort.Strings(ids)
	return ids
}
