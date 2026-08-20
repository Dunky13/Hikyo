package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// gitModeRefusal is normative in docs/spec/ui-spec.md § Git-mode. Server
// SafeDetail and the web banner intentionally copy those bytes exactly.
const gitModeRefusal = "Definitions for this project are managed in Git — changes arrive through `definitions plan` / `definitions apply`."

// requireDBManagedDefinitions is the git-mode write guard. Every
// `definitions-edit` write path calls it inside its transaction, AFTER
// authorization: a `git`-mode project accepts definition writes only through
// definitions apply, so any ordinary edit is refused with the fixed detail. It
// reads the project row the caller was already authorized to reach; apply never
// calls it (apply is the one allowed write).
func requireDBManagedDefinitions(ctx context.Context, r store.Repos, p authz.Proof) error {
	proj, err := r.Projects().Get(ctx, p)
	if err != nil {
		return err
	}
	if proj.DefinitionsSource == "git" {
		return &detailErr{detail: gitModeRefusal, err: fmt.Errorf("%w: %s", domain.ErrConflict, gitModeRefusal)}
	}
	return nil
}

var bearerShapedRe = regexp.MustCompile(`[A-Za-z0-9_\-]{32,}`)

// sanitizeProvenance bounds and screens one provenance label. Provenance is a
// display-only label, never an input to any decision (#70, ADR § Provenance),
// but a live token typed into `--actor` would land in the audit trail, so a
// bearer-token-shaped value is refused loudly rather than stored. Two matchers
// compose: the canonical hikyo token grammar (audit's redaction filter, which
// catches short-bodied tokens the generic run-length heuristic cannot) and the
// generic long-base64ish run for foreign credentials with no known grammar.
func sanitizeProvenance(field, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if len(s) > MaxProvenanceBytes {
		return "", fmt.Errorf("%w: %s exceeds %d bytes", domain.ErrInvalid, field, MaxProvenanceBytes)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: %s contains a control character", domain.ErrInvalid, field)
		}
	}
	if audit.RedactTokens(s) != s || bearerShapedRe.MatchString(s) {
		return "", fmt.Errorf("%w: %s looks like a credential; provenance is a label, not a secret", domain.ErrInvalid, field)
	}
	return s, nil
}

// Plan diffs a bundle against current state, pins it, and persists an immutable
// plan. The plan IS the impact preview: it renders deletions concretely and
// names the entries whose apply will need reveal.
func (s *Definitions) Plan(ctx context.Context, actor Actor, scope domain.Scope, raw []byte) (PlanView, error) {
	var view PlanView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsPlanCreate, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
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
		// Stale base: a based bundle must be based on current state.
		if !bundle.Additive() && *bundle.BaseRevision != cur.SchemaRevision {
			return &detailErr{
				detail: fmt.Sprintf("bundle base revision %d is not the current definitions revision %d — re-export and rebase",
					*bundle.BaseRevision, cur.SchemaRevision),
				err: fmt.Errorf("%w: stale base", domain.ErrConflict),
			}
		}
		res, err := definitions.Resolve(bundle, cur)
		if err != nil {
			var mod *definitions.AdditiveModificationError
			if errors.As(err, &mod) {
				ev, evErr := newAuditEvent(ctx, audit.EventDefinitionsAdditiveModificationRefused, caller.Principal,
					audit.Object{Type: "project", ID: string(scope.Project)}, audit.OutcomeDenied, "",
					audit.Payload{"name": audit.SanitizeFreeText(mod.Key)})
				if evErr != nil {
					return evErr
				}
				az.CaptureAudit(audit.TrailTenant, domain.Scope{Org: scope.Org, Project: scope.Project}, ev)
			}
			return err
		}
		if err := validateFinalDefinitions(cur, res); err != nil {
			return err
		}
		// Open-plan quota.
		open, err := r.Definitions().CountOpenPlans(ctx, p, s.now())
		if err != nil {
			return err
		}
		if open >= MaxOpenPlansPerProject {
			return fmt.Errorf("%w: project already holds %d open definitions plans (max %d)",
				domain.ErrLimitExceeded, open, MaxOpenPlansPerProject)
		}
		view, err = s.persistPlan(ctx, r, az, caller, p, scope, bundle, cur, res)
		return err
	})
	return view, err
}

func validateFinalDefinitions(cur definitions.CurrentState, res definitions.Resolution) error {
	environments := make(map[string]string, len(cur.Environments)+len(res.EnvCreates))
	for _, env := range cur.Environments {
		environments[env.ID] = env.Name
	}
	for _, deleted := range res.EnvDeletes {
		delete(environments, deleted.ID)
	}
	for _, renamed := range res.EnvRenames {
		environments[renamed.ID] = renamed.To
	}
	for _, name := range res.EnvCreates {
		environments["new:"+name] = name
	}
	if len(environments) > MaxEnvironmentsPerProject {
		return definitionLimit("final definitions contain %d environments; a project holds at most %d", len(environments), MaxEnvironmentsPerProject)
	}
	for _, name := range environments {
		if err := checkName("environment name", name); err != nil {
			return definitionInvalid("environment %q has an invalid name: %v", name, err)
		}
	}

	groups := make(map[string]string, len(cur.KeyGroups)+len(res.GroupCreates))
	for _, group := range cur.KeyGroups {
		groups[group.ID] = group.Name
	}
	for _, deleted := range res.GroupDeletes {
		delete(groups, deleted.ID)
	}
	for _, renamed := range res.GroupRenames {
		groups[renamed.ID] = renamed.To
	}
	for _, name := range res.GroupCreates {
		groups["new:"+name] = name
	}
	if len(groups) > schema.MaxKeyGroupsPerProject {
		return definitionLimit("final definitions contain %d key groups; a project declares at most %d", len(groups), schema.MaxKeyGroupsPerProject)
	}
	for _, name := range groups {
		if err := schema.CheckGroupName(name); err != nil {
			return definitionInvalid("key group %q has an invalid name: %v", name, err)
		}
	}

	keys := make(map[string]string, len(cur.Keys)+len(res.KeyCreates))
	for _, key := range cur.Keys {
		keys[key.ID] = key.Name
	}
	for _, deleted := range res.KeyDeletes {
		delete(keys, deleted.ID)
	}
	for _, updated := range res.KeyUpdates {
		keys[updated.ID] = updated.Desired.Name
	}
	for _, key := range res.KeyCreates {
		keys["new:"+key.Name] = key.Name
	}
	if len(keys) > schema.MaxKeysPerProject {
		return definitionLimit("final definitions contain %d keys; a project declares at most %d", len(keys), schema.MaxKeysPerProject)
	}
	for _, name := range keys {
		if err := schema.CheckKeyName(name); err != nil {
			return definitionInvalid("key %q has an invalid name: %v", name, err)
		}
	}
	return nil
}

func definitionInvalid(format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return &detailErr{detail: detail, err: fmt.Errorf("%w: %s", domain.ErrInvalid, detail)}
}

func definitionLimit(format string, args ...any) error {
	detail := fmt.Sprintf(format, args...)
	return &detailErr{detail: detail, err: fmt.Errorf("%w: %s", domain.ErrLimitExceeded, detail)}
}

// persistPlan enriches the diff with live-occurrence impact, computes the pins,
// writes the plan row, and audits it.
func (s *Definitions) persistPlan(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, bundle definitions.Bundle, cur definitions.CurrentState,
	res definitions.Resolution) (PlanView, error) {
	now := s.now()
	envNameByID := make(map[string]string, len(cur.Environments))
	for _, e := range cur.Environments {
		envNameByID[e.ID] = e.Name
	}

	diff := res.Diff()
	planDiff := PlanDiff{
		Environments:   diff.Environments,
		KeyGroups:      diff.KeyGroups,
		Keys:           diff.Keys,
		RevealRequired: diff.RevealRequired,
	}
	// Concrete key deletions with the environments still holding a live value.
	for _, del := range res.KeyDeletes {
		envs, err := r.Values().EnvironmentsWithValue(ctx, p, del.ID)
		if err != nil {
			return PlanView{}, err
		}
		names := make([]string, 0, len(envs))
		for _, id := range envs {
			names = append(names, envNameByID[id])
		}
		sort.Strings(names)
		planDiff.KeyDeletions = append(planDiff.KeyDeletions, KeyDeletion{Name: del.Name, LiveIn: names})
	}
	// Concrete environment deletions with their live-occurrence counts.
	for _, del := range res.EnvDeletes {
		count, err := r.Values().CountEnvironmentValues(ctx, p, del.ID)
		if err != nil {
			return PlanView{}, err
		}
		planDiff.EnvDeletions = append(planDiff.EnvDeletions, EnvDeletion{Name: del.Name, Occurrences: count})
	}

	// Pins: the digest, per-environment value revisions over EVERY environment
	// (0 if never published — so the set of keys also detects env create/delete),
	// and the protected-environment id set.
	digest, err := definitions.Digest(bundle)
	if err != nil {
		return PlanView{}, err
	}
	envRevs, err := s.envRevisions(ctx, r, p, cur)
	if err != nil {
		return PlanView{}, err
	}
	protection, err := r.Environments().ListProtection(ctx, p)
	if err != nil {
		return PlanView{}, err
	}
	protectedSet := protectedPins(protection, envNameByID)

	envRevsJSON, err := json.Marshal(envRevs)
	if err != nil {
		return PlanView{}, err
	}
	protectedJSON, err := json.Marshal(protectedSet)
	if err != nil {
		return PlanView{}, err
	}
	diffJSON, err := json.Marshal(planDiff)
	if err != nil {
		return PlanView{}, err
	}

	planID, err := newID("dpl")
	if err != nil {
		return PlanView{}, err
	}
	// The plan stores the CANONICAL bundle bytes, so a re-parse at apply is
	// byte-identical to what was pinned.
	canonical, err := definitions.Encode(bundle)
	if err != nil {
		return PlanView{}, err
	}
	newPlan := store.NewDefinitionsPlan{
		ID: planID, CreatedBy: string(caller.Principal), CreatedAt: now, ExpiresAt: now.Add(PlanTTL),
		Bundle: string(canonical), Digest: digest, BaseSchemaRevision: cur.SchemaRevision,
		EnvRevisions: string(envRevsJSON), ProtectedEnvs: string(protectedJSON), Diff: string(diffJSON),
		Additive: bundle.Additive(),
	}
	if err := r.Definitions().CreatePlan(ctx, p, newPlan); err != nil {
		return PlanView{}, err
	}
	ev, err := domainEvent(ctx, audit.EventDefinitionsPlanCreated, caller.Principal,
		audit.Object{Type: "definitions-plan", ID: planID}, audit.Payload{
			"plan_id":           planID,
			"additive":          bundle.Additive(),
			"deletions_present": res.DeletionsPresent(),
		})
	if err != nil {
		return PlanView{}, err
	}
	if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
		return PlanView{}, err
	}

	return PlanView{
		ID: planID, Digest: digest, BaseRevision: bundle.BaseRevision, CurrentRevision: cur.SchemaRevision,
		Additive: bundle.Additive(), ExpiresAt: now.Add(PlanTTL),
		ProtectedEnvironments: protectedPinNames(protectedSet),
		Diff:                  planDiff, DeletionsPresent: res.DeletionsPresent(), RevealRequired: res.RevealKeys,
	}, nil
}

// envRevisions maps EVERY environment id to its latest published value
// revision (0 if never published), so the pin detects both a concurrent value
// publish and an environment create/delete.
func (s *Definitions) envRevisions(ctx context.Context, r store.Repos, p authz.Proof, cur definitions.CurrentState) (map[string]int64, error) {
	published, err := r.Snapshots().ProjectRevisions(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(cur.Environments))
	for _, e := range cur.Environments {
		out[e.ID] = published[e.ID]
	}
	return out, nil
}

// GetPlan returns a stored plan's view.
func (s *Definitions) GetPlan(ctx context.Context, actor Actor, scope domain.Scope, planID string) (PlanView, error) {
	var view PlanView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsPlanGet, scope)
		if err != nil {
			return err
		}
		plan, err := r.Definitions().GetPlan(ctx, p, planID)
		if err != nil {
			return err
		}
		view, err = planViewOf(plan)
		return err
	})
	return view, err
}

// planViewOf reconstructs a plan view from a stored row.
func planViewOf(plan store.DefinitionsPlan) (PlanView, error) {
	var diff PlanDiff
	if err := json.Unmarshal([]byte(plan.Diff), &diff); err != nil {
		return PlanView{}, fmt.Errorf("service: plan %s: stored diff unreadable: %w", plan.ID, err)
	}
	var base *int64
	if !plan.Additive {
		b := plan.BaseSchemaRevision
		base = &b
	}
	var protected []protectedEnvironmentPin
	if err := json.Unmarshal([]byte(plan.ProtectedEnvs), &protected); err != nil {
		return PlanView{}, fmt.Errorf("service: plan %s: stored protected-environment pin unreadable: %w", plan.ID, err)
	}
	return PlanView{
		ID: plan.ID, Digest: plan.Digest, BaseRevision: base, CurrentRevision: plan.BaseSchemaRevision,
		Additive: plan.Additive, ExpiresAt: plan.ExpiresAt,
		ProtectedEnvironments: protectedPinNames(protected),
		Diff:                  diff, DeletionsPresent: len(diff.KeyDeletions) > 0 || len(diff.EnvDeletions) > 0 ||
			len(diff.Environments.Deletes) > 0 || len(diff.KeyGroups.Deletes) > 0,
		RevealRequired: diff.RevealRequired,
	}, nil
}
