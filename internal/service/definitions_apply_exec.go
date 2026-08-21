package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// Apply is the one write path a git-mode project allows. It re-checks every pin
// the plan recorded, then executes the whole final definition set through the
// store layer in ONE transaction — creates, deletes, name swaps, presence,
// groups — bumps the revision once, and fans schema publish out over every
// environment immediately before commit.
func (s *Definitions) Apply(ctx context.Context, actor Actor, scope domain.Scope, planID string, opts ApplyOptions) (ApplyResult, error) {
	commit, err := sanitizeProvenance("commit", opts.Commit)
	if err != nil {
		return ApplyResult{}, err
	}
	ref, err := sanitizeProvenance("ref", opts.Ref)
	if err != nil {
		return ApplyResult{}, err
	}
	actorLabel, err := sanitizeProvenance("actor", opts.Actor)
	if err != nil {
		return ApplyResult{}, err
	}

	// Surface-2 re-scan on ruleset-snapshot skew (#74 SS3, ADR §7 (c)), BEFORE
	// prepareSchemaPublish. The publish preparation mints the project DEK on first
	// use, in its OWN transaction outside the apply write — so a scan that refused
	// only inside the write transaction would roll the write back but leave that
	// minted DEK row behind (the F2a orphan-key bug scanSurface2Preflight closes).
	// This pre-flight reaches the verdict in a read transaction before the mint, so
	// a skew-blocked apply persists NOTHING but the finding_blocked events. A
	// same-version apply runs no scan here and returns no overrides.
	overrides, err := s.scanApplySkew(ctx, actor, scope, planID, opts.Acknowledgements)
	if err != nil {
		return ApplyResult{}, err
	}

	publisher, err := prepareSchemaPublish(ctx, s.DB, s.Keyring, s.Advisory, s.Budget, actor, authz.OpDefinitionsApply, scope)
	if err != nil {
		return ApplyResult{}, err
	}

	var result ApplyResult
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		now := s.now()
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsApply, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		plan, err := r.Definitions().GetPlan(ctx, p, planID)
		if err != nil {
			return err
		}
		if plan.Applied {
			return &detailErr{detail: "plan already applied; re-plan", err: fmt.Errorf("%w: plan %s is already applied", domain.ErrConflict, planID)}
		}
		if !now.Before(plan.ExpiresAt) {
			return &detailErr{detail: "plan expired; re-plan", err: fmt.Errorf("%w: plan %s expired", domain.ErrConflict, planID)}
		}

		bundle, err := definitions.Parse([]byte(plan.Bundle))
		if err != nil {
			return fmt.Errorf("service: plan %s: stored bundle unreadable: %w", planID, err)
		}
		cur, err := buildCurrentState(ctx, r.Catalogue(), r.Environments(), p)
		if err != nil {
			return err
		}

		if err := s.recheckPins(ctx, r, az, caller, p, scope, plan, bundle, cur, opts); err != nil {
			return err
		}

		if bundle.Additive() && opts.AllowDelete {
			return fmt.Errorf("%w: additive bundle derives no deletion; --allow-delete is meaningless", domain.ErrInvalid)
		}
		res, err := definitions.Resolve(bundle, cur)
		if err != nil {
			return err
		}
		if err := validateFinalDefinitions(cur, res); err != nil {
			return err
		}
		if res.Empty() {
			result = ApplyResult{Revision: cur.SchemaRevision, Published: []string{}, PlanID: planID}
			return nil
		}

		if err := s.guardDeletions(ctx, r, az, caller, p, scope, plan, res, opts); err != nil {
			return err
		}
		if err := s.enforceReveal(ctx, r, az, caller, p, scope, res); err != nil {
			return err
		}

		if err := s.executeResolution(ctx, r, az, caller, p, scope, res, cur, cur.SchemaRevision+1); err != nil {
			return err
		}
		if err := r.Catalogue().BumpSchemaRevision(ctx, p); err != nil {
			return err
		}
		newRevision, err := r.Catalogue().SchemaRevision(ctx, p)
		if err != nil {
			return err
		}

		applied, err := r.Definitions().MarkPlanApplied(ctx, p, planID, store.PlanApplyStamp{
			AppliedAt: now, AppliedBy: string(caller.Principal), Commit: commit, Ref: ref, Actor: actorLabel,
		})
		if err != nil {
			return err
		}
		if !applied {
			return fmt.Errorf("%w: plan %s is already applied", domain.ErrConflict, planID)
		}

		ev, err := domainEvent(ctx, audit.EventDefinitionsApplied, caller.Principal,
			audit.Object{Type: "definitions-plan", ID: planID}, audit.Payload{
				"plan_id":  planID,
				"revision": newRevision,
				"commit":   audit.SanitizeFreeText(commit),
				"ref":      audit.SanitizeFreeText(ref),
				"actor":    audit.SanitizeFreeText(actorLabel),
			})
		if err != nil {
			return err
		}
		if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
			return err
		}
		// finding_overridden for each skew re-scan finding the caller acknowledged,
		// committed in the apply's own transaction (ADR §5,§7). Empty on a
		// same-version apply, which ran no scan.
		if err := emitOverrides(ctx, r, p, caller.Principal, overrides); err != nil {
			return err
		}

		if err := publisher.fanOut(ctx, r, az, caller, p, scope, "definitions-apply"); err != nil {
			return err
		}
		published, err := r.Environments().List(ctx, p)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(published))
		for _, e := range published {
			names = append(names, e.Name)
		}
		result = ApplyResult{Revision: newRevision, Published: names, PlanID: planID}
		return nil
	})
	if err == nil {
		publisher.announce(scope)
	}
	return result, err
}

// scanApplySkew is the apply-time Surface-2 re-scan (#74 SS3, ADR §7 (c)),
// reached in a READ-only transaction before prepareSchemaPublish so a refusal
// mints no project DEK (see Apply's call site). It re-scans the plan's pinned
// bundle ONLY when the running ruleset snapshot differs from the one the plan
// recorded — a same-version apply is a scanner no-op (identical bytes, identical
// ruleset). On a finding it CAPTURES the finding_blocked events (ingress `apply`)
// and returns *scanRefusalErr; the read wrote nothing else, so settleDenials
// flushes the blocks while nothing else persists. On acceptance it returns the
// overridden acks for the caller to emit with the apply's write transaction.
//
// An already-applied or expired plan re-scans nothing: the write transaction
// yields the proper conflict, and blocking a plan that cannot apply would emit
// spurious events.
func (s *Definitions) scanApplySkew(ctx context.Context, actor Actor, scope domain.Scope, planID string, acks []string) ([]overrideAck, error) {
	if s.Scan == nil {
		return nil, nil // scanning off (pre-#74 test); a booted server always wires it
	}
	var overrides []overrideAck
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpDefinitionsApply, scope)
		if err != nil {
			return err
		}
		plan, err := r.Definitions().GetPlan(ctx, p, planID)
		if err != nil {
			return err
		}
		if plan.Applied || !s.now().Before(plan.ExpiresAt) {
			return nil // the write transaction produces the applied/expired conflict
		}
		if plan.ScanSnapshot == s.Scan.SnapshotVersion() {
			return nil // no skew: a same-version apply adds no second scan
		}
		bundle, err := definitions.Parse([]byte(plan.Bundle))
		if err != nil {
			return fmt.Errorf("service: plan %s: stored bundle unreadable: %w", planID, err)
		}
		res, err := scanDeclaration(ctx, s.Keyring, s.Scan, bundleLeaves(bundle), newAckSet(acks), s.now(), ingressApply)
		if err != nil {
			return err
		}
		if res.refuses() {
			for _, f := range res.blocked {
				ev, evErr := blockedEvent(ctx, caller.Principal, f)
				if evErr != nil {
					return evErr
				}
				az.CaptureAudit(audit.TrailTenant, domain.Scope{Org: scope.Org, Project: scope.Project}, ev)
			}
			return &scanRefusalErr{blocked: res.blocked, rejections: res.rejections}
		}
		overrides = res.overridden
		return nil
	})
	if err != nil {
		return nil, err
	}
	return overrides, nil
}

// recheckPins refuses the apply if the file digest or any pinned revision moved
// since the plan (#70, ADR § Plan and apply). Each refusal names what moved and
// records the rollback-surviving apply_rejected_stale event.
func (s *Definitions) recheckPins(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, plan store.DefinitionsPlan, bundle definitions.Bundle, cur definitions.CurrentState, opts ApplyOptions) error {
	moved := func(what string) error {
		ev, evErr := newAuditEvent(ctx, audit.EventDefinitionsApplyRejectedStale, caller.Principal,
			audit.Object{Type: "definitions-plan", ID: plan.ID}, audit.OutcomeDenied, "",
			audit.Payload{"plan_id": plan.ID, "moved": what})
		if evErr != nil {
			return evErr
		}
		az.CaptureAudit(audit.TrailTenant, domain.Scope{Org: scope.Org, Project: scope.Project}, ev)
		return &detailErr{
			detail: fmt.Sprintf("%s moved since the plan — re-export and re-plan", what),
			err:    fmt.Errorf("%w: stale plan pin (%s)", domain.ErrConflict, what),
		}
	}

	storedDigest, err := definitions.Digest(bundle)
	if err != nil {
		return fmt.Errorf("service: plan %s: stored bundle digest: %w", plan.ID, err)
	}
	if storedDigest != plan.Digest || (opts.Digest != "" && opts.Digest != plan.Digest) {
		return moved("bundle digest")
	}
	curRevs, err := s.envRevisions(ctx, r, p, cur)
	if err != nil {
		return err
	}
	var storedRevs map[string]int64
	if err := jsonUnmarshal(plan.EnvRevisions, &storedRevs); err != nil {
		return err
	}
	if !sameRevisionKeys(curRevs, storedRevs) {
		return moved("environment topology")
	}
	if cur.SchemaRevision != plan.BaseSchemaRevision {
		return moved("definitions revision")
	}
	if id, changed := changedRevision(curRevs, storedRevs); changed {
		name := id
		for _, env := range cur.Environments {
			if env.ID == id {
				name = env.Name
				break
			}
		}
		return moved(fmt.Sprintf("environment %q value revision", name))
	}

	protection, err := r.Environments().ListProtection(ctx, p)
	if err != nil {
		return err
	}
	var storedProtected []protectedEnvironmentPin
	if err := jsonUnmarshal(plan.ProtectedEnvs, &storedProtected); err != nil {
		return err
	}
	currentNames := make(map[string]string, len(cur.Environments))
	for _, env := range cur.Environments {
		currentNames[env.ID] = env.Name
	}
	if protectedSetGrew(protectedPinIDs(storedProtected), protectedPinIDs(protectedPins(protection, currentNames))) {
		return moved("the protected-environment set")
	}
	return nil
}

// guardDeletions enforces the two deletion guards: a plan carrying any deletion
// needs --allow-delete, and an environment holding any live occurrence is
// refused unconditionally.
func (s *Definitions) guardDeletions(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, plan store.DefinitionsPlan, res definitions.Resolution, opts ApplyOptions) error {
	refuse := func(detail string) error {
		ev, evErr := newAuditEvent(ctx, audit.EventDefinitionsDeletionRefused, caller.Principal,
			audit.Object{Type: "definitions-plan", ID: plan.ID}, audit.OutcomeDenied, "",
			audit.Payload{"plan_id": plan.ID})
		if evErr != nil {
			return evErr
		}
		az.CaptureAudit(audit.TrailTenant, domain.Scope{Org: scope.Org, Project: scope.Project}, ev)
		return &detailErr{detail: detail, err: fmt.Errorf("%w: %s", domain.ErrConflict, detail)}
	}
	// Environment deletion with any live occurrence is refused even with
	// --allow-delete: dropping an environment discards every value in it.
	for _, del := range res.EnvDeletes {
		count, err := r.Values().CountEnvironmentValues(ctx, p, del.ID)
		if err != nil {
			return err
		}
		if count > 0 {
			return refuse(fmt.Sprintf("environment %q holds %d live values and must be emptied before it can be deleted", del.Name, count))
		}
	}
	if res.DeletionsPresent() && !opts.AllowDelete {
		return refuse("plan deletes definitions; pass --allow-delete")
	}
	return nil
}

// enforceReveal runs the inherited reveal gate for a value-dependent rule
// change on a secret key. A secret → config update is refused here before the
// apply executor: only the interactive declassification ceremony may do it.
func (s *Definitions) enforceReveal(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, res definitions.Resolution) error {
	for _, upd := range res.KeyUpdates {
		if !definitions.NeedsReveal(upd) {
			continue
		}
		key, err := r.Catalogue().Get(ctx, p, upd.ID)
		if err != nil {
			return err
		}
		wasSecret := upd.PrevClassification == string(schema.Secret)
		if wasSecret && upd.DeclChanged {
			if err := revealGate(ctx, az, caller, scope, authz.OpKeySecretRuleChange, key, "value-dependent-rule-change"); err != nil {
				return &detailErr{
					detail: fmt.Sprintf("definitions apply requires reveal for key %q", key.Name),
					err:    err,
				}
			}
		}
		if wasSecret && upd.Desired.Classification == string(schema.Config) {
			return refuseApplyDeclassification(key.Name)
		}
	}
	return nil
}

// refuseApplyDeclassification closes Surface 1 for the definitions Git flow:
// apply has no plaintext legitimately in process to scan and ADR §6 forbids
// decrypting it without the disclosure ceremony. The equivalent direct
// transition also requires revealGate because config values escape the reveal
// ceremony; allowing apply to perform it would bypass that reauthentication.
func refuseApplyDeclassification(keyName string) error {
	detail := fmt.Sprintf("definitions apply cannot declassify key %q from secret to config: apply has no plaintext to run the Surface-1 scanner and must not decrypt it outside ceremony; use interactive `key reclassify` / declassification ceremony, which performs disclosure-class reauthentication and scanning", keyName)
	return &detailErr{detail: detail, err: fmt.Errorf("%w: %s", domain.ErrInvalid, detail)}
}

func jsonUnmarshal(s string, v any) error {
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("service: definitions plan: unreadable pin: %w", err)
	}
	return nil
}

func sameRevisionKeys(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

func changedRevision(a, b map[string]int64) (string, bool) {
	ids := make([]string, 0, len(a))
	for id := range a {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if a[id] != b[id] {
			return id, true
		}
	}
	return "", false
}

// protectedSetGrew reports whether the current protected id set contains any id
// absent from the pinned set. A rename keeps the id, so it never trips this; a
// newly protected environment does.
func protectedSetGrew(pinned, current []string) bool {
	was := make(map[string]bool, len(pinned))
	for _, id := range pinned {
		was[id] = true
	}
	for _, id := range current {
		if !was[id] {
			return true
		}
	}
	return false
}

// executeResolution writes the final definition set to the store in the order
// that keeps every intermediate state legal: deletes free names first, creates
// and the two-phase rename resolve swaps, and key creates/updates resolve their
// group and presence references against the final topology.
func (s *Definitions) executeResolution(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, res definitions.Resolution, cur definitions.CurrentState, finalRevision int64) error {
	now := s.now()

	// 1. Key deletes: clear the key's live values (so the foreign key admits the
	// delete), drop its presence and scanning-dismissal rows, then delete it.
	// Adapter-pinned keys are refused, reusing the ceremony's own check.
	for _, del := range res.KeyDeletes {
		key, err := r.Catalogue().Get(ctx, p, del.ID)
		if err != nil {
			return err
		}
		if err := refuseAdapterPinnedKey(ctx, r.Catalogue(), p, key); err != nil {
			return err
		}
		if _, err := r.Values().ClearKey(ctx, p, del.ID); err != nil {
			return err
		}
		if err := r.Catalogue().ReplacePresence(ctx, p, del.ID, nil); err != nil {
			return err
		}
		if _, err := r.Pending().DiscardKey(ctx, p, del.ID); err != nil {
			return err
		}
		if _, err := r.ScanningDismissals().DeleteByKey(ctx, p, del.ID); err != nil {
			return err
		}
		if err := r.Catalogue().Delete(ctx, p, del.ID); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyDeleted, "key", del.ID,
			audit.Payload{"name": audit.SanitizeFreeText(del.Name)}); err != nil {
			return err
		}
	}

	// 2. Group deletes: release members, then delete.
	for _, del := range res.GroupDeletes {
		members, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		released := 0
		for _, key := range members {
			if key.GroupID == del.ID {
				released++
			}
		}
		if err := r.Catalogue().ClearGroupMembers(ctx, p, del.ID); err != nil {
			return err
		}
		if err := r.Catalogue().DeleteGroup(ctx, p, del.ID); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyGroupDeleted, "key_group", del.ID,
			audit.Payload{"name": audit.SanitizeFreeText(del.Name), "members_released": released}); err != nil {
			return err
		}
	}

	// 3. Environment deletes: authorize OpEnvDelete per environment (it is env
	// scoped) and cascade, minus value clearing — a live environment was already
	// refused, so an empty one leaves nothing to clear.
	for _, del := range res.EnvDeletes {
		if err := s.deleteEnvironment(ctx, r, az, caller, scope, del.ID); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventEnvDeleted, "environment", del.ID,
			audit.Payload{"name": audit.SanitizeFreeText(del.Name)}); err != nil {
			return err
		}
	}

	// 4. Park every renamed identity first. This frees old names before a
	// create claims one of them, while retaining the two-phase swap guarantee.
	parked, err := s.parkRenames(ctx, r, az, caller, p, scope, res, cur)
	if err != nil {
		return err
	}

	// 5. Environment creates: append at the next display position.
	envIDByName := make(map[string]string, len(cur.Environments)+len(res.EnvCreates))
	for _, e := range cur.Environments {
		envIDByName[e.Name] = e.ID
	}
	// Drop deleted environments from the resolution map.
	for _, del := range res.EnvDeletes {
		for name, id := range envIDByName {
			if id == del.ID {
				delete(envIDByName, name)
			}
		}
	}
	for _, name := range res.EnvCreates {
		id, err := newID("env")
		if err != nil {
			return err
		}
		order, err := r.Environments().NextOrder(ctx, p)
		if err != nil {
			return err
		}
		if err := r.Environments().Create(ctx, p, store.NewEnvironment{
			ID: id, Name: name, DisplayOrder: order, CreatedAt: now,
		}); err != nil {
			return err
		}
		envIDByName[name] = id
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventEnvCreated, "environment", id,
			audit.Payload{"name": audit.SanitizeFreeText(name)}); err != nil {
			return err
		}
	}

	// 6. Group creates.
	groupIDByName := make(map[string]string, len(cur.KeyGroups)+len(res.GroupCreates))
	for _, g := range cur.KeyGroups {
		groupIDByName[g.Name] = g.ID
	}
	for _, del := range res.GroupDeletes {
		for name, id := range groupIDByName {
			if id == del.ID {
				delete(groupIDByName, name)
			}
		}
	}
	for _, name := range res.GroupCreates {
		id, err := newID("kgr")
		if err != nil {
			return err
		}
		if err := r.Catalogue().CreateGroup(ctx, p, store.NewCatalogueGroup{ID: id, Name: name, CreatedAt: now}); err != nil {
			return err
		}
		groupIDByName[name] = id
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyGroupCreated, "key_group", id,
			audit.Payload{"name": audit.SanitizeFreeText(name)}); err != nil {
			return err
		}
	}

	// 7. Finalize parked renames after creates have claimed any old names.
	if err := s.finishRenames(ctx, r, az, caller, p, scope, res, parked, envIDByName, groupIDByName); err != nil {
		return err
	}

	// 8. Key creates and updates, resolving group and presence names to the
	// final topology's ids.
	for _, k := range res.KeyCreates {
		if err := s.createKey(ctx, r, caller, p, k, envIDByName, groupIDByName); err != nil {
			return err
		}
	}
	for _, upd := range res.KeyUpdates {
		if err := s.updateKey(ctx, r, caller, p, upd, envIDByName, groupIDByName, finalRevision); err != nil {
			return err
		}
	}
	return nil
}

func insertDefinitionEvent(ctx context.Context, r store.Repos, p authz.Proof, caller authz.Identity,
	typeName audit.EventType, objectType, objectID string, payload audit.Payload) error {
	event, err := domainEvent(ctx, typeName, caller.Principal, audit.Object{Type: objectType, ID: objectID}, payload)
	if err != nil {
		return err
	}
	return r.Audit().InsertTenant(ctx, p, event)
}

// deleteEnvironment authorizes an env-scoped OpEnvDelete and cascades the
// environment out, mirroring Environments.Delete's store sequence minus value
// clearing (a live environment was already refused).
func (s *Definitions) deleteEnvironment(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	scope domain.Scope, envID string) error {
	envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
	ep, err := az.Authorize(ctx, caller, authz.OpEnvDelete, envScope)
	if err != nil {
		return err
	}
	if err := r.Pending().DiscardEnvironment(ctx, ep); err != nil {
		return err
	}
	if err := r.Snapshots().DeleteEnvironment(ctx, ep); err != nil {
		return err
	}
	if err := r.Pins().DeleteEnvironment(ctx, ep); err != nil {
		return err
	}
	if err := r.Catalogue().DeletePresenceForEnvironment(ctx, ep); err != nil {
		return err
	}
	return r.Environments().Delete(ctx, ep)
}

type parkedRenames struct {
	keys []struct{ id, to string }
}

// parkRenames moves every renamed identity to a reserved temporary name.
func (s *Definitions) parkRenames(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, res definitions.Resolution, cur definitions.CurrentState) (parkedRenames, error) {
	used := map[string]bool{}
	for _, e := range cur.Environments {
		used[e.Name] = true
	}
	for _, g := range cur.KeyGroups {
		used[g.Name] = true
	}
	for _, k := range cur.Keys {
		used[k.Name] = true
	}
	for _, name := range res.EnvCreates {
		used[name] = true
	}
	for _, name := range res.GroupCreates {
		used[name] = true
	}
	for _, key := range res.KeyCreates {
		used[key.Name] = true
	}
	for _, rename := range res.EnvRenames {
		used[rename.To] = true
	}
	for _, rename := range res.GroupRenames {
		used[rename.To] = true
	}
	for _, update := range res.KeyUpdates {
		used[update.Desired.Name] = true
	}
	counter := 0
	temp := func() string {
		for {
			name := fmt.Sprintf("TMP_RENAME_%d", counter)
			counter++
			if !used[name] {
				used[name] = true
				return name
			}
		}
	}

	var parked parkedRenames
	for _, upd := range res.KeyUpdates {
		if upd.Renamed {
			parked.keys = append(parked.keys, struct{ id, to string }{id: upd.ID, to: upd.Desired.Name})
		}
	}

	// Phase 1: everything renamed goes to a fresh temp name.
	for i := range res.EnvRenames {
		t := temp()
		if err := s.renameEnv(ctx, r, az, caller, scope, res.EnvRenames[i].ID, t); err != nil {
			return parkedRenames{}, err
		}
	}
	for i := range res.GroupRenames {
		if err := r.Catalogue().RenameGroup(ctx, p, res.GroupRenames[i].ID, temp()); err != nil {
			return parkedRenames{}, err
		}
	}
	for _, kr := range parked.keys {
		if err := r.Catalogue().Rename(ctx, p, kr.id, temp()); err != nil {
			return parkedRenames{}, err
		}
	}
	return parked, nil
}

// finishRenames moves parked identities to their final names.
func (s *Definitions) finishRenames(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	p authz.Proof, scope domain.Scope, res definitions.Resolution, parked parkedRenames,
	envIDByName, groupIDByName map[string]string) error {
	for i := range res.EnvRenames {
		if err := s.renameEnv(ctx, r, az, caller, scope, res.EnvRenames[i].ID, res.EnvRenames[i].To); err != nil {
			return err
		}
		envIDByName[res.EnvRenames[i].To] = res.EnvRenames[i].ID
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventEnvRenamed, "environment", res.EnvRenames[i].ID,
			audit.Payload{"previous_name": audit.SanitizeFreeText(res.EnvRenames[i].From), "name": audit.SanitizeFreeText(res.EnvRenames[i].To)}); err != nil {
			return err
		}
	}
	for i := range res.GroupRenames {
		if err := r.Catalogue().RenameGroup(ctx, p, res.GroupRenames[i].ID, res.GroupRenames[i].To); err != nil {
			return err
		}
		groupIDByName[res.GroupRenames[i].To] = res.GroupRenames[i].ID
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyGroupRenamed, "key_group", res.GroupRenames[i].ID,
			audit.Payload{"previous_name": audit.SanitizeFreeText(res.GroupRenames[i].From), "name": audit.SanitizeFreeText(res.GroupRenames[i].To)}); err != nil {
			return err
		}
	}
	for _, kr := range parked.keys {
		if err := r.Catalogue().Rename(ctx, p, kr.id, kr.to); err != nil {
			return err
		}
		from := ""
		for _, upd := range res.KeyUpdates {
			if upd.ID == kr.id {
				from = upd.PrevName
				break
			}
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyRenamed, "key", kr.id,
			audit.Payload{"previous_name": audit.SanitizeFreeText(from), "name": audit.SanitizeFreeText(kr.to)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Definitions) renameEnv(ctx context.Context, r store.Repos, az *authz.TxAuthorizer, caller authz.Identity,
	scope domain.Scope, envID, name string) error {
	envScope := domain.Scope{Org: scope.Org, Project: scope.Project, Env: domain.EnvID(envID)}
	ep, err := az.Authorize(ctx, caller, authz.OpEnvRename, envScope)
	if err != nil {
		return err
	}
	return r.Environments().Rename(ctx, ep, name)
}

func (s *Definitions) createKey(ctx context.Context, r store.Repos, caller authz.Identity, p authz.Proof, k definitions.Key,
	envIDByName, groupIDByName map[string]string) error {
	presence, err := resolvePresence(k, envIDByName)
	if err != nil {
		return err
	}
	if err := checkClassifiedDeclaration(k.Classification, k.Declaration, presence); err != nil {
		return err
	}
	canonical, err := schema.Canonical(k.Declaration)
	if err != nil {
		return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
	}
	id, err := newID("key")
	if err != nil {
		return err
	}
	groupID := ""
	if k.Group != "" {
		groupID = groupIDByName[k.Group]
	}
	if err := r.Catalogue().Create(ctx, p, store.NewCatalogueKey{
		ID: id, Name: k.Name, FolderPath: k.FolderPath, Classification: k.Classification,
		Description: k.Description, Deprecated: k.Deprecated, DeprecationNote: k.DeprecationNote,
		Declaration:  string(canonical),
		RequiredMode: string(presence.Required.Mode), ForbiddenMode: string(presence.Forbidden.Mode),
		GroupID: groupID, CreatedAt: s.now(),
	}); err != nil {
		return err
	}
	if err := r.Catalogue().ReplacePresence(ctx, p, id, presenceRowsFor(id, presence)); err != nil {
		return err
	}
	return insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyCreated, "key", id, audit.Payload{
		"name": audit.SanitizeFreeText(k.Name), "classification": k.Classification,
		"namespace": audit.SanitizeFreeText(k.FolderPath),
	})
}

func (s *Definitions) updateKey(ctx context.Context, r store.Repos, caller authz.Identity, p authz.Proof, upd definitions.KeyUpdate,
	envIDByName, groupIDByName map[string]string, finalRevision int64) error {
	k := upd.Desired
	before, err := r.Catalogue().Get(ctx, p, upd.ID)
	if err != nil {
		return err
	}
	presence, err := resolvePresence(k, envIDByName)
	if err != nil {
		return err
	}
	if err := checkClassifiedDeclaration(k.Classification, k.Declaration, presence); err != nil {
		return err
	}
	// Rename was already applied in the two-phase pass; metadata, declaration,
	// presence, classification and group are written here.
	if upd.MetaChanged {
		if err := r.Catalogue().UpdateMetadata(ctx, p, upd.ID, store.KeyMetadata{
			FolderPath: k.FolderPath, Description: k.Description,
			Deprecated: k.Deprecated, DeprecationNote: k.DeprecationNote,
		}); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyMetadataChanged, "key", upd.ID,
			audit.Payload{"name": audit.SanitizeFreeText(k.Name), "namespace": audit.SanitizeFreeText(k.FolderPath)}); err != nil {
			return err
		}
	}
	if upd.DeclChanged || upd.PresenceChanged {
		canonical, err := schema.Canonical(k.Declaration)
		if err != nil {
			return fmt.Errorf("%w: %s", domain.ErrInvalid, err)
		}
		if err := r.Catalogue().UpdateDeclaration(ctx, p, upd.ID, store.KeyDeclaration{
			Declaration:  string(canonical),
			RequiredMode: string(presence.Required.Mode), ForbiddenMode: string(presence.Forbidden.Mode),
		}); err != nil {
			return err
		}
		if err := r.Catalogue().ReplacePresence(ctx, p, upd.ID, presenceRowsFor(upd.ID, presence)); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyDeclarationChanged, "key", upd.ID, audit.Payload{
			"name": audit.SanitizeFreeText(k.Name), "schema_revision": finalRevision,
			"rules_changed": upd.DeclChanged, "presence_changed": upd.PresenceChanged,
		}); err != nil {
			return err
		}
	}
	if upd.Reclassified {
		key, err := r.Catalogue().Get(ctx, p, upd.ID)
		if err != nil {
			return err
		}
		if err := refuseAdapterPinnedKey(ctx, r.Catalogue(), p, key); err != nil {
			return err
		}
		if upd.PrevClassification == string(schema.Secret) && k.Classification == string(schema.Config) {
			// Surface 1 requires declassification to meet the scanner, but apply has
			// no plaintext in process and ADR §6 forbids decrypt-without-ceremony.
			// Direct `key reclassify` also requires disclosure-class revealGate;
			// applying the same transition here would bypass that reauthentication.
			return refuseApplyDeclassification(k.Name)
		}
		if err := r.Catalogue().SetClassification(ctx, p, upd.ID, k.Classification); err != nil {
			return err
		}
		if upd.PrevClassification == string(schema.Config) && k.Classification == string(schema.Secret) {
			// Tightening config → secret makes the key's dismissals moot and drops
			// them (ADR §4 lifecycle), so a later declassification re-fires.
			if _, err := r.ScanningDismissals().DeleteByKey(ctx, p, upd.ID); err != nil {
				return err
			}
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyReclassified, "key", upd.ID, audit.Payload{
			"name": audit.SanitizeFreeText(k.Name), "previous_classification": upd.PrevClassification,
			"classification": k.Classification,
		}); err != nil {
			return err
		}
	}
	if upd.GroupChanged {
		groupID := ""
		if k.Group != "" {
			groupID = groupIDByName[k.Group]
		}
		if err := r.Catalogue().SetGroup(ctx, p, upd.ID, groupID); err != nil {
			return err
		}
		if err := insertDefinitionEvent(ctx, r, p, caller, audit.EventKeyGroupMembershipChanged, "key", upd.ID, audit.Payload{
			"name": audit.SanitizeFreeText(k.Name), "previous_group_id": before.GroupID, "group_id": groupID,
		}); err != nil {
			return err
		}
	}
	return nil
}

// resolvePresence converts a bundle key's presence (env names) to store rules
// (env ids) against the final topology.
func resolvePresence(k definitions.Key, envIDByName map[string]string) (schema.PresenceRules, error) {
	req, err := resolvePresenceRule(k.RequiredIn, envIDByName)
	if err != nil {
		return schema.PresenceRules{}, err
	}
	forb, err := resolvePresenceRule(k.ForbiddenIn, envIDByName)
	if err != nil {
		return schema.PresenceRules{}, err
	}
	return schema.PresenceRules{Required: req, Forbidden: forb}, nil
}

func resolvePresenceRule(p definitions.Presence, envIDByName map[string]string) (schema.Presence, error) {
	out := schema.Presence{Mode: schema.PresenceMode(p.Mode)}
	for _, name := range p.Environments {
		id, ok := envIDByName[name]
		if !ok {
			return schema.Presence{}, fmt.Errorf("%w: presence references unknown environment %q", domain.ErrInvalid, name)
		}
		out.Environments = append(out.Environments, id)
	}
	return out, nil
}

// PruneExpiredPlans deletes expired, unapplied plans across the instance. The
// hourly retention GC calls it; it mints the same scheduler system authority the
// payload sweep uses.
func (s *Definitions) PruneExpiredPlans(ctx context.Context) (int64, error) {
	var pruned int64
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		p, err := authz.SystemAuthority(authz.SiteScheduler, az.Token())
		if err != nil {
			return err
		}
		pruned, err = r.Definitions().PruneExpiredPlans(ctx, p, store.CanonTime(s.now()))
		return err
	})
	return pruned, err
}
