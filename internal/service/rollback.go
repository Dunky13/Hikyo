package service

import (
	"context"
	"fmt"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// RestoreResult is a restore request's ordinary working-state output. The
// caller must publish the returned version ids through the normal pipeline.
type RestoreResult struct {
	Revision int64
	Changes  []StagedChange
	Preview  ImpactPreview
}

// Restore stages the two-way difference between one historical snapshot and
// the current published state. keyName narrows the comparison to one key; an
// empty name compares the whole environment.
func (s *Revisions) Restore(ctx context.Context, actor Actor, scope domain.Scope, revision int64, keyName string) (RestoreResult, error) {
	if scope.Env == "" {
		return RestoreResult{}, fmt.Errorf("%w: a restore addresses an environment", domain.ErrInvalid)
	}
	if revision <= 0 {
		return RestoreResult{}, invalidDetail("restore revision must be positive")
	}
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpRevisionRestore, scope)
	if err != nil {
		return RestoreResult{}, err
	}

	type announcement struct {
		keyID string
		name  string
		owner domain.PrincipalID
	}
	var announced []announcement
	stickySecret := map[string]bool{}
	out := RestoreResult{Revision: revision}
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out.Changes = nil
		out.Preview = ImpactPreview{}
		announced = nil
		clear(stickySecret)
		now := s.now()
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRevisionRestore, scope)
		if err != nil {
			return err
		}
		if err := r.Projects().Lock(ctx, p); err != nil {
			return err
		}
		latest, err := r.Snapshots().Latest(ctx, p)
		if err != nil {
			return err
		}
		target, err := r.Snapshots().AtRevision(ctx, p, revision)
		if err != nil {
			return err
		}
		if !target.PayloadPresent {
			return collectedRevisionError(target)
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		allKeys := keys
		if keyName != "" {
			key, err := keyByName(keys, keyName)
			if err != nil {
				return err
			}
			keys = []store.CatalogueKey{key}
		}
		targetEntries, err := r.Snapshots().Entries(ctx, p, target)
		if err != nil {
			return err
		}
		if keyName == "" {
			if err := validateSnapshotEntryKeys("revision", revision, keys, targetEntries); err != nil {
				return err
			}
		} else {
			for _, entry := range targetEntries {
				if entry.KeyName == keyName && entry.KeyID != keys[0].ID {
					return invalidDetail("revision %d contains an earlier key named %q with a different identity; refusing to clear its replacement", revision, keyName)
				}
			}
		}
		targetByKey := make(map[string]store.SnapshotEntry, len(targetEntries))
		for _, entry := range targetEntries {
			targetByKey[entry.KeyID] = entry
		}
		currentEntries, err := r.Values().List(ctx, p)
		if err != nil {
			return err
		}
		currentByKey := make(map[string]store.ValueEntry, len(currentEntries))
		for _, entry := range currentEntries {
			currentByKey[entry.KeyID] = entry
		}
		valueEntryIDs := make(map[string]struct{}, len(targetEntries)+len(currentEntries))
		for _, entry := range targetEntries {
			valueEntryIDs[entry.ValueEntryID] = struct{}{}
		}
		for _, entry := range currentEntries {
			valueEntryIDs[entry.ID] = struct{}{}
		}
		stickyValueSecrets, err := stickySecretValueEntries(ctx, r, p, valueEntryIDs)
		if err != nil {
			return err
		}

		historicalSecrets := make(map[string]store.SnapshotEntry)
		currentSecrets := make(map[string]bool)
		if target.Revision != latest.Revision {
			currentClassification := make(map[string]string, len(allKeys))
			for _, key := range allKeys {
				currentClassification[key.ID] = key.Classification
			}
			unit := make([]string, 0, len(keys))
			needsHistoricalReveal := false
			needsCurrentReveal := false
			for _, key := range keys {
				entry, ok := targetByKey[key.ID]
				currentEntry, currentSet := currentByKey[key.ID]
				historicalSecret := ok && (entry.Classification == string(schema.Secret) ||
					stickyValueSecrets[entry.ValueEntryID])
				// Current plaintext is opened only to compare two set values. A
				// restore-to-absent clear never reads it and therefore must not
				// demand the current reveal formula.
				currentSecret := ok && currentSet && (currentClassification[key.ID] == string(schema.Secret) ||
					stickyValueSecrets[currentEntry.ID])
				if !historicalSecret && !currentSecret {
					continue
				}
				unit = append(unit, key.ID)
				if historicalSecret {
					needsHistoricalReveal = true
					historicalSecrets[key.ID] = entry
				}
				if currentSecret {
					needsCurrentReveal = true
					currentSecrets[key.ID] = true
				}
			}
			if needsHistoricalReveal {
				if _, err := az.Authorize(ctx, caller, authz.OpRevisionRestoreHistory, scope); err != nil {
					return err
				}
			}
			if needsCurrentReveal {
				if _, err := az.Authorize(ctx, caller, authz.OpRevisionRestoreCurrent, scope); err != nil {
					return err
				}
			}
			if len(unit) > 0 {
				intent, err := NewRevealReauthIntent(string(scope.Env), unit)
				if err != nil {
					return err
				}
				if err := requireCeremony(ctx, s.Auth, az, caller, intent); err != nil {
					return err
				}
			}
		}
		for _, key := range keys {
			if target.Revision == latest.Revision {
				continue
			}
			targetEntry, targetSet := targetByKey[key.ID]
			currentEntry, currentSet := currentByKey[key.ID]
			operation := store.PendingUnset
			value := ""
			changed := targetSet != currentSet
			if targetSet {
				plain, err := sealer.OpenField(snapshotAAD(
					targetEntry.OrgID, targetEntry.ProjectID, targetEntry.EnvironmentID,
					targetEntry.KeyID, targetEntry.SnapshotID, targetEntry.ID), targetEntry.Ciphertext)
				if err != nil {
					return fmt.Errorf("service: snapshot entry %s: %w", targetEntry.ID, err)
				}
				value = string(plain)
				if historical, ok := historicalSecrets[key.ID]; ok {
					if err := auditSnapshotDisclosure(ctx, r.Audit(), p, caller.Principal,
						historical, "restore", target.Revision); err != nil {
						return err
					}
				}
				operation = store.PendingSet
				if currentSet {
					current, err := openCell(sealer, currentEntry)
					if err != nil {
						return err
					}
					if currentSecrets[key.ID] {
						if err := auditSnapshotDisclosure(ctx, r.Audit(), p, caller.Principal,
							store.SnapshotEntry{KeyID: key.ID, KeyName: key.Name}, "restore", latest.Revision); err != nil {
							return err
						}
					}
					changed = current != value
				}
			}
			if !changed {
				continue
			}
			versionID, err := newID("pcv")
			if err != nil {
				return err
			}
			var sealed []byte
			if operation == store.PendingSet {
				sealed, err = sealer.SealField(pendingAAD(
					string(scope.Org), string(scope.Project), string(scope.Env), key.ID, versionID), []byte(value))
				if err != nil {
					return err
				}
				// Writer fence (invariant 7): refuse a restored draft sealed under
				// a DEK version a concurrent rotate-dek retired.
				if err := fenceProject(ctx, r, p, sealer, scope); err != nil {
					return err
				}
			}
			baseline := ""
			if currentSet {
				baseline = currentEntry.ID
			}
			if err := r.Pending().Stage(ctx, p, store.NewPendingChange{
				ID: versionID, KeyID: key.ID, OwnerID: string(caller.Principal),
				Operation: operation, Ciphertext: sealed,
				StagedFromRevision: latest.Revision, StagedFromEntry: baseline,
				CreatedAt: now, Source: store.PendingSourceRestore,
				Secret: targetEntry.Classification == string(schema.Secret) ||
					stickyValueSecrets[targetEntry.ValueEntryID] || stickyValueSecrets[currentEntry.ID] ||
					key.Classification == string(schema.Secret),
				MaterialSecret: operation == store.PendingSet &&
					(targetEntry.Classification == string(schema.Secret) || stickyValueSecrets[targetEntry.ValueEntryID]),
			}); err != nil {
				return err
			}
			ev, err := domainEvent(ctx, audit.EventValueStaged, caller.Principal,
				audit.Object{Type: "key", ID: key.ID}, audit.Payload{
					"key_id": key.ID, "name": audit.SanitizeFreeText(key.Name),
					"classification": key.Classification, "operation": string(operation),
					"version_id": versionID,
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
			out.Changes = append(out.Changes, StagedChange{
				VersionID: versionID, KeyID: key.ID, Name: key.Name,
				Classification: key.Classification, Operation: string(operation),
				StagedFromRevision: latest.Revision, CreatedAt: now,
			})
			stickySecret[versionID] = targetEntry.Classification == string(schema.Secret) ||
				stickyValueSecrets[targetEntry.ValueEntryID] || stickyValueSecrets[currentEntry.ID] ||
				key.Classification == string(schema.Secret)
			announced = append(announced, announcement{keyID: key.ID, name: key.Name, owner: caller.Principal})
		}
		if len(out.Changes) > 0 {
			versionIDs := make([]string, 0, len(out.Changes))
			for _, change := range out.Changes {
				versionIDs = append(versionIDs, change.VersionID)
			}
			out.Preview, err = buildImpactPreview(ctx, r, p, sealer, s.Keyring, az, caller, scope, versionIDs, stickySecret)
			if err != nil {
				return err
			}
		}
		payload := audit.Payload{"revision": revision, "key_count": len(out.Changes)}
		if keyName != "" {
			payload["key"] = audit.SanitizeFreeText(keyName)
		}
		ev, err := domainEvent(ctx, audit.EventRevisionRestoreStaged, caller.Principal,
			audit.Object{Type: "environment", ID: string(scope.Env)}, payload)
		if err != nil {
			return err
		}
		return r.Audit().InsertTenant(ctx, p, ev)
	})
	if err != nil {
		return RestoreResult{}, err
	}
	for _, item := range announced {
		s.Advisory.staged(scope, item.keyID, item.name, item.owner)
	}
	return out, nil
}

func validateSnapshotEntryKeys(subject string, revision int64, keys []store.CatalogueKey, entries []store.SnapshotEntry) error {
	current := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		current[key.ID] = struct{}{}
	}
	for _, entry := range entries {
		if _, ok := current[entry.KeyID]; !ok {
			return invalidDetail("%s %d contains key %q, which is absent from the current schema", subject, revision, entry.KeyName)
		}
	}
	return nil
}
