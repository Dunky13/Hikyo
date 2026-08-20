package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/delivery"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// The read side of the revision model: history, one revision's detail, the
// matrix signals, and the one bulk-disclosure verb (`values export`, which the
// API/CLI ADR fixes as what "fetch resolved" actually is).

// RevisionView is one entry of an environment's history. It is LINEAGE: a
// number, who published it, when, what it pinned, and which keys moved. No
// value in any form, which is what lets lineage be retained forever while
// payloads are collected by policy.
type RevisionView struct {
	Revision       int64
	SchemaRevision int64
	PublishedBy    string
	PublishedAt    time.Time
	ChangedKeys    []ChangedKey
	// PayloadPresent is the collection bit (#52/#53). Lineage outlives its
	// payload, so a history entry says which of the two it still has -- and a
	// surface that offers diff, restore or pin on a collected revision would be
	// offering an act the service refuses. CollectedPolicy is the policy
	// stamped at collection, empty while the payload is present; it is what the
	// named refusal reports forever.
	PayloadPresent  bool
	CollectedPolicy string
}

// RevisionDetail is one revision, plus the change token derived for it under
// the CURRENT root token key.
type RevisionDetail struct {
	RevisionView
	ChangeToken string
	// Keys is the delivered key set of that revision -- names, classifications
	// and write-presence. It is the snapshot's own key set, under the schema
	// revision the snapshot pinned, so a later rename or key deletion does not
	// rewrite what history says was delivered.
	Keys []SnapshotKey
}

// SnapshotKey is one delivered key of one snapshot, without its value. The
// value lives behind Export and its formula; a browse verb never emits one.
type SnapshotKey struct {
	KeyID          string
	Name           string
	Classification string
}

// CellSignal is one `(key, environment)` cell's matrix signals.
//
// Both signals are computed on the RESOLVED value, which in a flat model is
// trivially the cell itself, and both degrade to write-presence for `secret`
// keys: the signal reports that someone WROTE here, never that the plaintext
// differs from the published one. A comparison status is itself an oracle -- a
// principal who can edit but not reveal could stage a guessed value and read
// "unchanged" to confirm it -- so no method here ever compares plaintexts.
type CellSignal struct {
	EnvironmentID  string
	KeyID          string
	Name           string
	Classification string
	// PendingVersionID is the caller's OWN live draft for this cell, "" when
	// they have none. It is the id a selective publish names.
	PendingVersionID string
	PendingOperation string
	// PendingByOthers reports that at least one other principal holds a draft
	// here -- the quieter collision marker, visible before publish time.
	PendingByOthers bool
	// ChangedInRevision is the environment's latest revision when this cell
	// moved in it, 0 otherwise. The "recently changed" signal.
	ChangedInRevision int64
}

// EnvironmentSignals is one environment's advisory state: its current revision
// and its cells' signals. It is the SSE channel's documented polling fallback
// as well as the matrix's ordinary read.
type EnvironmentSignals struct {
	EnvironmentID string
	Revision      int64
	Cells         []CellSignal
}

// PendingDraft is one caller-owned draft in an environment. Value carries
// plaintext only for a revealed config set; secret and unset drafts never
// carry material on this surface.
type PendingDraft struct {
	VersionID          string
	KeyID              string
	Name               string
	Classification     string
	Operation          string
	StagedFromRevision int64
	CreatedAt          time.Time
	Revealed           bool
	Value              string
}

// History lists one environment's revisions, newest first.
func (s *Revisions) History(ctx context.Context, actor Actor, scope domain.Scope) ([]RevisionView, error) {
	var out []RevisionView
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		out = nil
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRevisionList, scope)
		if err != nil {
			return err
		}
		snapshots, err := r.Snapshots().List(ctx, p)
		if err != nil {
			return err
		}
		for _, snapshot := range snapshots {
			changes, err := r.Snapshots().Changes(ctx, p, snapshot.Revision)
			if err != nil {
				return err
			}
			out = append(out, RevisionView{
				Revision: snapshot.Revision, SchemaRevision: snapshot.SchemaRevision,
				PublishedBy: snapshot.PublishedBy, PublishedAt: snapshot.PublishedAt,
				ChangedKeys:    changedKeys(changes),
				PayloadPresent: snapshot.PayloadPresent, CollectedPolicy: collectedPolicy(snapshot),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Show reads one revision, or the latest when revision is 0.
//
// It returns the change token, and that is the point of the verb for a machine
// caller: the token is derived here from the live root token key, so
// `rotate-token-key` moves it while the revision number, the pinned schema
// revision and every pinned value-entry revision stay exactly where they are.
func (s *Revisions) Show(ctx context.Context, actor Actor, scope domain.Scope, revision int64) (RevisionDetail, error) {
	if s.Keyring == nil {
		return RevisionDetail{}, errors.New("service: revision detail requires a keyring")
	}
	var out RevisionDetail
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		out = RevisionDetail{}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRevisionShow, scope)
		if err != nil {
			return err
		}
		snapshot, err := readSnapshot(ctx, r.Snapshots(), p, revision)
		if err != nil {
			return err
		}
		changes, err := r.Snapshots().Changes(ctx, p, snapshot.Revision)
		if err != nil {
			return err
		}
		entries, err := r.Snapshots().Entries(ctx, p, snapshot)
		if err != nil {
			return err
		}
		sealer, err := s.Keyring.ForProject(ctx, string(scope.Org), string(scope.Project))
		if err != nil {
			return err
		}
		rows := make([]delivery.Row, 0, len(entries))
		keys := make([]SnapshotKey, 0, len(entries))
		for _, entry := range entries {
			// The manifest is computed server-side over plaintext because the
			// token must move when a VALUE moves. Nothing decrypted here
			// reaches the caller: the token is keyed and un-invertible, and the
			// key set below carries no value.
			plain, err := sealer.OpenField(snapshotAAD(
				entry.OrgID, entry.ProjectID, entry.EnvironmentID, entry.KeyID, entry.SnapshotID, entry.ID), entry.Ciphertext)
			if err != nil {
				return fmt.Errorf("service: snapshot entry %s: %w", entry.ID, err)
			}
			rows = append(rows, delivery.Row{
				Key: entry.KeyName, Classification: entry.Classification, Value: string(plain),
			})
			keys = append(keys, SnapshotKey{
				KeyID: entry.KeyID, Name: entry.KeyName, Classification: entry.Classification,
			})
		}
		token, err := s.Keyring.ChangeToken(string(scope.Org), string(scope.Project), string(scope.Env),
			delivery.Manifest(rows))
		if err != nil {
			return err
		}
		out = RevisionDetail{
			RevisionView: RevisionView{
				Revision: snapshot.Revision, SchemaRevision: snapshot.SchemaRevision,
				PublishedBy: snapshot.PublishedBy, PublishedAt: snapshot.PublishedAt,
				ChangedKeys:     changedKeys(changes),
				PayloadPresent:  snapshot.PayloadPresent,
				CollectedPolicy: snapshot.CollectedPolicy,
			},
			ChangeToken: token,
			Keys:        keys,
		}
		return nil
	})
	if err != nil {
		return RevisionDetail{}, err
	}
	return out, nil
}

// readSnapshot resolves "latest" (revision 0) or one named revision. Payload
// consumers turn its durable presence fields into the named refusal below.
func readSnapshot(ctx context.Context, snapshots store.SnapshotReader, p authz.Proof, revision int64) (store.Snapshot, error) {
	if revision <= 0 {
		return snapshots.Latest(ctx, p)
	}
	return snapshots.AtRevision(ctx, p, revision)
}

// collectedPolicy reports the stamped policy only for a collected payload. A
// live snapshot carries whatever the column defaulted to, and reporting that as
// "the policy that collected this" would be a fact about nothing.
func collectedPolicy(snapshot store.Snapshot) string {
	if snapshot.PayloadPresent {
		return ""
	}
	return snapshot.CollectedPolicy
}

func collectedRevisionError(snapshot store.Snapshot) error {
	return &domain.CollectedRevisionError{
		Revision: snapshot.Revision,
		Policy:   snapshot.CollectedPolicy,
	}
}

func changedKeys(rows []store.RevisionKeyChange) []ChangedKey {
	out := make([]ChangedKey, 0, len(rows))
	for _, row := range rows {
		out = append(out, ChangedKey{KeyID: row.KeyID, Name: row.KeyName, Change: string(row.Change)})
	}
	return out
}

// Signals computes the matrix's two signals for one environment.
//
// It is a pure read over drafts and lineage: nothing is stored, so "a value
// publish recomputes matrix signals for exactly the touched environments"
// (mvp-boundary C2) holds structurally rather than by bookkeeping. An untouched
// environment's revision did not move and its lineage gained no rows, so its
// signals cannot have changed; a touched one's did, so they did.
func (s *Revisions) Signals(ctx context.Context, actor Actor, scope domain.Scope) (EnvironmentSignals, error) {
	var out EnvironmentSignals
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		out = EnvironmentSignals{EnvironmentID: string(scope.Env)}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRevisionSignals, scope)
		if err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		markers, err := r.Pending().ListMarkers(ctx, p)
		if err != nil {
			return err
		}
		revision := int64(0)
		changed := map[string]bool{}
		latest, err := r.Snapshots().Latest(ctx, p)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		default:
			revision = latest.Revision
			rows, err := r.Snapshots().Changes(ctx, p, revision)
			if err != nil {
				return err
			}
			for _, row := range rows {
				changed[row.KeyID] = true
			}
		}
		out.Revision = revision
		for _, key := range keys {
			cell := CellSignal{
				EnvironmentID: string(scope.Env), KeyID: key.ID, Name: key.Name,
				Classification: key.Classification,
			}
			if changed[key.ID] {
				cell.ChangedInRevision = revision
			}
			for _, marker := range markers {
				if marker.EnvironmentID != string(scope.Env) || marker.KeyID != key.ID {
					continue
				}
				if marker.OwnerID == string(caller.Principal) {
					cell.PendingVersionID = marker.ID
					cell.PendingOperation = string(marker.Operation)
					continue
				}
				// Another principal's draft is write-presence and nothing more:
				// no id (it is not publishable by this caller), no operation,
				// no owner name.
				cell.PendingByOthers = true
			}
			out.Cells = append(out.Cells, cell)
		}
		return nil
	})
	if err != nil {
		return EnvironmentSignals{}, err
	}
	return out, nil
}

// PendingDrafts lists only the caller's own drafts in one environment. The
// owner and environment predicates live in SQL; this layer joins catalogue
// names/classifications and opens config sets under the ordinary read gate.
// Secrets are never opened here because previewing them would require
// consuming a disclosure ceremony, outside this endpoint's scope.
func (s *Revisions) PendingDrafts(ctx context.Context, actor Actor, scope domain.Scope) ([]PendingDraft, error) {
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpValuePendingList, scope)
	if err != nil {
		return nil, err
	}
	var out []PendingDraft
	err = tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		out = nil
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpValuePendingList, scope)
		if err != nil {
			return err
		}
		changes, err := r.Pending().ListForOwnerInEnvironment(ctx, p, string(caller.Principal))
		if err != nil {
			return err
		}
		keys, err := r.Catalogue().List(ctx, p)
		if err != nil {
			return err
		}
		byID := make(map[string]store.CatalogueKey, len(keys))
		for _, key := range keys {
			byID[key.ID] = key
		}
		out = make([]PendingDraft, 0, len(changes))
		for _, change := range changes {
			key, ok := byID[change.KeyID]
			if !ok {
				return fmt.Errorf("service: pending change %s references missing key %s", change.ID, change.KeyID)
			}
			draft := PendingDraft{
				VersionID: change.ID, KeyID: change.KeyID, Name: key.Name,
				Classification: key.Classification, Operation: string(change.Operation),
				StagedFromRevision: change.StagedFromRevision, CreatedAt: change.CreatedAt,
			}
			// MaterialSecret is sticky across restores. A historically secret value
			// must never become readable merely because the key is now config.
			if change.Operation == store.PendingSet && key.Classification == string(schema.Config) && !change.MaterialSecret {
				plain, err := sealer.OpenField(pendingAAD(
					change.OrgID, change.ProjectID, change.EnvironmentID, change.KeyID, change.ID), change.Ciphertext)
				if err != nil {
					return fmt.Errorf("service: pending change %s: %w", change.ID, err)
				}
				draft.Revealed = true
				draft.Value = string(plain)
			}
			out = append(out, draft)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExportedValue is one key of an exported snapshot.
type ExportedValue struct {
	Name           string
	Classification string
	Value          string
	// Revealed says whether Value carries plaintext. A `config` value rides
	// `read`; a `secret` needs the reveal gate, and without it the row reports
	// write-presence with an empty value rather than being dropped -- a missing
	// row and an unreadable row are different facts.
	Revealed bool
}

// Export is the one bulk-disclosure verb: the resolved snapshot of one
// environment, from committed state, never from live values.
//
// FORMULA, stated separately because the capabilities imply nothing about each
// other: current material is `read(E)` and `reveal(E)`; historical material --
// any revision that is not the latest -- is `read(E)` and `reveal-history(E)`.
// A human session additionally runs the ceremony, which enumerates exactly the
// key set the export covers before any ciphertext is opened, and one audit
// event is written per disclosed key. Never "exported N secrets" as one row.
func (s *Revisions) Export(ctx context.Context, actor Actor, scope domain.Scope, revision int64, reveal bool) ([]ExportedValue, int64, error) {
	if s.Keyring == nil {
		return nil, 0, errors.New("service: value export requires a keyring")
	}
	// The sealer is resolved under the READ half of the formula; the
	// disclosure half is authorized in-transaction below, once the snapshot is
	// in hand and "current or historical" is a fact rather than a guess. The
	// reveal op cannot be chosen here: which one applies depends on whether
	// the named revision IS the latest, and the two are independently
	// strippable grants (permission-model ADR) -- demanding current `reveal` for a
	// historical export would refuse a caller the formula admits.
	sealer, err := sealerFor(ctx, s.DB, s.Keyring, actor, authz.OpValueExport, scope)
	if err != nil {
		return nil, 0, err
	}
	var out []ExportedValue
	var served int64
	// A disclosing export runs in a WRITE transaction: its disclosure records
	// must be durable BEFORE the plaintext leaves the server.
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		out, served = nil, 0
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpValueExport, scope)
		if err != nil {
			return err
		}
		snapshot, err := readSnapshot(ctx, r.Snapshots(), p, revision)
		if err != nil {
			return err
		}
		served = snapshot.Revision
		historical := false
		if revision > 0 {
			latest, err := r.Snapshots().Latest(ctx, p)
			if err != nil {
				return err
			}
			historical = snapshot.Revision != latest.Revision
		}
		if reveal {
			// The locked formula, evaluated over exactly the material it
			// governs: current material is `read AND reveal`; historical
			// material -- any revision that is not the latest -- is `read AND
			// reveal-history`. ONE of the two, never both: they are
			// independently strippable grants, and a historical export must
			// not demand the current-reveal grant it does not use.
			revealOp := authz.OpValueExportReveal
			if historical {
				revealOp = authz.OpValueExportRevealHistory
			}
			if p, err = az.Authorize(ctx, caller, revealOp, scope); err != nil {
				return err
			}
		}
		entries, err := r.Snapshots().Entries(ctx, p, snapshot)
		if err != nil {
			return err
		}
		if reveal {
			unit := make([]string, 0, len(entries))
			for _, entry := range entries {
				if entry.Classification == string(schema.Secret) {
					unit = append(unit, entry.KeyID)
				}
			}
			gate := ceremonyGate(ctx, s.Auth, az, caller, PurposeReveal, string(scope.Env))
			if err := gate(unit); err != nil {
				return err
			}
		}
		for _, entry := range entries {
			value := ExportedValue{Name: entry.KeyName, Classification: entry.Classification}
			if entry.Classification == string(schema.Config) || reveal {
				plain, err := sealer.OpenField(snapshotAAD(
					entry.OrgID, entry.ProjectID, entry.EnvironmentID, entry.KeyID, entry.SnapshotID, entry.ID), entry.Ciphertext)
				if err != nil {
					return fmt.Errorf("service: snapshot entry %s: %w", entry.ID, err)
				}
				value.Value, value.Revealed = string(plain), true
			}
			out = append(out, value)
			if entry.Classification != string(schema.Secret) || !value.Revealed {
				continue
			}
			ev, err := domainEvent(ctx, audit.EventValueRevealed, caller.Principal,
				audit.Object{Type: "key", ID: entry.KeyID}, audit.Payload{
					"key_id":   entry.KeyID,
					"name":     audit.SanitizeFreeText(entry.KeyName),
					"surface":  "export",
					"revision": snapshot.Revision,
				})
			if err != nil {
				return err
			}
			if err := r.Audit().InsertTenant(ctx, p, ev); err != nil {
				return err
			}
		}
		slices.SortFunc(out, func(a, b ExportedValue) int {
			switch {
			case a.Name < b.Name:
				return -1
			case a.Name > b.Name:
				return 1
			}
			return 0
		})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, served, nil
}

// TokenKeyRotation is one `rotate-token-key`.
type TokenKeyRotation struct {
	// Version is the root token key's new version. It is operator-facing
	// bookkeeping only: the change token's public contract carries the SCHEME
	// version (`v1:`), never the key version, because a consumer that could
	// tell key versions apart could tell a rotation from a content change.
	Version uint32
}

// RotateTokenKey mints a new root token key, retires the old one, and adopts
// the new one for every subsequent derivation.
//
// WHAT IT DOES NOT TOUCH, which is the whole acceptance criterion (mvp-boundary
// C4, encryption-model ADR CI invariant 15): no snapshot's content, no revision
// number, and no pinned input revision moves. It cannot, because a change token
// is not stored anywhere -- it is derived at read from the live key over the
// snapshot's delivery manifest. The encryption-model ADR's "invalidate the cache and
// recompute eagerly" protocol exists because a cached token would otherwise
// keep serving the old value; there is no cache here, so adopting the handle IS
// the rotation, atomically, with nothing to resume after a crash.
//
// It rides the `rotate-dek` capability. The permission-model ADR's capability set is
// CLOSED and names four rotation atoms for five rotation verbs; the token key
// is a tier-3 key alongside the DEKs, wrapped by the same master, retired
// through the same one-active-per-scope index -- so `rotate-dek` is the tier-3
// rotation authority, and inventing a fifth atom would amend a locked ADR to
// say what an existing one already says.
func (s *Revisions) RotateTokenKey(ctx context.Context, actor Actor) (TokenKeyRotation, error) {
	if s.Keyring == nil {
		return TokenKeyRotation{}, errors.New("service: token key rotation requires a keyring")
	}
	next, adopt, err := s.Keyring.PrepareTokenKeyRotation()
	if err != nil {
		return TokenKeyRotation{}, err
	}
	next.CreatedAt = store.CanonTime(s.now())
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateTokenKey, domain.Scope{})
		if err != nil {
			return err
		}
		// One store method, which also takes the hierarchy-generation fence:
		// the two calls it replaces are bound to the boot mint site, and a
		// store method is grant-evaluated or site-bound, never both.
		if err := r.Keys().RotateTokenKey(ctx, p, next); err != nil {
			return err
		}
		ev, err := newAuditEvent(ctx, audit.EventTokenKeyRotated, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{"key_version": int64(next.Version)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if errors.Is(err, store.ErrRotationSuperseded) {
		// A concurrent rotation won the store's compare-and-swap. Conflict,
		// not a server fault: the caller retries against the new key.
		return TokenKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return TokenKeyRotation{}, err
	}
	// Only after commit: an attempt that rolled back must not leave the process
	// deriving under a key version the datastore does not record. The adopt is
	// version-monotonic (see PrepareTokenKeyRotation), so a late adopt from a
	// slower winner cannot regress the live handle either.
	adopt()
	return TokenKeyRotation{Version: next.Version}, nil
}

// ScanningKeyRotation is one `rotate-scanning-key`.
type ScanningKeyRotation struct {
	// Version is the scanning-fingerprint key's new version — operator-facing
	// bookkeeping only, like TokenKeyRotation.Version.
	Version uint32
	// DismissalsDropped is how many dismissal rows the rotation invalidated, so
	// the operator sees the blast radius of the re-fire the rotation caused.
	DismissalsDropped int64
}

// RotateScanningKey mints a new scanning-fingerprint key, retires the old one,
// drops EVERY dismissal row, and adopts the new key for every subsequent
// fingerprint — all in one transaction.
//
// It is the exact twin of RotateTokenKey (secret-scanning ADR section 4), and
// the same reasoning applies: a scanning key is a tier-3 key alongside the
// DEKs, so `rotate-dek` is its authority and inventing a sixth atom would amend
// a locked ADR to say what an existing one already says. What differs is the
// dismissal drop: outright replacement makes every stored fingerprint
// unrecomputable, so keeping the rows would silently suppress warns that must
// now re-fire — dropping them is the safe direction, and it rides the same
// transaction so no crash window leaves the key rotated but the rows alive.
func (s *Revisions) RotateScanningKey(ctx context.Context, actor Actor) (ScanningKeyRotation, error) {
	if s.Keyring == nil {
		return ScanningKeyRotation{}, errors.New("service: scanning key rotation requires a keyring")
	}
	next, adopt, err := s.Keyring.PrepareScanningKeyRotation()
	if err != nil {
		return ScanningKeyRotation{}, err
	}
	next.CreatedAt = store.CanonTime(s.now())
	var dropped int64
	err = tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpRotateScanningKey, domain.Scope{})
		if err != nil {
			return err
		}
		if err := r.Keys().RotateScanningKey(ctx, p, next); err != nil {
			return err
		}
		// Every fingerprint is now unrecomputable under the new key: drop them
		// all in the same transaction as the key swap.
		if dropped, err = r.ScanningDismissals().DeleteAll(ctx, p); err != nil {
			return err
		}
		ev, err := newAuditEvent(ctx, audit.EventScanningKeyRotated, caller.Principal,
			audit.Object{Type: "instance", ID: "instance"}, audit.OutcomeSuccess, "",
			audit.Payload{"key_version": int64(next.Version)})
		if err != nil {
			return err
		}
		return r.Audit().InsertInstance(ctx, p, ev)
	})
	if errors.Is(err, store.ErrRotationSuperseded) {
		return ScanningKeyRotation{}, fmt.Errorf("%w: %s", domain.ErrConflict, err)
	}
	if err != nil {
		return ScanningKeyRotation{}, err
	}
	adopt()
	return ScanningKeyRotation{Version: next.Version, DismissalsDropped: dropped}, nil
}
