package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// Keyring persistence: rows hold wrapped-key ciphertext envelopes only.
// Absent keys map to crypto.ErrNoKey; uniqueness conflicts (two writers
// minting one scope's key, or two first boots racing) map to
// crypto.ErrKeyExists so the keyring can converge on the winner.

// KeyReader is the read side of keyring persistence.
type KeyReader interface {
	// ActiveMasterWrappers returns every active master wrapper (one per
	// root epoch; two while a root rotation is dual-wrapped; empty at
	// first boot), newest epoch first.
	ActiveMasterWrappers(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error)
	ActiveTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error)
	// Tier3Versions returns every still-openable version of one scope's key
	// (active + retiring, newest first) so the keyring can open ciphertext a
	// reencrypt has not yet moved off a superseded DEK version. Empty when the
	// scope has no key yet.
	Tier3Versions(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) ([]crypto.WrappedKey, error)
	// AllOpenableTier3 returns every still-openable tier-3 key across every
	// scope (active + retiring), for rotate-master-key to re-wrap.
	AllOpenableTier3(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error)
	// AssertActiveDEKVersion is the writer fence: it confirms (and, on postgres,
	// FOR SHARE-locks) that the DEK version a ciphertext was sealed under is
	// still active for its scope, refusing with ErrStaleDEK otherwise. Called
	// inside a ciphertext write's own transaction so a stale sealer cannot land a
	// write under a version reencrypt is about to retire.
	AssertActiveDEKVersion(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string, version uint32) error
}

// KeyRepo is the transactional keyring repository. InsertTier3 and
// InsertMaster are always preceded by AcquireHierarchyGeneration in the same
// transaction — the fence that will serialize key creation against master
// rotation (encryption-model ADR § Rotation; the rotation operations land later).
type KeyRepo interface {
	KeyReader
	AcquireHierarchyGeneration(ctx context.Context, pf authz.Proof) error
	InsertMaster(ctx context.Context, pf authz.Proof, k crypto.WrappedKey) error
	InsertTier3(ctx context.Context, pf authz.Proof, k crypto.WrappedKey) error
	// RotateTokenKey retires the active root token key and installs its
	// successor, both inside the hierarchy-generation fence.
	//
	// It is ONE store method rather than the three calls it performs, and that
	// is a rule, not a convenience: `keys.AcquireHierarchyGeneration` and
	// `keys.InsertTier3` are bound to the boot mint site, and a store method is
	// grant-evaluated or site-bound, never both (invariant 6). A rotation is
	// grant-evaluated -- an operator holding `rotate-dek` asks for it -- so it
	// reaches the same rows through a door of its own.
	RotateTokenKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error
	// RotateScanningKey retires the active scanning-fingerprint key and installs
	// its successor, the exact twin of RotateTokenKey for the sixth rotation
	// operation (#74). Dropping the dismissal rows is the service's, in the same
	// transaction (StoreScanningDismissalsDeleteAll) — this method owns only the
	// key swap, so the two concerns stay separately authorized.
	RotateScanningKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error
	// RotateDEK appends a new DEK version for one project or the instance scope
	// and demotes the previous active version to retiring — no longer written,
	// still openable until reencrypt walks its ciphertext. It runs inside the
	// hierarchy fence (serializing against master rotation) and the scope fence
	// (against writers and reencrypt); a concurrent rotation that already moved
	// the active version returns ErrRotationSuperseded.
	RotateDEK(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error
	// RotateMasterKey installs a new master, re-wraps every tier-3 key under it,
	// and retires the old master — all inside the hierarchy fence. It refuses
	// (crypto.ErrMasterRotationBlocked) while the root is dual-wrapped, and
	// returns ErrRotationSuperseded if a concurrent master rotation already moved
	// the active master.
	RotateMasterKey(ctx context.Context, pf authz.Proof, newMaster crypto.WrappedKey, rewrapped []crypto.WrappedKey) error
	// RetireRetiringTier3 retires every 'retiring' version of one scope, inside
	// the scope fence — reencrypt's completion, once the walk has moved every
	// ciphertext onto the active version. Returns how many versions retired.
	RetireRetiringTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (int64, error)
	// RootKeyRotatePrepare commits the second master wrapper (same version, new
	// epoch) of the dual-wrapped transition, inside the hierarchy fence. It
	// refuses (crypto.ErrRootRotationBlocked) unless exactly one active wrapper
	// exists — a prepare while one is already pending is the four-way matrix the
	// ADR refuses.
	RootKeyRotatePrepare(ctx context.Context, pf authz.Proof, newWrapper crypto.WrappedKey) error
	// RootKeyRotateFinalize retires the old-epoch wrapper and returns the new
	// active epoch. It refuses (crypto.ErrNotDualWrapped) when the master is not
	// dual-wrapped, and ErrRotationSuperseded when a concurrent finalize won.
	RootKeyRotateFinalize(ctx context.Context, pf authz.Proof) (uint32, error)
	InsertScopeGeneration(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) error
}

// ErrRotationSuperseded reports a tier-3 key rotation (token key or DEK) losing
// the compare-and-swap: the active version moved between prepare and commit
// because a concurrent rotation committed first. The caller refuses loudly;
// retrying mints a fresh successor against the new predecessor.
var ErrRotationSuperseded = errors.New("store: key rotation superseded by a concurrent rotation")

// ErrStaleDEK reports the writer fence refusing a ciphertext write: the DEK
// version it was sealed under is no longer active for its scope — a sealer built
// before a rotate-dek. The caller re-fetches a fresh sealer and retries; the
// service maps it to a conflict.
var ErrStaleDEK = errors.New("store: ciphertext sealed under a non-active DEK version; re-fetch the sealer and retry")

func scopeGenerationKey(p crypto.Purpose, orgID, projectID string) string {
	return fmt.Sprintf("tier3:%s:%s:%s", p, orgID, projectID)
}

func dbVersion(field string, v int64) (uint32, error) {
	if v < 0 || v > math.MaxUint32 {
		return 0, fmt.Errorf("store: %s %d out of range", field, v)
	}
	return uint32(v), nil
}

func parsePurpose(s string) (crypto.Purpose, error) {
	switch p := crypto.Purpose(s); p {
	case crypto.PurposeProject, crypto.PurposeInstance, crypto.PurposeToken, crypto.PurposeScanning:
		return p, nil
	default:
		return "", fmt.Errorf("store: unknown key purpose %q", s)
	}
}

// --- sqlite ---

type sqliteKeys struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteRepos) Keys() KeyRepo { return sqliteKeys{q: sqlitegen.New(r.db), tok: r.tok} }

// sqliteUniqueViolation matches exactly the uniqueness extended codes —
// mirroring postgres 23505. A broader SQLITE_CONSTRAINT match would turn
// CHECK/FK/NOT NULL bugs into a silent "key already exists" retry path.
func sqliteUniqueViolation(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) &&
		(se.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY)
}

func (k sqliteKeys) ActiveMasterWrappers(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysActiveMasterWrappers, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		version, err := dbVersion("key version", row.Version)
		if err != nil {
			return nil, err
		}
		epoch, err := dbVersion("root key epoch", row.RootKeyEpoch)
		if err != nil {
			return nil, err
		}
		created, err := time.Parse(timeFormat, row.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("store: master key created_at %q: %w", row.CreatedAt, err)
		}
		out = append(out, crypto.WrappedKey{
			Version:      version,
			RootKeyEpoch: epoch,
			Blob:         row.Blob,
			CreatedAt:    created.UTC(),
		})
	}
	return out, nil
}

func (k sqliteKeys) ActiveTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysActiveTier3, k.tok); err != nil {
		return crypto.WrappedKey{}, err
	}
	row, err := k.q.GetActiveTier3Key(ctx, sqlitegen.GetActiveTier3KeyParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return crypto.WrappedKey{}, crypto.ErrNoKey
	}
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	return tier3FromSQLite(row)
}

func (k sqliteKeys) Tier3Versions(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysTier3Versions, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.GetTier3Versions(ctx, sqlitegen.GetTier3VersionsParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		wk, err := tier3FromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, wk)
	}
	return out, nil
}

func tier3FromSQLite(row sqlitegen.Tier3Key) (crypto.WrappedKey, error) {
	purpose, err := parsePurpose(row.Purpose)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	version, err := dbVersion("key version", row.Version)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	masterVersion, err := dbVersion("master key version", row.MasterKeyVersion)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	created, err := time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return crypto.WrappedKey{}, fmt.Errorf("store: key %s created_at %q: %w", row.ID, row.CreatedAt, err)
	}
	return crypto.WrappedKey{
		ID:               row.ID,
		Purpose:          purpose,
		OrgID:            row.OrgID,
		ProjectID:        row.ProjectID,
		Version:          version,
		MasterKeyVersion: masterVersion,
		Blob:             row.Blob,
		CreatedAt:        created.UTC(),
	}, nil
}

func (k sqliteKeys) AcquireHierarchyGeneration(ctx context.Context, pf authz.Proof) error {
	if _, err := authz.Verify(pf, authz.StoreKeysAcquireHierarchyGeneration, k.tok); err != nil {
		return err
	}
	// sqlite: the single write connection plus BEGIN IMMEDIATE already
	// serializes writers globally; reading the row keeps the call shape (and
	// proves the row exists) until rotation gives it teeth.
	_, err := k.q.AcquireHierarchyGeneration(ctx)
	return err
}

func (k sqliteKeys) InsertMaster(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertMaster, k.tok); err != nil {
		return err
	}
	err := k.q.InsertMasterKey(ctx, sqlitegen.InsertMasterKeyParams{
		Version:      int64(key.Version),
		RootKeyEpoch: int64(key.RootKeyEpoch),
		Blob:         key.Blob,
		CreatedAt:    CanonTime(key.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) InsertTier3(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertTier3, k.tok); err != nil {
		return err
	}
	err := k.q.InsertTier3Key(ctx, sqlitegen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        CanonTime(key.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) RotateTokenKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateTokenKey, k.tok); err != nil {
		return err
	}
	// The fence first, for the reason every other tier-3 write takes it: a
	// master rotation must not slip between the retire and the insert.
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	// Compare-and-swap on the predecessor: the successor row was minted
	// against version-1, and if the active key is no longer that version a
	// concurrent rotation already won. Refusing here is what keeps the
	// in-memory adopt and the datastore agreeing on which key is live.
	retired, err := k.q.RetireTier3KeyAtVersion(ctx, sqlitegen.RetireTier3KeyAtVersionParams{
		Purpose: string(crypto.PurposeToken), OrgID: "", ProjectID: "",
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, sqlitegen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        CanonTime(key.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) AllOpenableTier3(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysAllOpenableTier3, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.AllOpenableTier3(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		wk, err := tier3FromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, wk)
	}
	return out, nil
}

func (k sqliteKeys) RotateMasterKey(ctx context.Context, pf authz.Proof, newMaster crypto.WrappedKey, rewrapped []crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateMasterKey, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	// Exactly one active master, or the root is dual-wrapped (two) / the
	// hierarchy is missing (zero): the two rotations are mutually exclusive.
	if len(masters) != 1 {
		return crypto.ErrMasterRotationBlocked
	}
	// The successor must be minted against the master that is still active — a
	// master rotation that slipped in before this fence moved the predecessor.
	if int64(newMaster.Version) != masters[0].Version+1 {
		return ErrRotationSuperseded
	}
	retired, err := k.q.RetireMasterAtVersion(ctx, masters[0].Version)
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertMasterKey(ctx, sqlitegen.InsertMasterKeyParams{
		Version:      int64(newMaster.Version),
		RootKeyEpoch: int64(newMaster.RootKeyEpoch),
		Blob:         newMaster.Blob,
		CreatedAt:    CanonTime(newMaster.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	if err != nil {
		return err
	}
	for _, row := range rewrapped {
		n, err := k.q.UpdateTier3Wrapping(ctx, sqlitegen.UpdateTier3WrappingParams{
			Blob:             row.Blob,
			MasterKeyVersion: int64(row.MasterKeyVersion),
			ID:               row.ID,
			Version:          int64(row.Version),
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("store: tier-3 key %s v%d vanished during master rotation", row.ID, row.Version)
		}
	}
	// Zero-reference check INSIDE the fence: a tier-3 key created or
	// version-appended in the window before this transaction (under the old
	// master) is not in `rewrapped`, so it still references the retired master.
	// Refuse and let the caller retry against the now-complete set rather than
	// strand it — the ADR's "verified by query inside the fence, never assumed".
	stranded, err := k.q.CountOpenableTier3NotAtMaster(ctx, int64(newMaster.Version))
	if err != nil {
		return err
	}
	if stranded != 0 {
		return ErrRotationSuperseded
	}
	return nil
}

// assertActiveMaster is the fence's teeth for a tier-3 rotation, mirroring the
// boot mint site's check: with the hierarchy generation held, the successor's
// wrapping master must still be the active one. A master rotation that slipped
// in between the mint and this insert would otherwise wrap a fresh DEK version
// under a retired master — CI invariant 9's writer race, structurally refused.
func (k sqliteKeys) assertActiveMaster(ctx context.Context, masterVersion uint32) error {
	wrappers, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	if len(wrappers) == 0 {
		return errors.New("store: no active master key — hierarchy missing")
	}
	for _, w := range wrappers {
		if w.Version != int64(masterVersion) {
			return crypto.ErrStaleMaster
		}
	}
	return nil
}

func (k sqliteKeys) AssertActiveDEKVersion(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string, version uint32) error {
	if _, err := authz.Verify(pf, authz.StoreKeysAssertActiveDEKVersion, k.tok); err != nil {
		return err
	}
	state, err := k.q.AssertActiveTier3Version(ctx, sqlitegen.AssertActiveTier3VersionParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID, Version: int64(version),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStaleDEK
	}
	if err != nil {
		return err
	}
	if state != "active" {
		return ErrStaleDEK
	}
	return nil
}

func (k sqliteKeys) RotateScanningKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateScanningKey, k.tok); err != nil {
		return err
	}
	// The fence first, then a compare-and-swap on the predecessor version — the
	// exact shape RotateTokenKey uses, purpose scanning.
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	retired, err := k.q.RetireTier3KeyAtVersion(ctx, sqlitegen.RetireTier3KeyAtVersionParams{
		Purpose: string(crypto.PurposeScanning), OrgID: "", ProjectID: "",
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, sqlitegen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        CanonTime(key.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) RotateDEK(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateDEK, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	if _, err := k.q.AcquireScopeGeneration(ctx, scopeGenerationKey(key.Purpose, key.OrgID, key.ProjectID)); err != nil {
		return err
	}
	if err := k.assertActiveMaster(ctx, key.MasterKeyVersion); err != nil {
		return err
	}
	demoted, err := k.q.DemoteActiveTier3ToRetiring(ctx, sqlitegen.DemoteActiveTier3ToRetiringParams{
		Purpose: string(key.Purpose), OrgID: key.OrgID, ProjectID: key.ProjectID,
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if demoted != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, sqlitegen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        CanonTime(key.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) RetireRetiringTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (int64, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysRetireRetiringTier3, k.tok); err != nil {
		return 0, err
	}
	if _, err := k.q.AcquireScopeGeneration(ctx, scopeGenerationKey(p, orgID, projectID)); err != nil {
		return 0, err
	}
	return k.q.RetireRetiringTier3ForScope(ctx, sqlitegen.RetireRetiringTier3ForScopeParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
}

func (k sqliteKeys) RootKeyRotatePrepare(ctx context.Context, pf authz.Proof, newWrapper crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRootRotatePrepare, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	if len(masters) != 1 {
		return crypto.ErrRootRotationBlocked
	}
	// Pin the master version INSIDE the fence: the wrapper was sealed over the
	// master version that was active when prepare read it. A master rotation that
	// completed in the gap moved that version, and inserting a wrapper for the old
	// version alongside the new master's wrapper is the two-different-versions
	// state the ADR refuses — it bricks boot under the new root. Refuse and retry.
	if masters[0].Version != int64(newWrapper.Version) {
		return crypto.ErrRootRotationBlocked
	}
	err = k.q.InsertMasterKey(ctx, sqlitegen.InsertMasterKeyParams{
		Version:      int64(newWrapper.Version),
		RootKeyEpoch: int64(newWrapper.RootKeyEpoch),
		Blob:         newWrapper.Blob,
		CreatedAt:    CanonTime(newWrapper.CreatedAt).Format(timeFormat),
	})
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k sqliteKeys) RootKeyRotateFinalize(ctx context.Context, pf authz.Proof) (uint32, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysRootRotateFinalize, k.tok); err != nil {
		return 0, err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return 0, err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return 0, err
	}
	if len(masters) != 2 {
		return 0, crypto.ErrNotDualWrapped
	}
	// GetActiveMasterKeys orders by root_key_epoch DESC: [new, old].
	newEpoch := masters[0].RootKeyEpoch
	old := masters[len(masters)-1]
	retired, err := k.q.RetireMasterWrapperAtEpoch(ctx, sqlitegen.RetireMasterWrapperAtEpochParams{
		Version:      old.Version,
		RootKeyEpoch: old.RootKeyEpoch,
	})
	if err != nil {
		return 0, err
	}
	if retired != 1 {
		return 0, ErrRotationSuperseded
	}
	epoch, err := dbVersion("root key epoch", newEpoch)
	if err != nil {
		return 0, err
	}
	return epoch, nil
}

func (k sqliteKeys) InsertScopeGeneration(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertScopeGeneration, k.tok); err != nil {
		return err
	}
	err := k.q.InsertKeyGeneration(ctx, scopeGenerationKey(p, orgID, projectID))
	if sqliteUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

// --- postgres ---

type pgKeys struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgRepos) Keys() KeyRepo { return pgKeys{q: pggen.New(r.db), tok: r.tok} }

func pgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (k pgKeys) ActiveMasterWrappers(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysActiveMasterWrappers, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		version, err := dbVersion("key version", row.Version)
		if err != nil {
			return nil, err
		}
		epoch, err := dbVersion("root key epoch", row.RootKeyEpoch)
		if err != nil {
			return nil, err
		}
		if !row.CreatedAt.Valid {
			return nil, errors.New("store: master key: null created_at")
		}
		out = append(out, crypto.WrappedKey{
			Version:      version,
			RootKeyEpoch: epoch,
			Blob:         row.Blob,
			CreatedAt:    row.CreatedAt.Time.UTC(),
		})
	}
	return out, nil
}

func (k pgKeys) ActiveTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysActiveTier3, k.tok); err != nil {
		return crypto.WrappedKey{}, err
	}
	row, err := k.q.GetActiveTier3Key(ctx, pggen.GetActiveTier3KeyParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return crypto.WrappedKey{}, crypto.ErrNoKey
	}
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	return tier3FromPG(row)
}

func (k pgKeys) Tier3Versions(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysTier3Versions, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.GetTier3Versions(ctx, pggen.GetTier3VersionsParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		wk, err := tier3FromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, wk)
	}
	return out, nil
}

func tier3FromPG(row pggen.Tier3Key) (crypto.WrappedKey, error) {
	purpose, err := parsePurpose(row.Purpose)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	version, err := dbVersion("key version", row.Version)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	masterVersion, err := dbVersion("master key version", row.MasterKeyVersion)
	if err != nil {
		return crypto.WrappedKey{}, err
	}
	if !row.CreatedAt.Valid {
		return crypto.WrappedKey{}, fmt.Errorf("store: key %s: null created_at", row.ID)
	}
	return crypto.WrappedKey{
		ID:               row.ID,
		Purpose:          purpose,
		OrgID:            row.OrgID,
		ProjectID:        row.ProjectID,
		Version:          version,
		MasterKeyVersion: masterVersion,
		Blob:             row.Blob,
		CreatedAt:        row.CreatedAt.Time.UTC(),
	}, nil
}

func (k pgKeys) AcquireHierarchyGeneration(ctx context.Context, pf authz.Proof) error {
	if _, err := authz.Verify(pf, authz.StoreKeysAcquireHierarchyGeneration, k.tok); err != nil {
		return err
	}
	// SELECT ... FOR UPDATE: the row lock serializes tier-3 key creation
	// against future master/root rotation in the same fence.
	_, err := k.q.AcquireHierarchyGeneration(ctx)
	return err
}

func (k pgKeys) InsertMaster(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertMaster, k.tok); err != nil {
		return err
	}
	err := k.q.InsertMasterKey(ctx, pggen.InsertMasterKeyParams{
		Version:      int64(key.Version),
		RootKeyEpoch: int64(key.RootKeyEpoch),
		Blob:         key.Blob,
		CreatedAt:    pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) InsertTier3(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertTier3, k.tok); err != nil {
		return err
	}
	err := k.q.InsertTier3Key(ctx, pggen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) RotateTokenKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateTokenKey, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	// Compare-and-swap on the predecessor: see the sqlite twin.
	retired, err := k.q.RetireTier3KeyAtVersion(ctx, pggen.RetireTier3KeyAtVersionParams{
		Purpose: string(crypto.PurposeToken), OrgID: "", ProjectID: "",
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, pggen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) AllOpenableTier3(ctx context.Context, pf authz.Proof) ([]crypto.WrappedKey, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysAllOpenableTier3, k.tok); err != nil {
		return nil, err
	}
	rows, err := k.q.AllOpenableTier3(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]crypto.WrappedKey, 0, len(rows))
	for _, row := range rows {
		wk, err := tier3FromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, wk)
	}
	return out, nil
}

func (k pgKeys) RotateMasterKey(ctx context.Context, pf authz.Proof, newMaster crypto.WrappedKey, rewrapped []crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateMasterKey, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	if len(masters) != 1 {
		return crypto.ErrMasterRotationBlocked
	}
	if int64(newMaster.Version) != masters[0].Version+1 {
		return ErrRotationSuperseded
	}
	retired, err := k.q.RetireMasterAtVersion(ctx, masters[0].Version)
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertMasterKey(ctx, pggen.InsertMasterKeyParams{
		Version:      int64(newMaster.Version),
		RootKeyEpoch: int64(newMaster.RootKeyEpoch),
		Blob:         newMaster.Blob,
		CreatedAt:    pgtype.Timestamptz{Time: CanonTime(newMaster.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	if err != nil {
		return err
	}
	for _, row := range rewrapped {
		n, err := k.q.UpdateTier3Wrapping(ctx, pggen.UpdateTier3WrappingParams{
			Blob:             row.Blob,
			MasterKeyVersion: int64(row.MasterKeyVersion),
			ID:               row.ID,
			Version:          int64(row.Version),
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("store: tier-3 key %s v%d vanished during master rotation", row.ID, row.Version)
		}
	}
	stranded, err := k.q.CountOpenableTier3NotAtMaster(ctx, int64(newMaster.Version))
	if err != nil {
		return err
	}
	if stranded != 0 {
		return ErrRotationSuperseded
	}
	return nil
}

func (k pgKeys) assertActiveMaster(ctx context.Context, masterVersion uint32) error {
	wrappers, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	if len(wrappers) == 0 {
		return errors.New("store: no active master key — hierarchy missing")
	}
	for _, w := range wrappers {
		if w.Version != int64(masterVersion) {
			return crypto.ErrStaleMaster
		}
	}
	return nil
}

func (k pgKeys) AssertActiveDEKVersion(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string, version uint32) error {
	if _, err := authz.Verify(pf, authz.StoreKeysAssertActiveDEKVersion, k.tok); err != nil {
		return err
	}
	state, err := k.q.AssertActiveTier3Version(ctx, pggen.AssertActiveTier3VersionParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID, Version: int64(version),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleDEK
	}
	if err != nil {
		return err
	}
	if state != "active" {
		return ErrStaleDEK
	}
	return nil
}

func (k pgKeys) RotateScanningKey(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateScanningKey, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	// Compare-and-swap on the predecessor: see the sqlite twin and RotateTokenKey.
	retired, err := k.q.RetireTier3KeyAtVersion(ctx, pggen.RetireTier3KeyAtVersionParams{
		Purpose: string(crypto.PurposeScanning), OrgID: "", ProjectID: "",
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if retired != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, pggen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) RotateDEK(ctx context.Context, pf authz.Proof, key crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRotateDEK, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	if _, err := k.q.AcquireScopeGeneration(ctx, scopeGenerationKey(key.Purpose, key.OrgID, key.ProjectID)); err != nil {
		return err
	}
	if err := k.assertActiveMaster(ctx, key.MasterKeyVersion); err != nil {
		return err
	}
	demoted, err := k.q.DemoteActiveTier3ToRetiring(ctx, pggen.DemoteActiveTier3ToRetiringParams{
		Purpose: string(key.Purpose), OrgID: key.OrgID, ProjectID: key.ProjectID,
		Version: int64(key.Version) - 1,
	})
	if err != nil {
		return err
	}
	if demoted != 1 {
		return ErrRotationSuperseded
	}
	err = k.q.InsertTier3Key(ctx, pggen.InsertTier3KeyParams{
		ID:               key.ID,
		Purpose:          string(key.Purpose),
		OrgID:            key.OrgID,
		ProjectID:        key.ProjectID,
		Version:          int64(key.Version),
		MasterKeyVersion: int64(key.MasterKeyVersion),
		Blob:             key.Blob,
		CreatedAt:        pgtype.Timestamptz{Time: CanonTime(key.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) RetireRetiringTier3(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) (int64, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysRetireRetiringTier3, k.tok); err != nil {
		return 0, err
	}
	if _, err := k.q.AcquireScopeGeneration(ctx, scopeGenerationKey(p, orgID, projectID)); err != nil {
		return 0, err
	}
	return k.q.RetireRetiringTier3ForScope(ctx, pggen.RetireRetiringTier3ForScopeParams{
		Purpose: string(p), OrgID: orgID, ProjectID: projectID,
	})
}

func (k pgKeys) RootKeyRotatePrepare(ctx context.Context, pf authz.Proof, newWrapper crypto.WrappedKey) error {
	if _, err := authz.Verify(pf, authz.StoreKeysRootRotatePrepare, k.tok); err != nil {
		return err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return err
	}
	if len(masters) != 1 {
		return crypto.ErrRootRotationBlocked
	}
	// Pin the master version inside the fence — see the sqlite twin.
	if masters[0].Version != int64(newWrapper.Version) {
		return crypto.ErrRootRotationBlocked
	}
	err = k.q.InsertMasterKey(ctx, pggen.InsertMasterKeyParams{
		Version:      int64(newWrapper.Version),
		RootKeyEpoch: int64(newWrapper.RootKeyEpoch),
		Blob:         newWrapper.Blob,
		CreatedAt:    pgtype.Timestamptz{Time: CanonTime(newWrapper.CreatedAt), Valid: true},
	})
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}

func (k pgKeys) RootKeyRotateFinalize(ctx context.Context, pf authz.Proof) (uint32, error) {
	if _, err := authz.Verify(pf, authz.StoreKeysRootRotateFinalize, k.tok); err != nil {
		return 0, err
	}
	if _, err := k.q.AcquireHierarchyGeneration(ctx); err != nil {
		return 0, err
	}
	masters, err := k.q.GetActiveMasterKeys(ctx)
	if err != nil {
		return 0, err
	}
	if len(masters) != 2 {
		return 0, crypto.ErrNotDualWrapped
	}
	newEpoch := masters[0].RootKeyEpoch
	old := masters[len(masters)-1]
	retired, err := k.q.RetireMasterWrapperAtEpoch(ctx, pggen.RetireMasterWrapperAtEpochParams{
		Version:      old.Version,
		RootKeyEpoch: old.RootKeyEpoch,
	})
	if err != nil {
		return 0, err
	}
	if retired != 1 {
		return 0, ErrRotationSuperseded
	}
	epoch, err := dbVersion("root key epoch", newEpoch)
	if err != nil {
		return 0, err
	}
	return epoch, nil
}

func (k pgKeys) InsertScopeGeneration(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) error {
	if _, err := authz.Verify(pf, authz.StoreKeysInsertScopeGeneration, k.tok); err != nil {
		return err
	}
	err := k.q.InsertKeyGeneration(ctx, scopeGenerationKey(p, orgID, projectID))
	if pgUniqueViolation(err) {
		return crypto.ErrKeyExists
	}
	return err
}
