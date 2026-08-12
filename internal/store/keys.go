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

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
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
}

// KeyRepo is the transactional keyring repository. InsertTier3 and
// InsertMaster are always preceded by AcquireHierarchyGeneration in the same
// transaction — the fence that will serialize key creation against master
// rotation (encryption ADR § Rotation; the rotation operations land later).
type KeyRepo interface {
	KeyReader
	AcquireHierarchyGeneration(ctx context.Context, pf authz.Proof) error
	InsertMaster(ctx context.Context, pf authz.Proof, k crypto.WrappedKey) error
	InsertTier3(ctx context.Context, pf authz.Proof, k crypto.WrappedKey) error
	InsertScopeGeneration(ctx context.Context, pf authz.Proof, p crypto.Purpose, orgID, projectID string) error
}

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
	case crypto.PurposeProject, crypto.PurposeInstance, crypto.PurposeToken:
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
