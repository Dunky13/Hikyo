package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// Secret-scanning dismissal rows (#74, secret-scanning ADR section 4). Same
// binding discipline as repos_values.go: every method verifies its own
// registered store operation at the boundary and binds the chain columns
// (org, project, and where the statement is environment-addressed, environment)
// exclusively from the verified proof's resolved chain. The (key identity, rule
// digest, value fingerprint) triple is the finding's own coordinates, passed by
// the caller — never a chain value.
//
// The fingerprint is computed by the crypto envelope package under the
// dedicated tier-3 scanning key; this layer only stores and compares the bytes.

// NewDismissal is a "keep as config" acknowledgement to persist.
type NewDismissal struct {
	ID          string
	KeyID       string
	RuleDigest  string
	Fingerprint []byte
	CreatedBy   string
	CreatedAt   time.Time
}

// --- sqlite ---

type sqliteScanningDismissals struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteRepos) ScanningDismissals() ScanningDismissalRepo {
	return sqliteScanningDismissals{q: sqlitegen.New(r.db), tok: r.tok}
}

func (r sqliteScanningDismissals) Insert(ctx context.Context, p authz.Proof, d NewDismissal) error {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreScanningDismissalsInsert)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertScanningDismissal(ctx, sqlitegen.InsertScanningDismissalParams{
		ID:               d.ID,
		OrgID:            string(chain.Org),
		ProjectID:        string(chain.Project),
		EnvironmentID:    env,
		KeyID:            d.KeyID,
		RuleDigest:       d.RuleDigest,
		ValueFingerprint: d.Fingerprint,
		CreatedAt:        CanonTime(d.CreatedAt).Format(timeFormat),
		CreatedBy:        d.CreatedBy,
	}))
}

func (r sqliteScanningDismissals) Exists(ctx context.Context, p authz.Proof, keyID, ruleDigest string, fingerprint []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsExists, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StoreScanningDismissalsExists)
	if err != nil {
		return false, err
	}
	_, err = r.q.GetScanningDismissal(ctx, sqlitegen.GetScanningDismissalParams{
		OrgID:            string(chain.Org),
		ProjectID:        string(chain.Project),
		EnvironmentID:    env,
		KeyID:            keyID,
		RuleDigest:       ruleDigest,
		ValueFingerprint: fingerprint,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r sqliteScanningDismissals) DeleteByKey(ctx context.Context, p authz.Proof, keyID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteByKey, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.DeleteScanningDismissalsForKey(ctx, sqlitegen.DeleteScanningDismissalsForKeyParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		KeyID:     keyID,
	})
}

func (r sqliteScanningDismissals) DeleteByProject(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteByProject, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.DeleteScanningDismissalsForProject(ctx, sqlitegen.DeleteScanningDismissalsForProjectParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
}

func (r sqliteScanningDismissals) DeleteAll(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteAll, r.tok); err != nil {
		return 0, err
	}
	return r.q.DeleteAllScanningDismissals(ctx)
}

// --- postgres ---

type pgScanningDismissals struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgRepos) ScanningDismissals() ScanningDismissalRepo {
	return pgScanningDismissals{q: pggen.New(r.db), tok: r.tok}
}

func (r pgScanningDismissals) Insert(ctx context.Context, p authz.Proof, d NewDismissal) error {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreScanningDismissalsInsert)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertScanningDismissal(ctx, pggen.InsertScanningDismissalParams{
		ID:               d.ID,
		ChainOrgID:       string(chain.Org),
		ChainProjectID:   string(chain.Project),
		ChainEnvID:       env,
		KeyID:            d.KeyID,
		RuleDigest:       d.RuleDigest,
		ValueFingerprint: d.Fingerprint,
		CreatedAt:        pgtype.Timestamptz{Time: CanonTime(d.CreatedAt), Valid: true},
		CreatedBy:        d.CreatedBy,
	}))
}

func (r pgScanningDismissals) Exists(ctx context.Context, p authz.Proof, keyID, ruleDigest string, fingerprint []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsExists, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StoreScanningDismissalsExists)
	if err != nil {
		return false, err
	}
	_, err = r.q.GetScanningDismissal(ctx, pggen.GetScanningDismissalParams{
		ChainOrgID:       string(chain.Org),
		ChainProjectID:   string(chain.Project),
		ChainEnvID:       env,
		KeyID:            keyID,
		RuleDigest:       ruleDigest,
		ValueFingerprint: fingerprint,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r pgScanningDismissals) DeleteByKey(ctx context.Context, p authz.Proof, keyID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteByKey, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.DeleteScanningDismissalsForKey(ctx, pggen.DeleteScanningDismissalsForKeyParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		KeyID:          keyID,
	})
}

func (r pgScanningDismissals) DeleteByProject(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteByProject, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.DeleteScanningDismissalsForProject(ctx, pggen.DeleteScanningDismissalsForProjectParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
}

func (r pgScanningDismissals) DeleteAll(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreScanningDismissalsDeleteAll, r.tok); err != nil {
		return 0, err
	}
	return r.q.DeleteAllScanningDismissals(ctx)
}
