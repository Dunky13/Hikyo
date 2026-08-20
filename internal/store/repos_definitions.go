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

// The definitions plan ledger's binding layer (#70). Chain columns come from the
// verified proof; the plan id is a caller argument like any other row id.

type sqliteDefinitions struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteDefinitions) CreatePlan(ctx context.Context, p authz.Proof, plan NewDefinitionsPlan) error {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreatePlan(ctx, sqlitegen.CreatePlanParams{
		ID:                 plan.ID,
		OrgID:              string(chain.Org),
		ProjectID:          string(chain.Project),
		CreatedBy:          plan.CreatedBy,
		CreatedAt:          CanonTime(plan.CreatedAt).Format(timeFormat),
		ExpiresAt:          CanonTime(plan.ExpiresAt).Format(timeFormat),
		Bundle:             plan.Bundle,
		Digest:             plan.Digest,
		BaseSchemaRevision: plan.BaseSchemaRevision,
		EnvRevisions:       plan.EnvRevisions,
		ProtectedEnvs:      plan.ProtectedEnvs,
		Diff:               plan.Diff,
		Additive:           boolToInt(plan.Additive),
	}))
}

func (r sqliteDefinitions) GetPlan(ctx context.Context, p authz.Proof, id string) (DefinitionsPlan, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanGet, r.tok)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	row, err := r.q.GetPlan(ctx, sqlitegen.GetPlanParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), ID: id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return DefinitionsPlan{}, ErrNotFound
	}
	if err != nil {
		return DefinitionsPlan{}, err
	}
	return planFromSQLite(row)
}

func (r sqliteDefinitions) LatestAppliedPlan(ctx context.Context, p authz.Proof) (DefinitionsPlan, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsLatestAppliedPlan, r.tok)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	row, err := r.q.GetLatestAppliedPlan(ctx, sqlitegen.GetLatestAppliedPlanParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), Applied: 1,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return DefinitionsPlan{}, ErrNotFound
	}
	if err != nil {
		return DefinitionsPlan{}, err
	}
	return planFromSQLite(row)
}

func (r sqliteDefinitions) CountOpenPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanCountOpen, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountOpenPlans(ctx, sqlitegen.CountOpenPlansParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), Applied: 0,
		ExpiresAt: CanonTime(now).Format(timeFormat),
	})
}

func (r sqliteDefinitions) MarkPlanApplied(ctx context.Context, p authz.Proof, id string, stamp PlanApplyStamp) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanApply, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.MarkPlanApplied(ctx, sqlitegen.MarkPlanAppliedParams{
		AppliedAt:        sql.NullString{String: CanonTime(stamp.AppliedAt).Format(timeFormat), Valid: true},
		AppliedBy:        sql.NullString{String: stamp.AppliedBy, Valid: true},
		ProvenanceCommit: nullString(stamp.Commit),
		ProvenanceRef:    nullString(stamp.Ref),
		ProvenanceActor:  nullString(stamp.Actor),
		OrgID:            string(chain.Org), ProjectID: string(chain.Project), ID: id, Applied: 0,
	})
	return n == 1, constraint(err)
}

func (r sqliteDefinitions) PruneExpiredPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreDefinitionsPlanPrune, r.tok); err != nil {
		return 0, err
	}
	n, err := r.q.PruneExpiredPlans(ctx, CanonTime(now).Format(timeFormat))
	return n, constraint(err)
}

func planFromSQLite(row sqlitegen.DefinitionsPlan) (DefinitionsPlan, error) {
	created, err := parseTime("definitions plan", row.ID, row.CreatedAt)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	expires, err := parseTime("definitions plan", row.ID, row.ExpiresAt)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	plan := DefinitionsPlan{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID, CreatedBy: row.CreatedBy,
		CreatedAt: created, ExpiresAt: expires, Bundle: row.Bundle, Digest: row.Digest,
		BaseSchemaRevision: row.BaseSchemaRevision, EnvRevisions: row.EnvRevisions,
		ProtectedEnvs: row.ProtectedEnvs, Diff: row.Diff, Additive: row.Additive != 0,
		AppliedBy:        row.AppliedBy.String,
		ProvenanceCommit: row.ProvenanceCommit.String,
		ProvenanceRef:    row.ProvenanceRef.String,
		ProvenanceActor:  row.ProvenanceActor.String,
	}
	if row.AppliedAt.Valid {
		at, err := parseTime("definitions plan applied", row.ID, row.AppliedAt.String)
		if err != nil {
			return DefinitionsPlan{}, err
		}
		plan.Applied = true
		plan.AppliedAt = at
	}
	return plan, nil
}

type pgDefinitions struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgDefinitions) CreatePlan(ctx context.Context, p authz.Proof, plan NewDefinitionsPlan) error {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreatePlan(ctx, pggen.CreatePlanParams{
		ID:                 plan.ID,
		ChainOrgID:         string(chain.Org),
		ChainProjectID:     string(chain.Project),
		CreatedBy:          plan.CreatedBy,
		CreatedAt:          pgtype.Timestamptz{Time: CanonTime(plan.CreatedAt), Valid: true},
		ExpiresAt:          pgtype.Timestamptz{Time: CanonTime(plan.ExpiresAt), Valid: true},
		Bundle:             plan.Bundle,
		Digest:             plan.Digest,
		BaseSchemaRevision: plan.BaseSchemaRevision,
		EnvRevisions:       plan.EnvRevisions,
		ProtectedEnvs:      plan.ProtectedEnvs,
		Diff:               plan.Diff,
		Additive:           plan.Additive,
	}))
}

func (r pgDefinitions) GetPlan(ctx context.Context, p authz.Proof, id string) (DefinitionsPlan, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanGet, r.tok)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	row, err := r.q.GetPlan(ctx, pggen.GetPlanParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ID: id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DefinitionsPlan{}, ErrNotFound
	}
	if err != nil {
		return DefinitionsPlan{}, err
	}
	return planFromPG(row)
}

func (r pgDefinitions) LatestAppliedPlan(ctx context.Context, p authz.Proof) (DefinitionsPlan, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsLatestAppliedPlan, r.tok)
	if err != nil {
		return DefinitionsPlan{}, err
	}
	row, err := r.q.GetLatestAppliedPlan(ctx, pggen.GetLatestAppliedPlanParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), Applied: true,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return DefinitionsPlan{}, ErrNotFound
	}
	if err != nil {
		return DefinitionsPlan{}, err
	}
	return planFromPG(row)
}

func (r pgDefinitions) CountOpenPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanCountOpen, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountOpenPlans(ctx, pggen.CountOpenPlansParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), Applied: false,
		Now: pgtype.Timestamptz{Time: CanonTime(now), Valid: true},
	})
}

func (r pgDefinitions) MarkPlanApplied(ctx context.Context, p authz.Proof, id string, stamp PlanApplyStamp) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreDefinitionsPlanApply, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.MarkPlanApplied(ctx, pggen.MarkPlanAppliedParams{
		AppliedAt:        pgtype.Timestamptz{Time: CanonTime(stamp.AppliedAt), Valid: true},
		AppliedBy:        pgtype.Text{String: stamp.AppliedBy, Valid: true},
		ProvenanceCommit: pgText(stamp.Commit),
		ProvenanceRef:    pgText(stamp.Ref),
		ProvenanceActor:  pgText(stamp.Actor),
		ChainOrgID:       string(chain.Org), ChainProjectID: string(chain.Project), ID: id, Applied: false,
	})
	return n == 1, constraint(err)
}

func (r pgDefinitions) PruneExpiredPlans(ctx context.Context, p authz.Proof, now time.Time) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreDefinitionsPlanPrune, r.tok); err != nil {
		return 0, err
	}
	n, err := r.q.PruneExpiredPlans(ctx, pgtype.Timestamptz{Time: CanonTime(now), Valid: true})
	return n, constraint(err)
}

func planFromPG(row pggen.DefinitionsPlan) (DefinitionsPlan, error) {
	if !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return DefinitionsPlan{}, errors.New("store: definitions plan " + row.ID + ": null timestamp")
	}
	plan := DefinitionsPlan{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID, CreatedBy: row.CreatedBy,
		CreatedAt: row.CreatedAt.Time.UTC(), ExpiresAt: row.ExpiresAt.Time.UTC(),
		Bundle: row.Bundle, Digest: row.Digest, BaseSchemaRevision: row.BaseSchemaRevision,
		EnvRevisions: row.EnvRevisions, ProtectedEnvs: row.ProtectedEnvs, Diff: row.Diff,
		Additive:         row.Additive,
		AppliedBy:        row.AppliedBy.String,
		ProvenanceCommit: row.ProvenanceCommit.String,
		ProvenanceRef:    row.ProvenanceRef.String,
		ProvenanceActor:  row.ProvenanceActor.String,
	}
	if row.AppliedAt.Valid {
		plan.Applied = true
		plan.AppliedAt = row.AppliedAt.Time.UTC()
	}
	return plan, nil
}

func pgText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}
