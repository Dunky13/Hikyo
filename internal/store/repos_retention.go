package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

type sqliteRetention struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteRetention) Eligible(ctx context.Context, p authz.Proof, now time.Time, limit int) ([]GCEligibleSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionEligible, r.tok); err != nil {
		return nil, err
	}
	stamp := CanonTime(now).Format(timeFormat)
	rows, err := r.q.ListEligibleSnapshotPayloads(ctx, sqlitegen.ListEligibleSnapshotPayloadsParams{
		Now: stamp, BatchLimit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]GCEligibleSnapshot, 0, len(rows))
	for _, row := range rows {
		out = append(out, GCEligibleSnapshot{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			EnvironmentID: row.EnvironmentID, Revision: row.Revision,
			Policy: RetentionPolicy{
				MaxAge: time.Duration(row.AgeSeconds) * time.Second, LastRevisions: row.RevisionCount,
			},
		})
	}
	return out, nil
}

func (r sqliteRetention) MarkCollected(ctx context.Context, p authz.Proof, snapshotID, policy string, now time.Time) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionMarkCollected, r.tok); err != nil {
		return false, err
	}
	stamp := CanonTime(now).Format(timeFormat)
	n, err := r.q.MarkSnapshotCollected(ctx, sqlitegen.MarkSnapshotCollectedParams{
		CollectedAt:     sql.NullString{String: stamp, Valid: true},
		CollectedPolicy: policy, ID: snapshotID, Now: stamp,
	})
	return n == 1, constraint(err)
}

func (r sqliteRetention) DeleteCollectedEntries(ctx context.Context, p authz.Proof, snapshotID string) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionDeleteEntries, r.tok); err != nil {
		return 0, err
	}
	n, err := r.q.DeleteCollectedSnapshotEntries(ctx, snapshotID)
	return n, constraint(err)
}

func (r sqliteRetention) LastPruneSuccess(ctx context.Context, p authz.Proof) (time.Time, bool, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionLastSuccess, r.tok); err != nil {
		return time.Time{}, false, err
	}
	got, err := r.q.GetLastPruneSuccess(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, ErrNotFound
	}
	if err != nil || !got.Valid {
		return time.Time{}, false, err
	}
	at, err := parseTime("retention runtime", "payload_gc", got.String)
	return at, err == nil, err
}

func (r sqliteRetention) SetLastPruneSuccess(ctx context.Context, p authz.Proof, at time.Time) error {
	if _, err := authz.Verify(p, authz.StoreRetentionSetLastSuccess, r.tok); err != nil {
		return err
	}
	return r.q.SetLastPruneSuccess(ctx, sql.NullString{
		String: CanonTime(at).Format(timeFormat), Valid: true,
	})
}

type pgRetention struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgRetention) Eligible(ctx context.Context, p authz.Proof, now time.Time, limit int) ([]GCEligibleSnapshot, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionEligible, r.tok); err != nil {
		return nil, err
	}
	if limit > int(^uint32(0)>>1) {
		return nil, fmt.Errorf("store: retention batch limit %d exceeds int32", limit)
	}
	rows, err := r.q.ListEligibleSnapshotPayloads(ctx, pggen.ListEligibleSnapshotPayloadsParams{
		Now: pgtype.Timestamptz{Time: CanonTime(now), Valid: true}, BatchLimit: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]GCEligibleSnapshot, 0, len(rows))
	for _, row := range rows {
		out = append(out, GCEligibleSnapshot{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			EnvironmentID: row.EnvironmentID, Revision: row.Revision,
			Policy: RetentionPolicy{
				MaxAge: time.Duration(row.AgeSeconds) * time.Second, LastRevisions: row.RevisionCount,
			},
		})
	}
	return out, nil
}

func (r pgRetention) MarkCollected(ctx context.Context, p authz.Proof, snapshotID, policy string, now time.Time) (bool, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionMarkCollected, r.tok); err != nil {
		return false, err
	}
	stamp := pgtype.Timestamptz{Time: CanonTime(now), Valid: true}
	n, err := r.q.MarkSnapshotCollected(ctx, pggen.MarkSnapshotCollectedParams{
		CollectedAt: stamp, CollectedPolicy: policy, SnapshotID: snapshotID, Now: stamp,
	})
	return n == 1, constraint(err)
}

func (r pgRetention) DeleteCollectedEntries(ctx context.Context, p authz.Proof, snapshotID string) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionDeleteEntries, r.tok); err != nil {
		return 0, err
	}
	n, err := r.q.DeleteCollectedSnapshotEntries(ctx, snapshotID)
	return n, constraint(err)
}

func (r pgRetention) LastPruneSuccess(ctx context.Context, p authz.Proof) (time.Time, bool, error) {
	if _, err := authz.Verify(p, authz.StoreRetentionLastSuccess, r.tok); err != nil {
		return time.Time{}, false, err
	}
	got, err := r.q.GetLastPruneSuccess(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, ErrNotFound
	}
	if err != nil || !got.Valid {
		return time.Time{}, false, err
	}
	return got.Time.UTC(), true, nil
}

func (r pgRetention) SetLastPruneSuccess(ctx context.Context, p authz.Proof, at time.Time) error {
	if _, err := authz.Verify(p, authz.StoreRetentionSetLastSuccess, r.tok); err != nil {
		return err
	}
	return r.q.SetLastPruneSuccess(ctx, pgtype.Timestamptz{Time: CanonTime(at), Valid: true})
}
