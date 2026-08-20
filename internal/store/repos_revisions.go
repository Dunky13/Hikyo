package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

// The revision model's binding layer (#51). Same discipline as repos.go and
// repos_values.go: every method verifies the proof at the boundary against its
// own registered store operation and binds every chain parameter exclusively
// from the verified proof's resolved chain.
//
// `environment_id` is not a chain column of these tables (see the migration),
// so every environment-addressed method binds it through envOf — a proof of
// project depth is refused loudly rather than binding the empty string. The
// project-scoped methods take no environment parameter at all.
//
// A publish addresses a PROJECT but writes per ENVIRONMENT. It does not
// smuggle an environment id past this boundary to do so: it authorizes
// `publish` on each affected environment and writes under the environment-depth
// proof that authorization mints, exactly as the copy path authorizes each
// destination.

func pendingOperation(raw string) (PendingOperation, error) {
	switch PendingOperation(raw) {
	case PendingSet:
		return PendingSet, nil
	case PendingUnset:
		return PendingUnset, nil
	}
	return "", fmt.Errorf("store: pending change carries unknown operation %q", raw)
}

func pendingSource(raw string) (PendingSource, error) {
	switch PendingSource(raw) {
	case PendingSourceValues:
		return PendingSourceValues, nil
	case PendingSourceRestore:
		return PendingSourceRestore, nil
	}
	return "", fmt.Errorf("store: pending change carries unknown source %q", raw)
}

func revisionChange(raw string) (RevisionChange, error) {
	switch RevisionChange(raw) {
	case RevisionChangeAdded:
		return RevisionChangeAdded, nil
	case RevisionChangeEdited:
		return RevisionChangeEdited, nil
	case RevisionChangeRemoved:
		return RevisionChangeRemoved, nil
	}
	return "", fmt.Errorf("store: revision lineage row carries unknown change %q", raw)
}

// --- sqlite ---

type sqlitePending struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqlitePending) ListForOwner(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForOwner, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingChangesForOwner(ctx, sqlitegen.ListPendingChangesForOwnerParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		OwnerID:   ownerID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingChange, 0, len(rows))
	for _, row := range rows {
		change, err := pendingFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	return out, nil
}

func (r sqlitePending) ListForOwnerInEnvironment(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForOwnerInEnvironment, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StorePendingListForOwnerInEnvironment)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingChangesForOwnerInEnvironment(ctx, sqlitegen.ListPendingChangesForOwnerInEnvironmentParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env, OwnerID: ownerID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingChange, 0, len(rows))
	for _, row := range rows {
		change, err := pendingFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	return out, nil
}

func (r sqlitePending) ListMarkers(ctx context.Context, p authz.Proof) ([]PendingMarker, error) {
	chain, err := authz.Verify(p, authz.StorePendingListMarkers, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingMarkers(ctx, sqlitegen.ListPendingMarkersParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingMarker, 0, len(rows))
	for _, row := range rows {
		op, err := pendingOperation(row.Operation)
		if err != nil {
			return nil, err
		}
		out = append(out, PendingMarker{
			ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID,
			OwnerID: row.OwnerID, Operation: op,
		})
	}
	return out, nil
}

func (r sqlitePending) CountForProjectExcludingCell(ctx context.Context, p authz.Proof, keyID, ownerID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePendingCountForProjectExcludingCell, r.tok)
	if err != nil {
		return 0, err
	}
	env, err := envOf(chain, authz.StorePendingCountForProjectExcludingCell)
	if err != nil {
		return 0, err
	}
	// Two provable, chain-scoped counts rather than one NOT-predicate the SQL
	// analyzer cannot confine: the project total minus this cell's own row (0 or
	// 1 by the pending_changes uniqueness) is the project size AROUND the row
	// being staged.
	total, err := r.q.CountPendingChangesForProject(ctx, sqlitegen.CountPendingChangesForProjectParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
	})
	if err != nil {
		return 0, err
	}
	cell, err := r.q.CountPendingChangeForCell(ctx, sqlitegen.CountPendingChangeForCellParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
		EnvironmentID: env, KeyID: keyID, OwnerID: ownerID,
	})
	if err != nil {
		return 0, err
	}
	return total - cell, nil
}

func (r sqlitePending) Stage(ctx context.Context, p authz.Proof, change NewPendingChange) error {
	chain, err := authz.Verify(p, authz.StorePendingStage, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePendingStage)
	if err != nil {
		return err
	}
	if _, err := r.q.DeletePendingChangeForCell(ctx, sqlitegen.DeletePendingChangeForCellParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		KeyID:         change.KeyID,
		OwnerID:       change.OwnerID,
	}); err != nil {
		return constraint(err)
	}
	return constraint(r.q.InsertPendingChange(ctx, sqlitegen.InsertPendingChangeParams{
		ID:                 change.ID,
		OrgID:              string(chain.Org),
		ProjectID:          string(chain.Project),
		EnvironmentID:      env,
		KeyID:              change.KeyID,
		OwnerID:            change.OwnerID,
		Operation:          string(change.Operation),
		Ciphertext:         change.Ciphertext,
		StagedFromRevision: change.StagedFromRevision,
		StagedFromEntry:    change.StagedFromEntry,
		CreatedAt:          CanonTime(change.CreatedAt).Format(timeFormat),
		Source:             string(change.Source),
		Secret:             boolInt(change.Secret),
		MaterialSecret:     boolInt(change.MaterialSecret),
	}))
}

func (r sqlitePending) ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForReencrypt, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingForReencrypt(ctx, sqlitegen.ListPendingForReencryptParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), ID: cursor, Limit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptFieldRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ReencryptFieldRow{ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, Ciphertext: row.Ciphertext})
	}
	return out, nil
}

func (r sqlitePending) Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePendingReencrypt, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.ReencryptPendingChange(ctx, sqlitegen.ReencryptPendingChangeParams{
		Ciphertext: newCiphertext, OrgID: string(chain.Org), ProjectID: string(chain.Project),
		ID: id, Ciphertext_2: oldCiphertext,
	})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r sqlitePending) Discard(ctx context.Context, p authz.Proof, id string) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePendingDiscard, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StorePendingDiscard)
	if err != nil {
		return false, err
	}
	rows, err := r.q.DeletePendingChangeByID(ctx, sqlitegen.DeletePendingChangeByIDParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		ID:            id,
	})
	if err != nil {
		return false, constraint(err)
	}
	return rows > 0, nil
}

func (r sqlitePending) DiscardEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StorePendingDiscardEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePendingDiscardEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeletePendingChangesForEnvironment(ctx, sqlitegen.DeletePendingChangesForEnvironmentParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	return constraint(err)
}

func (r sqlitePending) DiscardKey(ctx context.Context, p authz.Proof, keyID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePendingDiscardKey, r.tok)
	if err != nil {
		return 0, err
	}
	rows, err := r.q.DeletePendingChangesForKey(ctx, sqlitegen.DeletePendingChangesForKeyParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		KeyID:     keyID,
	})
	if err != nil {
		return 0, constraint(err)
	}
	return rows, nil
}

func pendingFromSQLite(row sqlitegen.PendingChange) (PendingChange, error) {
	op, err := pendingOperation(row.Operation)
	if err != nil {
		return PendingChange{}, err
	}
	created, err := parseTime("pending change", row.ID, row.CreatedAt)
	if err != nil {
		return PendingChange{}, err
	}
	source, err := pendingSource(row.Source)
	if err != nil {
		return PendingChange{}, err
	}
	return PendingChange{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, OwnerID: row.OwnerID,
		Operation: op, Ciphertext: row.Ciphertext,
		StagedFromRevision: row.StagedFromRevision, StagedFromEntry: row.StagedFromEntry,
		CreatedAt: created, Source: source, Secret: row.Secret == 1,
		MaterialSecret: row.MaterialSecret == 1,
	}, nil
}

type sqliteSnapshots struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteSnapshots) Latest(ctx context.Context, p authz.Proof) (Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsLatest, r.tok)
	if err != nil {
		return Snapshot{}, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsLatest)
	if err != nil {
		return Snapshot{}, err
	}
	row, err := r.q.GetLatestSnapshot(ctx, sqlitegen.GetLatestSnapshotParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := revisionSnapshotFromSQLite(row)
	if err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}

func (r sqliteSnapshots) ProjectRevisions(ctx context.Context, p authz.Proof) (map[string]int64, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsProjectRevisions, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ProjectSnapshotRevisions(ctx, sqlitegen.ProjectSnapshotRevisionsParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		if row.Revision > out[row.EnvironmentID] {
			out[row.EnvironmentID] = row.Revision
		}
	}
	return out, nil
}

func (r sqliteSnapshots) AtRevision(ctx context.Context, p authz.Proof, revision int64) (Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsAtRevision, r.tok)
	if err != nil {
		return Snapshot{}, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsAtRevision)
	if err != nil {
		return Snapshot{}, err
	}
	return r.atRevision(ctx, string(chain.Org), string(chain.Project), env, revision)
}

func (r sqliteSnapshots) atRevision(ctx context.Context, orgID, projectID, envID string, revision int64) (Snapshot, error) {
	row, err := r.q.GetSnapshotByRevision(ctx, sqlitegen.GetSnapshotByRevisionParams{
		OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Revision: revision,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	return revisionSnapshotFromSQLite(row)
}

func (r sqliteSnapshots) List(ctx context.Context, p authz.Proof) ([]Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshots(ctx, sqlitegen.ListSnapshotsParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(rows))
	for _, row := range rows {
		snap, err := revisionSnapshotFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

func (r sqliteSnapshots) Entries(ctx context.Context, p authz.Proof, snapshot Snapshot) ([]SnapshotEntry, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsEntries, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsEntries)
	if err != nil {
		return nil, err
	}
	if _, err := liveSnapshot(snapshot); err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshotEntries(ctx, sqlitegen.ListSnapshotEntriesParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		SnapshotID:    snapshot.ID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SnapshotEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, SnapshotEntry{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			EnvironmentID: row.EnvironmentID, SnapshotID: row.SnapshotID,
			KeyID: row.KeyID, KeyName: row.KeyName, Classification: row.Classification,
			Ciphertext: row.Ciphertext, ValueEntryID: row.ValueEntryID,
		})
	}
	// Recheck after reading entries. Under Postgres READ COMMITTED the GC may
	// commit between the first state read and the payload query; without this
	// second observation that race would turn collection into a silent empty
	// result. A collection after this check linearizes after this read.
	fresh, err := r.atRevision(ctx, string(chain.Org), string(chain.Project), env, snapshot.Revision)
	if err != nil {
		return nil, err
	}
	if _, err := liveSnapshot(fresh); err != nil {
		return nil, err
	}
	return out, nil
}

func (r sqliteSnapshots) SecretValueOccurrenceIDs(ctx context.Context, p authz.Proof) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsSecretValueOccurrenceIDs, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsSecretValueOccurrenceIDs)
	if err != nil {
		return nil, err
	}
	return r.q.ListSecretValueOccurrenceIDs(ctx, sqlitegen.ListSecretValueOccurrenceIDsParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
	})
}

func (r sqliteSnapshots) Changes(ctx context.Context, p authz.Proof, revision int64) ([]RevisionKeyChange, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsChanges, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsChanges)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListRevisionKeyChanges(ctx, sqlitegen.ListRevisionKeyChangesParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		Revision:      revision,
	})
	if err != nil {
		return nil, err
	}
	out := make([]RevisionKeyChange, 0, len(rows))
	for _, row := range rows {
		change, err := revisionChange(row.Change)
		if err != nil {
			return nil, err
		}
		out = append(out, RevisionKeyChange{
			EnvironmentID: row.EnvironmentID, Revision: row.Revision,
			KeyID: row.KeyID, KeyName: row.KeyName, Change: change,
		})
	}
	return out, nil
}

func (r sqliteSnapshots) ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsListForReencrypt, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshotEntriesForReencrypt(ctx, sqlitegen.ListSnapshotEntriesForReencryptParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), ID: cursor, Limit: int64(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptFieldRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ReencryptFieldRow{ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, SnapshotID: row.SnapshotID, Ciphertext: row.Ciphertext})
	}
	return out, nil
}

func (r sqliteSnapshots) Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsReencrypt, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.ReencryptSnapshotEntry(ctx, sqlitegen.ReencryptSnapshotEntryParams{
		Ciphertext: newCiphertext, OrgID: string(chain.Org), ProjectID: string(chain.Project),
		ID: id, Ciphertext_2: oldCiphertext,
	})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r sqliteSnapshots) Insert(ctx context.Context, p authz.Proof, snapshot NewSnapshot) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsert)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertSnapshot(ctx, sqlitegen.InsertSnapshotParams{
		ID:             snapshot.ID,
		OrgID:          string(chain.Org),
		ProjectID:      string(chain.Project),
		EnvironmentID:  env,
		Revision:       snapshot.Revision,
		SchemaRevision: snapshot.SchemaRevision,
		PublishedBy:    snapshot.PublishedBy,
		PublishedAt:    CanonTime(snapshot.PublishedAt).Format(timeFormat),
	}))
}

func (r sqliteSnapshots) InsertEntry(ctx context.Context, p authz.Proof, entry NewSnapshotEntry) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsertEntry, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsertEntry)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertSnapshotEntry(ctx, sqlitegen.InsertSnapshotEntryParams{
		ID:             entry.ID,
		OrgID:          string(chain.Org),
		ProjectID:      string(chain.Project),
		EnvironmentID:  env,
		SnapshotID:     entry.SnapshotID,
		KeyID:          entry.KeyID,
		KeyName:        entry.KeyName,
		Classification: entry.Classification,
		Ciphertext:     entry.Ciphertext,
		ValueEntryID:   entry.ValueEntryID,
	}))
}

func (r sqliteSnapshots) RecordSecretValueOccurrence(ctx context.Context, p authz.Proof, valueEntryID string) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsRecordSecretValueOccurrence, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsRecordSecretValueOccurrence)
	if err != nil {
		return err
	}
	return constraint(r.q.RecordSecretValueOccurrence(ctx, sqlitegen.RecordSecretValueOccurrenceParams{
		ValueEntryID: valueEntryID, OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
	}))
}

func (r sqliteSnapshots) InsertChange(ctx context.Context, p authz.Proof, revision int64, keyID, keyName string, change RevisionChange) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsertChange, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsertChange)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertRevisionKeyChange(ctx, sqlitegen.InsertRevisionKeyChangeParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
		Revision:      revision,
		KeyID:         keyID,
		KeyName:       keyName,
		Change:        string(change),
	}))
}

func (r sqliteSnapshots) DeleteEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsDeleteEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsDeleteEnvironment)
	if err != nil {
		return err
	}
	// Entries first: they reference the snapshot rows.
	if _, err := r.q.DeleteSecretValueOccurrencesForEnvironment(ctx, sqlitegen.DeleteSecretValueOccurrencesForEnvironmentParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
	}); err != nil {
		return constraint(err)
	}
	if _, err := r.q.DeleteSnapshotEntriesForEnvironment(ctx, sqlitegen.DeleteSnapshotEntriesForEnvironmentParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	}); err != nil {
		return constraint(err)
	}
	if _, err := r.q.DeleteRevisionKeyChangesForEnvironment(ctx, sqlitegen.DeleteRevisionKeyChangesForEnvironmentParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	}); err != nil {
		return constraint(err)
	}
	_, err = r.q.DeleteSnapshotsForEnvironment(ctx, sqlitegen.DeleteSnapshotsForEnvironmentParams{
		OrgID:         string(chain.Org),
		ProjectID:     string(chain.Project),
		EnvironmentID: env,
	})
	return constraint(err)
}

func revisionSnapshotFromSQLite(row sqlitegen.Snapshot) (Snapshot, error) {
	published, err := parseTime("snapshot", row.ID, row.PublishedAt)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		EnvironmentID: row.EnvironmentID, Revision: row.Revision,
		SchemaRevision: row.SchemaRevision, PublishedBy: row.PublishedBy,
		PublishedAt: published, CollectedPolicy: row.CollectedPolicy,
		PayloadPresent: row.PayloadPresent == 1,
	}
	if row.CollectedAt.Valid {
		collected, err := parseTime("snapshot collection", row.ID, row.CollectedAt.String)
		if err != nil {
			return Snapshot{}, err
		}
		snapshot.CollectedAt = &collected
	}
	return snapshot, nil
}

func liveSnapshot(snapshot Snapshot) (Snapshot, error) {
	if !snapshot.PayloadPresent {
		return Snapshot{}, &domain.CollectedRevisionError{
			Revision: snapshot.Revision, Policy: snapshot.CollectedPolicy,
		}
	}
	return snapshot, nil
}

type sqlitePins struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqlitePins) GetForWorkload(ctx context.Context, p authz.Proof, workloadPrincipalID string) (RevisionPin, error) {
	chain, err := authz.Verify(p, authz.StorePinsGetForWorkload, r.tok)
	if err != nil {
		return RevisionPin{}, err
	}
	env, err := envOf(chain, authz.StorePinsGetForWorkload)
	if err != nil {
		return RevisionPin{}, err
	}
	row, err := r.q.GetRevisionPinForWorkload(ctx, sqlitegen.GetRevisionPinForWorkloadParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
		WorkloadPrincipalID: workloadPrincipalID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return RevisionPin{}, ErrNotFound
	}
	if err != nil {
		return RevisionPin{}, err
	}
	return revisionPinFromSQLite(row)
}

func (r sqlitePins) List(ctx context.Context, p authz.Proof) ([]RevisionPin, error) {
	chain, err := authz.Verify(p, authz.StorePinsList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StorePinsList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListRevisionPins(ctx, sqlitegen.ListRevisionPinsParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]RevisionPin, 0, len(rows))
	for _, row := range rows {
		pin, err := revisionPinFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, pin)
	}
	return out, nil
}

func (r sqlitePins) CountProject(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePinsCountProject, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountRevisionPinsForProject(ctx, sqlitegen.CountRevisionPinsForProjectParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
	})
}

func (r sqlitePins) Insert(ctx context.Context, p authz.Proof, pin NewRevisionPin) error {
	chain, err := authz.Verify(p, authz.StorePinsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePinsInsert)
	if err != nil {
		return err
	}
	override := int64(0)
	if pin.SchemaOverride {
		override = 1
	}
	historyAuthorized := int64(0)
	if pin.HistoryAuthorized {
		historyAuthorized = 1
	}
	return constraint(r.q.InsertRevisionPin(ctx, sqlitegen.InsertRevisionPinParams{
		ID: pin.ID, OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
		WorkloadPrincipalID: pin.WorkloadPrincipalID, SnapshotID: pin.SnapshotID,
		Revision: pin.Revision, AuthorityPrincipalID: pin.AuthorityPrincipalID,
		ExpiresAt: CanonTime(pin.ExpiresAt).Format(timeFormat), CreatedAt: CanonTime(pin.CreatedAt).Format(timeFormat),
		AuthorizedAt:      CanonTime(pin.AuthorizedAt).Format(timeFormat),
		HistoryAuthorized: historyAuthorized, SchemaOverride: override,
	}))
}

func (r sqlitePins) Delete(ctx context.Context, p authz.Proof, workloadPrincipalID string) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePinsDelete, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StorePinsDelete)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeleteRevisionPin(ctx, sqlitegen.DeleteRevisionPinParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
		WorkloadPrincipalID: workloadPrincipalID,
	})
	return n > 0, constraint(err)
}

func (r sqlitePins) DeleteEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StorePinsDeleteEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePinsDeleteEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteRevisionPinsForEnvironment(ctx, sqlitegen.DeleteRevisionPinsForEnvironmentParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), EnvironmentID: env,
	})
	return constraint(err)
}

func revisionPinFromSQLite(row sqlitegen.RevisionPin) (RevisionPin, error) {
	expires, err := parseTime("revision pin", row.ID, row.ExpiresAt)
	if err != nil {
		return RevisionPin{}, err
	}
	created, err := parseTime("revision pin", row.ID, row.CreatedAt)
	if err != nil {
		return RevisionPin{}, err
	}
	authorized, err := parseTime("revision pin", row.ID, row.AuthorizedAt)
	if err != nil {
		return RevisionPin{}, err
	}
	return RevisionPin{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID, EnvironmentID: row.EnvironmentID,
		WorkloadPrincipalID: row.WorkloadPrincipalID, SnapshotID: row.SnapshotID, Revision: row.Revision,
		AuthorityPrincipalID: row.AuthorityPrincipalID, ExpiresAt: expires, CreatedAt: created,
		AuthorizedAt: authorized, HistoryAuthorized: row.HistoryAuthorized == 1,
		SchemaOverride: row.SchemaOverride == 1,
	}, nil
}

// --- postgres ---

type pgPending struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgPending) ListForOwner(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForOwner, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingChangesForOwner(ctx, pggen.ListPendingChangesForOwnerParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		OwnerID:        ownerID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingChange, 0, len(rows))
	for _, row := range rows {
		change, err := pendingFromPostgres(row)
		if err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	return out, nil
}

func (r pgPending) ListForOwnerInEnvironment(ctx context.Context, p authz.Proof, ownerID string) ([]PendingChange, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForOwnerInEnvironment, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StorePendingListForOwnerInEnvironment)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingChangesForOwnerInEnvironment(ctx, pggen.ListPendingChangesForOwnerInEnvironmentParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env, OwnerID: ownerID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingChange, 0, len(rows))
	for _, row := range rows {
		change, err := pendingFromPostgres(row)
		if err != nil {
			return nil, err
		}
		out = append(out, change)
	}
	return out, nil
}

func pendingFromPostgres(row pggen.PendingChange) (PendingChange, error) {
	op, err := pendingOperation(row.Operation)
	if err != nil {
		return PendingChange{}, err
	}
	source, err := pendingSource(row.Source)
	if err != nil {
		return PendingChange{}, err
	}
	return PendingChange{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, OwnerID: row.OwnerID,
		Operation: op, Ciphertext: row.Ciphertext,
		StagedFromRevision: row.StagedFromRevision, StagedFromEntry: row.StagedFromEntry,
		CreatedAt: row.CreatedAt.Time.UTC(), Source: source, Secret: row.Secret,
		MaterialSecret: row.MaterialSecret,
	}, nil
}

func (r pgPending) ListMarkers(ctx context.Context, p authz.Proof) ([]PendingMarker, error) {
	chain, err := authz.Verify(p, authz.StorePendingListMarkers, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingMarkers(ctx, pggen.ListPendingMarkersParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]PendingMarker, 0, len(rows))
	for _, row := range rows {
		op, err := pendingOperation(row.Operation)
		if err != nil {
			return nil, err
		}
		out = append(out, PendingMarker{
			ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID,
			OwnerID: row.OwnerID, Operation: op,
		})
	}
	return out, nil
}

func (r pgPending) CountForProjectExcludingCell(ctx context.Context, p authz.Proof, keyID, ownerID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePendingCountForProjectExcludingCell, r.tok)
	if err != nil {
		return 0, err
	}
	env, err := envOf(chain, authz.StorePendingCountForProjectExcludingCell)
	if err != nil {
		return 0, err
	}
	total, err := r.q.CountPendingChangesForProject(ctx, pggen.CountPendingChangesForProjectParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
	})
	if err != nil {
		return 0, err
	}
	cell, err := r.q.CountPendingChangeForCell(ctx, pggen.CountPendingChangeForCellParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project),
		EnvironmentID: env, KeyID: keyID, OwnerID: ownerID,
	})
	if err != nil {
		return 0, err
	}
	return total - cell, nil
}

func (r pgPending) Stage(ctx context.Context, p authz.Proof, change NewPendingChange) error {
	chain, err := authz.Verify(p, authz.StorePendingStage, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePendingStage)
	if err != nil {
		return err
	}
	if _, err := r.q.DeletePendingChangeForCell(ctx, pggen.DeletePendingChangeForCellParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		KeyID:          change.KeyID,
		OwnerID:        change.OwnerID,
	}); err != nil {
		return constraint(err)
	}
	return constraint(r.q.InsertPendingChange(ctx, pggen.InsertPendingChangeParams{
		ID:                 change.ID,
		ChainOrgID:         string(chain.Org),
		ChainProjectID:     string(chain.Project),
		ChainEnvID:         env,
		KeyID:              change.KeyID,
		OwnerID:            change.OwnerID,
		Operation:          string(change.Operation),
		Ciphertext:         change.Ciphertext,
		StagedFromRevision: change.StagedFromRevision,
		StagedFromEntry:    change.StagedFromEntry,
		CreatedAt:          pgtype.Timestamptz{Time: CanonTime(change.CreatedAt), Valid: true},
		Source:             string(change.Source),
		Secret:             change.Secret,
		MaterialSecret:     change.MaterialSecret,
	}))
}

func (r pgPending) ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error) {
	chain, err := authz.Verify(p, authz.StorePendingListForReencrypt, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingForReencrypt(ctx, pggen.ListPendingForReencryptParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), Cursor: cursor, PageLimit: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptFieldRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ReencryptFieldRow{ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, Ciphertext: row.Ciphertext})
	}
	return out, nil
}

func (r pgPending) Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePendingReencrypt, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.ReencryptPendingChange(ctx, pggen.ReencryptPendingChangeParams{
		NewCiphertext: newCiphertext, ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project),
		ID: id, OldCiphertext: oldCiphertext,
	})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r pgPending) Discard(ctx context.Context, p authz.Proof, id string) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePendingDiscard, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StorePendingDiscard)
	if err != nil {
		return false, err
	}
	rows, err := r.q.DeletePendingChangeByID(ctx, pggen.DeletePendingChangeByIDParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		ID:             id,
	})
	if err != nil {
		return false, constraint(err)
	}
	return rows > 0, nil
}

func (r pgPending) DiscardEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StorePendingDiscardEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePendingDiscardEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeletePendingChangesForEnvironment(ctx, pggen.DeletePendingChangesForEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	return constraint(err)
}

func (r pgPending) DiscardKey(ctx context.Context, p authz.Proof, keyID string) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePendingDiscardKey, r.tok)
	if err != nil {
		return 0, err
	}
	rows, err := r.q.DeletePendingChangesForKey(ctx, pggen.DeletePendingChangesForKeyParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		KeyID:          keyID,
	})
	if err != nil {
		return 0, constraint(err)
	}
	return rows, nil
}

type pgSnapshots struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgSnapshots) Latest(ctx context.Context, p authz.Proof) (Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsLatest, r.tok)
	if err != nil {
		return Snapshot{}, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsLatest)
	if err != nil {
		return Snapshot{}, err
	}
	row, err := r.q.GetLatestSnapshot(ctx, pggen.GetLatestSnapshotParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	return revisionSnapshotFromPG(row), nil
}

func (r pgSnapshots) ProjectRevisions(ctx context.Context, p authz.Proof) (map[string]int64, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsProjectRevisions, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ProjectSnapshotRevisions(ctx, pggen.ProjectSnapshotRevisionsParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, row := range rows {
		if row.Revision > out[row.EnvironmentID] {
			out[row.EnvironmentID] = row.Revision
		}
	}
	return out, nil
}

func (r pgSnapshots) AtRevision(ctx context.Context, p authz.Proof, revision int64) (Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsAtRevision, r.tok)
	if err != nil {
		return Snapshot{}, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsAtRevision)
	if err != nil {
		return Snapshot{}, err
	}
	return r.atRevision(ctx, string(chain.Org), string(chain.Project), env, revision)
}

func (r pgSnapshots) atRevision(ctx context.Context, orgID, projectID, envID string, revision int64) (Snapshot, error) {
	row, err := r.q.GetSnapshotByRevision(ctx, pggen.GetSnapshotByRevisionParams{
		ChainOrgID: orgID, ChainProjectID: projectID, ChainEnvID: envID, Revision: revision,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrNotFound
	}
	if err != nil {
		return Snapshot{}, err
	}
	return revisionSnapshotFromPG(row), nil
}

func (r pgSnapshots) List(ctx context.Context, p authz.Proof) ([]Snapshot, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshots(ctx, pggen.ListSnapshotsParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(rows))
	for _, row := range rows {
		out = append(out, revisionSnapshotFromPG(row))
	}
	return out, nil
}

func (r pgSnapshots) Entries(ctx context.Context, p authz.Proof, snapshot Snapshot) ([]SnapshotEntry, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsEntries, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsEntries)
	if err != nil {
		return nil, err
	}
	if _, err := liveSnapshot(snapshot); err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshotEntries(ctx, pggen.ListSnapshotEntriesParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		SnapshotID:     snapshot.ID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SnapshotEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, SnapshotEntry{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			EnvironmentID: row.EnvironmentID, SnapshotID: row.SnapshotID,
			KeyID: row.KeyID, KeyName: row.KeyName, Classification: row.Classification,
			Ciphertext: row.Ciphertext, ValueEntryID: row.ValueEntryID,
		})
	}
	fresh, err := r.atRevision(ctx, string(chain.Org), string(chain.Project), env, snapshot.Revision)
	if err != nil {
		return nil, err
	}
	if _, err := liveSnapshot(fresh); err != nil {
		return nil, err
	}
	return out, nil
}

func (r pgSnapshots) SecretValueOccurrenceIDs(ctx context.Context, p authz.Proof) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsSecretValueOccurrenceIDs, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsSecretValueOccurrenceIDs)
	if err != nil {
		return nil, err
	}
	return r.q.ListSecretValueOccurrenceIDs(ctx, pggen.ListSecretValueOccurrenceIDsParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
	})
}

func (r pgSnapshots) Changes(ctx context.Context, p authz.Proof, revision int64) ([]RevisionKeyChange, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsChanges, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StoreSnapshotsChanges)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListRevisionKeyChanges(ctx, pggen.ListRevisionKeyChangesParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		Revision:       revision,
	})
	if err != nil {
		return nil, err
	}
	out := make([]RevisionKeyChange, 0, len(rows))
	for _, row := range rows {
		change, err := revisionChange(row.Change)
		if err != nil {
			return nil, err
		}
		out = append(out, RevisionKeyChange{
			EnvironmentID: row.EnvironmentID, Revision: row.Revision,
			KeyID: row.KeyID, KeyName: row.KeyName, Change: change,
		})
	}
	return out, nil
}

func (r pgSnapshots) ListForReencrypt(ctx context.Context, p authz.Proof, cursor string, limit int) ([]ReencryptFieldRow, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsListForReencrypt, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListSnapshotEntriesForReencrypt(ctx, pggen.ListSnapshotEntriesForReencryptParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), Cursor: cursor, PageLimit: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReencryptFieldRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, ReencryptFieldRow{ID: row.ID, EnvironmentID: row.EnvironmentID, KeyID: row.KeyID, SnapshotID: row.SnapshotID, Ciphertext: row.Ciphertext})
	}
	return out, nil
}

func (r pgSnapshots) Reencrypt(ctx context.Context, p authz.Proof, id string, newCiphertext, oldCiphertext []byte) (bool, error) {
	chain, err := authz.Verify(p, authz.StoreSnapshotsReencrypt, r.tok)
	if err != nil {
		return false, err
	}
	n, err := r.q.ReencryptSnapshotEntry(ctx, pggen.ReencryptSnapshotEntryParams{
		NewCiphertext: newCiphertext, ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project),
		ID: id, OldCiphertext: oldCiphertext,
	})
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r pgSnapshots) Insert(ctx context.Context, p authz.Proof, snapshot NewSnapshot) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsert)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertSnapshot(ctx, pggen.InsertSnapshotParams{
		ID:             snapshot.ID,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		Revision:       snapshot.Revision,
		SchemaRevision: snapshot.SchemaRevision,
		PublishedBy:    snapshot.PublishedBy,
		PublishedAt:    pgtype.Timestamptz{Time: CanonTime(snapshot.PublishedAt), Valid: true},
	}))
}

func (r pgSnapshots) InsertEntry(ctx context.Context, p authz.Proof, entry NewSnapshotEntry) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsertEntry, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsertEntry)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertSnapshotEntry(ctx, pggen.InsertSnapshotEntryParams{
		ID:             entry.ID,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		SnapshotID:     entry.SnapshotID,
		KeyID:          entry.KeyID,
		KeyName:        entry.KeyName,
		Classification: entry.Classification,
		Ciphertext:     entry.Ciphertext,
		ValueEntryID:   entry.ValueEntryID,
	}))
}

func (r pgSnapshots) RecordSecretValueOccurrence(ctx context.Context, p authz.Proof, valueEntryID string) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsRecordSecretValueOccurrence, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsRecordSecretValueOccurrence)
	if err != nil {
		return err
	}
	return constraint(r.q.RecordSecretValueOccurrence(ctx, pggen.RecordSecretValueOccurrenceParams{
		ValueEntryID: valueEntryID, ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
	}))
}

func (r pgSnapshots) InsertChange(ctx context.Context, p authz.Proof, revision int64, keyID, keyName string, change RevisionChange) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsInsertChange, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsInsertChange)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertRevisionKeyChange(ctx, pggen.InsertRevisionKeyChangeParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
		Revision:       revision,
		KeyID:          keyID,
		KeyName:        keyName,
		Change:         string(change),
	}))
}

func (r pgSnapshots) DeleteEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreSnapshotsDeleteEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StoreSnapshotsDeleteEnvironment)
	if err != nil {
		return err
	}
	if _, err := r.q.DeleteSecretValueOccurrencesForEnvironment(ctx, pggen.DeleteSecretValueOccurrencesForEnvironmentParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
	}); err != nil {
		return constraint(err)
	}
	if _, err := r.q.DeleteSnapshotEntriesForEnvironment(ctx, pggen.DeleteSnapshotEntriesForEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	}); err != nil {
		return constraint(err)
	}
	if _, err := r.q.DeleteRevisionKeyChangesForEnvironment(ctx, pggen.DeleteRevisionKeyChangesForEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	}); err != nil {
		return constraint(err)
	}
	_, err = r.q.DeleteSnapshotsForEnvironment(ctx, pggen.DeleteSnapshotsForEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     env,
	})
	return constraint(err)
}

func revisionSnapshotFromPG(row pggen.Snapshot) Snapshot {
	snapshot := Snapshot{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		EnvironmentID: row.EnvironmentID, Revision: row.Revision,
		SchemaRevision: row.SchemaRevision, PublishedBy: row.PublishedBy,
		PublishedAt: row.PublishedAt.Time.UTC(), CollectedPolicy: row.CollectedPolicy,
		PayloadPresent: row.PayloadPresent,
	}
	if row.CollectedAt.Valid {
		collected := row.CollectedAt.Time.UTC()
		snapshot.CollectedAt = &collected
	}
	return snapshot
}

type pgPins struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgPins) GetForWorkload(ctx context.Context, p authz.Proof, workloadPrincipalID string) (RevisionPin, error) {
	chain, err := authz.Verify(p, authz.StorePinsGetForWorkload, r.tok)
	if err != nil {
		return RevisionPin{}, err
	}
	env, err := envOf(chain, authz.StorePinsGetForWorkload)
	if err != nil {
		return RevisionPin{}, err
	}
	row, err := r.q.GetRevisionPinForWorkload(ctx, pggen.GetRevisionPinForWorkloadParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
		WorkloadPrincipalID: workloadPrincipalID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RevisionPin{}, ErrNotFound
	}
	if err != nil {
		return RevisionPin{}, err
	}
	return revisionPinFromPG(row), nil
}

func (r pgPins) List(ctx context.Context, p authz.Proof) ([]RevisionPin, error) {
	chain, err := authz.Verify(p, authz.StorePinsList, r.tok)
	if err != nil {
		return nil, err
	}
	env, err := envOf(chain, authz.StorePinsList)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListRevisionPins(ctx, pggen.ListRevisionPinsParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
	})
	if err != nil {
		return nil, err
	}
	out := make([]RevisionPin, 0, len(rows))
	for _, row := range rows {
		out = append(out, revisionPinFromPG(row))
	}
	return out, nil
}

func (r pgPins) CountProject(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StorePinsCountProject, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountRevisionPinsForProject(ctx, pggen.CountRevisionPinsForProjectParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project),
	})
}

func (r pgPins) Insert(ctx context.Context, p authz.Proof, pin NewRevisionPin) error {
	chain, err := authz.Verify(p, authz.StorePinsInsert, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePinsInsert)
	if err != nil {
		return err
	}
	return constraint(r.q.InsertRevisionPin(ctx, pggen.InsertRevisionPinParams{
		ID: pin.ID, ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
		WorkloadPrincipalID: pin.WorkloadPrincipalID, SnapshotID: pin.SnapshotID,
		Revision: pin.Revision, AuthorityPrincipalID: pin.AuthorityPrincipalID,
		ExpiresAt:         pgtype.Timestamptz{Time: CanonTime(pin.ExpiresAt), Valid: true},
		CreatedAt:         pgtype.Timestamptz{Time: CanonTime(pin.CreatedAt), Valid: true},
		AuthorizedAt:      pgtype.Timestamptz{Time: CanonTime(pin.AuthorizedAt), Valid: true},
		HistoryAuthorized: pin.HistoryAuthorized,
		SchemaOverride:    pin.SchemaOverride,
	}))
}

func (r pgPins) Delete(ctx context.Context, p authz.Proof, workloadPrincipalID string) (bool, error) {
	chain, err := authz.Verify(p, authz.StorePinsDelete, r.tok)
	if err != nil {
		return false, err
	}
	env, err := envOf(chain, authz.StorePinsDelete)
	if err != nil {
		return false, err
	}
	n, err := r.q.DeleteRevisionPin(ctx, pggen.DeleteRevisionPinParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
		WorkloadPrincipalID: workloadPrincipalID,
	})
	return n > 0, constraint(err)
}

func (r pgPins) DeleteEnvironment(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StorePinsDeleteEnvironment, r.tok)
	if err != nil {
		return err
	}
	env, err := envOf(chain, authz.StorePinsDeleteEnvironment)
	if err != nil {
		return err
	}
	_, err = r.q.DeleteRevisionPinsForEnvironment(ctx, pggen.DeleteRevisionPinsForEnvironmentParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: env,
	})
	return constraint(err)
}

func revisionPinFromPG(row pggen.RevisionPin) RevisionPin {
	return RevisionPin{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID, EnvironmentID: row.EnvironmentID,
		WorkloadPrincipalID: row.WorkloadPrincipalID, SnapshotID: row.SnapshotID, Revision: row.Revision,
		AuthorityPrincipalID: row.AuthorityPrincipalID, ExpiresAt: row.ExpiresAt.Time.UTC(),
		CreatedAt: row.CreatedAt.Time.UTC(), AuthorizedAt: row.AuthorizedAt.Time.UTC(),
		HistoryAuthorized: row.HistoryAuthorized, SchemaOverride: row.SchemaOverride,
	}
}
