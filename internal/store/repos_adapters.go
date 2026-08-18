package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

type sqliteAdapters struct {
	db  sqlitegen.DBTX
	tok *authz.TxToken
}

type pgAdapters struct {
	db  pggen.DBTX
	tok *authz.TxToken
}

func (r sqliteRepos) Adapters() AdapterRepo { return sqliteAdapters{db: r.db, tok: r.tok} }
func (r pgRepos) Adapters() AdapterRepo     { return pgAdapters{db: r.db, tok: r.tok} }

func scanAdapterTarget(row interface{ Scan(...any) error }) (AdapterTarget, error) {
	var target AdapterTarget
	var failureRaw, warningRaw, selectedRaw []byte
	err := row.Scan(
		&target.ID, &target.AdapterID, &target.EnvironmentID, &target.Provider, &target.Origin,
		&target.DestinationKind, &target.DestinationOwner, &target.DestinationName, &target.DestinationEnvironment,
		&target.DestinationID, &target.RepositoryID, &target.Visibility, &selectedRaw,
		&target.NamePrefix, &target.Generation, &target.State,
		&target.SyncStatus, &target.ConvergedRevision, &failureRaw, &warningRaw, &target.AuthorityPrincipalID,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return AdapterTarget{}, ErrNotFound
		}
		return AdapterTarget{}, err
	}
	if len(failureRaw) != 0 {
		if err := json.Unmarshal(failureRaw, &target.FailureNames); err != nil {
			return AdapterTarget{}, fmt.Errorf("store: adapter target failure names: %w", err)
		}
	}
	if len(warningRaw) != 0 {
		if err := json.Unmarshal(warningRaw, &target.Warnings); err != nil {
			return AdapterTarget{}, fmt.Errorf("store: adapter target warning names: %w", err)
		}
	}
	if len(selectedRaw) != 0 {
		if err := json.Unmarshal(selectedRaw, &target.SelectedRepositoryIDs); err != nil {
			return AdapterTarget{}, fmt.Errorf("store: adapter target selected repository ids: %w", err)
		}
	}
	return target, nil
}

func (r sqliteAdapters) Target(ctx context.Context, p authz.Proof, targetID string) (AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTarget, r.tok)
	if err != nil {
		return AdapterTarget{}, err
	}
	return scanAdapterTarget(r.db.QueryRowContext(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=?`, targetID, chain.Org, chain.Project))
}

func (r pgAdapters) Target(ctx context.Context, p authz.Proof, targetID string) (AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTarget, r.tok)
	if err != nil {
		return AdapterTarget{}, err
	}
	return scanAdapterTarget(r.db.QueryRow(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$1 AND t.org_id=$2 AND t.project_id=$3`, targetID, chain.Org, chain.Project))
}

func (r sqliteAdapters) Mapping(ctx context.Context, p authz.Proof, targetID string) ([]adapter.ManifestEntry, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMapping, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT e.key_id,e.key_name,e.classification FROM snapshot_entries e JOIN adapter_target_keys k ON k.key_id=e.key_id AND k.target_id=? AND k.org_id=e.org_id AND k.project_id=e.project_id AND k.environment_id=e.environment_id JOIN adapter_targets t ON t.id=k.target_id AND t.org_id=k.org_id AND t.project_id=k.project_id AND t.environment_id=k.environment_id WHERE t.org_id=? AND t.project_id=? AND e.snapshot_id=(SELECT id FROM snapshots WHERE org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND payload_present=1 ORDER BY revision DESC LIMIT 1) ORDER BY e.key_name`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []adapter.ManifestEntry
	for rows.Next() {
		var row adapter.ManifestEntry
		if err := rows.Scan(&row.KeyID, &row.CanonicalName, &row.Classification); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r pgAdapters) Mapping(ctx context.Context, p authz.Proof, targetID string) ([]adapter.ManifestEntry, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersMapping, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT e.key_id,e.key_name,e.classification FROM snapshot_entries e JOIN adapter_target_keys k ON k.key_id=e.key_id AND k.target_id=$1 AND k.org_id=e.org_id AND k.project_id=e.project_id AND k.environment_id=e.environment_id JOIN adapter_targets t ON t.id=k.target_id AND t.org_id=k.org_id AND t.project_id=k.project_id AND t.environment_id=k.environment_id WHERE t.org_id=$2 AND t.project_id=$3 AND e.snapshot_id=(SELECT id FROM snapshots WHERE org_id=t.org_id AND project_id=t.project_id AND environment_id=t.environment_id AND payload_present=true ORDER BY revision DESC LIMIT 1) ORDER BY e.key_name`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []adapter.ManifestEntry
	for rows.Next() {
		var row adapter.ManifestEntry
		var classification string
		if err := rows.Scan(&row.KeyID, &row.CanonicalName, &classification); err != nil {
			return nil, err
		}
		row.Classification = adapter.Classification(classification)
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r sqliteAdapters) PlanMaterial(ctx context.Context, p authz.Proof, targetID string) (AdapterPlanMaterial, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersPlanMaterial, r.tok)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	target, err := scanAdapterTarget(r.db.QueryRowContext(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=?`, targetID, chain.Org, chain.Project))
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	var credential []byte
	if err := r.db.QueryRowContext(ctx, `SELECT credential_ciphertext FROM adapters WHERE id=? AND org_id=? AND project_id=?`, target.AdapterID, chain.Org, chain.Project).Scan(&credential); err != nil {
		return AdapterPlanMaterial{}, err
	}
	out := AdapterPlanMaterial{Target: target, CredentialCiphertext: credential}
	manifestRows, err := r.db.QueryContext(ctx, `SELECT e.key_id,e.key_name,e.classification FROM snapshot_entries e JOIN adapter_target_keys k ON k.key_id=e.key_id AND k.target_id=? AND k.org_id=e.org_id AND k.project_id=e.project_id AND k.environment_id=e.environment_id WHERE e.snapshot_id=(SELECT id FROM snapshots WHERE org_id=? AND project_id=? AND environment_id=? AND payload_present=1 ORDER BY revision DESC LIMIT 1) AND e.org_id=? AND e.project_id=? AND e.environment_id=? ORDER BY e.key_name`, targetID, chain.Org, chain.Project, target.EnvironmentID, chain.Org, chain.Project, target.EnvironmentID)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	for manifestRows.Next() {
		var row adapter.ManifestEntry
		if err := manifestRows.Scan(&row.KeyID, &row.CanonicalName, &row.Classification); err != nil {
			_ = manifestRows.Close()
			return AdapterPlanMaterial{}, err
		}
		out.Manifest = append(out.Manifest, row)
	}
	if err := manifestRows.Close(); err != nil {
		return AdapterPlanMaterial{}, err
	}
	ledgerRows, err := r.db.QueryContext(ctx, `SELECT surface,effective_name,state,missing FROM adapter_ledger WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state<>'released' ORDER BY surface,effective_name`, targetID, chain.Org, chain.Project, target.EnvironmentID)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	defer ledgerRows.Close()
	for ledgerRows.Next() {
		var surface, state string
		var row adapter.LedgerEntry
		var missing int
		if err := ledgerRows.Scan(&surface, &row.EffectiveName, &state, &missing); err != nil {
			return AdapterPlanMaterial{}, err
		}
		row.Missing = missing != 0
		row.Surface, row.State = adapter.Surface(surface), adapter.LedgerState(state)
		out.Ledger = append(out.Ledger, row)
	}
	return out, ledgerRows.Err()
}

func (r pgAdapters) PlanMaterial(ctx context.Context, p authz.Proof, targetID string) (AdapterPlanMaterial, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersPlanMaterial, r.tok)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	target, err := scanAdapterTarget(r.db.QueryRow(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$1 AND t.org_id=$2 AND t.project_id=$3`, targetID, chain.Org, chain.Project))
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	var credential []byte
	if err := r.db.QueryRow(ctx, `SELECT credential_ciphertext FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3`, target.AdapterID, chain.Org, chain.Project).Scan(&credential); err != nil {
		return AdapterPlanMaterial{}, err
	}
	out := AdapterPlanMaterial{Target: target, CredentialCiphertext: credential}
	manifestRows, err := r.db.Query(ctx, `SELECT e.key_id,e.key_name,e.classification FROM snapshot_entries e JOIN adapter_target_keys k ON k.key_id=e.key_id AND k.target_id=$1 AND k.org_id=e.org_id AND k.project_id=e.project_id AND k.environment_id=e.environment_id WHERE e.snapshot_id=(SELECT id FROM snapshots WHERE org_id=$2 AND project_id=$3 AND environment_id=$4 AND payload_present=true ORDER BY revision DESC LIMIT 1) AND e.org_id=$5 AND e.project_id=$6 AND e.environment_id=$7 ORDER BY e.key_name`, targetID, chain.Org, chain.Project, target.EnvironmentID, chain.Org, chain.Project, target.EnvironmentID)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	for manifestRows.Next() {
		var row adapter.ManifestEntry
		var classification string
		if err := manifestRows.Scan(&row.KeyID, &row.CanonicalName, &classification); err != nil {
			manifestRows.Close()
			return AdapterPlanMaterial{}, err
		}
		row.Classification = adapter.Classification(classification)
		out.Manifest = append(out.Manifest, row)
	}
	manifestRows.Close()
	if err := manifestRows.Err(); err != nil {
		return AdapterPlanMaterial{}, err
	}
	ledgerRows, err := r.db.Query(ctx, `SELECT surface,effective_name,state,missing FROM adapter_ledger WHERE target_id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4 AND state<>'released' ORDER BY surface,effective_name`, targetID, chain.Org, chain.Project, target.EnvironmentID)
	if err != nil {
		return AdapterPlanMaterial{}, err
	}
	defer ledgerRows.Close()
	for ledgerRows.Next() {
		var surface, state string
		var row adapter.LedgerEntry
		if err := ledgerRows.Scan(&surface, &row.EffectiveName, &state, &row.Missing); err != nil {
			return AdapterPlanMaterial{}, err
		}
		row.Surface, row.State = adapter.Surface(surface), adapter.LedgerState(state)
		out.Ledger = append(out.Ledger, row)
	}
	return out, ledgerRows.Err()
}

func (r sqliteAdapters) TargetEnvironments(ctx context.Context, p authz.Proof, targetID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTargetEnvironments, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT sibling.environment_id FROM adapter_targets target JOIN adapter_targets sibling ON sibling.adapter_id=target.adapter_id AND sibling.org_id=target.org_id AND sibling.project_id=target.project_id WHERE target.id=? AND target.org_id=? AND target.project_id=? AND sibling.state<>'tombstoned' ORDER BY sibling.environment_id`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r pgAdapters) TargetEnvironments(ctx context.Context, p authz.Proof, targetID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTargetEnvironments, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT sibling.environment_id FROM adapter_targets target JOIN adapter_targets sibling ON sibling.adapter_id=target.adapter_id AND sibling.org_id=target.org_id AND sibling.project_id=target.project_id WHERE target.id=$1 AND target.org_id=$2 AND target.project_id=$3 AND sibling.state<>'tombstoned' ORDER BY sibling.environment_id`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r sqliteAdapters) Environments(ctx context.Context, p authz.Proof, adapterID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnvironments, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT environment_id FROM adapter_targets WHERE adapter_id=? AND org_id=? AND project_id=? AND state='active' ORDER BY environment_id`, adapterID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r pgAdapters) Environments(ctx context.Context, p authz.Proof, adapterID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnvironments, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT DISTINCT environment_id FROM adapter_targets WHERE adapter_id=$1 AND org_id=$2 AND project_id=$3 AND state='active' ORDER BY environment_id`, adapterID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type conflictScanner interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func collectAdapterConflicts(rows conflictScanner) ([]AdapterConflictArtifact, error) {
	byID := make(map[string]int)
	var out []AdapterConflictArtifact
	for rows.Next() {
		var artifact AdapterConflictArtifact
		var entry AdapterConflictEntry
		var jobID sql.NullString
		var createdRaw any
		if err := rows.Scan(&artifact.ID, &artifact.TargetID, &jobID, &artifact.DestinationID, &artifact.RepositoryID, &artifact.TargetGeneration, &entry.Surface, &entry.EffectiveName, &createdRaw); err != nil {
			return nil, err
		}
		artifact.JobID = jobID.String
		switch value := createdRaw.(type) {
		case string:
			parsed, err := parseTime("adapter conflict", artifact.ID, value)
			if err != nil {
				return nil, err
			}
			artifact.CreatedAt = parsed
		case []byte:
			parsed, err := parseTime("adapter conflict", artifact.ID, string(value))
			if err != nil {
				return nil, err
			}
			artifact.CreatedAt = parsed
		case time.Time:
			artifact.CreatedAt = value.UTC()
		case nil:
		}
		if index, ok := byID[artifact.ID]; ok {
			out[index].Entries = append(out[index].Entries, entry)
		} else {
			artifact.Entries = []AdapterConflictEntry{entry}
			byID[artifact.ID] = len(out)
			out = append(out, artifact)
		}
	}
	return out, rows.Err()
}

func (r sqliteAdapters) Conflicts(ctx context.Context, p authz.Proof, targetID string) ([]AdapterConflictArtifact, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersConflicts, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT artifact_id,target_id,job_id,destination_id,repository_id,target_generation,surface,effective_name,created_at FROM adapter_conflicts WHERE target_id=? AND org_id=? AND project_id=? AND adopted_at IS NULL ORDER BY created_at,artifact_id,surface,effective_name`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterConflicts(rows)
}

func (r pgAdapters) Conflicts(ctx context.Context, p authz.Proof, targetID string) ([]AdapterConflictArtifact, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersConflicts, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT artifact_id,target_id,job_id,destination_id,repository_id,target_generation,surface,effective_name,created_at FROM adapter_conflicts WHERE target_id=$1 AND org_id=$2 AND project_id=$3 AND adopted_at IS NULL ORDER BY created_at,artifact_id,surface,effective_name`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterConflicts(rows)
}

func (r sqliteAdapters) RecordPlan(ctx context.Context, p authz.Proof, targetID, artifactID string, expectedGeneration, expectedRepositoryID, expectedDestinationID int64, entries []AdapterConflictEntry, at time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersRecordPlan, r.tok)
	if err != nil {
		return err
	}
	return recordAdapterPlan(ctx, sqliteAdoptDB{db: r.db}, chain, targetID, artifactID, expectedGeneration, expectedRepositoryID, expectedDestinationID, entries, at)
}

func (r pgAdapters) RecordPlan(ctx context.Context, p authz.Proof, targetID, artifactID string, expectedGeneration, expectedRepositoryID, expectedDestinationID int64, entries []AdapterConflictEntry, at time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersRecordPlan, r.tok)
	if err != nil {
		return err
	}
	return recordAdapterPlan(ctx, pgAdoptDB{db: r.db}, chain, targetID, artifactID, expectedGeneration, expectedRepositoryID, expectedDestinationID, entries, at)
}

func recordAdapterPlan(ctx context.Context, db adoptDB, chain domain.Scope, targetID, artifactID string, expectedGeneration, expectedRepositoryID, expectedDestinationID int64, entries []AdapterConflictEntry, at time.Time) error {
	if targetID == "" || artifactID == "" || expectedGeneration <= 0 || expectedDestinationID <= 0 || at.IsZero() {
		return fmt.Errorf("%w: incomplete adapter plan artifact", ErrConflict)
	}
	var environmentID string
	var destinationID, repositoryID, generation int64
	lookup := db.SQL(
		`SELECT environment_id,destination_id,repository_id,generation FROM adapter_targets WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`SELECT environment_id,destination_id,repository_id,generation FROM adapter_targets WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active' FOR SHARE`)
	if err := db.QueryRow(ctx, lookup, targetID, chain.Org, chain.Project).Scan(&environmentID, &destinationID, &repositoryID, &generation); err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if generation != expectedGeneration || repositoryID != expectedRepositoryID || destinationID != expectedDestinationID {
		return fmt.Errorf("%w: adapter target changed while planning", ErrConflict)
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		key := entry.Surface + "\x00" + strings.ToUpper(entry.EffectiveName)
		if (entry.Surface != string(adapter.Secret) && entry.Surface != string(adapter.Variable)) || entry.EffectiveName == "" || seen[key] {
			return fmt.Errorf("%w: invalid or duplicate adapter plan conflict", ErrConflict)
		}
		seen[key] = true
		insert := db.SQL(
			`INSERT INTO adapter_conflicts (id,artifact_id,org_id,project_id,environment_id,target_id,job_id,destination_id,repository_id,target_generation,surface,effective_name,created_at) VALUES (?,?,?,?,?,?,NULL,?,?,?,?,?,?)`,
			`INSERT INTO adapter_conflicts (id,artifact_id,org_id,project_id,environment_id,target_id,job_id,destination_id,repository_id,target_generation,surface,effective_name,created_at) VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,$10,$11,$12)`)
		if rows, err := db.Exec(ctx, insert, newAdapterID("acn"), artifactID, chain.Org, chain.Project, environmentID, targetID, destinationID, repositoryID, generation, entry.Surface, entry.EffectiveName, db.Stamp(at)); err != nil || rows != 1 {
			if err != nil {
				return err
			}
			return ErrConflict
		}
	}
	return nil
}

func validateAdapterAdoption(adoption AdapterAdoption) error {
	if adoption.TargetID == "" || adoption.ArtifactID == "" || adoption.AuthorityPrincipalID == "" || adoption.JobID == "" || adoption.AuditAt.IsZero() || len(adoption.Entries) == 0 || len(adoption.Entries) != len(adoption.LedgerIDs) {
		return fmt.Errorf("%w: incomplete adapter adoption", ErrConflict)
	}
	seen := make(map[string]bool, len(adoption.Entries))
	for i, entry := range adoption.Entries {
		key := entry.Surface + "\x00" + strings.ToUpper(entry.EffectiveName)
		if (entry.Surface != string(adapter.Secret) && entry.Surface != string(adapter.Variable)) || entry.EffectiveName == "" || adoption.LedgerIDs[i] == "" || seen[key] {
			return fmt.Errorf("%w: invalid or duplicate adapter adoption entry", ErrConflict)
		}
		seen[key] = true
	}
	return nil
}

func (r sqliteAdapters) Adopt(ctx context.Context, p authz.Proof, adoption AdapterAdoption) (AdapterAdoptionResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersAdopt, r.tok)
	if err != nil {
		return AdapterAdoptionResult{}, err
	}
	if err := validateAdapterAdoption(adoption); err != nil {
		return AdapterAdoptionResult{}, err
	}
	return adoptAdapter(ctx, sqliteAdoptDB{db: r.db}, chain, adoption)
}

func (r pgAdapters) Adopt(ctx context.Context, p authz.Proof, adoption AdapterAdoption) (AdapterAdoptionResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersAdopt, r.tok)
	if err != nil {
		return AdapterAdoptionResult{}, err
	}
	if err := validateAdapterAdoption(adoption); err != nil {
		return AdapterAdoptionResult{}, err
	}
	return adoptAdapter(ctx, pgAdoptDB{db: r.db}, chain, adoption)
}

type adoptDB interface {
	QueryRow(context.Context, string, ...any) interface{ Scan(...any) error }
	Query(context.Context, string, ...any) (adapterTargetRows, error)
	Exec(context.Context, string, ...any) (int64, error)
	SQL(string, string) string
	Stamp(time.Time) any
}

type sqliteAdoptDB struct{ db sqlitegen.DBTX }

func (d sqliteAdoptDB) QueryRow(ctx context.Context, query string, args ...any) interface{ Scan(...any) error } {
	return d.db.QueryRowContext(ctx, query, args...)
}
func (d sqliteAdoptDB) Query(ctx context.Context, query string, args ...any) (adapterTargetRows, error) {
	return d.db.QueryContext(ctx, query, args...)
}
func (d sqliteAdoptDB) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	result, err := d.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, constraint(err)
	}
	return result.RowsAffected()
}
func (sqliteAdoptDB) SQL(sqliteQuery, _ string) string { return sqliteQuery }
func (sqliteAdoptDB) Stamp(value time.Time) any        { return CanonTime(value).Format(timeFormat) }

type pgAdoptDB struct{ db pggen.DBTX }

func (d pgAdoptDB) QueryRow(ctx context.Context, query string, args ...any) interface{ Scan(...any) error } {
	return d.db.QueryRow(ctx, query, args...)
}
func (d pgAdoptDB) Query(ctx context.Context, query string, args ...any) (adapterTargetRows, error) {
	return d.db.Query(ctx, query, args...)
}
func (d pgAdoptDB) Exec(ctx context.Context, query string, args ...any) (int64, error) {
	tag, err := d.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, constraint(err)
	}
	return tag.RowsAffected(), nil
}
func (pgAdoptDB) SQL(_, postgresQuery string) string { return postgresQuery }
func (pgAdoptDB) Stamp(value time.Time) any          { return CanonTime(value) }

func adoptAdapter(ctx context.Context, db adoptDB, chain domain.Scope, adoption AdapterAdoption) (AdapterAdoptionResult, error) {
	var adapterID, environmentID, origin, destinationKind, priorJob string
	var destinationID, repositoryID, generation int64
	var providerBusy int
	lookup := db.SQL(
		`SELECT t.adapter_id,t.environment_id,a.origin,t.destination_kind,t.repository_id,t.destination_id,t.generation,CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>? THEN 1 ELSE 0 END,COALESCE(t.active_job_id,'') FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=? AND t.state='active'`,
		`SELECT t.adapter_id,t.environment_id,a.origin,t.destination_kind,t.repository_id,t.destination_id,t.generation,CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1 THEN 1 ELSE 0 END,COALESCE(t.active_job_id,'') FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$2 AND t.org_id=$3 AND t.project_id=$4 AND t.state='active' FOR UPDATE`)
	err := db.QueryRow(ctx, lookup, db.Stamp(adoption.AuditAt), adoption.TargetID, chain.Org, chain.Project).Scan(&adapterID, &environmentID, &origin, &destinationKind, &repositoryID, &destinationID, &generation, &providerBusy, &priorJob)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterAdoptionResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterAdoptionResult{}, err
	}
	if providerBusy == 1 {
		return AdapterAdoptionResult{}, adapter.ErrProviderBusy
	}
	stamp := db.Stamp(adoption.AuditAt)
	for i, entry := range adoption.Entries {
		var conflictRows int
		conflict := db.SQL(
			`SELECT COUNT(*) FROM adapter_conflicts WHERE artifact_id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND repository_id=? AND destination_id=? AND target_generation=? AND surface=? AND effective_name=? AND adopted_at IS NULL`,
			`SELECT COUNT(*) FROM adapter_conflicts WHERE artifact_id=$1 AND target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 AND repository_id=$6 AND destination_id=$7 AND target_generation=$8 AND surface=$9 AND effective_name=$10 AND adopted_at IS NULL`)
		if err := db.QueryRow(ctx, conflict, adoption.ArtifactID, adoption.TargetID, chain.Org, chain.Project, environmentID, repositoryID, destinationID, generation, entry.Surface, entry.EffectiveName).Scan(&conflictRows); err != nil {
			return AdapterAdoptionResult{}, err
		}
		if conflictRows != 1 {
			return AdapterAdoptionResult{}, fmt.Errorf("%w: stale or mismatched adapter conflict artifact", ErrConflict)
		}
		insert := db.SQL(
			`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_kind,repository_id,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'owned',?)`,
			`INSERT INTO adapter_ledger (id,org_id,project_id,environment_id,target_id,provider_origin,destination_kind,repository_id,destination_id,surface,effective_name,normalized_name,state,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'owned',$13)`)
		if rows, err := db.Exec(ctx, insert, adoption.LedgerIDs[i], chain.Org, chain.Project, environmentID, adoption.TargetID, origin, destinationKind, repositoryID, destinationID, entry.Surface, entry.EffectiveName, strings.ToUpper(entry.EffectiveName), stamp); err != nil || rows != 1 {
			if err != nil {
				return AdapterAdoptionResult{}, err
			}
			return AdapterAdoptionResult{}, ErrConflict
		}
		mark := db.SQL(
			`UPDATE adapter_conflicts SET adopted_at=? WHERE artifact_id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND surface=? AND effective_name=? AND adopted_at IS NULL`,
			`UPDATE adapter_conflicts SET adopted_at=$1 WHERE artifact_id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND surface=$7 AND effective_name=$8 AND adopted_at IS NULL`)
		if rows, err := db.Exec(ctx, mark, stamp, adoption.ArtifactID, adoption.TargetID, chain.Org, chain.Project, environmentID, entry.Surface, entry.EffectiveName); err != nil || rows != 1 {
			if err != nil {
				return AdapterAdoptionResult{}, err
			}
			return AdapterAdoptionResult{}, ErrConflict
		}
	}
	if priorJob != "" {
		supersede := db.SQL(`UPDATE adapter_outbox SET state='superseded',finished_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('queued','running')`, `UPDATE adapter_outbox SET state='superseded',finished_at=$1,lease_owner=NULL,lease_expires_at=NULL WHERE id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND state IN ('queued','running')`)
		rows, err := db.Exec(ctx, supersede, stamp, priorJob, adoption.TargetID, chain.Org, chain.Project, environmentID)
		if err != nil {
			return AdapterAdoptionResult{}, err
		}
		if rows != 1 {
			return AdapterAdoptionResult{}, adapter.ErrSuperseded
		}
	}
	nextGeneration := generation + 1
	insertJob := db.SQL(
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,'converge',?,?,?,0,?,'queued',?)`,
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,'converge',$6,$7,$8,0,$9,'queued',$10)`)
	if rows, err := db.Exec(ctx, insertJob, adoption.JobID, chain.Org, chain.Project, environmentID, adoption.TargetID, adoption.AuthorityPrincipalID, nextGeneration, adoption.TargetID, stamp, stamp); err != nil || rows != 1 {
		if err != nil {
			return AdapterAdoptionResult{}, err
		}
		return AdapterAdoptionResult{}, ErrConflict
	}
	updateTarget := db.SQL(
		`UPDATE adapter_targets SET generation=?,sync_status='converging',failure_names='[]',active_job_id=?,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=?)`,
		`UPDATE adapter_targets SET generation=$1,sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=$8)`)
	if rows, err := db.Exec(ctx, updateTarget, nextGeneration, adoption.JobID, adoption.TargetID, chain.Org, chain.Project, environmentID, generation, stamp); err != nil || rows != 1 {
		if err != nil {
			return AdapterAdoptionResult{}, err
		}
		return AdapterAdoptionResult{}, adapter.ErrProviderBusy
	}
	updateAdapter := db.SQL(`UPDATE adapters SET authority_principal_id=? WHERE id=? AND org_id=? AND project_id=?`, `UPDATE adapters SET authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4`)
	if rows, err := db.Exec(ctx, updateAdapter, adoption.AuthorityPrincipalID, adapterID, chain.Org, chain.Project); err != nil || rows != 1 {
		if err != nil {
			return AdapterAdoptionResult{}, err
		}
		return AdapterAdoptionResult{}, ErrNotFound
	}
	return AdapterAdoptionResult{Generation: nextGeneration, JobID: adoption.JobID, SupersededJobID: priorJob}, nil
}

type publishedAdapterTarget struct {
	id, environmentID, authority, activeJob string
	generation                              int64
}

func (r sqliteAdapters) EnqueuePublished(ctx context.Context, p authz.Proof, at time.Time) ([]AdapterEnqueueResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnqueuePublished, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,'') FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.org_id=? AND t.project_id=? AND t.environment_id=? AND t.state='active' ORDER BY t.id`, chain.Org, chain.Project, chain.Env)
	if err != nil {
		return nil, err
	}
	var targets []publishedAdapterTarget
	for rows.Next() {
		var target publishedAdapterTarget
		if err := rows.Scan(&target.id, &target.environmentID, &target.authority, &target.generation, &target.activeJob); err != nil {
			_ = rows.Close()
			return nil, err
		}
		targets = append(targets, target)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return enqueuePublishedTargets(ctx, sqliteAdoptDB{db: r.db}, chain, targets, at)
}

func (r pgAdapters) EnqueuePublished(ctx context.Context, p authz.Proof, at time.Time) ([]AdapterEnqueueResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnqueuePublished, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,'') FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.org_id=$1 AND t.project_id=$2 AND t.environment_id=$3 AND t.state='active' ORDER BY t.id FOR UPDATE OF t`, chain.Org, chain.Project, chain.Env)
	if err != nil {
		return nil, err
	}
	var targets []publishedAdapterTarget
	for rows.Next() {
		var target publishedAdapterTarget
		if err := rows.Scan(&target.id, &target.environmentID, &target.authority, &target.generation, &target.activeJob); err != nil {
			rows.Close()
			return nil, err
		}
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return enqueuePublishedTargets(ctx, pgAdoptDB{db: r.db}, chain, targets, at)
}

func enqueuePublishedTargets(ctx context.Context, db adoptDB, chain domain.Scope, targets []publishedAdapterTarget, at time.Time) ([]AdapterEnqueueResult, error) {
	stamp := db.Stamp(at)
	out := make([]AdapterEnqueueResult, 0, len(targets))
	for _, target := range targets {
		jobID := newAdapterID("job")
		if target.activeJob != "" {
			query := db.SQL(
				`UPDATE adapter_outbox SET state='superseded',finished_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('queued','running')`,
				`UPDATE adapter_outbox SET state='superseded',finished_at=$1,lease_owner=NULL,lease_expires_at=NULL WHERE id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND state IN ('queued','running')`)
			rows, err := db.Exec(ctx, query, stamp, target.activeJob, target.id, chain.Org, chain.Project, target.environmentID)
			if err != nil {
				return nil, err
			}
			if rows != 1 {
				return nil, adapter.ErrSuperseded
			}
		}
		next := target.generation + 1
		insert := db.SQL(
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,'converge',?,?,?,0,?,'queued',?)`,
			`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,'converge',$6,$7,$8,0,$9,'queued',$10)`)
		if rows, err := db.Exec(ctx, insert, jobID, chain.Org, chain.Project, target.environmentID, target.id, target.authority, next, target.id, stamp, stamp); err != nil || rows != 1 {
			if err != nil {
				return nil, err
			}
			return nil, ErrConflict
		}
		update := db.SQL(
			`UPDATE adapter_targets SET generation=?,sync_status='converging',failure_names='[]',active_job_id=? WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=?`,
			`UPDATE adapter_targets SET generation=$1,sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2 WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7`)
		rows, err := db.Exec(ctx, update, next, jobID, target.id, chain.Org, chain.Project, target.environmentID, target.generation)
		if err != nil {
			return nil, err
		}
		if rows != 1 {
			return nil, adapter.ErrSuperseded
		}
		out = append(out, AdapterEnqueueResult{
			TargetID: target.id, JobID: jobID, SupersededJobID: target.activeJob,
			AuthorityPrincipalID: target.authority, Generation: next,
		})
	}
	return out, nil
}

func (r sqliteAdapters) EnqueueManual(ctx context.Context, p authz.Proof, targetID, authorityPrincipalID string, at time.Time) (AdapterEnqueueResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnqueueManual, r.tok)
	if err != nil {
		return AdapterEnqueueResult{}, err
	}
	return enqueueManualTarget(ctx, sqliteAdoptDB{db: r.db}, chain, targetID, authorityPrincipalID, at)
}

func (r pgAdapters) EnqueueManual(ctx context.Context, p authz.Proof, targetID, authorityPrincipalID string, at time.Time) (AdapterEnqueueResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersEnqueueManual, r.tok)
	if err != nil {
		return AdapterEnqueueResult{}, err
	}
	return enqueueManualTarget(ctx, pgAdoptDB{db: r.db}, chain, targetID, authorityPrincipalID, at)
}

func enqueueManualTarget(ctx context.Context, db adoptDB, chain domain.Scope, targetID, authorityPrincipalID string, at time.Time) (AdapterEnqueueResult, error) {
	if targetID == "" || authorityPrincipalID == "" {
		return AdapterEnqueueResult{}, fmt.Errorf("%w: manual adapter sync requires target and authority", domain.ErrInvalid)
	}
	var target publishedAdapterTarget
	var providerBusy int
	lookup := db.SQL(
		`SELECT t.id,t.environment_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>? THEN 1 ELSE 0 END FROM adapter_targets t WHERE t.id=? AND t.org_id=? AND t.project_id=? AND t.state='active'`,
		`SELECT t.id,t.environment_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1 THEN 1 ELSE 0 END FROM adapter_targets t WHERE t.id=$2 AND t.org_id=$3 AND t.project_id=$4 AND t.state='active' FOR UPDATE`)
	err := db.QueryRow(ctx, lookup, db.Stamp(at), targetID, chain.Org, chain.Project).Scan(&target.id, &target.environmentID, &target.generation, &target.activeJob, &providerBusy)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterEnqueueResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterEnqueueResult{}, err
	}
	if providerBusy != 0 {
		return AdapterEnqueueResult{}, adapter.ErrProviderBusy
	}
	target.authority = authorityPrincipalID
	results, err := enqueuePublishedTargets(ctx, db, chain, []publishedAdapterTarget{target}, at)
	if err != nil {
		return AdapterEnqueueResult{}, err
	}
	return results[0], nil
}

type adapterTeardownTarget struct {
	adapterID, targetID, environmentID, authority, activeJob string
	generation                                               int64
	providerBusy                                             int
	orphaned                                                 []string
}

func (r sqliteAdapters) TeardownTarget(ctx context.Context, p authz.Proof, targetID string, keepRemote bool, at time.Time) (AdapterTeardownResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTeardownTarget, r.tok)
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	var target adapterTeardownTarget
	err = r.db.QueryRowContext(ctx, `SELECT t.adapter_id,t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>? THEN 1 ELSE 0 END FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=? AND t.state='active'`, CanonTime(at).Format(timeFormat), targetID, chain.Org, chain.Project).Scan(
		&target.adapterID, &target.targetID, &target.environmentID, &target.authority, &target.generation, &target.activeJob, &target.providerBusy)
	if errors.Is(err, sql.ErrNoRows) {
		return AdapterTeardownResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	target.orphaned, err = sqliteAdapterOrphans(ctx, r.db, chain, target.targetID, target.environmentID)
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	return teardownAdapterTarget(ctx, sqliteAdoptDB{db: r.db}, chain, target, keepRemote, at)
}

func (r pgAdapters) TeardownTarget(ctx context.Context, p authz.Proof, targetID string, keepRemote bool, at time.Time) (AdapterTeardownResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTeardownTarget, r.tok)
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	var target adapterTeardownTarget
	err = r.db.QueryRow(ctx, `SELECT t.adapter_id,t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1 THEN 1 ELSE 0 END FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$2 AND t.org_id=$3 AND t.project_id=$4 AND t.state='active' FOR UPDATE OF t`, CanonTime(at), targetID, chain.Org, chain.Project).Scan(
		&target.adapterID, &target.targetID, &target.environmentID, &target.authority, &target.generation, &target.activeJob, &target.providerBusy)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdapterTeardownResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	target.orphaned, err = pgAdapterOrphans(ctx, r.db, chain, target.targetID, target.environmentID)
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	return teardownAdapterTarget(ctx, pgAdoptDB{db: r.db}, chain, target, keepRemote, at)
}

func (r sqliteAdapters) TeardownAdapter(ctx context.Context, p authz.Proof, adapterID string, keepRemote bool, at time.Time) (AdapterTeardownBatch, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTeardownAdapter, r.tok)
	if err != nil {
		return AdapterTeardownBatch{}, err
	}
	var authority string
	if err := r.db.QueryRowContext(ctx, `SELECT authority_principal_id FROM adapters WHERE id=? AND org_id=? AND project_id=? AND state='active'`, adapterID, chain.Org, chain.Project).Scan(&authority); errors.Is(err, sql.ErrNoRows) {
		return AdapterTeardownBatch{}, ErrNotFound
	} else if err != nil {
		return AdapterTeardownBatch{}, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT t.adapter_id,t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>? THEN 1 ELSE 0 END FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.adapter_id=? AND t.org_id=? AND t.project_id=? AND t.state='active' ORDER BY t.id`, CanonTime(at).Format(timeFormat), adapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterTeardownBatch{}, err
	}
	var targets []adapterTeardownTarget
	for rows.Next() {
		var target adapterTeardownTarget
		if err := rows.Scan(&target.adapterID, &target.targetID, &target.environmentID, &target.authority, &target.generation, &target.activeJob, &target.providerBusy); err != nil {
			_ = rows.Close()
			return AdapterTeardownBatch{}, err
		}
		targets = append(targets, target)
	}
	if err := rows.Close(); err != nil {
		return AdapterTeardownBatch{}, err
	}
	for i := range targets {
		targets[i].orphaned, err = sqliteAdapterOrphans(ctx, r.db, chain, targets[i].targetID, targets[i].environmentID)
		if err != nil {
			return AdapterTeardownBatch{}, err
		}
	}
	return teardownWholeAdapter(ctx, sqliteAdoptDB{db: r.db}, chain, adapterID, authority, targets, keepRemote, at)
}

func (r pgAdapters) TeardownAdapter(ctx context.Context, p authz.Proof, adapterID string, keepRemote bool, at time.Time) (AdapterTeardownBatch, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTeardownAdapter, r.tok)
	if err != nil {
		return AdapterTeardownBatch{}, err
	}
	var authority string
	if err := r.db.QueryRow(ctx, `SELECT authority_principal_id FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active' FOR UPDATE`, adapterID, chain.Org, chain.Project).Scan(&authority); errors.Is(err, pgx.ErrNoRows) {
		return AdapterTeardownBatch{}, ErrNotFound
	} else if err != nil {
		return AdapterTeardownBatch{}, err
	}
	rows, err := r.db.Query(ctx, `SELECT t.adapter_id,t.id,t.environment_id,a.authority_principal_id,t.generation,COALESCE(t.active_job_id,''),CASE WHEN t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1 THEN 1 ELSE 0 END FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.adapter_id=$2 AND t.org_id=$3 AND t.project_id=$4 AND t.state='active' ORDER BY t.id FOR UPDATE OF t`, CanonTime(at), adapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterTeardownBatch{}, err
	}
	var targets []adapterTeardownTarget
	for rows.Next() {
		var target adapterTeardownTarget
		if err := rows.Scan(&target.adapterID, &target.targetID, &target.environmentID, &target.authority, &target.generation, &target.activeJob, &target.providerBusy); err != nil {
			rows.Close()
			return AdapterTeardownBatch{}, err
		}
		targets = append(targets, target)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return AdapterTeardownBatch{}, err
	}
	for i := range targets {
		targets[i].orphaned, err = pgAdapterOrphans(ctx, r.db, chain, targets[i].targetID, targets[i].environmentID)
		if err != nil {
			return AdapterTeardownBatch{}, err
		}
	}
	return teardownWholeAdapter(ctx, pgAdoptDB{db: r.db}, chain, adapterID, authority, targets, keepRemote, at)
}

func sqliteAdapterOrphans(ctx context.Context, db sqlitegen.DBTX, chain domain.Scope, targetID, environmentID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT surface,effective_name FROM adapter_ledger WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('owned','dispatched') ORDER BY surface,effective_name`, targetID, chain.Org, chain.Project, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var surface, name string
		if err := rows.Scan(&surface, &name); err != nil {
			return nil, err
		}
		out = append(out, surface+":"+name)
	}
	return out, rows.Err()
}

func pgAdapterOrphans(ctx context.Context, db pggen.DBTX, chain domain.Scope, targetID, environmentID string) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT surface,effective_name FROM adapter_ledger WHERE target_id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4 AND state IN ('owned','dispatched') ORDER BY surface,effective_name`, targetID, chain.Org, chain.Project, environmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var surface, name string
		if err := rows.Scan(&surface, &name); err != nil {
			return nil, err
		}
		out = append(out, surface+":"+name)
	}
	return out, rows.Err()
}

func teardownAdapterTarget(ctx context.Context, db adoptDB, chain domain.Scope, target adapterTeardownTarget, keepRemote bool, at time.Time) (AdapterTeardownResult, error) {
	if target.providerBusy == 1 {
		return AdapterTeardownResult{}, adapter.ErrProviderBusy
	}
	stamp := db.Stamp(at)
	result := AdapterTeardownResult{
		TargetID: target.targetID, AuthorityPrincipalID: target.authority,
		SupersededJobID: target.activeJob, Generation: target.generation + 1,
	}
	if target.activeJob != "" {
		supersede := db.SQL(
			`UPDATE adapter_outbox SET state='superseded',finished_at=?,lease_owner=NULL,lease_expires_at=NULL WHERE id=? AND target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state IN ('queued','running')`,
			`UPDATE adapter_outbox SET state='superseded',finished_at=$1,lease_owner=NULL,lease_expires_at=NULL WHERE id=$2 AND target_id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND state IN ('queued','running')`)
		rows, err := db.Exec(ctx, supersede, stamp, target.activeJob, target.targetID, chain.Org, chain.Project, target.environmentID)
		if err != nil {
			return AdapterTeardownResult{}, err
		}
		if rows != 1 {
			return AdapterTeardownResult{}, adapter.ErrSuperseded
		}
	}
	if keepRemote {
		release := db.SQL(
			`UPDATE adapter_ledger SET state='released',updated_at=? WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=? AND state<>'released'`,
			`UPDATE adapter_ledger SET state='released',updated_at=$1 WHERE target_id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 AND state<>'released'`)
		if _, err := db.Exec(ctx, release, stamp, target.targetID, chain.Org, chain.Project, target.environmentID); err != nil {
			return AdapterTeardownResult{}, err
		}
		update := db.SQL(
			`UPDATE adapter_targets SET generation=?,state='tombstoned',sync_status='converged',failure_names='[]',active_job_id=NULL,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=?)`,
			`UPDATE adapter_targets SET generation=$1,state='tombstoned',sync_status='converged',failure_names='[]'::jsonb,active_job_id=NULL,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=$2 AND org_id=$3 AND project_id=$4 AND environment_id=$5 AND generation=$6 AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=$7)`)
		rows, err := db.Exec(ctx, update, result.Generation, target.targetID, chain.Org, chain.Project, target.environmentID, target.generation, stamp)
		if err != nil {
			return AdapterTeardownResult{}, err
		}
		if rows != 1 {
			return AdapterTeardownResult{}, adapter.ErrProviderBusy
		}
		result.Orphaned = append([]string(nil), target.orphaned...)
		return result, nil
	}
	result.JobID = newAdapterID("job")
	insert := db.SQL(
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES (?,?,?,?,?,'scrub',?,?,?,0,?,'queued',?)`,
		`INSERT INTO adapter_outbox (id,org_id,project_id,environment_id,target_id,kind,authority_principal_id,generation,dedup_key,attempt_count,next_attempt_at,state,created_at) VALUES ($1,$2,$3,$4,$5,'scrub',$6,$7,$8,0,$9,'queued',$10)`)
	if rows, err := db.Exec(ctx, insert, result.JobID, chain.Org, chain.Project, target.environmentID, target.targetID, target.authority, result.Generation, target.targetID, stamp, stamp); err != nil || rows != 1 {
		if err != nil {
			return AdapterTeardownResult{}, err
		}
		return AdapterTeardownResult{}, ErrConflict
	}
	update := db.SQL(
		`UPDATE adapter_targets SET generation=?,state='tombstoned',sync_status='converging',failure_names='[]',active_job_id=?,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=? AND org_id=? AND project_id=? AND environment_id=? AND generation=? AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=?)`,
		`UPDATE adapter_targets SET generation=$1,state='tombstoned',sync_status='converging',failure_names='[]'::jsonb,active_job_id=$2,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE id=$3 AND org_id=$4 AND project_id=$5 AND environment_id=$6 AND generation=$7 AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=$8)`)
	rows, err := db.Exec(ctx, update, result.Generation, result.JobID, target.targetID, chain.Org, chain.Project, target.environmentID, target.generation, stamp)
	if err != nil {
		return AdapterTeardownResult{}, err
	}
	if rows != 1 {
		return AdapterTeardownResult{}, adapter.ErrProviderBusy
	}
	return result, nil
}

func teardownWholeAdapter(ctx context.Context, db adoptDB, chain domain.Scope, adapterID, authority string, targets []adapterTeardownTarget, keepRemote bool, at time.Time) (AdapterTeardownBatch, error) {
	results := make([]AdapterTeardownResult, 0, len(targets))
	for _, target := range targets {
		result, err := teardownAdapterTarget(ctx, db, chain, target, keepRemote, at)
		if err != nil {
			return AdapterTeardownBatch{}, err
		}
		results = append(results, result)
	}
	mark := db.SQL(
		`UPDATE adapters SET state='tombstoned' WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapters SET state='tombstoned' WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active'`)
	rows, err := db.Exec(ctx, mark, adapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterTeardownBatch{}, err
	}
	if rows != 1 {
		return AdapterTeardownBatch{}, ErrNotFound
	}
	erase := db.SQL(
		`UPDATE adapters SET credential_ciphertext=NULL,credential_set_at=NULL,credential_expires_at=NULL WHERE id=? AND org_id=? AND project_id=? AND NOT EXISTS (SELECT 1 FROM adapter_targets WHERE adapter_id=? AND state<>'tombstoned') AND NOT EXISTS (SELECT 1 FROM adapter_outbox j JOIN adapter_targets t ON t.id=j.target_id AND t.org_id=j.org_id AND t.project_id=j.project_id AND t.environment_id=j.environment_id WHERE t.adapter_id=? AND j.kind='scrub' AND j.state IN ('queued','running'))`,
		`UPDATE adapters SET credential_ciphertext=NULL,credential_set_at=NULL,credential_expires_at=NULL WHERE id=$1 AND org_id=$2 AND project_id=$3 AND NOT EXISTS (SELECT 1 FROM adapter_targets WHERE adapter_id=$4 AND state<>'tombstoned') AND NOT EXISTS (SELECT 1 FROM adapter_outbox j JOIN adapter_targets t ON t.id=j.target_id AND t.org_id=j.org_id AND t.project_id=j.project_id AND t.environment_id=j.environment_id WHERE t.adapter_id=$5 AND j.kind='scrub' AND j.state IN ('queued','running'))`)
	if _, err := db.Exec(ctx, erase, adapterID, chain.Org, chain.Project, adapterID, adapterID); err != nil {
		return AdapterTeardownBatch{}, err
	}
	return AdapterTeardownBatch{AuthorityPrincipalID: authority, Targets: results}, nil
}

func (r sqliteAdapters) ReplaceCredential(ctx context.Context, p authz.Proof, mutation AdapterCredentialMutation) (AdapterCredentialResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceCredential, r.tok)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if mutation.AdapterID == "" || mutation.AuthorityPrincipalID == "" || len(mutation.CredentialCiphertext) == 0 {
		return AdapterCredentialResult{}, fmt.Errorf("%w: credential replacement requires adapter, sealed credential, and authority", domain.ErrInvalid)
	}
	return replaceAdapterCredential(ctx, sqliteAdoptDB{db: r.db}, chain, mutation)
}

func (r pgAdapters) ReplaceCredential(ctx context.Context, p authz.Proof, mutation AdapterCredentialMutation) (AdapterCredentialResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersReplaceCredential, r.tok)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if mutation.AdapterID == "" || mutation.AuthorityPrincipalID == "" || len(mutation.CredentialCiphertext) == 0 {
		return AdapterCredentialResult{}, fmt.Errorf("%w: credential replacement requires adapter, sealed credential, and authority", domain.ErrInvalid)
	}
	return replaceAdapterCredential(ctx, pgAdoptDB{db: r.db}, chain, mutation)
}

func replaceAdapterCredential(ctx context.Context, db adoptDB, chain domain.Scope, mutation AdapterCredentialMutation) (AdapterCredentialResult, error) {
	stamp := db.Stamp(mutation.At)
	var previous string
	var targetCount, providerBusy int
	lookup := db.SQL(
		`SELECT a.authority_principal_id,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active'),(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active' AND t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>?) FROM adapters a WHERE a.id=? AND a.org_id=? AND a.project_id=? AND a.state='active'`,
		`SELECT a.authority_principal_id,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active'),(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active' AND t.provider_lease_job_id IS NOT NULL AND t.provider_lease_expires_at>$1) FROM adapters a WHERE a.id=$2 AND a.org_id=$3 AND a.project_id=$4 AND a.state='active' FOR UPDATE`)
	err := db.QueryRow(ctx, lookup, stamp, mutation.AdapterID, chain.Org, chain.Project).Scan(&previous, &targetCount, &providerBusy)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterCredentialResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if providerBusy != 0 {
		return AdapterCredentialResult{}, adapter.ErrProviderBusy
	}
	update := db.SQL(
		`UPDATE adapters SET credential_ciphertext=?,credential_set_at=?,credential_expires_at=NULL,authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapters SET credential_ciphertext=$1,credential_set_at=$2,credential_expires_at=NULL,authority_principal_id=$3 WHERE id=$4 AND org_id=$5 AND project_id=$6 AND state='active'`)
	rows, err := db.Exec(ctx, update, mutation.CredentialCiphertext, stamp, mutation.AuthorityPrincipalID, mutation.AdapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if rows != 1 {
		return AdapterCredentialResult{}, ErrNotFound
	}
	bump := db.SQL(
		`UPDATE adapter_targets SET generation=generation+1,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE adapter_id=? AND org_id=? AND project_id=? AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=?)`,
		`UPDATE adapter_targets SET generation=generation+1,provider_lease_job_id=NULL,provider_lease_effect_id=NULL,provider_lease_expires_at=NULL WHERE adapter_id=$1 AND org_id=$2 AND project_id=$3 AND state='active' AND (provider_lease_job_id IS NULL OR provider_lease_expires_at<=$4)`)
	rows, err = db.Exec(ctx, bump, mutation.AdapterID, chain.Org, chain.Project, stamp)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if rows != int64(targetCount) {
		return AdapterCredentialResult{}, adapter.ErrProviderBusy
	}
	return AdapterCredentialResult{PreviousAuthorityPrincipalID: previous, AuthorityPrincipalID: mutation.AuthorityPrincipalID, TargetCount: targetCount}, nil
}

func (r sqliteAdapters) RevokeCredential(ctx context.Context, p authz.Proof, adapterID string, at time.Time) (AdapterCredentialResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersRevokeCredential, r.tok)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	return revokeAdapterCredential(ctx, sqliteAdoptDB{db: r.db}, chain, adapterID, at)
}

func (r pgAdapters) RevokeCredential(ctx context.Context, p authz.Proof, adapterID string, at time.Time) (AdapterCredentialResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersRevokeCredential, r.tok)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	return revokeAdapterCredential(ctx, pgAdoptDB{db: r.db}, chain, adapterID, at)
}

func revokeAdapterCredential(ctx context.Context, db adoptDB, chain domain.Scope, adapterID string, at time.Time) (AdapterCredentialResult, error) {
	if adapterID == "" {
		return AdapterCredentialResult{}, fmt.Errorf("%w: credential revocation requires adapter id", domain.ErrInvalid)
	}
	var authority string
	var targetCount int
	lookup := db.SQL(
		`SELECT a.authority_principal_id,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active') FROM adapters a WHERE a.id=? AND a.org_id=? AND a.project_id=? AND a.state='active'`,
		`SELECT a.authority_principal_id,(SELECT COUNT(*) FROM adapter_targets t WHERE t.adapter_id=a.id AND t.org_id=a.org_id AND t.project_id=a.project_id AND t.state='active') FROM adapters a WHERE a.id=$1 AND a.org_id=$2 AND a.project_id=$3 AND a.state='active' FOR UPDATE`)
	err := db.QueryRow(ctx, lookup, adapterID, chain.Org, chain.Project).Scan(&authority, &targetCount)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterCredentialResult{}, ErrNotFound
	}
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	clearCredential := db.SQL(
		`UPDATE adapters SET credential_ciphertext=NULL,credential_set_at=NULL,credential_expires_at=NULL WHERE id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapters SET credential_ciphertext=NULL,credential_set_at=NULL,credential_expires_at=NULL WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active'`)
	rows, err := db.Exec(ctx, clearCredential, adapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if rows != 1 {
		return AdapterCredentialResult{}, ErrNotFound
	}
	bump := db.SQL(
		`UPDATE adapter_targets SET generation=generation+1 WHERE adapter_id=? AND org_id=? AND project_id=? AND state='active'`,
		`UPDATE adapter_targets SET generation=generation+1 WHERE adapter_id=$1 AND org_id=$2 AND project_id=$3 AND state='active'`)
	rows, err = db.Exec(ctx, bump, adapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterCredentialResult{}, err
	}
	if rows != int64(targetCount) {
		return AdapterCredentialResult{}, ErrConflict
	}
	return AdapterCredentialResult{PreviousAuthorityPrincipalID: authority, AuthorityPrincipalID: authority, TargetCount: targetCount}, nil
}
