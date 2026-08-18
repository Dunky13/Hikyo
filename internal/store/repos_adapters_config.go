package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

func scanAdapterRecord(row interface{ Scan(...any) error }) (AdapterRecord, error) {
	var out AdapterRecord
	var credential int
	var credentialSetAt, credentialExpiresAt, createdAt adapterStoredTime
	err := row.Scan(&out.ID, &out.Provider, &out.Origin, &credential, &credentialSetAt, &credentialExpiresAt, &out.AuthorityPrincipalID, &out.State, &createdAt)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return AdapterRecord{}, ErrNotFound
	}
	if err != nil {
		return AdapterRecord{}, err
	}
	out.CredentialPresent = credential == 1
	out.CredentialSetAt = credentialSetAt.value
	out.CredentialExpiresAt = credentialExpiresAt.value
	out.CreatedAt = createdAt.value
	return out, nil
}

const adapterRecordColumns = `id,provider,origin,CASE WHEN credential_ciphertext IS NULL THEN 0 ELSE 1 END,credential_set_at,credential_expires_at,authority_principal_id,state,created_at`

type adapterStoredTime struct{ value string }

func (t *adapterStoredTime) Scan(src any) error {
	switch value := src.(type) {
	case nil:
		t.value = ""
		return nil
	case time.Time:
		t.value = CanonTime(value).Format(timeFormat)
		return nil
	case string:
		if value == "" {
			t.value = ""
			return nil
		}
		parsed, err := time.Parse(timeFormat, value)
		if err != nil {
			return fmt.Errorf("store: malformed adapter timestamp %q: %w", value, err)
		}
		t.value = CanonTime(parsed).Format(timeFormat)
		return nil
	case []byte:
		return t.Scan(string(value))
	default:
		return fmt.Errorf("store: unsupported adapter timestamp type %T", src)
	}
}

func (r sqliteAdapters) Get(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersGet, r.tok)
	if err != nil {
		return AdapterRecord{}, err
	}
	return scanAdapterRecord(r.db.QueryRowContext(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE id=? AND org_id=? AND project_id=? AND state='active'`, adapterID, chain.Org, chain.Project))
}

func (r pgAdapters) Get(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersGet, r.tok)
	if err != nil {
		return AdapterRecord{}, err
	}
	return scanAdapterRecord(r.db.QueryRow(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active'`, adapterID, chain.Org, chain.Project))
}

func (r sqliteAdapters) Configuration(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, []byte, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersConfiguration, r.tok)
	if err != nil {
		return AdapterRecord{}, nil, err
	}
	var record AdapterRecord
	var credential []byte
	var present int
	var credentialSetAt, credentialExpiresAt, createdAt adapterStoredTime
	err = r.db.QueryRowContext(ctx, `SELECT `+adapterRecordColumns+`,credential_ciphertext FROM adapters WHERE id=? AND org_id=? AND project_id=? AND state<>'tombstoned'`, adapterID, chain.Org, chain.Project).Scan(&record.ID, &record.Provider, &record.Origin, &present, &credentialSetAt, &credentialExpiresAt, &record.AuthorityPrincipalID, &record.State, &createdAt, &credential)
	if errors.Is(err, sql.ErrNoRows) {
		return AdapterRecord{}, nil, ErrNotFound
	}
	if err != nil {
		return AdapterRecord{}, nil, err
	}
	record.CredentialPresent = present == 1
	record.CredentialSetAt = credentialSetAt.value
	record.CredentialExpiresAt = credentialExpiresAt.value
	record.CreatedAt = createdAt.value
	return record, credential, nil
}

func (r pgAdapters) Configuration(ctx context.Context, p authz.Proof, adapterID string) (AdapterRecord, []byte, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersConfiguration, r.tok)
	if err != nil {
		return AdapterRecord{}, nil, err
	}
	var record AdapterRecord
	var credential []byte
	var present int
	var credentialSetAt, credentialExpiresAt, createdAt adapterStoredTime
	err = r.db.QueryRow(ctx, `SELECT `+adapterRecordColumns+`,credential_ciphertext FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state<>'tombstoned'`, adapterID, chain.Org, chain.Project).Scan(&record.ID, &record.Provider, &record.Origin, &present, &credentialSetAt, &credentialExpiresAt, &record.AuthorityPrincipalID, &record.State, &createdAt, &credential)
	if errors.Is(err, pgx.ErrNoRows) {
		return AdapterRecord{}, nil, ErrNotFound
	}
	if err != nil {
		return AdapterRecord{}, nil, err
	}
	record.CredentialPresent = present == 1
	record.CredentialSetAt = credentialSetAt.value
	record.CredentialExpiresAt = credentialExpiresAt.value
	record.CreatedAt = createdAt.value
	return record, credential, nil
}

type adapterRecordRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func collectAdapterRecords(rows adapterRecordRows) ([]AdapterRecord, error) {
	var out []AdapterRecord
	for rows.Next() {
		record, err := scanAdapterRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (r sqliteAdapters) List(ctx context.Context, p authz.Proof) ([]AdapterRecord, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE org_id=? AND project_id=? AND state='active' ORDER BY id`, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterRecords(rows)
}

func (r pgAdapters) List(ctx context.Context, p authz.Proof) ([]AdapterRecord, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE org_id=$1 AND project_id=$2 AND state='active' ORDER BY id`, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterRecords(rows)
}

type adapterTargetRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

func collectAdapterTargets(rows adapterTargetRows) ([]AdapterTarget, error) {
	var out []AdapterTarget
	for rows.Next() {
		target, err := scanAdapterTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, rows.Err()
}

const adapterTargetColumns = `t.id,t.adapter_id,t.environment_id,a.provider,a.origin,t.destination_kind,t.destination_owner,t.destination_name,t.destination_environment,t.destination_id,t.repository_id,t.visibility,t.selected_repository_ids,t.name_prefix,t.generation,t.state,t.sync_status,t.converged_revision,t.failure_names,t.warnings,a.authority_principal_id`

func (r sqliteAdapters) ListTargets(ctx context.Context, p authz.Proof, adapterID string) ([]AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersListTargets, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.adapter_id=? AND t.org_id=? AND t.project_id=? AND t.state='active' ORDER BY t.id`, adapterID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterTargets(rows)
}

func (r pgAdapters) ListTargets(ctx context.Context, p authz.Proof, adapterID string) ([]AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersListTargets, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT `+adapterTargetColumns+` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.adapter_id=$1 AND t.org_id=$2 AND t.project_id=$3 AND t.state='active' ORDER BY t.id`, adapterID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAdapterTargets(rows)
}

func collectStrings(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]string, error) {
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (r sqliteAdapters) TargetKeyIDs(ctx context.Context, p authz.Proof, targetID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTargetKeyIDs, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `SELECT key_id FROM adapter_target_keys WHERE target_id=? AND org_id=? AND project_id=? ORDER BY key_id`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStrings(rows)
}

func (r pgAdapters) TargetKeyIDs(ctx context.Context, p authz.Proof, targetID string) ([]string, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersTargetKeyIDs, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, `SELECT key_id FROM adapter_target_keys WHERE target_id=$1 AND org_id=$2 AND project_id=$3 ORDER BY key_id`, targetID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectStrings(rows)
}

func validateTargetMutation(m AdapterTargetMutation) error {
	if m.ID == "" || m.AdapterID == "" || m.EnvironmentID == "" || m.DestinationOwner == "" || m.DestinationID <= 0 || len(m.KeyIDs) == 0 {
		return fmt.Errorf("%w: adapter target requires ids, environment, destination, and an explicit non-empty key subset", domain.ErrInvalid)
	}
	switch m.DestinationKind {
	case string(adapter.Repository):
		if m.DestinationName == "" || m.DestinationEnvironment != "" || m.RepositoryID != 0 || m.Visibility != "" || len(m.SelectedRepositoryIDs) != 0 {
			return fmt.Errorf("%w: repository target requires repository name", domain.ErrInvalid)
		}
	case string(adapter.Organization):
		if m.DestinationName != "" || m.DestinationEnvironment != "" || m.RepositoryID != 0 {
			return fmt.Errorf("%w: organization target does not take repository routing fields", domain.ErrInvalid)
		}
		switch m.Visibility {
		case "", "all", "private":
			if len(m.SelectedRepositoryIDs) != 0 {
				return fmt.Errorf("%w: selected repository ids require selected visibility", domain.ErrInvalid)
			}
		case "selected":
			if len(m.SelectedRepositoryIDs) == 0 {
				return fmt.Errorf("%w: selected visibility requires repository ids", domain.ErrInvalid)
			}
		default:
			return fmt.Errorf("%w: organization visibility must be all, private, or selected", domain.ErrInvalid)
		}
	case string(adapter.Environment):
		if m.DestinationName == "" || m.DestinationEnvironment == "" || m.RepositoryID <= 0 || m.Visibility != "" || len(m.SelectedRepositoryIDs) != 0 {
			return fmt.Errorf("%w: environment target requires repository and environment identities", domain.ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported adapter destination kind", domain.ErrInvalid)
	}
	seenRepositories := map[int64]bool{}
	for _, id := range m.SelectedRepositoryIDs {
		if id <= 0 || seenRepositories[id] {
			return fmt.Errorf("%w: selected repository ids must be positive and unique", domain.ErrInvalid)
		}
		seenRepositories[id] = true
	}
	seen := map[string]bool{}
	for _, id := range m.KeyIDs {
		if id == "" || seen[id] {
			return fmt.Errorf("%w: adapter target key ids must be non-empty and unique", domain.ErrInvalid)
		}
		seen[id] = true
	}
	return nil
}

type targetConfigDB interface {
	Query(context.Context, string, ...any) (adapterTargetRows, error)
	Exec(context.Context, string, ...any) (int64, error)
}

type sqliteTargetConfigDB struct {
	db interface {
		QueryContext(context.Context, string, ...any) (*sql.Rows, error)
		ExecContext(context.Context, string, ...any) (sql.Result, error)
	}
}

func (d sqliteTargetConfigDB) Query(ctx context.Context, q string, args ...any) (adapterTargetRows, error) {
	return d.db.QueryContext(ctx, q, args...)
}
func (d sqliteTargetConfigDB) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := d.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type pgTargetConfigDB struct {
	db interface {
		Query(context.Context, string, ...any) (pgx.Rows, error)
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	}
}

func (d pgTargetConfigDB) Query(ctx context.Context, q string, args ...any) (adapterTargetRows, error) {
	return d.db.Query(ctx, q, args...)
}
func (d pgTargetConfigDB) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	tag, err := d.db.Exec(ctx, q, args...)
	return tag.RowsAffected(), err
}

func placeholders(n int, postgres bool, start int) string {
	out := make([]string, n)
	for i := range out {
		if postgres {
			out[i] = fmt.Sprintf("$%d", start+i)
		} else {
			out[i] = "?"
		}
	}
	return strings.Join(out, ",")
}

func targetManifest(ctx context.Context, db targetConfigDB, chain domain.Scope, m AdapterTargetMutation, postgres bool) ([]adapter.ManifestEntry, error) {
	providerQuery := `SELECT provider FROM adapters WHERE id=? AND org_id=? AND project_id=?`
	if postgres {
		providerQuery = `SELECT provider FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3`
	}
	providerRows, err := db.Query(ctx, providerQuery, m.AdapterID, chain.Org, chain.Project)
	if err != nil {
		return nil, err
	}
	var provider string
	if !providerRows.Next() {
		if err := providerRows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	if err := providerRows.Scan(&provider); err != nil {
		return nil, err
	}
	if providerRows.Next() {
		return nil, fmt.Errorf("store: adapter provider lookup was not unique")
	}
	if err := providerRows.Err(); err != nil {
		return nil, err
	}
	args := []any{chain.Org, chain.Project}
	for _, id := range m.KeyIDs {
		args = append(args, id)
	}
	q := `SELECT id,name,classification FROM keys WHERE org_id=? AND project_id=? AND id IN (` + placeholders(len(m.KeyIDs), false, 3) + `) ORDER BY id`
	if postgres {
		q = `SELECT id,name,classification FROM keys WHERE org_id=$1 AND project_id=$2 AND id IN (` + placeholders(len(m.KeyIDs), true, 3) + `) ORDER BY id`
	}
	rows, err := db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var manifest []adapter.ManifestEntry
	for rows.Next() {
		var row adapter.ManifestEntry
		var classification string
		if err := rows.Scan(&row.KeyID, &row.CanonicalName, &classification); err != nil {
			return nil, err
		}
		row.Classification = adapter.Classification(classification)
		manifest = append(manifest, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(manifest) != len(m.KeyIDs) {
		return nil, ErrNotFound
	}
	if err := adapter.ValidateProviderManifest(provider, m.NamePrefix, manifest, false); err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrInvalid, err)
	}
	return manifest, nil
}

func refuseDestinationNameCollision(ctx context.Context, db targetConfigDB, chain domain.Scope, m AdapterTargetMutation, manifest []adapter.ManifestEntry, postgres bool, excludeTargetID string) error {
	desired := map[string]struct{}{m.NamePrefix + adapter.SentinelName: {}}
	for _, entry := range manifest {
		desired[m.NamePrefix+entry.CanonicalName] = struct{}{}
	}
	q := `SELECT t.id,t.name_prefix,COALESCE(k.name,'')
		FROM adapter_targets t
		JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id
		JOIN adapters candidate ON candidate.id=? AND candidate.org_id=t.org_id AND candidate.project_id=t.project_id
		LEFT JOIN adapter_target_keys tk ON tk.target_id=t.id AND tk.org_id=t.org_id AND tk.project_id=t.project_id AND tk.environment_id=t.environment_id
		LEFT JOIN keys k ON k.id=tk.key_id AND k.org_id=tk.org_id AND k.project_id=tk.project_id
		WHERE t.org_id=? AND t.project_id=? AND t.state='active' AND a.state='active'
		AND a.origin=candidate.origin AND t.destination_kind=? AND t.destination_id=? AND t.id<>?
		ORDER BY t.id,k.name`
	if postgres {
		q = `SELECT t.id,t.name_prefix,COALESCE(k.name,'')
			FROM adapter_targets t
			JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id
			JOIN adapters candidate ON candidate.id=$1 AND candidate.org_id=t.org_id AND candidate.project_id=t.project_id
			LEFT JOIN adapter_target_keys tk ON tk.target_id=t.id AND tk.org_id=t.org_id AND tk.project_id=t.project_id AND tk.environment_id=t.environment_id
			LEFT JOIN keys k ON k.id=tk.key_id AND k.org_id=tk.org_id AND k.project_id=tk.project_id
			WHERE t.org_id=$2 AND t.project_id=$3 AND t.state='active' AND a.state='active'
			AND a.origin=candidate.origin AND t.destination_kind=$4 AND t.destination_id=$5 AND t.id<>$6
			ORDER BY t.id,k.name`
	}
	rows, err := db.Query(ctx, q, m.AdapterID, chain.Org, chain.Project, m.DestinationKind, m.DestinationID, excludeTargetID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var targetID, prefix, canonicalName string
		if err := rows.Scan(&targetID, &prefix, &canonicalName); err != nil {
			return err
		}
		if _, found := desired[prefix+adapter.SentinelName]; found {
			return fmt.Errorf("%w: effective name %q is already configured by target %q on this destination", domain.ErrConflict, prefix+adapter.SentinelName, targetID)
		}
		if canonicalName != "" {
			if _, found := desired[prefix+canonicalName]; found {
				return fmt.Errorf("%w: effective name %q is already configured by target %q on this destination", domain.ErrConflict, prefix+canonicalName, targetID)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	pendingQuery := `SELECT c.target_id,c.effective_name FROM adapter_route_move_claims c JOIN adapters candidate ON candidate.id=? AND candidate.org_id=c.org_id AND candidate.project_id=c.project_id WHERE c.org_id=? AND c.project_id=? AND c.provider_origin=candidate.origin AND c.destination_kind=? AND c.destination_owner=? AND c.destination_name=? AND c.destination_environment=? AND c.target_id<>? ORDER BY c.target_id,c.effective_name`
	if postgres {
		pendingQuery = `SELECT c.target_id,c.effective_name FROM adapter_route_move_claims c JOIN adapters candidate ON candidate.id=$1 AND candidate.org_id=c.org_id AND candidate.project_id=c.project_id WHERE c.org_id=$2 AND c.project_id=$3 AND c.provider_origin=candidate.origin AND c.destination_kind=$4 AND c.destination_owner=$5 AND c.destination_name=$6 AND c.destination_environment=$7 AND c.target_id<>$8 ORDER BY c.target_id,c.effective_name`
	}
	pendingRows, err := db.Query(ctx, pendingQuery, m.AdapterID, chain.Org, chain.Project, m.DestinationKind, m.DestinationOwner, m.DestinationName, m.DestinationEnvironment, excludeTargetID)
	if err != nil {
		return err
	}
	for pendingRows.Next() {
		var targetID, effectiveName string
		if err := pendingRows.Scan(&targetID, &effectiveName); err != nil {
			return err
		}
		if _, found := desired[effectiveName]; found {
			return fmt.Errorf("%w: effective name %q is reserved by pending target %q on this destination", domain.ErrConflict, effectiveName, targetID)
		}
	}
	return pendingRows.Err()
}

func insertTargetConfig(ctx context.Context, db targetConfigDB, chain domain.Scope, m AdapterTargetMutation, at string, postgres bool) error {
	manifest, err := targetManifest(ctx, db, chain, m, postgres)
	if err != nil {
		return err
	}
	if err := refuseDestinationNameCollision(ctx, db, chain, m, manifest, postgres, ""); err != nil {
		return err
	}
	selected, err := json.Marshal(m.SelectedRepositoryIDs)
	if err != nil {
		return err
	}
	q := `INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_environment,destination_id,repository_id,visibility,selected_repository_ids,name_prefix,generation,state,sync_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'active','never',?)`
	if postgres {
		q = `INSERT INTO adapter_targets (id,org_id,project_id,environment_id,adapter_id,destination_kind,destination_owner,destination_name,destination_environment,destination_id,repository_id,visibility,selected_repository_ids,name_prefix,generation,state,sync_status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,'active','never',$15)`
	}
	if _, err := db.Exec(ctx, q, m.ID, chain.Org, chain.Project, m.EnvironmentID, m.AdapterID, m.DestinationKind, m.DestinationOwner, m.DestinationName, m.DestinationEnvironment, m.DestinationID, m.RepositoryID, m.Visibility, selected, m.NamePrefix, at); err != nil {
		return constraint(err)
	}
	for _, keyID := range m.KeyIDs {
		q = `INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES (?,?,?,?,?,?)`
		if postgres {
			q = `INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ($1,$2,$3,$4,$5,$6)`
		}
		if _, err := db.Exec(ctx, q, chain.Org, chain.Project, m.EnvironmentID, m.ID, m.AdapterID, keyID); err != nil {
			return constraint(err)
		}
	}
	return nil
}

func (r sqliteAdapters) Create(ctx context.Context, p authz.Proof, m AdapterCreate) (AdapterRecord, AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersCreate, r.tok)
	if err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	if m.ID == "" || (m.Provider != "forgejo" && m.Provider != "github-actions") || m.Origin == "" || len(m.CredentialCiphertext) == 0 || m.AuthorityPrincipalID == "" || m.Target.AdapterID != m.ID {
		return AdapterRecord{}, AdapterTarget{}, fmt.Errorf("%w: incomplete atomic adapter bootstrap", domain.ErrInvalid)
	}
	if err := validateTargetMutation(m.Target); err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	at := CanonTime(m.At).Format(timeFormat)
	var expires any
	if !m.CredentialExpiresAt.IsZero() {
		expires = CanonTime(m.CredentialExpiresAt).Format(timeFormat)
	}
	if _, err := r.db.ExecContext(ctx, `INSERT INTO adapters (id,org_id,project_id,provider,origin,credential_ciphertext,credential_set_at,credential_expires_at,authority_principal_id,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,'active',?)`, m.ID, chain.Org, chain.Project, m.Provider, m.Origin, m.CredentialCiphertext, at, expires, m.AuthorityPrincipalID, at); err != nil {
		return AdapterRecord{}, AdapterTarget{}, constraint(err)
	}
	if err := insertTargetConfig(ctx, sqliteTargetConfigDB{db: r.db}, chain, m.Target, at, false); err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	record := AdapterRecord{ID: m.ID, Provider: m.Provider, Origin: m.Origin, CredentialPresent: true, CredentialSetAt: at, AuthorityPrincipalID: m.AuthorityPrincipalID, State: "active", CreatedAt: at}
	if expires != nil {
		record.CredentialExpiresAt = expires.(string)
	}
	target := mutationTarget(record, m.Target, 1)
	return record, target, nil
}

func (r pgAdapters) Create(ctx context.Context, p authz.Proof, m AdapterCreate) (AdapterRecord, AdapterTarget, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersCreate, r.tok)
	if err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	if m.ID == "" || (m.Provider != "forgejo" && m.Provider != "github-actions") || m.Origin == "" || len(m.CredentialCiphertext) == 0 || m.AuthorityPrincipalID == "" || m.Target.AdapterID != m.ID {
		return AdapterRecord{}, AdapterTarget{}, fmt.Errorf("%w: incomplete atomic adapter bootstrap", domain.ErrInvalid)
	}
	if err := validateTargetMutation(m.Target); err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	at := CanonTime(m.At)
	var expires any
	if !m.CredentialExpiresAt.IsZero() {
		expires = CanonTime(m.CredentialExpiresAt)
	}
	if _, err := r.db.Exec(ctx, `INSERT INTO adapters (id,org_id,project_id,provider,origin,credential_ciphertext,credential_set_at,credential_expires_at,authority_principal_id,state,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10)`, m.ID, chain.Org, chain.Project, m.Provider, m.Origin, m.CredentialCiphertext, at, expires, m.AuthorityPrincipalID, at); err != nil {
		return AdapterRecord{}, AdapterTarget{}, constraint(err)
	}
	if err := insertTargetConfig(ctx, pgTargetConfigDB{db: r.db}, chain, m.Target, at.Format(timeFormat), true); err != nil {
		return AdapterRecord{}, AdapterTarget{}, err
	}
	atString := at.Format(timeFormat)
	record := AdapterRecord{ID: m.ID, Provider: m.Provider, Origin: m.Origin, CredentialPresent: true, CredentialSetAt: atString, AuthorityPrincipalID: m.AuthorityPrincipalID, State: "active", CreatedAt: atString}
	if !m.CredentialExpiresAt.IsZero() {
		record.CredentialExpiresAt = CanonTime(m.CredentialExpiresAt).Format(timeFormat)
	}
	return record, mutationTarget(record, m.Target, 1), nil
}

func mutationTarget(record AdapterRecord, m AdapterTargetMutation, generation int64) AdapterTarget {
	return AdapterTarget{ID: m.ID, AdapterID: m.AdapterID, Provider: record.Provider, EnvironmentID: m.EnvironmentID, Origin: record.Origin, DestinationKind: m.DestinationKind, DestinationOwner: m.DestinationOwner, DestinationName: m.DestinationName, DestinationEnvironment: m.DestinationEnvironment, DestinationID: m.DestinationID, RepositoryID: m.RepositoryID, Visibility: m.Visibility, SelectedRepositoryIDs: append([]int64(nil), m.SelectedRepositoryIDs...), NamePrefix: m.NamePrefix, Generation: generation, State: "active", SyncStatus: "never", AuthorityPrincipalID: record.AuthorityPrincipalID}
}

func (r sqliteAdapters) AddTarget(ctx context.Context, p authz.Proof, m AdapterTargetUpdate) (AdapterTargetAddResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersAddTarget, r.tok)
	if err != nil {
		return AdapterTargetAddResult{}, err
	}
	if err := validateTargetMutation(m.Target); err != nil {
		return AdapterTargetAddResult{}, err
	}
	record, err := scanAdapterRecord(r.db.QueryRowContext(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE id=? AND org_id=? AND project_id=? AND state='active'`, m.Target.AdapterID, chain.Org, chain.Project))
	if err != nil {
		return AdapterTargetAddResult{}, err
	}
	if !record.CredentialPresent {
		return AdapterTargetAddResult{}, adapter.ErrProviderAuth
	}
	previousAuthority := record.AuthorityPrincipalID
	at := CanonTime(m.At).Format(timeFormat)
	if err := insertTargetConfig(ctx, sqliteTargetConfigDB{db: r.db}, chain, m.Target, at, false); err != nil {
		return AdapterTargetAddResult{}, err
	}
	expires := any(nil)
	if !m.CredentialExpiresAt.IsZero() {
		expires = CanonTime(m.CredentialExpiresAt).Format(timeFormat)
	}
	result, err := r.db.ExecContext(ctx, `UPDATE adapters SET authority_principal_id=?,credential_expires_at=COALESCE(?,credential_expires_at) WHERE id=? AND org_id=? AND project_id=? AND state='active'`, m.AuthorityPrincipalID, expires, m.Target.AdapterID, chain.Org, chain.Project)
	if err != nil {
		return AdapterTargetAddResult{}, err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return AdapterTargetAddResult{}, errors.Join(err, ErrNotFound)
	}
	record.AuthorityPrincipalID = m.AuthorityPrincipalID
	if expires != nil {
		record.CredentialExpiresAt = expires.(string)
	}
	return AdapterTargetAddResult{Target: mutationTarget(record, m.Target, 1), PreviousAuthorityPrincipalID: previousAuthority, AuthorityPrincipalID: m.AuthorityPrincipalID}, nil
}

func (r pgAdapters) AddTarget(ctx context.Context, p authz.Proof, m AdapterTargetUpdate) (AdapterTargetAddResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersAddTarget, r.tok)
	if err != nil {
		return AdapterTargetAddResult{}, err
	}
	if err := validateTargetMutation(m.Target); err != nil {
		return AdapterTargetAddResult{}, err
	}
	record, err := scanAdapterRecord(r.db.QueryRow(ctx, `SELECT `+adapterRecordColumns+` FROM adapters WHERE id=$1 AND org_id=$2 AND project_id=$3 AND state='active' FOR UPDATE`, m.Target.AdapterID, chain.Org, chain.Project))
	if err != nil {
		return AdapterTargetAddResult{}, err
	}
	if !record.CredentialPresent {
		return AdapterTargetAddResult{}, adapter.ErrProviderAuth
	}
	previousAuthority := record.AuthorityPrincipalID
	at := CanonTime(m.At)
	if err := insertTargetConfig(ctx, pgTargetConfigDB{db: r.db}, chain, m.Target, at.Format(timeFormat), true); err != nil {
		return AdapterTargetAddResult{}, err
	}
	var expires any
	if !m.CredentialExpiresAt.IsZero() {
		expires = CanonTime(m.CredentialExpiresAt)
	}
	if tag, err := r.db.Exec(ctx, `UPDATE adapters SET authority_principal_id=$1,credential_expires_at=COALESCE($2,credential_expires_at) WHERE id=$3 AND org_id=$4 AND project_id=$5 AND state='active'`, m.AuthorityPrincipalID, expires, m.Target.AdapterID, chain.Org, chain.Project); err != nil || tag.RowsAffected() != 1 {
		return AdapterTargetAddResult{}, errors.Join(err, ErrNotFound)
	}
	record.AuthorityPrincipalID = m.AuthorityPrincipalID
	if expires != nil {
		record.CredentialExpiresAt = CanonTime(m.CredentialExpiresAt).Format(timeFormat)
	}
	return AdapterTargetAddResult{Target: mutationTarget(record, m.Target, 1), PreviousAuthorityPrincipalID: previousAuthority, AuthorityPrincipalID: m.AuthorityPrincipalID}, nil
}

func (r sqliteAdapters) RecordCredentialExpiry(ctx context.Context, p authz.Proof, adapterID string, expiresAt time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersRecordCredentialExpiry, r.tok)
	if err != nil {
		return err
	}
	if adapterID == "" || expiresAt.IsZero() {
		return fmt.Errorf("%w: credential expiry requires adapter and timestamp", domain.ErrInvalid)
	}
	result, err := r.db.ExecContext(ctx, `UPDATE adapters SET credential_expires_at=? WHERE id=? AND org_id=? AND project_id=? AND state='active'`, CanonTime(expiresAt).Format(timeFormat), adapterID, chain.Org, chain.Project)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return errors.Join(err, ErrNotFound)
	}
	return nil
}

func (r pgAdapters) RecordCredentialExpiry(ctx context.Context, p authz.Proof, adapterID string, expiresAt time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersRecordCredentialExpiry, r.tok)
	if err != nil {
		return err
	}
	if adapterID == "" || expiresAt.IsZero() {
		return fmt.Errorf("%w: credential expiry requires adapter and timestamp", domain.ErrInvalid)
	}
	tag, err := r.db.Exec(ctx, `UPDATE adapters SET credential_expires_at=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state='active'`, CanonTime(expiresAt), adapterID, chain.Org, chain.Project)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.Join(err, ErrNotFound)
	}
	return nil
}

func validateAdapterConfigureFence(fence AdapterConfigureFence) error {
	if fence.TargetID == "" || fence.EnvironmentID == "" || fence.DestinationKind != string(adapter.Environment) || fence.DestinationOwner == "" || fence.DestinationName == "" || fence.DestinationEnvironment == "" || fence.Generation != 1 || fence.EffectID == "" || fence.LeaseExpiresAt.IsZero() || fence.At.IsZero() || !fence.LeaseExpiresAt.After(fence.At) {
		return fmt.Errorf("%w: incomplete adapter configure fence", ErrConflict)
	}
	return nil
}

func (r sqliteAdapters) BeginConfigureEffect(ctx context.Context, p authz.Proof, fence AdapterConfigureFence) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersBeginConfigureEffect, r.tok)
	if err != nil {
		return err
	}
	if err := validateAdapterConfigureFence(fence); err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO adapter_configure_fences (target_id,org_id,project_id,environment_id,destination_kind,destination_owner,destination_name,destination_environment,generation,effect_id,lease_expires_at,state,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,'leased',?)`, fence.TargetID, chain.Org, chain.Project, fence.EnvironmentID, fence.DestinationKind, fence.DestinationOwner, fence.DestinationName, fence.DestinationEnvironment, fence.Generation, fence.EffectID, CanonTime(fence.LeaseExpiresAt).Format(timeFormat), CanonTime(fence.At).Format(timeFormat))
	return constraint(err)
}

func (r pgAdapters) BeginConfigureEffect(ctx context.Context, p authz.Proof, fence AdapterConfigureFence) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersBeginConfigureEffect, r.tok)
	if err != nil {
		return err
	}
	if err := validateAdapterConfigureFence(fence); err != nil {
		return err
	}
	_, err = r.db.Exec(ctx, `INSERT INTO adapter_configure_fences (target_id,org_id,project_id,environment_id,destination_kind,destination_owner,destination_name,destination_environment,generation,effect_id,lease_expires_at,state,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'leased',$12)`, fence.TargetID, chain.Org, chain.Project, fence.EnvironmentID, fence.DestinationKind, fence.DestinationOwner, fence.DestinationName, fence.DestinationEnvironment, fence.Generation, fence.EffectID, CanonTime(fence.LeaseExpiresAt), CanonTime(fence.At))
	return constraint(err)
}

func validateAdapterConfigureOutcome(targetID, effectID, outcome string, at time.Time) error {
	if targetID == "" || effectID == "" || (outcome != "succeeded" && outcome != "failed") || at.IsZero() {
		return fmt.Errorf("%w: incomplete adapter configure outcome", ErrConflict)
	}
	return nil
}

func (r sqliteAdapters) FinishConfigureEffect(ctx context.Context, p authz.Proof, targetID, effectID, outcome string, at time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersFinishConfigureEffect, r.tok)
	if err != nil {
		return err
	}
	if err := validateAdapterConfigureOutcome(targetID, effectID, outcome, at); err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `UPDATE adapter_configure_fences SET state=?,completed_at=? WHERE target_id=? AND effect_id=? AND org_id=? AND project_id=? AND state='leased'`, outcome, CanonTime(at).Format(timeFormat), targetID, effectID, chain.Org, chain.Project)
	if err != nil {
		return constraint(err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return errors.Join(err, ErrConflict)
	}
	return nil
}

func (r pgAdapters) FinishConfigureEffect(ctx context.Context, p authz.Proof, targetID, effectID, outcome string, at time.Time) error {
	chain, err := authz.Verify(p, authz.StoreAdaptersFinishConfigureEffect, r.tok)
	if err != nil {
		return err
	}
	if err := validateAdapterConfigureOutcome(targetID, effectID, outcome, at); err != nil {
		return err
	}
	tag, err := r.db.Exec(ctx, `UPDATE adapter_configure_fences SET state=$1,completed_at=$2 WHERE target_id=$3 AND effect_id=$4 AND org_id=$5 AND project_id=$6 AND state='leased'`, outcome, CanonTime(at), targetID, effectID, chain.Org, chain.Project)
	if err != nil {
		return constraint(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (r sqliteAdapters) UpdateTarget(ctx context.Context, p authz.Proof, m AdapterTargetUpdate) (AdapterTargetUpdateResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersUpdateTarget, r.tok)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	return updateTargetConfig(ctx, sqliteAdoptDB{db: r.db}, chain, m, false)
}
func (r pgAdapters) UpdateTarget(ctx context.Context, p authz.Proof, m AdapterTargetUpdate) (AdapterTargetUpdateResult, error) {
	chain, err := authz.Verify(p, authz.StoreAdaptersUpdateTarget, r.tok)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	return updateTargetConfig(ctx, pgAdoptDB{db: r.db}, chain, m, true)
}

func updateTargetConfig(ctx context.Context, db adoptDB, chain domain.Scope, m AdapterTargetUpdate, postgres bool) (AdapterTargetUpdateResult, error) {
	if err := validateTargetMutation(m.Target); err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	if m.ExpectedGeneration <= 0 || m.AuthorityPrincipalID == "" {
		return AdapterTargetUpdateResult{}, fmt.Errorf("%w: target update requires generation and authority", domain.ErrInvalid)
	}
	manifest, err := targetManifest(ctx, db, chain, m.Target, postgres)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	if err := refuseDestinationNameCollision(ctx, db, chain, m.Target, manifest, postgres, m.Target.ID); err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	lookup := `SELECT ` + adapterTargetColumns + ` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=? AND t.org_id=? AND t.project_id=? AND t.state='active'`
	if postgres {
		lookup = `SELECT ` + adapterTargetColumns + ` FROM adapter_targets t JOIN adapters a ON a.id=t.adapter_id AND a.org_id=t.org_id AND a.project_id=t.project_id WHERE t.id=$1 AND t.org_id=$2 AND t.project_id=$3 AND t.state='active' FOR UPDATE`
	}
	rows, err := db.Query(ctx, lookup, m.Target.ID, chain.Org, chain.Project)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	if !rows.Next() {
		return AdapterTargetUpdateResult{}, ErrNotFound
	}
	current, err := scanAdapterTarget(rows)
	for rows.Next() {
	}
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	if current.Generation != m.ExpectedGeneration {
		return AdapterTargetUpdateResult{}, adapter.ErrSuperseded
	}
	previousAuthority := current.AuthorityPrincipalID
	if current.AdapterID != m.Target.AdapterID || current.EnvironmentID != m.Target.EnvironmentID || current.DestinationKind != m.Target.DestinationKind || current.DestinationOwner != m.Target.DestinationOwner || current.DestinationName != m.Target.DestinationName || current.DestinationEnvironment != m.Target.DestinationEnvironment || current.DestinationID != m.Target.DestinationID || current.RepositoryID != m.Target.RepositoryID {
		return AdapterTargetUpdateResult{}, fmt.Errorf("%w: moving an adapter target requires the scrub transition", domain.ErrConflict)
	}
	var activeJob string
	activeQuery := db.SQL(
		`SELECT COALESCE(active_job_id,'') FROM adapter_targets WHERE id=? AND org_id=? AND project_id=? AND environment_id=?`,
		`SELECT COALESCE(active_job_id,'') FROM adapter_targets WHERE id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4`)
	if err := db.QueryRow(ctx, activeQuery, m.Target.ID, chain.Org, chain.Project, m.Target.EnvironmentID).Scan(&activeJob); err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	q := `DELETE FROM adapter_target_keys WHERE target_id=? AND org_id=? AND project_id=? AND environment_id=?`
	if postgres {
		q = `DELETE FROM adapter_target_keys WHERE target_id=$1 AND org_id=$2 AND project_id=$3 AND environment_id=$4`
	}
	if _, err := db.Exec(ctx, q, m.Target.ID, chain.Org, chain.Project, m.Target.EnvironmentID); err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	for _, keyID := range m.Target.KeyIDs {
		q = `INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES (?,?,?,?,?,?)`
		if postgres {
			q = `INSERT INTO adapter_target_keys (org_id,project_id,environment_id,target_id,adapter_id,key_id) VALUES ($1,$2,$3,$4,$5,$6)`
		}
		if _, err := db.Exec(ctx, q, chain.Org, chain.Project, m.Target.EnvironmentID, m.Target.ID, m.Target.AdapterID, keyID); err != nil {
			return AdapterTargetUpdateResult{}, constraint(err)
		}
	}
	selectedJSON, err := json.Marshal(m.Target.SelectedRepositoryIDs)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	q = `UPDATE adapter_targets SET visibility=?,selected_repository_ids=?,name_prefix=? WHERE id=? AND org_id=? AND project_id=? AND generation=? AND state='active' AND provider_lease_job_id IS NULL`
	if postgres {
		q = `UPDATE adapter_targets SET visibility=$1,selected_repository_ids=$2,name_prefix=$3 WHERE id=$4 AND org_id=$5 AND project_id=$6 AND generation=$7 AND state='active' AND provider_lease_job_id IS NULL`
	}
	n, err := db.Exec(ctx, q, m.Target.Visibility, selectedJSON, m.Target.NamePrefix, m.Target.ID, chain.Org, chain.Project, m.ExpectedGeneration)
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	if n != 1 {
		return AdapterTargetUpdateResult{}, adapter.ErrProviderBusy
	}
	enqueued, err := enqueuePublishedTargets(ctx, db, chain, []publishedAdapterTarget{{
		id: m.Target.ID, environmentID: m.Target.EnvironmentID, generation: current.Generation,
		activeJob: activeJob, authority: m.AuthorityPrincipalID,
	}}, CanonTime(m.At))
	if err != nil {
		return AdapterTargetUpdateResult{}, err
	}
	q = `UPDATE adapters SET authority_principal_id=? WHERE id=? AND org_id=? AND project_id=? AND state='active'`
	if postgres {
		q = `UPDATE adapters SET authority_principal_id=$1 WHERE id=$2 AND org_id=$3 AND project_id=$4 AND state='active'`
	}
	if n, err = db.Exec(ctx, q, m.AuthorityPrincipalID, m.Target.AdapterID, chain.Org, chain.Project); err != nil || n != 1 {
		return AdapterTargetUpdateResult{}, errors.Join(err, ErrNotFound)
	}
	current.NamePrefix = m.Target.NamePrefix
	current.Visibility = m.Target.Visibility
	current.SelectedRepositoryIDs = append([]int64(nil), m.Target.SelectedRepositoryIDs...)
	current.Generation = enqueued[0].Generation
	current.SyncStatus = "converging"
	current.FailureNames = nil
	current.AuthorityPrincipalID = m.AuthorityPrincipalID
	sort.Strings(m.Target.KeyIDs)
	return AdapterTargetUpdateResult{Target: current, Enqueue: enqueued[0], PreviousAuthorityPrincipalID: previousAuthority, AuthorityPrincipalID: m.AuthorityPrincipalID}, nil
}
