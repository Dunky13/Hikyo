package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlite "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/store/pggen"
	"github.com/Dunky13/hikyo/internal/store/sqlitegen"
)

// This file is the store's binding layer: every repository method verifies
// the proof at the boundary (authz.Verify — nil, foreign-transaction,
// ended-transaction and operation-mismatched proofs die here, before any
// query), and binds the chain parameters of every statement exclusively
// from the verified proof's resolved chain. Caller arguments cannot reach a
// chain predicate or a chain column of an insert: the caller-facing
// signatures expose no chain parameters at all, and the conformance suite
// asserts this file is where every chain parameter comes from.

// SQLiteTxRepos and PGTxRepos bind repositories to an open transaction and
// its identity token; they exist for internal/store/tx, which owns the
// transactional boundary.
func SQLiteTxRepos(tx *sql.Tx, tok *authz.TxToken) Repos { return sqliteRepos{db: tx, tok: tok} }
func PGTxRepos(tx pgx.Tx, tok *authz.TxToken) Repos      { return pgRepos{db: tx, tok: tok} }

// SQLiteTxReadRepos and PGTxReadRepos narrow to the read side for read
// transactions, so the compiler — not convention — keeps writes off the
// read pool.
func SQLiteTxReadRepos(tx *sql.Tx, tok *authz.TxToken) ReadRepos {
	return sqliteReadRepos{sqliteRepos{db: tx, tok: tok}}
}
func PGTxReadRepos(tx pgx.Tx, tok *authz.TxToken) ReadRepos {
	return pgReadRepos{pgRepos{db: tx, tok: tok}}
}

type sqliteReadRepos struct{ r sqliteRepos }

func (s sqliteReadRepos) Orgs() OrgReader                 { return s.r.Orgs() }
func (s sqliteReadRepos) Keys() KeyReader                 { return s.r.Keys() }
func (s sqliteReadRepos) Catalogue() CatalogueReader      { return s.r.Catalogue() }
func (s sqliteReadRepos) Values() ValueReader             { return s.r.Values() }
func (s sqliteReadRepos) Pending() PendingReader          { return s.r.Pending() }
func (s sqliteReadRepos) Snapshots() SnapshotReader       { return s.r.Snapshots() }
func (s sqliteReadRepos) Projects() ProjectReader         { return s.r.Projects() }
func (s sqliteReadRepos) Environments() EnvironmentReader { return s.r.Environments() }
func (s sqliteReadRepos) Folders() FolderReader           { return s.r.Folders() }
func (s sqliteReadRepos) Audit() AuditReader              { return s.r.Audit() }

type pgReadRepos struct{ r pgRepos }

func (p pgReadRepos) Orgs() OrgReader                 { return p.r.Orgs() }
func (p pgReadRepos) Keys() KeyReader                 { return p.r.Keys() }
func (p pgReadRepos) Catalogue() CatalogueReader      { return p.r.Catalogue() }
func (p pgReadRepos) Values() ValueReader             { return p.r.Values() }
func (p pgReadRepos) Pending() PendingReader          { return p.r.Pending() }
func (p pgReadRepos) Snapshots() SnapshotReader       { return p.r.Snapshots() }
func (p pgReadRepos) Projects() ProjectReader         { return p.r.Projects() }
func (p pgReadRepos) Environments() EnvironmentReader { return p.r.Environments() }
func (p pgReadRepos) Folders() FolderReader           { return p.r.Folders() }
func (p pgReadRepos) Audit() AuditReader              { return p.r.Audit() }

// CanonTime fixes the canonical cross-engine timestamp semantics: UTC,
// microsecond precision (postgres timestamptz cannot hold more; sqlite text
// stores the same so both engines round-trip identically). Callers producing
// timestamps use it too, so the rule lives in exactly one place.
func CanonTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

const timeFormat = time.RFC3339Nano

func validMetadata(m json.RawMessage) error {
	if !json.Valid(m) {
		return errors.New("store: org metadata is not valid JSON")
	}
	return nil
}

func parseTime(kind, id, raw string) (time.Time, error) {
	t, err := time.Parse(timeFormat, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: %s %s created_at %q: %w", kind, id, raw, err)
	}
	return t.UTC(), nil
}

// constraint maps an engine's integrity-constraint failure onto ErrConflict,
// in exactly one place per engine.
//
// The classes this surface can hit are a duplicate name among live siblings and
// a parent still referenced by children (v1 deletes never cascade). Both are
// the same answer to the caller — "the current state refuses this" — and the
// fixed-message-per-code rule means the response could not distinguish them
// anyway.
//
// Detection is by TYPED extended code on both engines, never by matching the
// driver's message text: a message is a locale- and version-dependent string,
// and a caller-visible outcome that hinges on one is a silent behaviour change
// waiting for a dependency bump. The named set is also deliberately narrow —
// NOT NULL is absent from it, because a NULL reaching a NOT NULL column is a
// defect in this package, not a state the caller can fix, and mapping it to
// 409 is how a storage bug becomes a conflict nobody investigates.
func constraint(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "23503", "23514": // unique_violation, foreign_key_violation, check_violation
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		}
		return err
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlitelib.SQLITE_CONSTRAINT_UNIQUE,
			sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY,
			sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY,
			sqlitelib.SQLITE_CONSTRAINT_CHECK:
			return fmt.Errorf("%w: sqlite constraint %d", ErrConflict, se.Code())
		}
	}
	return err
}

// affected turns an :execrows result into the canonical outcome: zero rows
// touched on a chain-addressed mutation means the row is not there or not
// reachable, which are the same answer by design.
func affected(n int64, err error) error {
	if err != nil {
		return constraint(err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- sqlite ---

type sqliteRepos struct {
	db  sqlitegen.DBTX
	tok *authz.TxToken
}

func (r sqliteRepos) SCIM() SCIMRepo { return scimRepo{sq: sqlitegen.New(r.db), tok: r.tok} }

func (r sqliteRepos) Orgs() OrgRepo { return sqliteOrgs{q: sqlitegen.New(r.db), tok: r.tok} }
func (r sqliteRepos) Projects() ProjectRepo {
	return sqliteProjects{q: sqlitegen.New(r.db), tok: r.tok}
}
func (r sqliteRepos) Environments() EnvironmentRepo {
	return sqliteEnvs{q: sqlitegen.New(r.db), tok: r.tok}
}
func (r sqliteRepos) Folders() FolderRepo {
	return sqliteFolders{q: sqlitegen.New(r.db), tok: r.tok}
}
func (r sqliteRepos) Catalogue() CatalogueRepo {
	return sqliteCatalogue{q: sqlitegen.New(r.db), tok: r.tok}
}

func (r sqliteRepos) Values() ValueRepo {
	return sqliteValues{q: sqlitegen.New(r.db), tok: r.tok}
}

func (r sqliteRepos) Pending() PendingRepo {
	return sqlitePending{q: sqlitegen.New(r.db), tok: r.tok}
}

func (r sqliteRepos) Snapshots() SnapshotRepo {
	return sqliteSnapshots{q: sqlitegen.New(r.db), tok: r.tok}
}

type sqliteOrgs struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (o sqliteOrgs) Create(ctx context.Context, p authz.Proof, org Org) error {
	if _, err := authz.Verify(p, authz.StoreOrgsCreate, o.tok); err != nil {
		return err
	}
	if err := validMetadata(org.Metadata); err != nil {
		return err
	}
	active := int64(0)
	if org.Active {
		active = 1
	}
	return constraint(o.q.CreateOrg(ctx, sqlitegen.CreateOrgParams{
		ID:        org.ID,
		Name:      org.Name,
		Active:    active,
		Metadata:  string(org.Metadata),
		CreatedAt: CanonTime(org.CreatedAt).Format(timeFormat),
	}))
}

func (o sqliteOrgs) Get(ctx context.Context, p authz.Proof) (Org, error) {
	chain, err := authz.Verify(p, authz.StoreOrgsGet, o.tok)
	if err != nil {
		return Org{}, err
	}
	row, err := o.q.GetOrg(ctx, string(chain.Org)) // chain column: proof-bound
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, err
	}
	return orgFromSQLite(row)
}

func (o sqliteOrgs) List(ctx context.Context, p authz.Proof) ([]Org, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsList, o.tok); err != nil {
		return nil, err
	}
	rows, err := o.q.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Org, 0, len(rows))
	for _, row := range rows {
		org, err := orgFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, org)
	}
	return out, nil
}

func (o sqliteOrgs) Count(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsCount, o.tok); err != nil {
		return 0, err
	}
	return o.q.CountOrgs(ctx)
}

func (o sqliteOrgs) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreOrgsRename, o.tok)
	if err != nil {
		return err
	}
	return affected(o.q.RenameOrg(ctx, sqlitegen.RenameOrgParams{
		Name: name,
		ID:   string(chain.Org), // chain column: proof-bound
	}))
}

func (o sqliteOrgs) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreOrgsDelete, o.tok)
	if err != nil {
		return err
	}
	return affected(o.q.DeleteOrg(ctx, string(chain.Org)))
}

func orgFromSQLite(row sqlitegen.Org) (Org, error) {
	created, err := parseTime("org", row.ID, row.CreatedAt)
	if err != nil {
		return Org{}, err
	}
	// The CHECK constraint enforces 0/1 at write time; parse-don't-cast on
	// the way out too rather than coercing unknown integers to true.
	if row.Active != 0 && row.Active != 1 {
		return Org{}, fmt.Errorf("store: org %s: active = %d, not a boolean", row.ID, row.Active)
	}
	metadata := json.RawMessage(row.Metadata)
	if err := validMetadata(metadata); err != nil {
		return Org{}, fmt.Errorf("store: org %s: %w", row.ID, err)
	}
	return Org{
		ID:        row.ID,
		Name:      row.Name,
		Active:    row.Active == 1,
		Metadata:  metadata,
		CreatedAt: created,
	}, nil
}

type sqliteProjects struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteProjects) Create(ctx context.Context, p authz.Proof, proj NewProject) error {
	chain, err := authz.Verify(p, authz.StoreProjectsCreate, r.tok)
	if err != nil {
		return err
	}
	if err := constraint(r.q.CreateProject(ctx, sqlitegen.CreateProjectParams{
		ID:        proj.ID,
		OrgID:     string(chain.Org), // chain column: proof-bound, never caller input
		Name:      proj.Name,
		CreatedAt: CanonTime(proj.CreatedAt).Format(timeFormat),
	})); err != nil {
		return err
	}
	// The project's key-catalogue revision row is born with the project (#49).
	// It rides inside this method, not beside it, so there is no window in
	// which a project exists without the revision every later schema change
	// advances — and no second store operation to authorize for a row nobody
	// addresses independently.
	return constraint(r.q.InsertProjectSchemaRevision(ctx, sqlitegen.InsertProjectSchemaRevisionParams{
		OrgID:     string(chain.Org), // chain column: proof-bound
		ProjectID: proj.ID,           // the row being created, like ID above
	}))
}

func (r sqliteProjects) Get(ctx context.Context, p authz.Proof) (Project, error) {
	chain, err := authz.Verify(p, authz.StoreProjectsGet, r.tok)
	if err != nil {
		return Project{}, err
	}
	row, err := r.q.GetProject(ctx, sqlitegen.GetProjectParams{
		OrgID: string(chain.Org),
		ID:    string(chain.Project),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return projectFromSQLite(row)
}

func (r sqliteProjects) List(ctx context.Context, p authz.Proof) ([]Project, error) {
	chain, err := authz.Verify(p, authz.StoreProjectsList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListProjects(ctx, string(chain.Org))
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(rows))
	for _, row := range rows {
		proj, err := projectFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, proj)
	}
	return out, nil
}

func (r sqliteProjects) Lock(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreProjectsLock, r.tok)
	if err != nil {
		return err
	}
	_, err = r.q.LockProject(ctx, sqlitegen.LockProjectParams{
		OrgID: string(chain.Org),
		ID:    string(chain.Project),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (r sqliteProjects) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreProjectsRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameProject(ctx, sqlitegen.RenameProjectParams{
		Name:  name,
		OrgID: string(chain.Org),
		ID:    string(chain.Project),
	}))
}

func (r sqliteProjects) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreProjectsDelete, r.tok)
	if err != nil {
		return err
	}
	// The key-catalogue revision row dies with the project, inside the same
	// store operation that created it (#49). It is the project's own counter,
	// not content: a project holding keys or groups is refused by THEIR foreign
	// keys, which is the non-empty-parent refusal, and this row must not add a
	// second refusal for an empty one.
	if err := constraint(r.q.DeleteProjectSchemaRevision(ctx, sqlitegen.DeleteProjectSchemaRevisionParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})); err != nil {
		return err
	}
	return affected(r.q.DeleteProject(ctx, sqlitegen.DeleteProjectParams{
		OrgID: string(chain.Org),
		ID:    string(chain.Project),
	}))
}

func projectFromSQLite(row sqlitegen.Project) (Project, error) {
	created, err := parseTime("project", row.ID, row.CreatedAt)
	if err != nil {
		return Project{}, err
	}
	return Project{ID: row.ID, OrgID: row.OrgID, Name: row.Name, CreatedAt: created}, nil
}

type sqliteEnvs struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteEnvs) Create(ctx context.Context, p authz.Proof, env NewEnvironment) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateEnvironment(ctx, sqlitegen.CreateEnvironmentParams{
		ID:           env.ID,
		OrgID:        string(chain.Org),     // chain column: proof-bound
		ProjectID:    string(chain.Project), // chain column: proof-bound
		Name:         env.Name,
		Note:         env.Note,
		DisplayOrder: env.DisplayOrder,
		CreatedAt:    CanonTime(env.CreatedAt).Format(timeFormat),
	}))
}

func (r sqliteEnvs) Get(ctx context.Context, p authz.Proof) (Environment, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsGet, r.tok)
	if err != nil {
		return Environment{}, err
	}
	row, err := r.q.GetEnvironment(ctx, sqlitegen.GetEnvironmentParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        string(chain.Env),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Environment{}, ErrNotFound
	}
	if err != nil {
		return Environment{}, err
	}
	created, err := parseTime("environment", row.ID, row.CreatedAt)
	if err != nil {
		return Environment{}, err
	}
	return Environment{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, Note: row.Note, DisplayOrder: row.DisplayOrder, CreatedAt: created,
	}, nil
}

func (r sqliteEnvs) List(ctx context.Context, p authz.Proof) ([]Environment, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListEnvironments(ctx, sqlitegen.ListEnvironmentsParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Environment, 0, len(rows))
	for _, row := range rows {
		created, err := parseTime("environment", row.ID, row.CreatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, Environment{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			Name: row.Name, Note: row.Note, DisplayOrder: row.DisplayOrder, CreatedAt: created,
		})
	}
	return out, nil
}

func (r sqliteEnvs) Count(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountEnvironments(ctx, sqlitegen.CountEnvironmentsParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
}

func (r sqliteEnvs) NextOrder(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsNextOrder, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.NextEnvironmentOrder(ctx, sqlitegen.NextEnvironmentOrderParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
}

// Settings / SetSettings: the protected-environment flag and the
// per-environment reauthentication window (#55). Both columns are non-chain,
// so they mutate under the ordinary binding rule; the chain still comes
// exclusively from the proof.
func (r sqliteEnvs) Settings(ctx context.Context, p authz.Proof) (EnvironmentSettings, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsGetSettings, r.tok)
	if err != nil {
		return EnvironmentSettings{}, err
	}
	row, err := r.q.GetEnvironmentSettings(ctx, sqlitegen.GetEnvironmentSettingsParams{
		OrgID: string(chain.Org), ProjectID: string(chain.Project), ID: string(chain.Env),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return EnvironmentSettings{}, ErrNotFound
	}
	if err != nil {
		return EnvironmentSettings{}, err
	}
	return EnvironmentSettings{
		Protected: row.Protected == 1,
		HasWindow: row.ReauthWindowSeconds.Valid,
		Window:    time.Duration(row.ReauthWindowSeconds.Int64) * time.Second,
	}, nil
}

func (r sqliteEnvs) SetSettings(ctx context.Context, p authz.Proof, s EnvironmentSettings) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsSetSettings, r.tok)
	if err != nil {
		return err
	}
	protected := int64(0)
	if s.Protected {
		protected = 1
	}
	return affected(r.q.SetEnvironmentSettings(ctx, sqlitegen.SetEnvironmentSettingsParams{
		Protected:           protected,
		ReauthWindowSeconds: nullWindow(s),
		OrgID:               string(chain.Org),
		ProjectID:           string(chain.Project),
		ID:                  string(chain.Env),
	}))
}

// nullWindow renders "no window of its own" as SQL NULL rather than a zero,
// because 0 is a legal window value (every disclosure reauthenticates) and
// must never be confused with "inherit the instance default".
func nullWindow(s EnvironmentSettings) sql.NullInt64 {
	if !s.HasWindow {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(s.Window / time.Second), Valid: true}
}

func (r sqliteEnvs) UpdateNote(ctx context.Context, p authz.Proof, note string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsUpdateNote, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateEnvironmentNote(ctx, sqlitegen.UpdateEnvironmentNoteParams{
		Note:      note,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        string(chain.Env),
	}))
}

func (r sqliteEnvs) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameEnvironment(ctx, sqlitegen.RenameEnvironmentParams{
		Name:      name,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        string(chain.Env),
	}))
}

func (r sqliteEnvs) SetOrder(ctx context.Context, p authz.Proof, id string, order int64) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsSetOrder, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetEnvironmentOrder(ctx, sqlitegen.SetEnvironmentOrderParams{
		DisplayOrder: order,
		OrgID:        string(chain.Org),
		ProjectID:    string(chain.Project),
		ID:           id,
	}))
}

func (r sqliteEnvs) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteEnvironment(ctx, sqlitegen.DeleteEnvironmentParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        string(chain.Env),
	}))
}

type sqliteFolders struct {
	q   *sqlitegen.Queries
	tok *authz.TxToken
}

func (r sqliteFolders) Create(ctx context.Context, p authz.Proof, folder NewFolder) error {
	chain, err := authz.Verify(p, authz.StoreFoldersCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateFolder(ctx, sqlitegen.CreateFolderParams{
		ID:        folder.ID,
		OrgID:     string(chain.Org),     // chain column: proof-bound
		ProjectID: string(chain.Project), // chain column: proof-bound
		Path:      folder.Path,
		CreatedAt: CanonTime(folder.CreatedAt).Format(timeFormat),
	}))
}

func (r sqliteFolders) Get(ctx context.Context, p authz.Proof, id string) (Folder, error) {
	chain, err := authz.Verify(p, authz.StoreFoldersGet, r.tok)
	if err != nil {
		return Folder{}, err
	}
	row, err := r.q.GetFolder(ctx, sqlitegen.GetFolderParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return Folder{}, ErrNotFound
	}
	if err != nil {
		return Folder{}, err
	}
	return folderFromSQLite(row)
}

func (r sqliteFolders) List(ctx context.Context, p authz.Proof) ([]Folder, error) {
	chain, err := authz.Verify(p, authz.StoreFoldersList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListFolders(ctx, sqlitegen.ListFoldersParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Folder, 0, len(rows))
	for _, row := range rows {
		folder, err := folderFromSQLite(row)
		if err != nil {
			return nil, err
		}
		out = append(out, folder)
	}
	return out, nil
}

func (r sqliteFolders) Rename(ctx context.Context, p authz.Proof, id, path string) error {
	chain, err := authz.Verify(p, authz.StoreFoldersRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameFolder(ctx, sqlitegen.RenameFolderParams{
		Path:      path,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func (r sqliteFolders) Delete(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreFoldersDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteFolder(ctx, sqlitegen.DeleteFolderParams{
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        id,
	}))
}

func folderFromSQLite(row sqlitegen.Folder) (Folder, error) {
	created, err := parseTime("folder", row.ID, row.CreatedAt)
	if err != nil {
		return Folder{}, err
	}
	return Folder{ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID, Path: row.Path, CreatedAt: created}, nil
}

// --- postgres ---

type pgRepos struct {
	db  pggen.DBTX
	tok *authz.TxToken
}

func (r pgRepos) SCIM() SCIMRepo                { return scimRepo{pg: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Orgs() OrgRepo                 { return pgOrgs{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Projects() ProjectRepo         { return pgProjects{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Environments() EnvironmentRepo { return pgEnvs{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Folders() FolderRepo           { return pgFolders{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Catalogue() CatalogueRepo      { return pgCatalogue{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Values() ValueRepo             { return pgValues{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Pending() PendingRepo          { return pgPending{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Snapshots() SnapshotRepo       { return pgSnapshots{q: pggen.New(r.db), tok: r.tok} }

type pgOrgs struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (o pgOrgs) Create(ctx context.Context, p authz.Proof, org Org) error {
	if _, err := authz.Verify(p, authz.StoreOrgsCreate, o.tok); err != nil {
		return err
	}
	if err := validMetadata(org.Metadata); err != nil {
		return err
	}
	return constraint(o.q.CreateOrg(ctx, pggen.CreateOrgParams{
		ID:        org.ID,
		Name:      org.Name,
		Active:    org.Active,
		Metadata:  string(org.Metadata),
		CreatedAt: pgtype.Timestamptz{Time: CanonTime(org.CreatedAt), Valid: true},
	}))
}

func (o pgOrgs) Get(ctx context.Context, p authz.Proof) (Org, error) {
	chain, err := authz.Verify(p, authz.StoreOrgsGet, o.tok)
	if err != nil {
		return Org{}, err
	}
	row, err := o.q.GetOrg(ctx, string(chain.Org)) // chain column: proof-bound
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, err
	}
	return orgFromPG(row)
}

func (o pgOrgs) List(ctx context.Context, p authz.Proof) ([]Org, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsList, o.tok); err != nil {
		return nil, err
	}
	rows, err := o.q.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Org, 0, len(rows))
	for _, row := range rows {
		org, err := orgFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, org)
	}
	return out, nil
}

func (o pgOrgs) Count(ctx context.Context, p authz.Proof) (int64, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsCount, o.tok); err != nil {
		return 0, err
	}
	return o.q.CountOrgs(ctx)
}

func (o pgOrgs) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreOrgsRename, o.tok)
	if err != nil {
		return err
	}
	return affected(o.q.RenameOrg(ctx, pggen.RenameOrgParams{
		Name:       name,
		ChainOrgID: string(chain.Org), // chain column: proof-bound
	}))
}

func (o pgOrgs) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreOrgsDelete, o.tok)
	if err != nil {
		return err
	}
	return affected(o.q.DeleteOrg(ctx, string(chain.Org)))
}

func orgFromPG(row pggen.Org) (Org, error) {
	if !row.CreatedAt.Valid {
		return Org{}, fmt.Errorf("store: org %s: null created_at", row.ID)
	}
	metadata := json.RawMessage(row.Metadata)
	if err := validMetadata(metadata); err != nil {
		return Org{}, fmt.Errorf("store: org %s: %w", row.ID, err)
	}
	return Org{
		ID:        row.ID,
		Name:      row.Name,
		Active:    row.Active,
		Metadata:  metadata,
		CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}

type pgProjects struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgProjects) Create(ctx context.Context, p authz.Proof, proj NewProject) error {
	chain, err := authz.Verify(p, authz.StoreProjectsCreate, r.tok)
	if err != nil {
		return err
	}
	if err := constraint(r.q.CreateProject(ctx, pggen.CreateProjectParams{
		ID:         proj.ID,
		ChainOrgID: string(chain.Org), // chain column: proof-bound, never caller input
		Name:       proj.Name,
		CreatedAt:  pgtype.Timestamptz{Time: CanonTime(proj.CreatedAt), Valid: true},
	})); err != nil {
		return err
	}
	// See the sqlite copy: the key-catalogue revision row is born with the
	// project, inside the same store operation.
	return constraint(r.q.InsertProjectSchemaRevision(ctx, pggen.InsertProjectSchemaRevisionParams{
		ChainOrgID: string(chain.Org), // chain column: proof-bound
		ProjectID:  proj.ID,           // the row being created, like ID above
	}))
}

func (r pgProjects) Get(ctx context.Context, p authz.Proof) (Project, error) {
	chain, err := authz.Verify(p, authz.StoreProjectsGet, r.tok)
	if err != nil {
		return Project{}, err
	}
	row, err := r.q.GetProject(ctx, pggen.GetProjectParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	return projectFromPG(row)
}

func (r pgProjects) List(ctx context.Context, p authz.Proof) ([]Project, error) {
	chain, err := authz.Verify(p, authz.StoreProjectsList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListProjects(ctx, string(chain.Org))
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(rows))
	for _, row := range rows {
		proj, err := projectFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, proj)
	}
	return out, nil
}

func (r pgProjects) Lock(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreProjectsLock, r.tok)
	if err != nil {
		return err
	}
	_, err = r.q.LockProject(ctx, pggen.LockProjectParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (r pgProjects) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreProjectsRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameProject(ctx, pggen.RenameProjectParams{
		Name:           name,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	}))
}

func (r pgProjects) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreProjectsDelete, r.tok)
	if err != nil {
		return err
	}
	// See the sqlite copy: the revision row dies with the project.
	if err := constraint(r.q.DeleteProjectSchemaRevision(ctx, pggen.DeleteProjectSchemaRevisionParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})); err != nil {
		return err
	}
	return affected(r.q.DeleteProject(ctx, pggen.DeleteProjectParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	}))
}

func projectFromPG(row pggen.Project) (Project, error) {
	if !row.CreatedAt.Valid {
		return Project{}, fmt.Errorf("store: project %s: null created_at", row.ID)
	}
	return Project{ID: row.ID, OrgID: row.OrgID, Name: row.Name, CreatedAt: row.CreatedAt.Time.UTC()}, nil
}

type pgEnvs struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgEnvs) Create(ctx context.Context, p authz.Proof, env NewEnvironment) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateEnvironment(ctx, pggen.CreateEnvironmentParams{
		ID:             env.ID,
		ChainOrgID:     string(chain.Org),     // chain column: proof-bound
		ChainProjectID: string(chain.Project), // chain column: proof-bound
		Name:           env.Name,
		Note:           env.Note,
		DisplayOrder:   env.DisplayOrder,
		CreatedAt:      pgtype.Timestamptz{Time: CanonTime(env.CreatedAt), Valid: true},
	}))
}

func (r pgEnvs) Get(ctx context.Context, p authz.Proof) (Environment, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsGet, r.tok)
	if err != nil {
		return Environment{}, err
	}
	row, err := r.q.GetEnvironment(ctx, pggen.GetEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     string(chain.Env),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	}
	if err != nil {
		return Environment{}, err
	}
	if !row.CreatedAt.Valid {
		return Environment{}, fmt.Errorf("store: environment %s: null created_at", row.ID)
	}
	return Environment{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Name: row.Name, Note: row.Note, DisplayOrder: row.DisplayOrder,
		CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}

func (r pgEnvs) List(ctx context.Context, p authz.Proof) ([]Environment, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListEnvironments(ctx, pggen.ListEnvironmentsParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Environment, 0, len(rows))
	for _, row := range rows {
		if !row.CreatedAt.Valid {
			return nil, fmt.Errorf("store: environment %s: null created_at", row.ID)
		}
		out = append(out, Environment{
			ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
			Name: row.Name, Note: row.Note, DisplayOrder: row.DisplayOrder,
			CreatedAt: row.CreatedAt.Time.UTC(),
		})
	}
	return out, nil
}

func (r pgEnvs) Count(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsCount, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.CountEnvironments(ctx, pggen.CountEnvironmentsParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
}

func (r pgEnvs) NextOrder(ctx context.Context, p authz.Proof) (int64, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsNextOrder, r.tok)
	if err != nil {
		return 0, err
	}
	return r.q.NextEnvironmentOrder(ctx, pggen.NextEnvironmentOrderParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
}

func (r pgEnvs) UpdateNote(ctx context.Context, p authz.Proof, note string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsUpdateNote, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.UpdateEnvironmentNote(ctx, pggen.UpdateEnvironmentNoteParams{
		Note:           note,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     string(chain.Env),
	}))
}

func (r pgEnvs) Settings(ctx context.Context, p authz.Proof) (EnvironmentSettings, error) {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsGetSettings, r.tok)
	if err != nil {
		return EnvironmentSettings{}, err
	}
	row, err := r.q.GetEnvironmentSettings(ctx, pggen.GetEnvironmentSettingsParams{
		ChainOrgID: string(chain.Org), ChainProjectID: string(chain.Project), ChainEnvID: string(chain.Env),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return EnvironmentSettings{}, ErrNotFound
	}
	if err != nil {
		return EnvironmentSettings{}, err
	}
	return EnvironmentSettings{
		Protected: row.Protected,
		HasWindow: row.ReauthWindowSeconds.Valid,
		Window:    time.Duration(row.ReauthWindowSeconds.Int64) * time.Second,
	}, nil
}

func (r pgEnvs) SetSettings(ctx context.Context, p authz.Proof, s EnvironmentSettings) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsSetSettings, r.tok)
	if err != nil {
		return err
	}
	window := pgtype.Int8{}
	if s.HasWindow {
		window = pgtype.Int8{Int64: int64(s.Window / time.Second), Valid: true}
	}
	return affected(r.q.SetEnvironmentSettings(ctx, pggen.SetEnvironmentSettingsParams{
		Protected:           s.Protected,
		ReauthWindowSeconds: window,
		ChainOrgID:          string(chain.Org),
		ChainProjectID:      string(chain.Project),
		ChainEnvID:          string(chain.Env),
	}))
}

func (r pgEnvs) Rename(ctx context.Context, p authz.Proof, name string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameEnvironment(ctx, pggen.RenameEnvironmentParams{
		Name:           name,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     string(chain.Env),
	}))
}

func (r pgEnvs) SetOrder(ctx context.Context, p authz.Proof, id string, order int64) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsSetOrder, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.SetEnvironmentOrder(ctx, pggen.SetEnvironmentOrderParams{
		DisplayOrder:   order,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgEnvs) Delete(ctx context.Context, p authz.Proof) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteEnvironment(ctx, pggen.DeleteEnvironmentParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     string(chain.Env),
	}))
}

type pgFolders struct {
	q   *pggen.Queries
	tok *authz.TxToken
}

func (r pgFolders) Create(ctx context.Context, p authz.Proof, folder NewFolder) error {
	chain, err := authz.Verify(p, authz.StoreFoldersCreate, r.tok)
	if err != nil {
		return err
	}
	return constraint(r.q.CreateFolder(ctx, pggen.CreateFolderParams{
		ID:             folder.ID,
		ChainOrgID:     string(chain.Org),     // chain column: proof-bound
		ChainProjectID: string(chain.Project), // chain column: proof-bound
		Path:           folder.Path,
		CreatedAt:      pgtype.Timestamptz{Time: CanonTime(folder.CreatedAt), Valid: true},
	}))
}

func (r pgFolders) Get(ctx context.Context, p authz.Proof, id string) (Folder, error) {
	chain, err := authz.Verify(p, authz.StoreFoldersGet, r.tok)
	if err != nil {
		return Folder{}, err
	}
	row, err := r.q.GetFolder(ctx, pggen.GetFolderParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Folder{}, ErrNotFound
	}
	if err != nil {
		return Folder{}, err
	}
	return folderFromPG(row)
}

func (r pgFolders) List(ctx context.Context, p authz.Proof) ([]Folder, error) {
	chain, err := authz.Verify(p, authz.StoreFoldersList, r.tok)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListFolders(ctx, pggen.ListFoldersParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Folder, 0, len(rows))
	for _, row := range rows {
		folder, err := folderFromPG(row)
		if err != nil {
			return nil, err
		}
		out = append(out, folder)
	}
	return out, nil
}

func (r pgFolders) Rename(ctx context.Context, p authz.Proof, id, path string) error {
	chain, err := authz.Verify(p, authz.StoreFoldersRename, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.RenameFolder(ctx, pggen.RenameFolderParams{
		Path:           path,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func (r pgFolders) Delete(ctx context.Context, p authz.Proof, id string) error {
	chain, err := authz.Verify(p, authz.StoreFoldersDelete, r.tok)
	if err != nil {
		return err
	}
	return affected(r.q.DeleteFolder(ctx, pggen.DeleteFolderParams{
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ID:             id,
	}))
}

func folderFromPG(row pggen.Folder) (Folder, error) {
	if !row.CreatedAt.Valid {
		return Folder{}, fmt.Errorf("store: folder %s: null created_at", row.ID)
	}
	return Folder{
		ID: row.ID, OrgID: row.OrgID, ProjectID: row.ProjectID,
		Path: row.Path, CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}
