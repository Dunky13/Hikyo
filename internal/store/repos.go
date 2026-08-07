package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
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
func (s sqliteReadRepos) Environments() EnvironmentReader { return s.r.Environments() }
func (s sqliteReadRepos) Audit() AuditReader              { return s.r.Audit() }

type pgReadRepos struct{ r pgRepos }

func (p pgReadRepos) Orgs() OrgReader                 { return p.r.Orgs() }
func (p pgReadRepos) Keys() KeyReader                 { return p.r.Keys() }
func (p pgReadRepos) Environments() EnvironmentReader { return p.r.Environments() }
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

// --- sqlite ---

type sqliteRepos struct {
	db  sqlitegen.DBTX
	tok *authz.TxToken
}

func (r sqliteRepos) Orgs() OrgRepo { return sqliteOrgs{q: sqlitegen.New(r.db), tok: r.tok} }
func (r sqliteRepos) Projects() ProjectRepo {
	return sqliteProjects{q: sqlitegen.New(r.db), tok: r.tok}
}
func (r sqliteRepos) Environments() EnvironmentRepo {
	return sqliteEnvs{q: sqlitegen.New(r.db), tok: r.tok}
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
	return o.q.CreateOrg(ctx, sqlitegen.CreateOrgParams{
		ID:        org.ID,
		Name:      org.Name,
		Active:    active,
		Metadata:  string(org.Metadata),
		CreatedAt: CanonTime(org.CreatedAt).Format(timeFormat),
	})
}

func (o sqliteOrgs) Get(ctx context.Context, p authz.Proof, id string) (Org, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsGet, o.tok); err != nil {
		return Org{}, err
	}
	row, err := o.q.GetOrg(ctx, id)
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
	return r.q.CreateProject(ctx, sqlitegen.CreateProjectParams{
		ID:        proj.ID,
		OrgID:     string(chain.Org), // chain column: proof-bound, never caller input
		Name:      proj.Name,
		CreatedAt: CanonTime(proj.CreatedAt).Format(timeFormat),
	})
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
	return r.q.CreateEnvironment(ctx, sqlitegen.CreateEnvironmentParams{
		ID:        env.ID,
		OrgID:     string(chain.Org),     // chain column: proof-bound
		ProjectID: string(chain.Project), // chain column: proof-bound
		Name:      env.Name,
		Note:      env.Note,
		CreatedAt: CanonTime(env.CreatedAt).Format(timeFormat),
	})
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
		Name: row.Name, Note: row.Note, CreatedAt: created,
	}, nil
}

func (r sqliteEnvs) UpdateNote(ctx context.Context, p authz.Proof, note string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsUpdateNote, r.tok)
	if err != nil {
		return err
	}
	n, err := r.q.UpdateEnvironmentNote(ctx, sqlitegen.UpdateEnvironmentNoteParams{
		Note:      note,
		OrgID:     string(chain.Org),
		ProjectID: string(chain.Project),
		ID:        string(chain.Env),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- postgres ---

type pgRepos struct {
	db  pggen.DBTX
	tok *authz.TxToken
}

func (r pgRepos) Orgs() OrgRepo                 { return pgOrgs{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Projects() ProjectRepo         { return pgProjects{q: pggen.New(r.db), tok: r.tok} }
func (r pgRepos) Environments() EnvironmentRepo { return pgEnvs{q: pggen.New(r.db), tok: r.tok} }

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
	return o.q.CreateOrg(ctx, pggen.CreateOrgParams{
		ID:        org.ID,
		Name:      org.Name,
		Active:    org.Active,
		Metadata:  string(org.Metadata),
		CreatedAt: pgtype.Timestamptz{Time: CanonTime(org.CreatedAt), Valid: true},
	})
}

func (o pgOrgs) Get(ctx context.Context, p authz.Proof, id string) (Org, error) {
	if _, err := authz.Verify(p, authz.StoreOrgsGet, o.tok); err != nil {
		return Org{}, err
	}
	row, err := o.q.GetOrg(ctx, id)
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
	return r.q.CreateProject(ctx, pggen.CreateProjectParams{
		ID:         proj.ID,
		ChainOrgID: string(chain.Org), // chain column: proof-bound, never caller input
		Name:       proj.Name,
		CreatedAt:  pgtype.Timestamptz{Time: CanonTime(proj.CreatedAt), Valid: true},
	})
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
	return r.q.CreateEnvironment(ctx, pggen.CreateEnvironmentParams{
		ID:             env.ID,
		ChainOrgID:     string(chain.Org),     // chain column: proof-bound
		ChainProjectID: string(chain.Project), // chain column: proof-bound
		Name:           env.Name,
		Note:           env.Note,
		CreatedAt:      pgtype.Timestamptz{Time: CanonTime(env.CreatedAt), Valid: true},
	})
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
		Name: row.Name, Note: row.Note, CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}

func (r pgEnvs) UpdateNote(ctx context.Context, p authz.Proof, note string) error {
	chain, err := authz.Verify(p, authz.StoreEnvironmentsUpdateNote, r.tok)
	if err != nil {
		return err
	}
	n, err := r.q.UpdateEnvironmentNote(ctx, pggen.UpdateEnvironmentNoteParams{
		Note:           note,
		ChainOrgID:     string(chain.Org),
		ChainProjectID: string(chain.Project),
		ChainEnvID:     string(chain.Env),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
