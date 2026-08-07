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

	"github.com/Dunky13/wenv/internal/store/pggen"
	"github.com/Dunky13/wenv/internal/store/sqlitegen"
)

// SQLiteTxRepos and PGTxRepos bind repositories to an open transaction; they
// exist for internal/store/tx, which owns the transactional boundary.
func SQLiteTxRepos(tx *sql.Tx) Repos { return sqliteRepos{db: tx} }
func PGTxRepos(tx pgx.Tx) Repos      { return pgRepos{db: tx} }

// sqliteReadRepos / pgReadRepos narrow the full repos to their read side, so
// the compiler — not convention — keeps autocommit writes off the read pool.
type sqliteReadRepos struct{ r sqliteRepos }

func (s sqliteReadRepos) Orgs() OrgReader { return s.r.Orgs() }

type pgReadRepos struct{ r pgRepos }

func (p pgReadRepos) Orgs() OrgReader { return p.r.Orgs() }

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

// --- sqlite ---

type sqliteRepos struct{ db sqlitegen.DBTX }

func (r sqliteRepos) Orgs() OrgRepo { return sqliteOrgs{q: sqlitegen.New(r.db)} }

type sqliteOrgs struct{ q *sqlitegen.Queries }

func (o sqliteOrgs) Create(ctx context.Context, org Org) error {
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

func (o sqliteOrgs) Get(ctx context.Context, id string) (Org, error) {
	row, err := o.q.GetOrg(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, err
	}
	return orgFromSQLite(row)
}

func (o sqliteOrgs) List(ctx context.Context) ([]Org, error) {
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

func (o sqliteOrgs) Count(ctx context.Context) (int64, error) {
	return o.q.CountOrgs(ctx)
}

func orgFromSQLite(row sqlitegen.Org) (Org, error) {
	created, err := time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return Org{}, fmt.Errorf("store: org %s created_at %q: %w", row.ID, row.CreatedAt, err)
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
		CreatedAt: created.UTC(),
	}, nil
}

// --- postgres ---

type pgRepos struct{ db pggen.DBTX }

func (r pgRepos) Orgs() OrgRepo { return pgOrgs{q: pggen.New(r.db)} }

type pgOrgs struct{ q *pggen.Queries }

func (o pgOrgs) Create(ctx context.Context, org Org) error {
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

func (o pgOrgs) Get(ctx context.Context, id string) (Org, error) {
	row, err := o.q.GetOrg(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, err
	}
	return orgFromPG(row)
}

func (o pgOrgs) List(ctx context.Context) ([]Org, error) {
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

func (o pgOrgs) Count(ctx context.Context) (int64, error) {
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
