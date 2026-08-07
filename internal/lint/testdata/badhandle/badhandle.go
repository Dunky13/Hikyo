// Package badhandle is a negative fixture for the driver-handle check: it
// reaches the datastore the two ways that bypass the proof boundary in one
// line — a raw driver handle, and the generated query package — with a
// caller-controlled tenant chain and no proof anywhere.
package badhandle

import (
	"context"

	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/pggen"
)

func stealAcrossTenants(ctx context.Context, db *store.DB, org, project, env string) (pggen.Environment, error) {
	q := pggen.New(db.PG())
	return q.GetEnvironment(ctx, pggen.GetEnvironmentParams{
		ChainOrgID:     org,
		ChainProjectID: project,
		ChainEnvID:     env,
	})
}

func rawWrite(ctx context.Context, db *store.DB, sql string) error {
	_, err := db.SQLiteWrite().ExecContext(ctx, sql)
	return err
}

var _ = stealAcrossTenants
var _ = rawWrite
