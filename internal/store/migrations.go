package store

import "embed"

// MigrationsFS embeds the per-dialect goose migration directories.
// Roll-forward only: no down-migrations in production paths.
//
//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var MigrationsFS embed.FS
