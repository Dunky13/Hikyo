package store

// Datastore export and restore (#76, encryption ADR § Backups and exports,
// ops spec § 11). This file owns the CONTENTS of a backup archive; the
// age container around it is internal/crypto/backup's, and the orchestration
// that composes the two — plus the credential-epoch bump a restore performs —
// is internal/app's.
//
// The archive is a tar (stdlib, no dependency) whose FIRST member is always
// the manifest, so a reader knows what it is holding before it reads a byte
// of payload. What follows is engine-native, because the engine's own
// consistent-snapshot mechanism is both the cheapest and the most faithful
// thing to reach for:
//
//   - sqlite: one `VACUUM INTO` file. SQLite takes the snapshot; the restore
//     is a file placement. Page-exact, including the goose version table.
//   - postgres: one `COPY … TO STDOUT` stream per table, taken inside a
//     SERIALIZABLE READ ONLY DEFERRABLE transaction so every table is read at
//     one instant, in a foreign-key-safe order derived from pg_constraint
//     (never a curated list — a new migration must not silently drop a table
//     out of the backup). Sequence positions ride in the manifest.
//
// An archive restores into the SAME engine that produced it; the manifest
// names the engine and the schema version, and both are checked before any
// state is touched. Cross-engine migration is deliberately not offered here:
// it is a different feature with different failure modes, and pretending a
// backup is one would make the restore path the place it broke.

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
)

// ArchiveFormat is the archive's format identifier. A reader that does not
// recognise it refuses rather than guessing at the layout.
const ArchiveFormat = "hikyo-backup/v1"

// Archive member names. The manifest is first by construction.
const (
	manifestMember = "manifest.json"
	sqliteMember   = "payload/sqlite.db"
	pgMemberPrefix = "payload/postgres/"
)

// Manifest describes an archive: what produced it, and what a restore needs
// to know before it commits anything.
type Manifest struct {
	Format string `json:"format"`
	Engine Engine `json:"engine"`
	// SchemaVersion is the highest applied goose migration. Restore refuses
	// an archive this binary's migration set does not contain.
	SchemaVersion int64     `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	// Tables is the postgres COPY member order — foreign-key-safe, so the
	// restore replays it as-is. Empty for sqlite.
	Tables []string `json:"tables,omitempty"`
	// Sequences carries each postgres sequence's position, because COPY
	// restores rows and not the counters behind them: a restored instance
	// whose audit sequence starts at 1 would collide on its next write.
	Sequences map[string]int64 `json:"sequences,omitempty"`
}

// ErrArchiveFormat reports an archive this build cannot read.
var ErrArchiveFormat = errors.New("store: unrecognised backup archive")

// ErrEngineMismatch reports an archive taken on the other engine. It is its
// own sentinel because the operator error is specific and the fix is
// specific: restore it on the engine that produced it.
var ErrEngineMismatch = errors.New("store: backup archive was taken on a different datastore engine")

// ErrTargetNotEmpty reports a restore aimed at a datastore that already holds
// state. Restore never merges: it reconstructs an instance, and merging a
// backup into a live instance is how two identity sets become one.
var ErrTargetNotEmpty = errors.New("store: restore target is not an empty datastore")

// ErrNoSchema reports a datastore with no goose version table at all: a
// datastore no migration has ever touched. Callers that treat "fresh
// instance" differently from "the store is broken" (the pre-migration export
// preflight) branch on this by name; every other failure stays an error.
var ErrNoSchema = errors.New("store: datastore has no schema (goose version table missing)")

// SchemaVersion reports the highest applied goose migration.
func SchemaVersion(ctx context.Context, db *DB) (int64, error) {
	const q = "SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version"
	var v int64
	var err error
	if db.engine == EnginePostgres {
		err = db.pool.QueryRow(ctx, q).Scan(&v)
	} else {
		err = db.sqRead.QueryRowContext(ctx, q).Scan(&v)
	}
	if err != nil {
		if isMissingGooseTable(err) {
			return 0, fmt.Errorf("%w: %v", ErrNoSchema, err)
		}
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	return v, nil
}

// isMissingGooseTable matches exactly "the goose version table does not
// exist" on both engines — postgres undefined_table (42P01), sqlite's
// "no such table" — and nothing broader, so a connection failure or a
// permission error never reads as a fresh instance.
func isMissingGooseTable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01"
	}
	var se *sqlite.Error
	return errors.As(err, &se) && strings.Contains(se.Error(), "no such table: goose_db_version")
}

// Export writes a complete archive to w. workDir holds the engine's snapshot
// while it is being framed; the caller owns it and its cleanup.
//
// Export needs no root key and produces none: every sensitive field in the
// snapshot is already envelope ciphertext, and the wrapped key hierarchy
// travels with it. That is what makes a backup readable only by someone
// holding BOTH the backup identity and the root key.
func Export(ctx context.Context, db *DB, w io.Writer, workDir string) (Manifest, error) {
	version, err := SchemaVersion(ctx, db)
	if err != nil {
		return Manifest{}, err
	}
	m := Manifest{
		Format:        ArchiveFormat,
		Engine:        db.engine,
		SchemaVersion: version,
		CreatedAt:     CanonTime(time.Now()),
	}
	tw := tar.NewWriter(w)
	switch db.engine {
	case EngineSQLite:
		err = exportSQLite(ctx, db, tw, &m, workDir)
	case EnginePostgres:
		err = exportPostgres(ctx, db, tw, &m, workDir)
	default:
		err = fmt.Errorf("store: export for unknown engine %q", db.engine)
	}
	if err != nil {
		return Manifest{}, err
	}
	if err := tw.Close(); err != nil {
		return Manifest{}, fmt.Errorf("store: finish archive: %w", err)
	}
	return m, nil
}

// exportSQLite snapshots through VACUUM INTO — sqlite's own consistent
// online snapshot — and frames the resulting file.
func exportSQLite(ctx context.Context, db *DB, tw *tar.Writer, m *Manifest, workDir string) error {
	snapshot := filepath.Join(workDir, "snapshot.db")
	// VACUUM INTO refuses an existing target, which is the behaviour wanted:
	// a stale snapshot must never be framed as this one.
	if _, err := db.sqWrite.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return fmt.Errorf("store: sqlite snapshot: %w", err)
	}
	// The manifest is written first, so a reader knows the engine before it
	// meets the payload. The snapshot exists by now, so the manifest cannot
	// describe an export that then failed to take one.
	if err := writeManifest(tw, *m); err != nil {
		return err
	}
	return writeFileMember(tw, sqliteMember, snapshot)
}

// exportPostgres reads every table at one instant. DEFERRABLE is what makes
// a SERIALIZABLE READ ONLY transaction wait for a genuinely safe snapshot
// instead of risking a serialization failure part-way through a long dump.
func exportPostgres(ctx context.Context, db *DB, tw *tar.Writer, m *Manifest, workDir string) error {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire connection for export: %w", err)
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.Serializable,
		AccessMode:     pgx.ReadOnly,
		DeferrableMode: pgx.Deferrable,
	})
	if err != nil {
		return fmt.Errorf("store: begin export snapshot: %w", err)
	}
	defer tx.Rollback(ctx)

	tables, err := pgTableOrder(ctx, tx)
	if err != nil {
		return err
	}
	sequences, err := pgSequencePositions(ctx, tx)
	if err != nil {
		return err
	}
	m.Tables, m.Sequences = tables, sequences
	if err := writeManifest(tw, *m); err != nil {
		return err
	}

	for _, table := range tables {
		path := filepath.Join(workDir, "copy-"+table)
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("store: stage copy stream for %s: %w", table, err)
		}
		_, copyErr := tx.Conn().PgConn().CopyTo(ctx, f, "COPY "+pgIdent(table)+" TO STDOUT")
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("store: copy out %s: %w", table, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("store: stage copy stream for %s: %w", table, closeErr)
		}
		if err := writeFileMember(tw, pgMemberPrefix+table, path); err != nil {
			return err
		}
	}
	return nil
}

// pgTableOrder returns every table in the current schema, parents before
// children. The order is derived from the live foreign keys rather than
// curated, so a migration that adds a table or an edge cannot leave the
// restore inserting a child before its parent.
func pgTableOrder(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT c.relname
		FROM pg_class AS c
		JOIN pg_namespace AS n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r' AND n.nspname = current_schema()
		ORDER BY c.relname`)
	if err != nil {
		return nil, fmt.Errorf("store: list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: list tables: %w", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list tables: %w", err)
	}
	if len(tables) == 0 {
		return nil, errors.New("store: export found no tables — refusing to write an empty archive")
	}

	edges, err := tx.Query(ctx, `SELECT child.relname, parent.relname
		FROM pg_constraint AS con
		JOIN pg_class AS child ON child.oid = con.conrelid
		JOIN pg_class AS parent ON parent.oid = con.confrelid
		JOIN pg_namespace AS n ON n.oid = con.connamespace
		WHERE con.contype = 'f' AND n.nspname = current_schema()`)
	if err != nil {
		return nil, fmt.Errorf("store: list foreign keys: %w", err)
	}
	parents := map[string]map[string]bool{}
	for edges.Next() {
		var child, parent string
		if err := edges.Scan(&child, &parent); err != nil {
			edges.Close()
			return nil, fmt.Errorf("store: list foreign keys: %w", err)
		}
		if child == parent {
			continue // self-reference: one table, already in order with itself
		}
		if parents[child] == nil {
			parents[child] = map[string]bool{}
		}
		parents[child][parent] = true
	}
	edges.Close()
	if err := edges.Err(); err != nil {
		return nil, fmt.Errorf("store: list foreign keys: %w", err)
	}
	return topoSort(tables, parents)
}

// topoSort emits tables parents-first. A cycle is a loud refusal: silently
// picking an order would produce an archive that cannot be restored, and
// discovering that at restore time is the worst possible moment.
func topoSort(tables []string, parents map[string]map[string]bool) ([]string, error) {
	placed := map[string]bool{}
	out := make([]string, 0, len(tables))
	for len(out) < len(tables) {
		progress := false
		for _, t := range tables {
			if placed[t] {
				continue
			}
			ready := true
			for parent := range parents[t] {
				if !placed[parent] {
					ready = false
					break
				}
			}
			if ready {
				placed[t] = true
				out = append(out, t)
				progress = true
			}
		}
		if !progress {
			var stuck []string
			for _, t := range tables {
				if !placed[t] {
					stuck = append(stuck, t)
				}
			}
			sort.Strings(stuck)
			return nil, fmt.Errorf("store: foreign-key cycle among %s — no restore order exists", strings.Join(stuck, ", "))
		}
	}
	return out, nil
}

// pgSequencePositions records every sequence's current value. COPY moves
// rows, never the counters behind them.
func pgSequencePositions(ctx context.Context, tx pgx.Tx) (map[string]int64, error) {
	rows, err := tx.Query(ctx,
		`SELECT sequencename, COALESCE(last_value, 1) FROM pg_sequences WHERE schemaname = current_schema()`)
	if err != nil {
		return nil, fmt.Errorf("store: list sequences: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var value int64
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("store: list sequences: %w", err)
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list sequences: %w", err)
	}
	return out, nil
}

func writeManifest(tw *tar.Writer, m Manifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode manifest: %w", err)
	}
	hdr := &tar.Header{Name: manifestMember, Mode: 0o600, Size: int64(len(body)), ModTime: m.CreatedAt}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("store: write manifest header: %w", err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("store: write manifest: %w", err)
	}
	return nil
}

func writeFileMember(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: read archive member %s: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("store: stat archive member %s: %w", name, err)
	}
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: info.Size(), ModTime: info.ModTime()}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("store: write archive header %s: %w", name, err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("store: write archive member %s: %w", name, err)
	}
	return nil
}

// ReadManifest reads the archive's first member. It is separate from the
// restore itself because every refusal a restore can make on shape —
// unrecognised format, wrong engine, unknown schema version — is decidable
// from the manifest alone, and deciding them before opening a datastore is
// what "refused before any state is committed" means in practice.
func ReadManifest(archive io.Reader) (Manifest, error) {
	_, m, err := openArchive(archive)
	return m, err
}

// openArchive consumes the manifest member and hands back the live tar
// reader positioned on it. One reader for the whole archive is not a detail:
// a second tar.Reader over the same stream would start mid-member.
func openArchive(archive io.Reader) (*tar.Reader, Manifest, error) {
	tr := tar.NewReader(archive)
	hdr, err := tr.Next()
	if err != nil {
		return nil, Manifest{}, fmt.Errorf("%w: %v", ErrArchiveFormat, err)
	}
	if hdr.Name != manifestMember {
		return nil, Manifest{}, fmt.Errorf("%w: first member is %q, want %q", ErrArchiveFormat, hdr.Name, manifestMember)
	}
	var m Manifest
	if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&m); err != nil {
		return nil, Manifest{}, fmt.Errorf("%w: manifest: %v", ErrArchiveFormat, err)
	}
	if m.Format != ArchiveFormat {
		return nil, Manifest{}, fmt.Errorf("%w: format %q, this build reads %q", ErrArchiveFormat, m.Format, ArchiveFormat)
	}
	switch m.Engine {
	case EngineSQLite, EnginePostgres:
	default:
		return nil, Manifest{}, fmt.Errorf("%w: engine %q", ErrArchiveFormat, m.Engine)
	}
	return tr, m, nil
}

// RestoreSQLite writes the archive's snapshot to path, which must not exist.
// The file is fully written and fsynced under a temporary name and then
// renamed into place, so a crash mid-restore cannot leave a half-written
// database where a complete one is expected.
//
// mutate runs against the restored file BEFORE it is published, which is
// where the credential-epoch bump belongs: a restored datastore must never be
// reachable, even for an instant, in a state where its pre-restore bearer
// credentials still authenticate.
func RestoreSQLite(ctx context.Context, archive io.Reader, path string, mutate func(ctx context.Context, db *DB) error) (Manifest, error) {
	tr, m, err := openArchive(archive)
	if err != nil {
		return Manifest{}, err
	}
	if m.Engine != EngineSQLite {
		return Manifest{}, fmt.Errorf("%w: archive is %s, target is sqlite", ErrEngineMismatch, m.Engine)
	}
	if _, err := os.Stat(path); err == nil {
		return Manifest{}, fmt.Errorf("%w: %s already exists", ErrTargetNotEmpty, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("store: check restore target: %w", err)
	}

	// The staging name is unique per restore attempt: a fixed `<path>.restoring`
	// would let two concurrent restores write the same file and publish each
	// other's bytes.
	staging := fmt.Sprintf("%s.restoring-%d", path, os.Getpid())
	if err := os.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("store: clear restore staging file: %w", err)
	}
	if err := extractMemberTo(tr, sqliteMember, staging); err != nil {
		return Manifest{}, err
	}
	// sqlite checkpoints and deletes the -wal on last close, but a crash can
	// leave the sidecars behind, and a stale one beside the staging name would
	// outlive the restore.
	defer func() {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			os.Remove(staging + suffix)
		}
	}()

	if mutate != nil {
		db, err := Open(ctx, Config{Engine: EngineSQLite, Path: staging})
		if err != nil {
			return Manifest{}, fmt.Errorf("store: open restored snapshot: %w", err)
		}
		mutateErr := mutate(ctx, db)
		closeErr := db.Close()
		if mutateErr != nil {
			return Manifest{}, mutateErr
		}
		if closeErr != nil {
			return Manifest{}, fmt.Errorf("store: close restored snapshot: %w", closeErr)
		}
	}
	if err := fsyncFile(staging); err != nil {
		return Manifest{}, err
	}
	// link(2), not rename(2): the not-exists check above raced everything that
	// happened since, and rename would silently overwrite a database created
	// in the meantime. Link fails on an existing target, which re-asserts
	// "must not exist" at the moment of publication. The staging name is
	// removed by the deferred cleanup.
	if err := os.Link(staging, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Manifest{}, fmt.Errorf("%w: %s appeared during the restore", ErrTargetNotEmpty, path)
		}
		return Manifest{}, fmt.Errorf("store: publish restored database: %w", err)
	}
	return m, nil
}

// extractMemberTo walks the archive (already positioned past the manifest)
// to the named member and writes it out.
func extractMemberTo(tr *tar.Reader, member, path string) error {
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: no %s member", ErrArchiveFormat, member)
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
		if hdr.Name != member {
			continue
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("store: create %s: %w", path, err)
		}
		_, copyErr := io.Copy(f, tr)
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("store: write %s: %w", path, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("store: write %s: %w", path, closeErr)
		}
		return nil
	}
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("store: reopen for fsync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: fsync restored database: %w", err)
	}
	return nil
}

// RestorePostgres loads an archive into a database whose schema is already at
// the archive's version. Everything — the truncate, every COPY, the sequence
// positions and mutate's credential-epoch bump — happens in ONE transaction,
// so there is no instant at which a restored row is visible under the old
// epoch.
func RestorePostgres(ctx context.Context, db *DB, archive io.Reader, mutate func(context.Context, pgx.Tx) error) (Manifest, error) {
	tr, m, err := openArchive(archive)
	if err != nil {
		return Manifest{}, err
	}
	if m.Engine != EnginePostgres {
		return Manifest{}, fmt.Errorf("%w: archive is %s, target is postgres", ErrEngineMismatch, m.Engine)
	}
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return Manifest{}, fmt.Errorf("store: acquire connection for restore: %w", err)
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Manifest{}, fmt.Errorf("store: begin restore: %w", err)
	}
	defer tx.Rollback(ctx)

	quoted := make([]string, 0, len(m.Tables))
	for _, t := range m.Tables {
		quoted = append(quoted, pgIdent(t))
	}
	// Lock first, THEN verify emptiness, THEN truncate — in that order and all
	// in this transaction. The caller's pre-migration emptiness check raced
	// everything since (a server booting against the same DSN could have
	// written rows), and a truncate that trusted it would silently destroy
	// that state. Under the lock the check cannot go stale before the
	// truncate acts on it.
	if _, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(quoted, ", ")+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return Manifest{}, fmt.Errorf("store: lock restore target: %w", err)
	}
	if err := assertOnlyMigrationSeeds(ctx, tx, m.Tables); err != nil {
		return Manifest{}, err
	}
	if _, err := tx.Exec(ctx, "TRUNCATE "+strings.Join(quoted, ", ")+" RESTART IDENTITY CASCADE"); err != nil {
		return Manifest{}, fmt.Errorf("store: clear restore target: %w", err)
	}

	// User triggers are OFF for the load, and only for the load. The audit
	// tables carry a BEFORE trigger that stamps recorded_at and a deferred
	// constraint trigger that owns commit_seq and REFUSES a supplied value —
	// both correct for a live append, both wrong for a restore, which must
	// replay history verbatim rather than re-timestamp it and re-number it.
	// Referential integrity is untouched: foreign keys are internal triggers,
	// which `DISABLE TRIGGER USER` does not reach, so the manifest's
	// parents-first order still has to be right.
	if err := setUserTriggers(ctx, tx, quoted, "DISABLE"); err != nil {
		return Manifest{}, err
	}
	loaded, err := copyMembersIn(ctx, tx, tr, m.Tables)
	if err != nil {
		return Manifest{}, err
	}
	if err := setUserTriggers(ctx, tx, quoted, "ENABLE"); err != nil {
		return Manifest{}, err
	}
	for _, table := range m.Tables {
		if !loaded[table] {
			return Manifest{}, fmt.Errorf("%w: manifest names table %q with no COPY member", ErrArchiveFormat, table)
		}
	}
	for name, value := range m.Sequences {
		if _, err := tx.Exec(ctx, "SELECT setval($1, $2, true)", name, value); err != nil {
			return Manifest{}, fmt.Errorf("store: restore sequence %s: %w", name, err)
		}
	}
	if mutate != nil {
		if err := mutate(ctx, tx); err != nil {
			return Manifest{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Manifest{}, fmt.Errorf("store: commit restore: %w", err)
	}
	return m, nil
}

// migrationSeededTables are the tables a fresh migration run leaves non-empty
// (singleton defaults). Every other table must be empty at the moment the
// restore truncates, or the truncate would be destroying real state rather
// than replacing seeds.
var migrationSeededTables = map[string]bool{
	"auth_instance_state": true,
	"key_generations":     true,
	"credential_policy":   true,
	// The instance's own opaque identity (#71) is minted BY THE MIGRATION,
	// deliberately: the only correct moment for it to exist is the moment the
	// schema does, and a boot mint site would have grown the system-proof
	// operation set that invariant 11 closes. So a freshly migrated target
	// carries exactly one of these rows, and it is a seed like the others.
	// The truncate replacing it with the archive's is right rather than
	// merely tolerable: a restore reconstitutes THAT instance, and a remote
	// that pinned the old identity must keep resolving to it.
	"instance_identity": true,
	// The version table is populated by the RunUpTo that created this schema
	// moments ago; its rows are the migration run's own bookkeeping, not
	// instance state, and the truncate replaces them with the archive's.
	"goose_db_version": true,
}

// assertOnlyMigrationSeeds re-verifies, under the restore's own table locks,
// that the target holds nothing but the rows the migrations seed.
func assertOnlyMigrationSeeds(ctx context.Context, tx pgx.Tx, tables []string) error {
	for _, table := range tables {
		if migrationSeededTables[table] {
			continue
		}
		var occupied bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+pgIdent(table)+")").Scan(&occupied); err != nil {
			return fmt.Errorf("store: check restore target %s: %w", table, err)
		}
		if occupied {
			return fmt.Errorf("%w: %s has rows", ErrTargetNotEmpty, table)
		}
	}
	return nil
}

// setUserTriggers flips every restored table's user triggers. It runs inside
// the restore transaction, so an aborted restore leaves them enabled.
func setUserTriggers(ctx context.Context, tx pgx.Tx, quotedTables []string, action string) error {
	for _, table := range quotedTables {
		if _, err := tx.Exec(ctx, "ALTER TABLE "+table+" "+action+" TRIGGER USER"); err != nil {
			return fmt.Errorf("store: %s triggers on %s during restore: %w", strings.ToLower(action), table, err)
		}
	}
	return nil
}

func copyMembersIn(ctx context.Context, tx pgx.Tx, tr *tar.Reader, tables []string) (map[string]bool, error) {
	want := map[string]bool{}
	for _, t := range tables {
		want[t] = true
	}
	loaded := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return loaded, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrArchiveFormat, err)
		}
		table, ok := strings.CutPrefix(hdr.Name, pgMemberPrefix)
		if !ok {
			continue
		}
		if !want[table] {
			return nil, fmt.Errorf("%w: archive carries COPY member %q the manifest does not name", ErrArchiveFormat, table)
		}
		if _, err := tx.Conn().PgConn().CopyFrom(ctx, tr, "COPY "+pgIdent(table)+" FROM STDIN"); err != nil {
			return nil, fmt.Errorf("store: copy in %s: %w", table, err)
		}
		loaded[table] = true
	}
}

// PostgresIsEmpty reports whether the target database has no tables at all.
// Restore refuses anything else: it reconstructs an instance, and reusing a
// database that already carries one is how two instances become one.
func PostgresIsEmpty(ctx context.Context, db *DB) (bool, error) {
	var n int64
	err := db.pool.QueryRow(ctx, `SELECT count(*) FROM pg_class AS c
		JOIN pg_namespace AS ns ON ns.oid = c.relnamespace
		WHERE c.relkind = 'r' AND ns.nspname = current_schema()`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: inspect restore target: %w", err)
	}
	return n == 0, nil
}

// pgIdent quotes an identifier. Every name reaching it comes from the
// catalogue or from a manifest this build wrote, but a backup file is
// operator-supplied input by the time it is read back.
func pgIdent(name string) string { return `"` + strings.ReplaceAll(name, `"`, `""`) + `"` }
