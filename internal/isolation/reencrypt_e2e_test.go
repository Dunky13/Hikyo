package isolation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
)

// injectRetryOnce returns an AfterChunk hook that fails the first chunk of each
// named table with a retryable error, then never again — a deterministic
// commit-time serialization retry to prove the walker publishes its cursor and
// moved-count only after the transaction commits (#187 reopen). Firing once per
// distinct table exercises each walker family independently.
func injectRetryOnce(tables ...string) func(context.Context, string) error {
	pending := map[string]bool{}
	for _, t := range tables {
		pending[t] = true
	}
	return func(_ context.Context, table string) error {
		if pending[table] {
			pending[table] = false
			return store.ErrRetrySerialization
		}
		return nil
	}
}

// reencCompletedRowsMoved asserts exactly one crypto.reencrypt_completed event
// exists and its payload's rows_moved equals want (the completion audit count is
// exact, #187 acceptance). It decodes the payload and compares numerically — a
// substring/LIKE match would let rows_moved=2 pass against a stored 20.
func reencCompletedRowsMoved(t *testing.T, db *store.DB, ctx context.Context, trail string, want int) {
	t.Helper()
	table := "audit_tenant_events"
	if trail == "instance" {
		table = "audit_instance_events"
	}
	payloads := reencQueryStrings(t, db, ctx, "SELECT payload FROM "+table+" WHERE type='crypto.reencrypt_completed'")
	if len(payloads) != 1 {
		t.Fatalf("crypto.reencrypt_completed events = %d, want exactly 1", len(payloads))
	}
	var got struct {
		RowsMoved int64 `json:"rows_moved"`
	}
	if err := json.Unmarshal([]byte(payloads[0]), &got); err != nil {
		t.Fatalf("decode reencrypt_completed payload %q: %v", payloads[0], err)
	}
	if got.RowsMoved != int64(want) {
		t.Fatalf("crypto.reencrypt_completed rows_moved = %d, want %d (exact audit count)", got.RowsMoved, want)
	}
}

// reencQueryStrings runs a single-text-column query on either engine.
func reencQueryStrings(t *testing.T, db *store.DB, ctx context.Context, query string) []string {
	t.Helper()
	var out []string
	switch db.Engine() {
	case store.EngineSQLite:
		rows, err := db.SQLiteRead().QueryContext(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	default:
		rows, err := db.PG().Query(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// A commit-time serialization retry must not skip a page or double-count moved
// rows. The #187 reopen found the walkers advanced their pagination cursor and
// incremented the moved count from inside the replayable tx.Write closure, so a
// retried chunk re-listed past the rolled-back page (stranding rows on the
// retiring key, which the dryness gate then refuses) and counted the lost page
// twice. AfterChunk injects one retryable failure per walker family; the run
// must still move every row exactly once, retire v1, and report an exact count.
func TestReencryptProjectRetrySafe(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptProjectRetrySafe(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptProjectRetrySafe(t, openPostgres) })
}

func reencryptProjectRetrySafe(t *testing.T, open func(*testing.T) *store.DB) {
	// Control: no injection, to learn the exact moved count for this seed (the
	// seeded project may carry a real draft the walk also moves).
	control := reencProjectCycle(t, open, nil)
	if control.err != nil {
		t.Fatalf("control reencrypt: %v", control.err)
	}
	// Injected: one retryable failure on the first `value` chunk. With the bug,
	// attempt 2 re-lists past the rolled-back row — it stays on v1, the dryness
	// gate refuses the retire with ErrConflict, and the count double-reports.
	got := reencProjectCycle(t, open, injectRetryOnce("value"))
	if got.err != nil {
		t.Fatalf("reencrypt with an injected retry: %v", got.err)
	}
	if got.moved != control.moved {
		t.Fatalf("moved with a retried chunk = %d, want %d (control) — retry skipped or double-counted", got.moved, control.moved)
	}
	if got.v1 != "retired" {
		t.Fatalf("DEK v1 = %q after a retried walk, want retired (a skipped page leaves it retiring)", got.v1)
	}
	reencCompletedRowsMoved(t, got.db, tctx(t), "project", got.moved)
}

type reencOutcome struct {
	db    *store.DB
	moved int
	v1    string
	err   error
}

// reencProjectCycle seeds one value row, rotates the project DEK, and runs
// reencrypt with the given AfterChunk hook. With ChunkSize=1, a chunk that fails
// retryably rolls back its row move; a walker that advanced its cursor from
// inside that closure re-lists past the row on retry and strands it on v1, which
// the dryness gate then refuses (the #187 skip). One row suffices to prove it.
func reencProjectCycle(t *testing.T, open func(*testing.T) *store.DB, inject func(context.Context, string) error) reencOutcome {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	aad := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_rs", FieldTag: "value"}
	ct := reencSealValue(t, sealer.SealValue, aad, "retry-secret")
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_rs','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_rs','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		ct)
	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}
	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1, AfterChunk: inject}
	res, err := re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj)
	out := reencOutcome{db: db, moved: res.RowsMoved, err: err}
	if err != nil {
		return out
	}
	states, serr := queryTier3States(db, ctx, org, prj)
	if serr != nil {
		t.Fatal(serr)
	}
	out.v1 = states[1]
	return out
}

// The instance walk has two more walker families than the project walk: the
// row_version tables (password_credentials) and the blob-CAS remotes table.
// Inject one retryable failure into each and assert the same retry-safety.
func TestReencryptInstanceRetrySafe(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptInstanceRetrySafe(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptInstanceRetrySafe(t, openPostgres) })
}

func reencryptInstanceRetrySafe(t *testing.T, open func(*testing.T) *store.DB) {
	control := reencInstanceCycle(t, open, nil)
	if control.err != nil {
		t.Fatalf("control reencrypt --instance: %v", control.err)
	}
	got := reencInstanceCycle(t, open, injectRetryOnce("password_credentials", "remotes"))
	if got.err != nil {
		t.Fatalf("reencrypt --instance with an injected retry: %v", got.err)
	}
	if got.moved != control.moved {
		t.Fatalf("moved with retried chunks = %d, want %d (control) — retry skipped or double-counted", got.moved, control.moved)
	}
	if got.v1 != "retired" {
		t.Fatalf("instance DEK v1 = %q after a retried walk, want retired", got.v1)
	}
	reencCompletedRowsMoved(t, got.db, tctx(t), "instance", got.moved)
}

// injectRetryOnNthChunk fails the n-th chunk of the named table once (retryable),
// then never again — a mid-walk retry, unlike injectRetryOnce which always hits
// the first chunk. It proves committed earlier pages are not re-counted and the
// retried middle chunk advances exactly once (#187 validation: multi-chunk).
func injectRetryOnNthChunk(table string, n int) func(context.Context, string) error {
	seen, fired := 0, false
	return func(_ context.Context, tbl string) error {
		if tbl != table {
			return nil
		}
		seen++
		if seen == n && !fired {
			fired = true
			return store.ErrRetrySerialization
		}
		return nil
	}
}

// The reopen's failure scenario is literally a multi-chunk walk (IDs 1–100 then
// a later page retrying): the shared walkChunked primitive must publish the
// cursor and moved-count only after each chunk commits, so a retry of chunk 2
// re-counts neither chunk 1 (committed) nor itself. Three remotes with
// ChunkSize=1 yield three chunks; inject the retry on the second.
func TestReencryptMultiChunkRetrySafe(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptMultiChunkRetrySafe(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptMultiChunkRetrySafe(t, openPostgres) })
}

func reencryptMultiChunkRetrySafe(t *testing.T, open func(*testing.T) *store.DB) {
	control := reencMultiRemoteCycle(t, open, nil)
	if control.err != nil {
		t.Fatalf("control reencrypt --instance: %v", control.err)
	}
	got := reencMultiRemoteCycle(t, open, injectRetryOnNthChunk("remotes", 2))
	if got.err != nil {
		t.Fatalf("reencrypt --instance with a mid-walk retry: %v", got.err)
	}
	if got.moved != control.moved {
		t.Fatalf("moved with a retried middle chunk = %d, want %d (control) — retry re-counted a committed page or itself", got.moved, control.moved)
	}
	if got.v1 != "retired" {
		t.Fatalf("instance DEK v1 = %q after a multi-chunk retried walk, want retired", got.v1)
	}
	reencCompletedRowsMoved(t, got.db, tctx(t), "instance", got.moved)
}

func reencMultiRemoteCycle(t *testing.T, open func(*testing.T) *store.DB, inject func(context.Context, string) error) reencOutcome {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	inst := kr.ForInstance()
	for _, rm := range []struct{ id, secret string }{{"rmt_mc1", "cred-1"}, {"rmt_mc2", "cred-2"}, {"rmt_mc3", "cred-3"}} {
		aad := crypto.InstanceFieldAAD{OwnerTable: "remotes", OwnerRowID: rm.id, FieldTag: "credential"}
		ct, err := inst.SealField(aad, []byte(rm.secret))
		if err != nil {
			t.Fatal(err)
		}
		reencExec(t, db, ctx,
			`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES (?,?,'https://r','sha256-x',?, '2026-01-01T00:00:00Z','usr_root')`,
			`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES ($1,$2,'https://r','sha256-x',$3, '2026-01-01T00:00:00Z','usr_root')`,
			rm.id, rm.id, ct)
	}
	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{Instance: true}); err != nil {
		t.Fatalf("rotate-dek --instance: %v", err)
	}
	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1, AfterChunk: inject}
	res, err := re.ReencryptInstance(ctx, service.LocalPrincipal(root))
	out := reencOutcome{db: db, moved: res.RowsMoved, err: err}
	if err != nil {
		return out
	}
	states, serr := queryTier3StatesPurpose(db, ctx, "instance", "", "")
	if serr != nil {
		t.Fatal(serr)
	}
	out.v1 = states[1]
	return out
}

func reencInstanceCycle(t *testing.T, open func(*testing.T) *store.DB, inject func(context.Context, string) error) reencOutcome {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	inst := kr.ForInstance()
	// One password_credentials row (row_version family) and one remote (blob-CAS
	// family). ChunkSize=1: a retried chunk that advanced its cursor strands the
	// row on v1 and the dryness gate refuses. One row per family proves it.
	pwAAD := crypto.InstanceFieldAAD{OwnerTable: "password_credentials", OwnerRowID: "acc_rs", FieldTag: "verifier"}
	pwCT, err := inst.SealField(pwAAD, []byte("verifier-secret"))
	if err != nil {
		t.Fatal(err)
	}
	reencExec(t, db, ctx,
		`INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_rs','usr_root','rsuser','RS','2026-01-01T00:00:00Z')`,
		`INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_rs','usr_root','rsuser','RS','2026-01-01T00:00:00Z')`)
	reencExec(t, db, ctx,
		`INSERT INTO password_credentials (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism, dek_version, credential_epoch, row_version, updated_at) VALUES ('acc_rs',?,64,3,1,1,0,0,'2026-01-01T00:00:00Z')`,
		`INSERT INTO password_credentials (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism, dek_version, credential_epoch, row_version, updated_at) VALUES ('acc_rs',$1,64,3,1,1,0,0,'2026-01-01T00:00:00Z')`,
		pwCT)
	rmAAD := crypto.InstanceFieldAAD{OwnerTable: "remotes", OwnerRowID: "rmt_rs", FieldTag: "credential"}
	rmCT, err := inst.SealField(rmAAD, []byte("remote-secret"))
	if err != nil {
		t.Fatal(err)
	}
	reencExec(t, db, ctx,
		`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES ('rmt_rs','rs-remote','https://r','sha256-x',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES ('rmt_rs','rs-remote','https://r','sha256-x',$1, '2026-01-01T00:00:00Z','usr_root')`,
		rmCT)
	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{Instance: true}); err != nil {
		t.Fatalf("rotate-dek --instance: %v", err)
	}
	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1, AfterChunk: inject}
	res, err := re.ReencryptInstance(ctx, service.LocalPrincipal(root))
	out := reencOutcome{db: db, moved: res.RowsMoved, err: err}
	if err != nil {
		return out
	}
	states, serr := queryTier3StatesPurpose(db, ctx, "instance", "", "")
	if serr != nil {
		t.Fatal(serr)
	}
	out.v1 = states[1]
	return out
}

// reencExec runs a raw statement on either engine (sqlite `?` / postgres `$n`
// placeholders), for seeding ciphertext rows the reencrypt walk then moves.
func reencExec(t *testing.T, db *store.DB, ctx context.Context, sqliteSQL, pgSQL string, args ...any) {
	t.Helper()
	switch db.Engine() {
	case store.EngineSQLite:
		if _, err := db.SQLiteWrite().ExecContext(ctx, sqliteSQL, args...); err != nil {
			t.Fatal(err)
		}
	default:
		if _, err := db.PG().Exec(ctx, pgSQL, args...); err != nil {
			t.Fatal(err)
		}
	}
}

func reencReadBlob(t *testing.T, db *store.DB, ctx context.Context, query string) []byte {
	t.Helper()
	var b []byte
	switch db.Engine() {
	case store.EngineSQLite:
		if err := db.SQLiteRead().QueryRowContext(ctx, query).Scan(&b); err != nil {
			t.Fatal(err)
		}
	default:
		if err := db.PG().QueryRow(ctx, query).Scan(&b); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// The reencrypt walk moves every project ciphertext table's rows onto the DEK
// version a rotate-dek made active — the completion half of a project DEK
// rotation (#75/#187). Covers the value, snapshot-entry and pending-draft AAD
// reconstructions (a wrong field would be a permanent decrypt failure).
func TestReencryptProjectMovesValueToActiveVersion(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptProjectCycle(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptProjectCycle(t, openPostgres) })
}

func reencryptProjectCycle(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	// value_entries row, sealed under v1.
	valAAD := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_reenc", FieldTag: "value"}
	valCT := reencSealValue(t, sealer.SealValue, valAAD, "value-secret")
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_reenc','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_reenc','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		valCT)

	// pending_changes draft, sealed under v1 (project_field, no snapshot_id).
	pendAAD := crypto.ProjectFieldAAD{OrgID: org, ProjectID: prj, OwnerTable: "pending_changes", OwnerRowID: "pcv_reenc", FieldTag: "pending_value", EnvironmentID: env, KeyID: key}
	pendCT := reencSealField(t, sealer, pendAAD, "pending-secret")
	reencExec(t, db, ctx,
		`INSERT INTO pending_changes (id, org_id, project_id, environment_id, key_id, owner_id, operation, ciphertext, staged_from_revision, staged_from_entry, created_at) VALUES ('pcv_reenc','org_a','prj_a1','env_a1','key_a1','usr_root','set',?,0,'', '2026-01-01T00:00:00Z')`,
		`INSERT INTO pending_changes (id, org_id, project_id, environment_id, key_id, owner_id, operation, ciphertext, staged_from_revision, staged_from_entry, created_at) VALUES ('pcv_reenc','org_a','prj_a1','env_a1','key_a1','usr_root','set',$1,0,'', '2026-01-01T00:00:00Z')`,
		pendCT)

	// snapshot + snapshot_entries, sealed under v1 (project_field with snapshot_id).
	reencExec(t, db, ctx,
		`INSERT INTO snapshots (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at) VALUES ('snap_reenc','org_a','prj_a1','env_a1',1,0,'usr_root','2026-01-01T00:00:00Z')`,
		`INSERT INTO snapshots (id, org_id, project_id, environment_id, revision, schema_revision, published_by, published_at) VALUES ('snap_reenc','org_a','prj_a1','env_a1',1,0,'usr_root','2026-01-01T00:00:00Z')`)
	snapAAD := crypto.ProjectFieldAAD{OrgID: org, ProjectID: prj, OwnerTable: "snapshot_entries", OwnerRowID: "se_reenc", FieldTag: "snapshot_value", EnvironmentID: env, KeyID: key, SnapshotID: "snap_reenc"}
	snapCT := reencSealField(t, sealer, snapAAD, "snapshot-secret")
	reencExec(t, db, ctx,
		`INSERT INTO snapshot_entries (id, org_id, project_id, environment_id, snapshot_id, key_id, key_name, classification, ciphertext, value_entry_id) VALUES ('se_reenc','org_a','prj_a1','env_a1','snap_reenc','key_a1','SHARED_KEY','config',?, 'row_reenc')`,
		`INSERT INTO snapshot_entries (id, org_id, project_id, environment_id, snapshot_id, key_id, key_name, classification, ciphertext, value_entry_id) VALUES ('se_reenc','org_a','prj_a1','env_a1','snap_reenc','key_a1','SHARED_KEY','config',$1, 'row_reenc')`,
		snapCT)

	// adapter + adapter_route_move credential, sealed under v1 (project_field,
	// AAD owner_row = the adapter id for BOTH).
	adpAAD := crypto.ProjectFieldAAD{OrgID: org, ProjectID: prj, OwnerTable: "adapters", OwnerRowID: "adp_reenc", FieldTag: "credential"}
	adpCT := reencSealField(t, sealer, adpAAD, "adapter-secret")
	reencExec(t, db, ctx,
		`INSERT INTO adapters (id, org_id, project_id, provider, origin, credential_ciphertext, credential_set_at, authority_principal_id, state, created_at) VALUES ('adp_reenc','org_a','prj_a1','forgejo','https://reenc-origin',?, '2026-01-01T00:00:00Z','usr_root','active','2026-01-01T00:00:00Z')`,
		`INSERT INTO adapters (id, org_id, project_id, provider, origin, credential_ciphertext, credential_set_at, authority_principal_id, state, created_at) VALUES ('adp_reenc','org_a','prj_a1','forgejo','https://reenc-origin',$1, '2026-01-01T00:00:00Z','usr_root','active','2026-01-01T00:00:00Z')`,
		adpCT)
	mvCT := reencSealField(t, sealer, adpAAD, "move-secret")
	reencExec(t, db, ctx,
		`INSERT INTO adapter_route_moves (id, org_id, project_id, adapter_id, target_id, kind, pending_origin, pending_credential_ciphertext, authority_principal_id, state, keep_remote, created_at) VALUES ('arm_reenc','org_a','prj_a1','adp_reenc',NULL,'origin','https://new',?, 'usr_root','scrubbing',0,'2026-01-01T00:00:00Z')`,
		`INSERT INTO adapter_route_moves (id, org_id, project_id, adapter_id, target_id, kind, pending_origin, pending_credential_ciphertext, authority_principal_id, state, keep_remote, created_at) VALUES ('arm_reenc','org_a','prj_a1','adp_reenc',NULL,'origin','https://new',$1, 'usr_root','scrubbing',false,'2026-01-01T00:00:00Z')`,
		mvCT)

	// rotate-dek --project: v2 active, v1 retiring.
	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}

	// reencrypt --project walks all three tables onto v2. At least our three
	// rows move; the seeded project may also carry a real service-sealed draft,
	// which the walk moves too (that it opens+reseals a real draft is itself the
	// validation), so assert a lower bound and verify each of our rows below.
	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1}
	res, err := re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj)
	if err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	if res.RowsMoved < 5 {
		t.Fatalf("rows moved = %d, want >= 5 (value + pending + snapshot + adapter + move)", res.RowsMoved)
	}

	sealer2, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	reencAssertMoved(t, db, ctx, sealer2, "value_entries", "ciphertext", "row_reenc", valAAD, "value-secret", true)
	reencAssertMoved(t, db, ctx, sealer2, "pending_changes", "ciphertext", "pcv_reenc", pendAAD, "pending-secret", false)
	reencAssertMoved(t, db, ctx, sealer2, "snapshot_entries", "ciphertext", "se_reenc", snapAAD, "snapshot-secret", false)
	reencAssertMoved(t, db, ctx, sealer2, "adapters", "credential_ciphertext", "adp_reenc", adpAAD, "adapter-secret", false)
	reencAssertMoved(t, db, ctx, sealer2, "adapter_route_moves", "pending_credential_ciphertext", "arm_reenc", adpAAD, "move-secret", false)

	// Retire completed: the old version is retired, only the new one active.
	states := map[int]string{}
	rows, err := queryTier3States(db, ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	for v, st := range rows {
		states[v] = st
	}
	if states[1] != "retired" {
		t.Errorf("DEK v1 state = %q, want retired after reencrypt", states[1])
	}
	if states[2] != "active" {
		t.Errorf("DEK v2 state = %q, want active", states[2])
	}

	// Resumable/idempotent: a second run moves nothing.
	res2, err := re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj)
	if err != nil {
		t.Fatal(err)
	}
	if res2.RowsMoved != 0 {
		t.Fatalf("second reencrypt moved %d, want 0", res2.RowsMoved)
	}
}

// The retire's dryness gate (ADR invariant 7) must refuse when a ciphertext is
// still off the active version — never retire a referenced key. Both scenarios
// use the BeforeRetire hook to reach the window the gate guards: (a) a straggler
// row appears after the walk; (b) a concurrent rotate-dek demotes the version
// the walk sealed onto. In both, retire must refuse and leave the version
// retiring (not retired), so a re-run can complete safely.
func TestReencryptRetireRefusesStraggler(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptRetireRefusesStraggler(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptRetireRefusesStraggler(t, openPostgres) })
}

func reencryptRetireRefusesStraggler(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	valAAD := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_dry", FieldTag: "value"}
	valCT := reencSealValue(t, sealer.SealValue, valAAD, "dry-secret")
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_dry','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_dry','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		valCT)

	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}

	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1}
	// After the walk moves row_dry to v2, regress its ciphertext back to the v1
	// blob — a straggler the walk has already passed. The dryness scan must catch
	// it and refuse the retire rather than destroy v1 while it is still referenced.
	re.BeforeRetire = func(ctx context.Context) error {
		reencExec(t, db, ctx,
			`UPDATE value_entries SET ciphertext = ? WHERE id = 'row_dry'`,
			`UPDATE value_entries SET ciphertext = $1 WHERE id = 'row_dry'`,
			valCT)
		return nil
	}
	_, err = re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("reencrypt with a straggler: err = %v, want domain.ErrConflict", err)
	}
	states, err := queryTier3States(db, ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	if states[1] != "retiring" {
		t.Errorf("DEK v1 state = %q, want retiring (retire must NOT complete with a straggler)", states[1])
	}
}

func TestReencryptRetireRefusesVersionRace(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptRetireRefusesVersionRace(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptRetireRefusesVersionRace(t, openPostgres) })
}

func reencryptRetireRefusesVersionRace(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	valAAD := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_race", FieldTag: "value"}
	valCT := reencSealValue(t, sealer.SealValue, valAAD, "race-secret")
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_race','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_race','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		valCT)

	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}

	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1}
	// The walk seals onto v2. Before retire, a concurrent rotate-dek makes v3 the
	// active version and demotes v2 to retiring. Retire must re-read the current
	// active, see its captured v2 is no longer active, and refuse — never retire
	// v2 out from under the rows it just moved onto it (the Codex data-loss path).
	re.BeforeRetire = func(ctx context.Context) error {
		_, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj})
		return err
	}
	_, err = re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj)
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("reencrypt racing a rotate-dek: err = %v, want domain.ErrConflict", err)
	}
	states, err := queryTier3States(db, ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	if states[2] != "retiring" {
		t.Errorf("DEK v2 state = %q, want retiring (retire must NOT retire the version it sealed onto)", states[2])
	}
}

// The scheduler's read-only sweep (#75/#187 option A) reports scopes with a
// retiring DEK version and nothing after reencrypt clears them.
func TestReencryptSweepReportsRetiringScopes(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptSweep(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptSweep(t, openPostgres) })
}

func reencryptSweep(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	valAAD := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_sweep", FieldTag: "value"}
	valCT := reencSealValue(t, sealer.SealValue, valAAD, "sweep-secret")
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_sweep','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_sweep','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		valCT)

	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1}
	// No rotation yet: one openable version, nothing to reencrypt.
	if scopes, err := re.SweepRetiring(ctx); err != nil || len(scopes) != 0 {
		t.Fatalf("sweep before rotation: %v, %v, want empty", scopes, err)
	}

	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}
	// A retiring v1 now exists: the sweep must report exactly this scope.
	scopes, err := re.SweepRetiring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sc := range scopes {
		if sc.Purpose == "project" && sc.OrgID == org && sc.ProjectID == prj {
			found = true
		}
	}
	if !found {
		t.Fatalf("sweep after rotate-dek did not report %s/%s: %v", org, prj, scopes)
	}

	if _, err := re.ReencryptProject(ctx, service.LocalPrincipal(root), org, prj); err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	// Retire cleared the retiring version: the scope drops off the sweep.
	after, err := re.SweepRetiring(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range after {
		if sc.Purpose == "project" && sc.OrgID == org && sc.ProjectID == prj {
			t.Fatalf("sweep still reports %s/%s after reencrypt: %v", org, prj, after)
		}
	}
}

func reencSealValue(t *testing.T, fn func(crypto.ValueAAD, []byte) ([]byte, error), aad crypto.ValueAAD, plain string) []byte {
	t.Helper()
	ct, err := fn(aad, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := crypto.RecordKeyVersion(ct); err != nil || v != 1 {
		t.Fatalf("sealed under version %d (err %v), want 1", v, err)
	}
	return ct
}

func reencSealField(t *testing.T, s *crypto.ProjectSealer, aad crypto.ProjectFieldAAD, plain string) []byte {
	t.Helper()
	ct, err := s.SealField(aad, []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

// The --instance walk moves the instance credential tables onto the active
// instance DEK version and retires the old. Covers both CAS variants: a
// row_version table (password_credentials) and the blob-CAS table (remotes).
func TestReencryptInstanceMovesCredentials(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { reencryptInstanceCycle(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { reencryptInstanceCycle(t, openPostgres) })
}

func reencryptInstanceCycle(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	inst := kr.ForInstance()

	pwAAD := crypto.InstanceFieldAAD{OwnerTable: "password_credentials", OwnerRowID: "acc_reenc", FieldTag: "verifier"}
	pwCT, err := inst.SealField(pwAAD, []byte("password-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	rmAAD := crypto.InstanceFieldAAD{OwnerTable: "remotes", OwnerRowID: "rmt_reenc", FieldTag: "credential"}
	rmCT, err := inst.SealField(rmAAD, []byte("remote-credential"))
	if err != nil {
		t.Fatal(err)
	}
	reencExec(t, db, ctx,
		`INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_reenc','usr_root','reencuser','Reenc','2026-01-01T00:00:00Z')`,
		`INSERT INTO accounts (id, principal_id, username, display_name, created_at) VALUES ('acc_reenc','usr_root','reencuser','Reenc','2026-01-01T00:00:00Z')`)
	reencExec(t, db, ctx,
		`INSERT INTO password_credentials (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism, dek_version, credential_epoch, row_version, updated_at) VALUES ('acc_reenc',?,64,3,1,1,0,0,'2026-01-01T00:00:00Z')`,
		`INSERT INTO password_credentials (account_id, verifier, kdf_memory_kib, kdf_time, kdf_parallelism, dek_version, credential_epoch, row_version, updated_at) VALUES ('acc_reenc',$1,64,3,1,1,0,0,'2026-01-01T00:00:00Z')`,
		pwCT)
	reencExec(t, db, ctx,
		`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES ('rmt_reenc','reenc-remote','https://r','sha256-x',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO remotes (id, name, url, spki_pin, credential_sealed, created_at, created_by) VALUES ('rmt_reenc','reenc-remote','https://r','sha256-x',$1, '2026-01-01T00:00:00Z','usr_root')`,
		rmCT)

	rotation := &service.Rotation{DB: db, Keyring: kr, RootKey: probeRootSource{db: db}}
	if _, err := rotation.RotateDEK(ctx, service.LocalPrincipal(root), service.DEKScope{Instance: true}); err != nil {
		t.Fatalf("rotate-dek --instance: %v", err)
	}
	re := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 1, ChunkPause: -1}
	res, err := re.ReencryptInstance(ctx, service.LocalPrincipal(root))
	if err != nil {
		t.Fatalf("reencrypt --instance: %v", err)
	}
	if res.RowsMoved < 2 {
		t.Fatalf("rows moved = %d, want >= 2 (password + remote)", res.RowsMoved)
	}

	inst2 := kr.ForInstance()
	pw2 := reencReadBlob(t, db, ctx, "SELECT verifier FROM password_credentials WHERE account_id='acc_reenc'")
	if v, err := crypto.RecordKeyVersion(pw2); err != nil || v != 2 {
		t.Fatalf("password verifier version = %d (err %v), want 2", v, err)
	}
	if pt, err := inst2.OpenField(pwAAD, pw2); err != nil || string(pt) != "password-verifier" {
		t.Fatalf("open reencrypted verifier: %q, %v", pt, err)
	}
	rm2 := reencReadBlob(t, db, ctx, "SELECT credential_sealed FROM remotes WHERE id='rmt_reenc'")
	if v, err := crypto.RecordKeyVersion(rm2); err != nil || v != 2 {
		t.Fatalf("remote credential version = %d (err %v), want 2", v, err)
	}
	if pt, err := inst2.OpenField(rmAAD, rm2); err != nil || string(pt) != "remote-credential" {
		t.Fatalf("open reencrypted remote: %q, %v", pt, err)
	}

	states, err := queryTier3StatesPurpose(db, ctx, "instance", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if states[1] != "retired" {
		t.Errorf("instance DEK v1 state = %q, want retired", states[1])
	}
	if states[2] != "active" {
		t.Errorf("instance DEK v2 state = %q, want active", states[2])
	}
}

// The full post-compromise recovery order on live data (encryption-model ADR
// § Rotation): rotate-root-key → rotate-master-key → rotate-dek → reencrypt, run
// in sequence against a real value row, with the value readable at every step
// and correctly re-keyed at the end. This is the acceptance's "all rotations on
// live data" exercised as one composed flow.
func TestFullRecoveryOrderOnLiveData(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { recoveryOrder(t, openSQLite) })
	t.Run("postgres", func(t *testing.T) { recoveryOrder(t, openPostgres) })
}

func recoveryOrder(t *testing.T, open func(*testing.T) *store.DB) {
	db := seededDB(t, open)
	kr := probeKeyring(t, db)
	ctx := tctx(t)
	const org, prj, env, key = "org_a", "prj_a1", "env_a1", "key_a1"
	aad := crypto.ValueAAD{OrgID: org, ProjectID: prj, EnvID: env, KeyID: key, RowID: "row_rec", FieldTag: "value"}
	secret := "recovery-order-secret"

	sealer, err := kr.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.SealValue(aad, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	reencExec(t, db, ctx,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_rec','org_a','prj_a1','env_a1','key_a1',?, '2026-01-01T00:00:00Z','usr_root')`,
		`INSERT INTO value_entries (id, org_id, project_id, environment_id, key_id, ciphertext, updated_at, updated_by) VALUES ('row_rec','org_a','prj_a1','env_a1','key_a1',$1, '2026-01-01T00:00:00Z','usr_root')`,
		ct)

	opens := func(stage string) {
		s, err := kr.ForProject(ctx, org, prj)
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		stored := reencReadBlob(t, db, ctx, "SELECT ciphertext FROM value_entries WHERE id='row_rec'")
		pt, err := s.OpenValue(aad, stored)
		if err != nil || string(pt) != secret {
			t.Fatalf("value unreadable after %s: %q, %v", stage, pt, err)
		}
	}

	reenc := &service.Reencrypt{DB: db, Keyring: kr, ChunkSize: 4, ChunkPause: -1}
	actor := service.LocalPrincipal(root)

	// 1. rotate-root-key (prepare → install → verify → finalize).
	newRoot, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	curRoot, _ := (probeRootSource{db: db}).Current(ctx)
	src := &mutableRootSource{current: curRoot, next: newRoot}
	rootRot := &service.Rotation{DB: db, Keyring: kr, RootKey: src}
	if _, err := rootRot.RotateRootKey(ctx, actor, service.RootRotatePrepare); err != nil {
		t.Fatalf("root prepare: %v", err)
	}
	src.install()
	if _, err := rootRot.RotateRootKey(ctx, actor, service.RootRotateVerify); err != nil {
		t.Fatalf("root verify: %v", err)
	}
	if _, err := rootRot.RotateRootKey(ctx, actor, service.RootRotateFinalize); err != nil {
		t.Fatalf("root finalize: %v", err)
	}
	opens("rotate-root-key")

	// 2. rotate-master-key. 3. rotate-dek --project. 4. reencrypt --project.
	if _, err := rootRot.RotateMasterKey(ctx, actor); err != nil {
		t.Fatalf("rotate-master-key: %v", err)
	}
	opens("rotate-master-key")
	if _, err := rootRot.RotateDEK(ctx, actor, service.DEKScope{OrgID: org, ProjectID: prj}); err != nil {
		t.Fatalf("rotate-dek: %v", err)
	}
	opens("rotate-dek")
	if _, err := reenc.ReencryptProject(ctx, actor, org, prj); err != nil {
		t.Fatalf("reencrypt: %v", err)
	}
	opens("reencrypt")

	// The value ends on the active (post-rotation) DEK version, and a fresh boot
	// under the NEW root reads it — the whole flow is durable, not just in-memory.
	final := reencReadBlob(t, db, ctx, "SELECT ciphertext FROM value_entries WHERE id='row_rec'")
	if v, err := crypto.RecordKeyVersion(final); err != nil || v != 2 {
		t.Fatalf("value on DEK version %d (err %v), want 2 after reencrypt", v, err)
	}
	kr2, err := crypto.LoadKeyring(ctx, &keyring.Store{DB: db}, bytes.Clone(newRoot))
	if err != nil {
		t.Fatalf("reboot under new root after recovery: %v", err)
	}
	s2, err := kr2.ForProject(ctx, org, prj)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := s2.OpenValue(aad, final); err != nil || string(pt) != secret {
		t.Fatalf("value unreadable after reboot under new root: %q, %v", pt, err)
	}
}

func queryTier3States(db *store.DB, ctx context.Context, org, proj string) (map[int]string, error) {
	return queryTier3StatesPurpose(db, ctx, "project", org, proj)
}

func queryTier3StatesPurpose(db *store.DB, ctx context.Context, purpose, org, proj string) (map[int]string, error) {
	out := map[int]string{}
	q := "SELECT version, state FROM tier3_keys WHERE purpose='" + purpose + "' AND org_id='" + org + "' AND project_id='" + proj + "'"
	switch db.Engine() {
	case store.EngineSQLite:
		rows, err := db.SQLiteRead().QueryContext(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			var st string
			if err := rows.Scan(&v, &st); err != nil {
				return nil, err
			}
			out[v] = st
		}
		return out, rows.Err()
	default:
		rows, err := db.PG().Query(ctx, q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			var st string
			if err := rows.Scan(&v, &st); err != nil {
				return nil, err
			}
			out[v] = st
		}
		return out, rows.Err()
	}
}

func reencAssertMoved(t *testing.T, db *store.DB, ctx context.Context, s *crypto.ProjectSealer, table, col, id string, aad crypto.AAD, want string, isValue bool) {
	t.Helper()
	ct := reencReadBlob(t, db, ctx, "SELECT "+col+" FROM "+table+" WHERE id = '"+id+"'")
	if v, err := crypto.RecordKeyVersion(ct); err != nil || v != 2 {
		t.Fatalf("%s %s version = %d (err %v), want 2", table, id, v, err)
	}
	var plain []byte
	var err error
	if isValue {
		plain, err = s.OpenValue(aad.(crypto.ValueAAD), ct)
	} else {
		plain, err = s.OpenField(aad.(crypto.ProjectFieldAAD), ct)
	}
	if err != nil || string(plain) != want {
		t.Fatalf("open reencrypted %s: %q, %v", table, plain, err)
	}
}
