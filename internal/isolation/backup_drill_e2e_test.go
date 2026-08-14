package isolation

// The backup -> destroy -> restore drill (#76, mvp-boundary K2) and the
// headline guarantee (K3), on both engines.
//
// K2's evidence row enumerates the restore rules one by one, and this file is
// written to exercise them one by one rather than to assert that a restore
// "worked":
//
//	bearer credentials dead BY PRESENTATION ATTEMPT ............ machineDead
//	browser/CLI sessions dead .................................. sessionDead
//	single-use artifacts dead .................................. authorityDead
//	restored verifiers never trusted (password re-establishment)  passwordDead
//	MFA/recovery re-establishment via the establishment authority  totpDead
//	OIDC links re-validated, not trusted ....................... epoch-carried
//	grants inert until the operator commits the reconciled set .. grantsInert
//	per-principal reconciliation, NO BULK-ACCEPT PATH .......... TestNoBulkAccept
//	truncated backup refused before any state is committed ..... truncation
//	custody separation as two distinct identities .............. custody
//
// Two rules in that row cannot be exercised today and are recorded here
// rather than quietly skipped: the FEDERATED iat-skew predicate has no
// subject, because no federation credential kind exists yet (the
// machine_credentials CHECK admits `hikyo-token` only), and ADAPTER OUTBOUND
// CREDENTIALS have no subject because no adapter exists. The anchor the first
// needs — reactivated_at — is written by this restore, so the predicate lands
// with federation rather than needing a schema change then.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/admission"
	"github.com/Hikyo-Org/hikyo/internal/app"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/config"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/crypto/backup"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/Hikyo-Org/hikyo/internal/service"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/keyring"
	"github.com/Hikyo-Org/hikyo/internal/store/migrate"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
	"github.com/Hikyo-Org/hikyo/internal/webauthntest"
)

// custody models the escrow runbook's requirement literally: the age backup
// identity and the root key are held in SEPARATE stores with separate access,
// and the drill fetches each from its own store. Two keys in one password
// manager is one failure domain wearing two names, so a drill that read both
// out of one variable would prove nothing about the separation.
type custody struct {
	backupStore string // holds the age identity, and nothing else
	rootStore   string // holds the root key, and nothing else
}

func newCustody(t *testing.T) custody {
	t.Helper()
	c := custody{backupStore: t.TempDir(), rootStore: t.TempDir()}

	identity, recipient, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	write := func(dir, name, value string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(c.backupStore, "identity", identity)
	write(c.backupStore, "recipient", recipient)

	root, err := crypto.GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	write(c.rootStore, "rootkey", crypto.EncodeRootKey(root))
	crypto.Zero(root)
	return c
}

func (c custody) read(t *testing.T, dir, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// identityFile is the path the restore verb is handed: the drill fetches the
// backup identity from its own custody store and never from the root key's.
func (c custody) identityFile() string          { return filepath.Join(c.backupStore, "identity") }
func (c custody) recipient(t *testing.T) string { return c.read(t, c.backupStore, "recipient") }

// rootKey fetches the root key from ITS OWN store. It returns fresh bytes each
// call because LoadKeyring consumes (and zeroes) what it is given.
func (c custody) rootKey(t *testing.T) []byte {
	t.Helper()
	key, err := crypto.ReadRootKey(filepath.Join(c.rootStore, "rootkey"), "")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// drillTarget is one datastore the drill can build, destroy and rebuild. The
// two engines differ only in what "destroy" means.
type drillTarget struct {
	cfg     *config.Config
	destroy func(t *testing.T)
}

func sqliteTarget(t *testing.T, backupDir, recipient string) drillTarget {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "hikyo.db")
	return drillTarget{
		cfg: &config.Config{
			Store:            config.Datastore{Engine: config.EngineSQLite, Path: path},
			AutoMigrate:      true,
			BackupDir:        backupDir,
			BackupRecipients: []string{recipient},
		},
		destroy: func(t *testing.T) {
			t.Helper()
			for _, suffix := range []string{"", "-wal", "-shm", ".lock"} {
				if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("destroy %s: %v", path+suffix, err)
				}
			}
		},
	}
}

func postgresTarget(t *testing.T, backupDir, recipient string) drillTarget {
	t.Helper()
	base := os.Getenv("HIKYO_TEST_POSTGRES_DSN")
	if base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI run without HIKYO_TEST_POSTGRES_DSN: the postgres backup drill must not silently skip in CI")
		}
		t.Skip("HIKYO_TEST_POSTGRES_DSN not set")
	}
	dsn := derivedDatabase(t, base, "_drill")
	drop := func(t *testing.T) {
		t.Helper()
		db, err := store.Open(t.Context(), store.Config{Engine: store.EnginePostgres, DSN: dsn})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		// Drop the whole schema rather than an enumerated table list: this is
		// the drill's "the instance is gone" step, and a list that drifted
		// from the migrations would leave the restore merging into debris.
		if _, err := db.PG().Exec(t.Context(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
			t.Fatalf("destroy postgres instance: %v", err)
		}
	}
	drop(t) // start from a genuinely empty database
	return drillTarget{
		cfg: &config.Config{
			Store:            config.Datastore{Engine: config.EnginePostgres, DSN: dsn},
			AutoMigrate:      true,
			BackupDir:        backupDir,
			BackupRecipients: []string{recipient},
		},
		destroy: drop,
	}
}

func (d drillTarget) storeConfig() store.Config {
	return store.Config{
		Engine: store.Engine(d.cfg.Store.Engine),
		Path:   d.cfg.Store.Path,
		DSN:    d.cfg.Store.DSN,
	}
}

func (d drillTarget) open(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(t.Context(), d.storeConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// artifacts are every credential value the drill holds in its hand before the
// backup is taken. Each one is replayed after the restore and must be refused.
type artifacts struct {
	password   string
	session    string
	machine    string
	recovery   []string
	totpSecret string
	authority  string
	adminUser  string
	adminPrin  domain.PrincipalID
	// secretValue is the planted secret VALUE (#50): the headline row's first
	// half. It must appear nowhere in the dump or archive in the clear.
	secretValue string
	// passkey is the authenticator enrolled BEFORE the backup. Ops spec § 11:
	// a pre-backup enrolment must not resurrect across a restore.
	passkey *webauthntest.Device
	// superseded holds every session token the fixture rotated past. The
	// values left the client; the plaintext scan covers them like the live one.
	superseded []string
}

// authWithRoot builds the auth service on a NAMED root key, so the drill can
// prove later that the restored datastore boots with that key and with no
// other. authService (audit_e2e) generates one internally and throws it away,
// which is exactly what a custody-separation drill must not do.
func authWithRoot(t *testing.T, db *store.DB, root []byte) *service.Auth {
	t.Helper()
	kr, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: db}, root)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := admission.New(admission.Config{ArgonMemoryKiB: crypto.PasswordFloor.MemoryKiB})
	if err != nil {
		t.Fatal(err)
	}
	a := &service.Auth{DB: db, Keyring: kr, KDF: crypto.PasswordFloor, Admission: limiter,
		ReauthWindow: 5 * time.Minute, ReauthHardCap: time.Hour}
	// The drill's K2 checklist includes the passkey leg, so every acting
	// service — pre-backup and post-restore alike — speaks WebAuthn.
	a.ExternalOrigin = waOrigin
	if err := a.ConfigureWebAuthnRP(); err != nil {
		t.Fatalf("configuring the webauthn relying party: %v", err)
	}
	return a
}

// buildInstance seeds an instance carrying one of every credential artifact
// the restore checklist names, and hands back the VALUES. Holding the values
// is what lets the post-restore assertions be presentation attempts rather
// than row inspections — K2 says "dead by presentation attempt", and a row
// that merely looks inert is not the same claim.
func buildInstance(t *testing.T, target drillTarget, c custody) (*store.DB, artifacts) {
	t.Helper()
	if err := migrate.Run(t.Context(), target.storeConfig()); err != nil {
		t.Fatal(err)
	}
	db := target.open(t)
	for _, stmt := range fixtureSQL {
		execRaw(t, db, stmt)
	}
	seedOrigins(t, db)
	identityFixtures(t, db)

	auth := authWithRoot(t, db, c.rootKey(t))
	ctx := t.Context()
	a := artifacts{password: "correct horse battery staple drill", adminUser: "drill-admin"}

	boot, err := auth.BootstrapAdmin(ctx, a.adminUser, "Drill Admin", "terminal")
	if err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	a.adminPrin = boot.PrincipalID
	if err := auth.EstablishCredential(ctx, boot.Authority, a.password); err != nil {
		t.Fatalf("establish credential: %v", err)
	}
	// An UNCONSUMED single-use artifact, minted BEFORE any session exists so
	// that the reset's own session sweep is not what kills the session the
	// drill later replays. "Single-use artifacts dead" needs a live subject,
	// not a spent one.
	reset, err := auth.BreakGlassResetCredential(ctx, string(boot.PrincipalID), "terminal")
	if err != nil {
		t.Fatalf("break-glass reset: %v", err)
	}
	a.authority = reset.Authority

	login, err := auth.LocalLogin(ctx, a.adminUser, a.password, service.ArtifactCLI)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// Regenerating recovery codes is an account-security mutation, so it
	// ROTATES the acting session: the old token is gone and the rotated one is
	// what the rest of the setup carries.
	codes, rotated, err := auth.GenerateRecoveryCodes(ctx, login.SessionToken, a.password)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	a.recovery = codes
	// A live TOTP factor: its seed is envelope-encrypted, so the base32 secret
	// is a PLANTED PLAINTEXT for K3's dump scan as well as a re-establishment
	// subject for K2.
	uri, err := auth.EnrolTOTPStart(ctx, rotated.SessionToken, a.password)
	if err != nil {
		t.Fatalf("enrol totp: %v", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	a.totpSecret = parsed.Query().Get("secret")
	if a.totpSecret == "" {
		t.Fatal("enrolment produced no TOTP secret to plant")
	}
	confirmed, err := auth.EnrolTOTPConfirm(ctx, rotated.SessionToken,
		totpCode(t, uri, time.Now().UTC().Add(30*time.Second)))
	if err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	// A live passkey, enrolled BEFORE the backup: K2's passkey leg. The device
	// itself rides in the artifacts so the post-restore probe can present a
	// REAL assertion, not inspect a row.
	a.passkey = webauthntest.New(waRPID, waOrigin)
	withPasskey := enrolPasskey(t, auth, ctx, confirmed.SessionToken, a.password, a.passkey)
	a.session = withPasskey
	// Every token the setup rotated past left the client at some point; the
	// plaintext scan covers them all, not only the survivor.
	a.superseded = []string{login.SessionToken, rotated.SessionToken, confirmed.SessionToken}

	sa, err := identitySvc(db).CreateServiceAccount(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), "drill-workload", domain.ClassWorkload)
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	minted, err := identitySvc(db).MintCredential(ctx, service.LocalPrincipal(identAdmin),
		prjScope(), sa.ID, service.MintRequest{})
	if err != nil {
		t.Fatalf("mint credential: %v", err)
	}
	a.machine = minted.Value

	// A SECRET VALUE, planted through the real values surface (#50): the
	// headline guarantee is "no values and no replayable credentials", and
	// until this row existed the scan could only speak for the second half.
	kr, err := crypto.LoadKeyring(ctx, &keyring.Store{DB: db}, c.rootKey(t))
	if err != nil {
		t.Fatal(err)
	}
	valueActor := service.LocalPrincipal(custodian)
	// The drill's datastore is minted under the custody root, so every service
	// that seals here shares THAT keyring. probeKeyring would hand back a
	// hierarchy under a freshly generated root, which the store refuses — and a
	// key create now seals too, because a semantic schema change materializes
	// every environment in the project (#51).
	if _, err := (&service.Keys{DB: db, Keyring: kr}).Create(ctx, valueActor, prjScope(), service.KeySpec{
		Name: "DRILL_PLANTED_SECRET", Classification: string(schema.Secret),
		Declaration: schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
		Presence:    schema.DefaultPresenceRules(),
	}); err != nil {
		t.Fatalf("create planted secret key: %v", err)
	}
	a.secretValue = "the-drill-planted-secret-material-7f3a9c"
	envScope := prjScope()
	envScope.Env = "env_a1"
	// Staged and PUBLISHED: a pending change is not a delivered value, and the
	// headline guarantee is about material the instance actually serves.
	publishValue(t, &service.Values{DB: db, Keyring: kr}, valueActor, envScope,
		"DRILL_PLANTED_SECRET", a.secretValue)

	// Everything must be live BEFORE the backup, or the post-restore
	// assertions would pass against artifacts that never worked.
	if id := authenticate(t, db, a.session); id.Principal == "" {
		t.Fatal("the drill's session did not authenticate before the backup")
	}
	if id := authenticate(t, db, a.machine); id.Principal != sa.Principal {
		t.Fatal("the drill's machine credential did not authenticate before the backup")
	}
	if err := grantsAuthorize(t, db); err != nil {
		t.Fatalf("grants did not authorize before the backup: %v", err)
	}
	return db, a
}

// grantsAuthorize is the grant-inertness probe: the fixture operator listing
// organisations. It succeeds on a healthy instance and must be refused on a
// restored one until its principal is reconciled.
func grantsAuthorize(t *testing.T, db *store.DB) error {
	t.Helper()
	_, err := (&service.Orgs{DB: db}).List(t.Context(), service.LocalPrincipal(root))
	return err
}

func drillLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// exportArchive runs the real operator verb, so the drill covers the CLI
// surface rather than the service call underneath it.
func exportArchive(t *testing.T, target drillTarget) string {
	t.Helper()
	before := archiveFiles(t, target.cfg.BackupDir)
	if err := app.RunBackup(t.Context(), target.cfg, drillLogger(), []string{"export"}, io.Discard); err != nil {
		t.Fatalf("backup export: %v", err)
	}
	after := archiveFiles(t, target.cfg.BackupDir)
	if len(after) != len(before)+1 {
		t.Fatalf("export published %d archives, want exactly one more than %d", len(after), len(before))
	}
	for name := range after {
		if !before[name] {
			return name
		}
	}
	t.Fatal("no new archive after export")
	return ""
}

func archiveFiles(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".age") {
			out[filepath.Join(dir, e.Name())] = true
		}
	}
	return out
}

func TestBackupRestoreDrillSQLite(t *testing.T) {
	c := newCustody(t)
	runBackupRestoreDrill(t, sqliteTarget(t, t.TempDir(), c.recipient(t)), c)
}

func TestBackupRestoreDrillPostgres(t *testing.T) {
	c := newCustody(t)
	runBackupRestoreDrill(t, postgresTarget(t, t.TempDir(), c.recipient(t)), c)
}

func runBackupRestoreDrill(t *testing.T, target drillTarget, c custody) {
	db, a := buildInstance(t, target, c)

	// Survival expectations are captured NOW, before the export: the export's
	// own audit record and anything the replay probes append land AFTER the
	// snapshot, so a count read any later would not match the archive. And on
	// postgres a count read after the restore would compare the restored
	// state with itself and prove nothing (`db` and `restored` are the same
	// database there).
	survivalTables := []string{
		"orgs", "projects", "environments", "principals", "grants", "grant_origins",
		"accounts", "password_credentials", "recovery_codes", "totp_credentials",
		"sessions", "credential_authorities", "service_accounts", "machine_credentials",
		"master_keys", "tier3_keys", "audit_instance_events", "audit_tenant_events",
	}
	beforeCounts := map[string]int64{}
	for _, table := range survivalTables {
		beforeCounts[table] = queryInt(t, db, "SELECT COUNT(*) FROM "+table)
	}
	orgNamesBefore := queryStrings(t, db, "SELECT name FROM orgs ORDER BY id")

	archive := exportArchive(t, target)
	dumpBefore := rawDatastoreBytes(t, target, db)

	// K3, the scan half: no artifact the drill holds may appear in the raw
	// datastore or in the backup, in the clear.
	assertNoPlaintext(t, "datastore", dumpBefore, a)
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPlaintext(t, "backup archive", archiveBytes, a)

	// K3, the replay half: everything an attacker can lift OUT of the dump —
	// verifiers, session rows, recovery-code hashes — presented against a live
	// instance and refused.
	assertDumpMaterialIsUnreplayable(t, authWithRoot(t, db, c.rootKey(t)), db, a.adminUser, dumpBefore)

	t.Run("truncated_backup_refused_before_any_state_is_committed", func(t *testing.T) {
		// Two cut points, because they fail for different reasons and only one
		// of them is the interesting case. A cut inside a chunk fails that
		// chunk's authentication tag — indistinguishable from tampering, and
		// caught either way. A cut on a CHUNK BOUNDARY authenticates every
		// byte present and fails only because the final chunk never arrived:
		// that is the truncation a stream-and-apply restore would commit a
		// prefix of, and it is asserted by name.
		cuts := map[string]struct {
			at       int
			sentinel error
		}{
			"chunk boundary": {ageStreamBoundary(t, archiveBytes), backup.ErrTruncated},
			"mid-chunk":      {len(archiveBytes) - 4096, nil},
		}
		for name, cut := range cuts {
			t.Run(name, func(t *testing.T) {
				truncated := filepath.Join(t.TempDir(), "truncated.age")
				if err := os.WriteFile(truncated, archiveBytes[:cut.at], 0o600); err != nil {
					t.Fatal(err)
				}
				target.destroy(t)
				err := app.RunRestore(t.Context(), target.cfg, drillLogger(),
					[]string{"run", "--from", truncated, "--identity-file", c.identityFile()},
					io.Discard)
				if err == nil {
					t.Fatal("a truncated archive restored")
				}
				if cut.sentinel != nil && !errors.Is(err, cut.sentinel) {
					t.Fatalf("truncated restore error = %v, want %v", err, cut.sentinel)
				}
				assertTargetUntouched(t, target)
			})
		}
	})

	t.Run("custody_separation_is_two_distinct_identities", func(t *testing.T) {
		// The backup is undecryptable with the ROOT KEY alone: the root key is
		// not an age identity and is not among the container's recipients.
		rootHex := c.read(t, c.rootStore, "rootkey")
		for name, u := range map[string]backup.Unlock{
			"root key as an age identity": {Identity: rootHex},
			"root key as a passphrase":    {Passphrase: rootHex},
		} {
			if err := backup.ExtractTo(io.Discard, bytes.NewReader(archiveBytes), u); err == nil {
				t.Fatalf("%s opened the backup container", name)
			}
		}
		// And a foreign age identity does not open it either, so the refusal
		// above is about custody and not about the encoding.
		other, _, err := backup.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if err := backup.ExtractTo(io.Discard, bytes.NewReader(archiveBytes), backup.Unlock{Identity: other}); err == nil {
			t.Fatal("a foreign age identity opened the backup container")
		}
	})

	// The restore itself. Destroy explicitly rather than relying on the
	// truncation subtest having left the target empty: the drill's
	// backup -> DESTROY -> restore shape must not depend on the order the
	// subtests above happened to run in.
	target.destroy(t)
	if _, err := os.Stat(archive); err != nil {
		t.Fatal(err)
	}
	if err := app.RunRestore(t.Context(), target.cfg, drillLogger(),
		[]string{"run", "--from", archive, "--identity-file", c.identityFile()},
		io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored := target.open(t)

	t.Run("the_instance_actually_came_back", func(t *testing.T) {
		// The drill's other assertions are all about what STOPPED working, so
		// one about what survived is what keeps them from being satisfiable by
		// restoring an empty database. Every expectation was read off the
		// pre-destroy instance (beforeCounts, above) rather than written down,
		// so a fixture that grows cannot leave this checking a stale number.
		for _, table := range survivalTables {
			want := beforeCounts[table]
			if want == 0 {
				t.Errorf("%s was empty before the backup: it proves nothing about the restore", table)
			}
			if table == "audit_instance_events" {
				// The restore appends exactly one event of its own,
				// restore.completed, inside the restore transaction.
				want++
			}
			if got := queryInt(t, restored, "SELECT COUNT(*) FROM "+table); got != want {
				t.Errorf("%s: restored %d rows, the instance had %d", table, got, want)
			}
		}
		if got := queryInt(t, restored, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'restore.completed'"); got != 1 {
			t.Errorf("restored trail has %d restore.completed events, want exactly 1", got)
		}
		got := queryStrings(t, restored, "SELECT name FROM orgs ORDER BY id")
		if !strings.Contains(got, "org-a") || got != orgNamesBefore {
			t.Errorf("restored organisation names = %q, want the pre-destroy %q", got, orgNamesBefore)
		}
	})

	t.Run("unbootable_with_the_age_identity_alone", func(t *testing.T) {
		// The age identity opened the container; it cannot open the DATA. A
		// keyring load under any key other than the escrowed root refuses.
		wrong, err := crypto.GenerateRootKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: restored}, wrong); err == nil {
			t.Fatal("the restored datastore booted under a root key that never wrapped it")
		}
		// And the escrowed root, fetched from its OWN custody store, does boot
		// it — so the refusal above is about the key, not about the restore.
		if _, err := crypto.LoadKeyring(t.Context(), &keyring.Store{DB: restored}, c.rootKey(t)); err != nil {
			t.Fatalf("the restored datastore did not boot under its escrowed root key: %v", err)
		}
	})

	t.Run("every_recoverable_credential_is_dead_by_presentation", func(t *testing.T) {
		auth := authWithRoot(t, restored, c.rootKey(t))
		ctx := t.Context()

		if id := authenticate(t, restored, a.session); id.Principal != "" {
			t.Error("a restored CLI session still authenticated")
		}
		if id := authenticate(t, restored, a.machine); id.Principal != "" {
			t.Error("a restored machine bearer credential still authenticated")
		}
		if _, err := auth.LocalLogin(ctx, a.adminUser, a.password, service.ArtifactCLI); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("a restored password verifier still authenticated: %v", err)
		}
		if _, err := auth.ConsumeRecoveryCode(ctx, a.adminUser, a.recovery[1]); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("a restored recovery code was still consumable: %v", err)
		}
		if err := auth.EstablishCredential(ctx, a.authority, "a brand new password entirely"); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("a restored single-use establishment authority was still consumable: %v", err)
		}
		// The TOTP factor is inert with the rest: its row carries the epoch,
		// so re-establishment goes through the credential-establishment
		// authority like every other authenticator.
		if _, err := auth.StepUpTOTP(ctx, a.session, totpCode(t, "otpauth://totp/x?secret="+a.totpSecret, time.Now().UTC())); err == nil {
			t.Error("a restored TOTP factor still elevated a session")
		}
		// The pre-backup passkey presents a REAL assertion and must be refused:
		// ops spec § 11, a pre-backup enrolment (the attacker-enrolment case)
		// must not resurrect across a restore.
		if _, err := discoverableLogin(t, auth, ctx, a.passkey); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("a restored passkey still logged in: %v", err)
		}
	})

	t.Run("grants_are_inert_until_the_operator_commits_them", func(t *testing.T) {
		if err := grantsAuthorize(t, restored); err == nil {
			t.Fatal("restored grants authorized before any reconciliation")
		}
		svc := &service.Restore{DB: restored}
		status, err := svc.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !status.State.Restored() {
			t.Fatal("the restored instance does not report a restore")
		}
		if status.State.ReactivatedAt.IsZero() {
			t.Fatal("the restore recorded no reactivation instant: the federated iat-skew predicate has no anchor")
		}
		if len(status.Pending) == 0 {
			t.Fatal("no principal is awaiting reconciliation after a restore")
		}

		// Per principal: reconciling the operator restores THAT principal's
		// authority and nobody else's.
		if _, err := svc.Reconcile(t.Context(), root); err != nil {
			t.Fatalf("reconcile %s: %v", root, err)
		}
		if err := grantsAuthorize(t, restored); err != nil {
			t.Fatalf("a reconciled principal's grants still did not authorize: %v", err)
		}
		if _, err := (&service.Projects{DB: restored}).List(t.Context(), service.LocalPrincipal(alice), orgA); err == nil {
			t.Fatal("an unreconciled principal's grants authorized on the back of another principal's reconciliation")
		}
		after, err := svc.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(after.Pending) != len(status.Pending)-1 {
			t.Fatalf("reconciling one principal moved %d of them", len(status.Pending)-len(after.Pending))
		}
	})

	t.Run("re_establishment_through_the_credential_authority_works", func(t *testing.T) {
		// Every other assertion here is about what STOPPED working. Without
		// this one the whole drill would still pass against an instance that
		// nobody can ever get back into — which is not a restored instance,
		// it is a brick with good audit records.
		auth := authWithRoot(t, restored, c.rootKey(t))
		ctx := t.Context()

		reset, err := auth.BreakGlassResetCredential(ctx, string(a.adminPrin), "terminal")
		if err != nil {
			t.Fatalf("minting a post-restore establishment authority: %v", err)
		}
		const reestablished = "a completely different passphrase after the restore"
		if err := auth.EstablishCredential(ctx, reset.Authority, reestablished); err != nil {
			t.Fatalf("re-establishing the administrator's credential after a restore: %v", err)
		}
		login, err := auth.LocalLogin(ctx, a.adminUser, reestablished, service.ArtifactCLI)
		if err != nil {
			t.Fatalf("logging in with the re-established credential: %v", err)
		}
		if id := authenticate(t, restored, login.SessionToken); id.Principal != a.adminPrin {
			t.Fatal("the re-established session did not authenticate")
		}

		// AUTHENTICATION is back; AUTHORIZATION is still gated. This is the
		// whole point of keeping the credential epoch and the reconciliation
		// epoch as two facts: proving who you are does not re-approve what you
		// may reach, and the operator's per-principal assertion is what does.
		if _, err := (&service.Orgs{DB: restored}).List(ctx, service.LocalPrincipal(a.adminPrin)); err == nil {
			t.Fatal("a re-authenticated but unreconciled principal's grants authorized")
		}
		if _, err := (&service.Restore{DB: restored}).Reconcile(ctx, a.adminPrin); err != nil {
			t.Fatalf("reconcile %s: %v", a.adminPrin, err)
		}
		if _, err := (&service.Orgs{DB: restored}).List(ctx, service.LocalPrincipal(a.adminPrin)); err != nil {
			t.Fatalf("a re-established, reconciled administrator still could not act: %v", err)
		}

		// Passkey re-establishment rides the same authority chain: the
		// re-established password is the proof for a FRESH enrolment, the new
		// passkey logs in — and the pre-backup device stays dead beside it,
		// so the working path is not what resurrects the attacker's.
		fresh := webauthntest.New(waRPID, waOrigin)
		session := enrolPasskey(t, auth, ctx, login.SessionToken, reestablished, fresh)
		if id := authenticate(t, restored, session); id.Principal != a.adminPrin {
			t.Fatal("the session reissued by passkey enrolment did not authenticate")
		}
		if _, err := discoverableLogin(t, auth, ctx, fresh); err != nil {
			t.Fatalf("a passkey re-established after the restore could not log in: %v", err)
		}
		if _, err := discoverableLogin(t, auth, ctx, a.passkey); !errors.Is(err, domain.ErrUnauthenticated) {
			t.Errorf("the pre-backup passkey resurrected once a new one was enrolled: %v", err)
		}
	})

	t.Run("reconciliation_names_one_principal_and_only_one", func(t *testing.T) {
		svc := &service.Restore{DB: restored}
		if _, err := svc.Reconcile(t.Context(), ""); err == nil {
			t.Error("reconciliation accepted an empty principal")
		}
		if _, err := svc.Reconcile(t.Context(), domain.PrincipalID("usr_does_not_exist")); err == nil {
			t.Error("reconciliation accepted a principal the restored state does not contain")
		}
	})
}

// ageStreamBoundary is the offset of the end of the container's FIRST payload
// chunk: past the header's MAC line, past the 16-byte STREAM nonce, past one
// 64 KiB chunk and its 16-byte tag. Cutting there leaves a container whose
// every present byte authenticates and whose final chunk is missing.
func ageStreamBoundary(t *testing.T, container []byte) int {
	t.Helper()
	mac := bytes.Index(container, []byte("\n---"))
	if mac < 0 {
		t.Fatal("no age header MAC line in the container")
	}
	streamStart := mac + 1 + bytes.IndexByte(container[mac+1:], '\n') + 1
	const nonce, chunk = 16, 64*1024 + 16
	if at := streamStart + nonce + chunk; at < len(container) {
		return at
	}
	// A container smaller than one chunk has exactly one boundary that is not
	// the end of the file: the point where the payload begins and no chunk has
	// arrived yet. Same property, same refusal.
	return streamStart + nonce
}

// assertTargetUntouched is the "before any state is committed" half of the
// truncation rule: the refused restore must have left nothing behind.
func assertTargetUntouched(t *testing.T, target drillTarget) {
	t.Helper()
	sc := target.storeConfig()
	if sc.Engine == store.EngineSQLite {
		if _, err := os.Stat(sc.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused restore left %s behind", sc.Path)
		}
		return
	}
	db, err := store.Open(t.Context(), sc)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	empty, err := store.PostgresIsEmpty(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if !empty {
		t.Fatal("a refused restore left tables behind")
	}
}

// rawDatastoreBytes is "the dump" an attacker walks off with: on sqlite the
// database file itself, on postgres every table's COPY output. Neither is
// produced through pg_dump — the drill must not depend on a client binary
// whose version may not match the server it is pointed at.
func rawDatastoreBytes(t *testing.T, target drillTarget, db *store.DB) []byte {
	t.Helper()
	sc := target.storeConfig()
	if sc.Engine == store.EngineSQLite {
		// Snapshot rather than read the live file: WAL means the file on disk
		// need not yet carry the most recent writes, and a scan that missed a
		// planted value because it was still in the WAL would be a scan that
		// proves nothing.
		dir := t.TempDir()
		if _, err := db.SQLiteWrite().ExecContext(t.Context(), "VACUUM INTO ?", filepath.Join(dir, "dump.db")); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "dump.db"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var out bytes.Buffer
	work := t.TempDir()
	// store.Export writes the archive, and its postgres payload IS the dump.
	if _, err := store.Export(t.Context(), db, &out, work); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// assertNoPlaintext is K3's CI scan: every value the drill planted must be
// absent from the bytes, in the clear.
func assertNoPlaintext(t *testing.T, what string, blob []byte, a artifacts) {
	t.Helper()
	planted := map[string]string{
		"password":                a.password,
		"TOTP seed":               a.totpSecret,
		"CLI session token":       a.session,
		"machine bearer token":    a.machine,
		"establishment authority": a.authority,
		"first recovery code":     a.recovery[0],
		"last recovery code":      a.recovery[len(a.recovery)-1],
		"planted secret value":    a.secretValue,
	}
	// Superseded session tokens left the client exactly like the live one; a
	// rotation that stored its predecessor in the clear would scan green
	// without these.
	for i, token := range a.superseded {
		planted[fmt.Sprintf("superseded session token %d", i)] = token
	}
	for name, value := range planted {
		if value == "" {
			t.Fatalf("%s: nothing planted for %s — a vacuous scan proves nothing", what, name)
		}
		if bytes.Contains(blob, []byte(value)) {
			t.Errorf("%s contains the %s in the clear", what, name)
		}
	}
}

// assertDumpMaterialIsUnreplayable takes what an attacker actually recovers
// from a dump — verifier bytes, session rows, recovery-code hashes — and
// presents each of them against a live instance, in every encoding a naive
// attacker would try. Every one must be refused.
//
// The claim being tested is precise: the dump yields VERIFIERS, and a verifier
// is not a credential. It is the entire content of "no directly replayable
// stored credentials".
func assertDumpMaterialIsUnreplayable(t *testing.T, auth *service.Auth, db *store.DB, adminUser string, dump []byte) {
	t.Helper()
	candidates := replayCandidates(t, db)
	if len(candidates) == 0 {
		t.Fatal("no stored verifier found to replay — the replay probe would be vacuous")
	}
	for _, candidate := range candidates {
		// The bearer-token path takes every candidate: it is the presentation
		// an attacker holding opaque dump bytes tries first.
		if id := authenticate(t, db, candidate.value); id.Principal != "" {
			t.Errorf("%s replayed from the dump authenticated as %s", candidate.what, id.Principal)
		}
		// Recovery material also gets its NATIVE presentation path: K3 names
		// recovery-code hashes explicitly, and refusing them as tokens says
		// nothing about the recovery flow itself.
		if candidate.recovery {
			if _, err := auth.ConsumeRecoveryCode(t.Context(), adminUser, candidate.value); !errors.Is(err, domain.ErrUnauthenticated) {
				t.Errorf("%s replayed through the recovery flow was not refused: %v", candidate.what, err)
			}
		}
	}
	// The dump really does contain EVERY verifier the probe replayed, so a
	// change that stopped storing one class of verifier cannot make its leg
	// pass vacuously. The encoding differs by engine — sqlite writes the
	// bytes, postgres' COPY text format writes \x<hex> — so presence is
	// accepted in either rendering.
	checked := map[string]bool{}
	for _, candidate := range candidates {
		if checked[string(candidate.raw)] {
			continue
		}
		checked[string(candidate.raw)] = true
		if !bytes.Contains(dump, candidate.raw) &&
			!bytes.Contains(dump, []byte(fmt.Sprintf("%x", candidate.raw))) {
			t.Errorf("%s does not appear in the dump at all: the probe is not reading what an attacker would", candidate.what)
		}
	}
}

type replayCandidate struct {
	what     string
	raw      []byte
	value    string
	recovery bool
}

// replayCandidates lifts stored verifiers straight out of the tables an
// attacker reads — K3 names token verifiers, session rows and recovery-code
// hashes — and renders each in the encodings a replay would use.
func replayCandidates(t *testing.T, db *store.DB) []replayCandidate {
	t.Helper()
	var out []replayCandidate
	for what, source := range map[string]struct {
		query    string
		recovery bool
	}{
		"session verifier":            {query: "SELECT verifier FROM sessions"},
		"machine credential verifier": {query: "SELECT verifier FROM machine_credentials"},
		"authority verifier":          {query: "SELECT verifier FROM credential_authorities"},
		"recovery-code batch":         {query: "SELECT batch FROM recovery_codes", recovery: true},
	} {
		for _, raw := range queryBlobs(t, db, source.query) {
			for encoding, rendered := range map[string]string{
				"raw":    string(raw),
				"hex":    fmt.Sprintf("%x", raw),
				"base64": base64.StdEncoding.EncodeToString(raw),
			} {
				out = append(out, replayCandidate{
					what: what + " (" + encoding + ")", raw: raw, value: rendered,
					recovery: source.recovery,
				})
			}
		}
	}
	return out
}

func queryBlobs(t *testing.T, db *store.DB, q string) [][]byte {
	t.Helper()
	var out [][]byte
	if db.Engine() == store.EnginePostgres {
		rows, err := db.PG().Query(t.Context(), q)
		if err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		defer rows.Close()
		for rows.Next() {
			var v []byte
			if err := rows.Scan(&v); err != nil {
				t.Fatalf("query %q: %v", q, err)
			}
			if len(v) > 0 {
				out = append(out, v)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		return out
	}
	rows, err := db.SQLiteRead().QueryContext(t.Context(), q)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	defer rows.Close()
	for rows.Next() {
		var v []byte
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		if len(v) > 0 {
			out = append(out, v)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return out
}

// TestNoBulkAcceptInTheAPISurface is K2's "no bulk-accept path in the API
// surface", asserted as an ABSENCE and from three directions, because an
// absence is exactly the property a future convenience commit erases without
// meaning to.
func TestNoBulkAcceptInTheAPISurface(t *testing.T) {
	// 1. No reconciliation method anywhere takes a collection. The signature
	//    is the guarantee: one principal in, one answer out.
	for _, subject := range []struct {
		name string
		typ  reflect.Type
	}{
		{"service.Restore", reflect.TypeOf(&service.Restore{})},
		{"authz.TxAuthorizer", reflect.TypeOf(&authz.TxAuthorizer{})},
	} {
		for i := 0; i < subject.typ.NumMethod(); i++ {
			m := subject.typ.Method(i)
			if !strings.Contains(strings.ToLower(m.Name), "reconcil") {
				continue
			}
			for j := 0; j < m.Type.NumIn(); j++ {
				in := m.Type.In(j)
				if in.Kind() == reflect.Slice || in.Kind() == reflect.Map {
					t.Errorf("%s.%s takes a %s: reconciliation is per principal and has no set-taking form",
						subject.name, m.Name, in.Kind())
				}
			}
		}
	}

	// 2. The CLI refuses anything but exactly one named principal. `--all` is
	//    the flag a hurried operator reaches for, and it must not exist.
	cfg := &config.Config{Store: config.Datastore{Engine: config.EngineSQLite, Path: filepath.Join(t.TempDir(), "unused.db")}}
	for _, args := range [][]string{
		{"reconcile"},
		{"reconcile", "--all"},
		{"reconcile", "--principals", "usr_a,usr_b"},
	} {
		if err := app.RunRestore(t.Context(), cfg, drillLogger(), args, io.Discard); err == nil {
			t.Errorf("`hikyo restore %s` was accepted", strings.Join(args, " "))
		}
	}

	// 3. No HTTP route reaches restore or reconciliation at all. The
	//    classification-totality invariant already asserts that cli:restore is
	//    system-class with no route; this names the words, so a route added
	//    under a different verb still fails here.
	for entry := range facts.Wire() {
		if !strings.HasPrefix(entry, "http:") {
			continue
		}
		lowered := strings.ToLower(entry)
		for _, banned := range []string{"reconcil", "restore", "backup"} {
			if strings.Contains(lowered, banned) {
				t.Errorf("HTTP route %s reaches the restore surface: restore and its reconciliation are local host authority only", entry)
			}
		}
	}
}

// runBackupLifecycle drives every backup.* and restore.* event type through a
// real emitter, so the audit suite's "declaration without an emitter" check
// has something behind each registration.
//
// It advances the restore epoch on the shared fixture datastore and then
// reconciles the principals it made inert — ONE CALL PER PRINCIPAL, through
// the same per-principal surface an operator uses. That loop is a test walking
// a list, not a bulk-accept path: there is no call that reconciles a set, and
// TestNoBulkAcceptInTheAPISurface asserts there is none.
func runBackupLifecycle(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()
	_, recipient, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	svc := &service.Backup{DB: db, Options: backup.Options{Recipients: []string{recipient}}}
	result, err := svc.Export(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("backup.exported: %v", err)
	}
	if err := svc.RecordExport(ctx, service.TriggerManual, result); err != nil {
		t.Fatalf("backup.exported: %v", err)
	}
	if err := svc.RecordSkip(ctx, service.TriggerPreMigration, "drill"); err != nil {
		t.Fatalf("backup.export_skipped: %v", err)
	}

	// restore.completed is the restore transaction's own closure. Running it
	// here against the fixture datastore is the same act it performs there.
	if err := runRestoreClosure(ctx, db, result.Manifest); err != nil {
		t.Fatalf("restore.completed: %v", err)
	}
	restore := &service.Restore{DB: db}
	status, err := restore.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range status.Pending {
		if _, err := restore.Reconcile(ctx, p.ID); err != nil {
			t.Fatalf("restore.principal_reconciled (%s): %v", p.ID, err)
		}
	}
	final, err := restore.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Pending) != 0 {
		t.Fatalf("%d principals remain inert after the lifecycle", len(final.Pending))
	}

	// Put the shared fixture datastore back the way it was found. This
	// function exists to prove every registered event type has a real emitter,
	// not to leave the suites that run after it testing a restored instance:
	// they seed principals with raw SQL, which bypasses the born-reconciled
	// stamp, and would then be silently unauthorized for reasons that have
	// nothing to do with what they are asserting. The real restore semantics
	// are the drill's subject, on a datastore of its own.
	execRaw(t, db, "UPDATE auth_instance_state SET credential_epoch = 1, restore_epoch = 0, reactivated_at = NULL WHERE id = 1")
	execRaw(t, db, "UPDATE principals SET reconciled_epoch = 0")
}

func runRestoreClosure(ctx context.Context, db *store.DB, m store.Manifest) error {
	return tx.Reconcile(ctx, db, service.CompleteRestore(time.Now().UTC(), m))
}

// MaxKnownCredentialEpoch is a curated table list, and a curated list's
// failure mode is omission: a future epoch-stamped table left out of it would
// let a forged archive plant a credential the restore's bump never clears.
// This pins the list to the SCHEMA — every table carrying a credential_epoch
// column, discovered by introspection on a freshly migrated database, must be
// named in BOTH engines' query text.
func TestMaxKnownCredentialEpochCoversEveryEpochColumn(t *testing.T) {
	cfg := store.Config{Engine: store.EngineSQLite, Path: filepath.Join(t.TempDir(), "epoch.db")}
	if err := migrate.Run(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tables := strings.Fields(queryStrings(t, db,
		`SELECT m.name || char(10) FROM sqlite_master m JOIN pragma_table_info(m.name) c
		 ON c.name = 'credential_epoch' WHERE m.type = 'table' ORDER BY m.name`))
	if len(tables) < 10 {
		t.Fatalf("schema introspection found only %d epoch-stamped tables: the guard is not reading the schema", len(tables))
	}
	for _, engine := range []string{"sqlite", "postgres"} {
		src, err := os.ReadFile(filepath.Join("..", "store", "queries", engine, "authn.sql"))
		if err != nil {
			t.Fatal(err)
		}
		_, after, found := strings.Cut(string(src), "name: MaxKnownCredentialEpoch")
		if !found {
			t.Fatalf("%s/authn.sql has no MaxKnownCredentialEpoch query", engine)
		}
		block, _, _ := strings.Cut(after, "-- name:")
		for _, table := range tables {
			if !strings.Contains(block, " FROM "+table) {
				t.Errorf("%s MaxKnownCredentialEpoch does not scan %s: a forged epoch stamp there would survive a restore", engine, table)
			}
		}
	}
}

// A forged counter at the top of int64 must be refused, not wrapped: the +1
// of a MaxInt64 stamp is MinInt64, an epoch an attacker can plant a second
// credential at. The guard is engine-shared Go (authn.nextEpoch), so one
// engine's leg covers it.
func TestRestoreRefusesImplausibleEpochStamps(t *testing.T) {
	c := newCustody(t)
	target := sqliteTarget(t, t.TempDir(), c.recipient(t))
	if err := migrate.Run(t.Context(), target.storeConfig()); err != nil {
		t.Fatal(err)
	}
	db := target.open(t)
	for _, stmt := range fixtureSQL {
		execRaw(t, db, stmt)
	}
	seedOrigins(t, db)
	execRaw(t, db, `UPDATE auth_instance_state SET restore_epoch = 9223372036854775807 WHERE id = 1`)
	archive := exportArchive(t, target)
	target.destroy(t)
	err := app.RunRestore(t.Context(), target.cfg, drillLogger(),
		[]string{"run", "--from", archive, "--identity-file", c.identityFile()},
		io.Discard)
	if err == nil || !strings.Contains(err.Error(), "outside the sane range") {
		t.Fatalf("a MaxInt64 epoch stamp was not refused by name: %v", err)
	}
	// Refused BEFORE publication: no datastore may exist at the target.
	if _, statErr := os.Stat(target.cfg.Store.Path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the refused restore left state behind: %v", statErr)
	}
}

// The restore must not trust the archive's OWN epoch bookkeeping (K2:
// restored verifiers never trusted — including their epoch stamps). An
// archive is forgeable by anyone holding the PUBLIC recipient, so a forged
// one can understate the instance epoch while stamping planted credentials
// ahead of it, or stamp its principals pre-reconciled against any restore
// epoch it predicts. Both forgeries must land dead: the new epoch is one past
// the LARGEST stamp found anywhere in the restored state, and every
// principal's reconciliation stamp is stripped.
func TestRestoreDistrustsArchiveEpochStampsSQLite(t *testing.T) {
	c := newCustody(t)
	runRestoreEpochForgery(t, sqliteTarget(t, t.TempDir(), c.recipient(t)), c)
}

func TestRestoreDistrustsArchiveEpochStampsPostgres(t *testing.T) {
	c := newCustody(t)
	runRestoreEpochForgery(t, postgresTarget(t, t.TempDir(), c.recipient(t)), c)
}

func runRestoreEpochForgery(t *testing.T, target drillTarget, c custody) {
	if err := migrate.Run(t.Context(), target.storeConfig()); err != nil {
		t.Fatal(err)
	}
	db := target.open(t)
	for _, stmt := range fixtureSQL {
		execRaw(t, db, stmt)
	}
	seedOrigins(t, db)

	// The forgery: a session stamped ahead of the instance epoch, the instance
	// row claiming a restore epoch chosen so that "archive counter + 1" would
	// bring the planted stamps to life, and every principal marked reconciled
	// against a far-future restore epoch.
	verifier := "X'666f7267656421'"
	if target.cfg.Store.Engine == config.EnginePostgres {
		verifier = `'\x666f7267656421'`
	}
	execRaw(t, db, `INSERT INTO sessions (id, principal_id, verifier, artifact, session_generation, credential_epoch, auth_method, factors, authenticated_at, created_at, last_seen_at, idle_expires_at, absolute_expires_at, source_ip, user_agent) `+
		`VALUES ('ses_forged', 'usr_alice', `+verifier+`, 'cli', 1, 50, 'password', '[]', `+ts+`, `+ts+`, `+ts+`, '2030-01-01T00:00:00.000000Z', '2030-01-01T00:00:00.000000Z', '127.0.0.1', 'forge')`)
	execRaw(t, db, `UPDATE auth_instance_state SET credential_epoch = 3, restore_epoch = 9999 WHERE id = 1`)
	execRaw(t, db, `UPDATE principals SET reconciled_epoch = 100000`)

	archive := exportArchive(t, target)
	target.destroy(t)
	if err := app.RunRestore(t.Context(), target.cfg, drillLogger(),
		[]string{"run", "--from", archive, "--identity-file", c.identityFile()},
		io.Discard); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored := target.open(t)

	// One past the largest stamp anywhere in the archive (the forged 9999),
	// never the archive's credential counter + 1 (which would be 4 and leave
	// nothing distinguishing the planted 50 from a legitimate future bump).
	if got := queryInt(t, restored, "SELECT credential_epoch FROM auth_instance_state WHERE id = 1"); got != 10000 {
		t.Errorf("post-restore credential epoch = %d, want 10000 (max forged stamp + 1)", got)
	}
	if got := queryInt(t, restored, "SELECT restore_epoch FROM auth_instance_state WHERE id = 1"); got != 10000 {
		t.Errorf("post-restore restore epoch = %d, want 10000", got)
	}
	// The planted session survived as a ROW (restore replays state verbatim)
	// but its stamp no longer matches any epoch the instance will ever serve
	// under; the main drill proves the presentation-level refusal.
	if got := queryInt(t, restored, "SELECT COUNT(*) FROM sessions WHERE credential_epoch = 50"); got != 1 {
		t.Errorf("forged session row count = %d, want 1", got)
	}
	// Every reconciliation stamp is stripped, including the forged 100000 that
	// out-ran the new restore epoch.
	if got := queryInt(t, restored, "SELECT COUNT(*) FROM principals WHERE reconciled_epoch != 0"); got != 0 {
		t.Errorf("%d principals kept a forged reconciliation stamp", got)
	}
	if err := grantsAuthorize(t, restored); err == nil {
		t.Error("a forged pre-reconciled principal authorized after the restore")
	}
}
