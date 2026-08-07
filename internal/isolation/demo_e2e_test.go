package isolation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/wenv/internal/cli"
	"github.com/Dunky13/wenv/internal/server"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
)

// The #47 demo criterion, end to end on both engines:
//
//	fresh install -> bootstrap admin -> CLI login -> authenticated audited
//	API call
//
// Real datastore, real keyring, real Argon2id at the production floor, real
// HTTP server, real CLI over a socket. The only substitution is the terminal:
// the password prompt and the establishment ceremony are injected, because a
// test process has no controlling terminal — which is itself the behaviour
// the non-TTY refusals assert elsewhere.

func TestDemoFlowSQLite(t *testing.T) { runDemoFlow(t, seededDB(t, openSQLite)) }

func TestDemoFlowPostgres(t *testing.T) { runDemoFlow(t, seededDB(t, openPostgres)) }

func runDemoFlow(t *testing.T, db *store.DB) {
	auth := authService(t, db)
	orgs := &service.Orgs{DB: db}

	httpSrv := httptest.NewServer(server.New(&service.System{DB: db}, &server.API{
		Auth: auth, Orgs: orgs, Version: "e2e",
	}))
	t.Cleanup(httpSrv.Close)

	// Fresh install: the first administrator is minted on the host, never
	// over the network. The authority it returns creates no session.
	boot, err := auth.BootstrapAdmin(t.Context(), "demo-admin", "Demo Admin", "terminal")
	if err != nil {
		t.Fatal(err)
	}

	const password = "a perfectly ordinary passphrase"
	stateDir := t.TempDir()
	workDir := t.TempDir()

	// The CLI's view of the world: a loopback http origin (no certificate, so
	// no pin — and the client refuses plaintext http to anything but
	// loopback), established through the interactive ceremony with the
	// terminal injected.
	prompts := map[string]string{}
	ios := func() cli.IO {
		var confirmed fakeTerminal
		return cli.IO{
			Stdout:  io.Discard,
			Stderr:  io.Discard,
			Workdir: workDir,
			Env: cli.Env{Getenv: func(k string) string {
				if k == "WENV_STATE_DIR" {
					return stateDir
				}
				return ""
			}},
			ReadPassword: func(prompt string) (string, error) {
				for match, answer := range prompts {
					if strings.Contains(prompt, match) {
						return answer, nil
					}
				}
				t.Fatalf("unexpected prompt: %q", prompt)
				return "", nil
			},
			OpenTerminal: func() (io.WriteCloser, error) { return &confirmed, nil },
		}
	}

	// Establish the credential with the one-time authority. It creates no
	// session: the next step is a real login.
	prompts["authority"] = boot.Authority
	prompts["New password"] = password
	prompts["Repeat"] = password
	if code := cli.Run(t.Context(), ios(), []string{
		"account", "establish-credential", "--instance", httpSrv.URL, "--as", "demo-admin",
	}); code != cli.ExitOK {
		t.Fatalf("establish-credential exited %d", code)
	}

	// CLI login over the local floor.
	delete(prompts, "authority")
	delete(prompts, "New password")
	delete(prompts, "Repeat")
	prompts["Password for demo-admin"] = password
	if code := cli.Run(t.Context(), ios(), []string{
		"login", httpSrv.URL, "--local", "--as", "demo-admin",
	}); code != cli.ExitOK {
		t.Fatalf("login exited %d", code)
	}

	// The session artifact is on disk, 0600, and holds the origin it was
	// established against.
	sessionFile := filepath.Join(stateDir, "sessions.json")
	info, err := os.Stat(sessionFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("session artifact mode %04o, want 0600", perm)
	}

	// whoami resolves the session through the chokepoint.
	stdout := &strings.Builder{}
	who := ios()
	who.Stdout = stdout
	if code := cli.Run(t.Context(), who, []string{"whoami", "-o", "json"}); code != cli.ExitOK {
		t.Fatalf("whoami exited %d", code)
	}
	var whoami struct {
		Principal struct{ Id, Kind string }
		Session   struct {
			Artifact  string
			Assurance struct {
				Method  string
				Factors []string
			}
		}
	}
	if err := json.Unmarshal([]byte(stdout.String()), &whoami); err != nil {
		t.Fatalf("whoami output: %v\n%s", err, stdout.String())
	}
	if whoami.Principal.Id != string(boot.PrincipalID) {
		t.Errorf("whoami reports %q, want %q", whoami.Principal.Id, boot.PrincipalID)
	}
	if whoami.Session.Artifact != "cli" {
		t.Errorf("artifact %q, want cli", whoami.Session.Artifact)
	}
	if whoami.Session.Assurance.Method != "local-password" ||
		len(whoami.Session.Assurance.Factors) != 1 || whoami.Session.Assurance.Factors[0] != "password" {
		t.Errorf("assurance %+v: the record must say truthfully what was presented", whoami.Session.Assurance)
	}

	// The authenticated, audited API call — the demo's last step. It goes
	// through authorize() against the admin template's real grant rows and
	// commits its audit event in the same transaction.
	before := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'settings.org_created'")
	create := ios()
	create.Stdout = &strings.Builder{}
	if code := cli.Run(t.Context(), create, []string{"org", "create", "--name", "demo-org"}); code != cli.ExitOK {
		t.Fatalf("org create exited %d", code)
	}
	after := queryInt(t, db, "SELECT COUNT(*) FROM audit_instance_events WHERE type = 'settings.org_created'")
	if after != before+1 {
		t.Fatalf("org.created audit events: %d -> %d, want exactly one more", before, after)
	}

	// Logging out revokes the artifact; the next call is refused with the
	// authentication exit code, not a stale success.
	if code := cli.Run(t.Context(), ios(), []string{"logout"}); code != cli.ExitOK {
		t.Fatalf("logout exited %d", code)
	}
	if code := cli.Run(t.Context(), ios(), []string{"org", "list", "-o", "json"}); code != cli.ExitAuth {
		t.Fatalf("a revoked session still worked (exit %d)", code)
	}
}

// fakeTerminal stands in for /dev/tty. Confirm reads a line from it, so an
// establishment ceremony in this harness answers "y" — the human's decision,
// pre-made, because a test process has no terminal to make it at.
type fakeTerminal struct {
	written strings.Builder
	read    bool
}

func (f *fakeTerminal) Write(p []byte) (int, error) { return f.written.Write(p) }

func (f *fakeTerminal) Read(p []byte) (int, error) {
	if f.read {
		return 0, io.EOF
	}
	f.read = true
	n := copy(p, "y\n")
	return n, nil
}

func (f *fakeTerminal) Close() error { return nil }

// A login must not hold the write lock while it derives.
//
// At the locked Argon2id floor a derivation costs 64 MiB and hundreds of
// milliseconds, and sqlite has a single write connection. If verification ran
// inside a write transaction, a handful of concurrent logins — four fit in
// the admission budget — would stall every other write on the instance for as
// long as they took. That is a denial of service reachable by anyone who can
// reach the login endpoint.
//
// The check is structural rather than a stopwatch: an unrelated write must
// complete while several failing logins are in flight. A timing assertion
// would be flaky on a loaded machine; this one fails only if the writes are
// actually serialised behind the derivations.
func TestLoginDoesNotHoldTheWriteLockWhileDeriving(t *testing.T) {
	db := seededDB(t, openSQLite)
	auth := authService(t, db)
	orgs := &service.Orgs{DB: db}

	boot, err := auth.BootstrapAdmin(t.Context(), "lockcheck", "Lock Check", "terminal")
	if err != nil {
		t.Fatal(err)
	}
	const password = "another perfectly ordinary passphrase"
	if err := auth.EstablishCredential(t.Context(), boot.Authority, password); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Wrong password: burns a full derivation every time.
				_, _ = auth.LocalLogin(t.Context(), "lockcheck", "not the password at all")
			}
		}()
	}
	t.Cleanup(func() { close(stop); wg.Wait() })

	// An unrelated write, while those are in flight. The transaction package
	// allows an initial try plus three retries inside a 15s deadline, so if
	// the writes were queued behind derivations this would exhaust them.
	deadline := time.Now().Add(20 * time.Second)
	for i := range 5 {
		if time.Now().After(deadline) {
			t.Fatal("unrelated writes could not make progress while logins were deriving")
		}
		if _, err := orgs.Create(t.Context(), boot.PrincipalID, fmt.Sprintf("lockcheck-%d", i), true, []byte(`{}`)); err != nil {
			t.Fatalf("write %d blocked behind a login derivation: %v", i, err)
		}
	}
}
