package isolation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Dunky13/hikyo/internal/cli"
	"github.com/Dunky13/hikyo/internal/server"
	"github.com/Dunky13/hikyo/internal/service"
	"github.com/Dunky13/hikyo/internal/store"
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

	// A controllable server clock: after the assurance flip, `org create`
	// (instance-config, MFA-mandatory) needs a stepped-up session, and TOTP
	// confirm and step-up must present codes from later time steps than
	// enrolment consumed. The clock is mutex-guarded because the post-response
	// idle-clock slide reads it from a detached goroutine.
	base := time.Now().UTC()
	var clockMu sync.Mutex
	clk := base
	auth.Now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clk
	}
	advanceClock := func(d time.Duration) {
		clockMu.Lock()
		clk = clk.Add(d)
		clockMu.Unlock()
	}

	// requests records every request the CLI actually makes. It is what turns
	// "the command refused" into "the command refused BEFORE reaching the
	// server": exit 4 alone cannot tell a client-side confirmation refusal from a
	// server-side conflict, and both are exit 4 on this surface.
	var wireMu sync.Mutex
	var requests []string
	recorded := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wireMu.Lock()
			requests = append(requests, r.Method+" "+r.URL.Path)
			wireMu.Unlock()
			next.ServeHTTP(w, r)
		})
	}
	takeRequests := func() []string {
		wireMu.Lock()
		defer wireMu.Unlock()
		out := requests
		requests = nil
		return out
	}

	httpSrv := httptest.NewServer(recorded(server.New(&service.System{DB: db}, &server.API{
		Auth: auth, Orgs: orgs,
		Projects:     &service.Projects{DB: db},
		Environments: &service.Environments{DB: db},
		Folders:      &service.Folders{DB: db},
		Version:      "e2e",
	})))
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
				if k == "HIKYO_STATE_DIR" {
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

	// After the assurance flip a password-only session is refused instance-config:
	// `org create` needs a stepped-up session. The admin enrols TOTP, confirms,
	// and steps up before it can administer — the in-product path out of the
	// bootstrap's single-factor state.
	//
	// The password-only session is refused the MFA-mandatory operation.
	if code := cli.Run(t.Context(), ios(), []string{"org", "create", "--name", "premature"}); code != cli.ExitRefused {
		t.Fatalf("a password-only session created an org (exit %d); the assurance gate is not enforcing", code)
	}

	// Enrol TOTP: the URI (carrying the seed) is delivered through the print
	// triad's file leg, and the test plays the authenticator app.
	totpFile := filepath.Join(workDir, "totp.uri")
	prompts["to authorize enrolment"] = password
	if code := cli.Run(t.Context(), ios(), []string{
		"account", "factor", "enrol-totp", "--output-file", totpFile,
	}); code != cli.ExitOK {
		t.Fatalf("factor enrol-totp exited %d", code)
	}
	uriBytes, err := os.ReadFile(totpFile)
	if err != nil {
		t.Fatal(err)
	}
	otpauthURI := strings.TrimSpace(string(uriBytes))

	// Confirm with a code from a later step than enrolment consumed.
	advanceClock(30 * time.Second)
	prompts["to confirm"] = totpCode(t, otpauthURI, base.Add(30*time.Second))
	if code := cli.Run(t.Context(), ios(), []string{"account", "factor", "confirm-totp"}); code != cli.ExitOK {
		t.Fatalf("factor confirm-totp exited %d", code)
	}

	// Step up to present the factor; the token rotates and the CLI persists it.
	advanceClock(30 * time.Second)
	prompts["authenticator:"] = totpCode(t, otpauthURI, base.Add(60*time.Second))
	if code := cli.Run(t.Context(), ios(), []string{"account", "factor", "step-up"}); code != cli.ExitOK {
		t.Fatalf("factor step-up exited %d", code)
	}

	// whoami now reports two factor classes: the step-up is recorded truthfully.
	stepUp := &strings.Builder{}
	whoUp := ios()
	whoUp.Stdout = stepUp
	if code := cli.Run(t.Context(), whoUp, []string{"whoami", "-o", "json"}); code != cli.ExitOK {
		t.Fatalf("whoami (post step-up) exited %d", code)
	}
	var elevated struct {
		Session struct {
			Assurance struct{ Factors []string }
		}
	}
	if err := json.Unmarshal([]byte(stepUp.String()), &elevated); err != nil {
		t.Fatalf("whoami output: %v\n%s", err, stepUp.String())
	}
	if got := elevated.Session.Assurance.Factors; len(got) != 2 ||
		!(got[0] == "password" && got[1] == "totp") {
		t.Errorf("post-step-up assurance factors %v, want [password totp]", got)
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

	// The hierarchy demo (#48), through the real CLI over the socket:
	// create org -> project -> environments -> folders, then list and rename
	// them. This is the acceptance criterion's demo, executed rather than
	// described.
	runHierarchyDemo(t, db, ios, takeRequests)

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
		if _, err := orgs.Create(t.Context(), service.LocalPrincipal(boot.PrincipalID), fmt.Sprintf("lockcheck-%d", i), true, []byte(`{}`)); err != nil {
			t.Fatalf("write %d blocked behind a login derivation: %v", i, err)
		}
	}
}

// runHierarchyDemo is #48's acceptance demo, driven through the real CLI
// against the real server: create org → project → envs → folders, list and
// rename them. It asserts on the CLI's own `-o json` output, because that is
// the surface the criterion names and the one scripts consume.
func runHierarchyDemo(t *testing.T, db *store.DB, ios func() cli.IO, takeRequests func() []string) {
	t.Helper()

	run := func(args ...string) string {
		t.Helper()
		out := &strings.Builder{}
		io := ios()
		io.Stdout = out
		if code := cli.Run(t.Context(), io, args); code != cli.ExitOK {
			t.Fatalf("hikyo %s exited %d\n%s", strings.Join(args, " "), code, out.String())
		}
		return out.String()
	}
	decode := func(raw string, into any) {
		t.Helper()
		if err := json.Unmarshal([]byte(raw), into); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, raw)
		}
	}
	type row struct {
		Id           string
		Name         string
		Path         string
		DisplayOrder int `json:"display_order"`
	}
	type list struct {
		Items []row
		Count int
	}

	var org row
	decode(run("org", "create", "--name", "hierarchy-demo", "-o", "json"), &org)

	var project row
	decode(run("project", "create", "--org", org.Id, "--name", "checkout", "-o", "json"), &project)

	// Environments, created in order, appended to the display order.
	var envs []row
	for _, name := range []string{"dev", "staging", "prod"} {
		var env row
		decode(run("env", "create", "--org", org.Id, "--project", project.Id, "--name", name, "-o", "json"), &env)
		envs = append(envs, env)
	}
	var envList list
	decode(run("env", "list", "--org", org.Id, "--project", project.Id, "-o", "json"), &envList)
	// BOTH the count and the items: a body with `count: 3, items: []` would
	// otherwise satisfy the count check and skip every assertion in the loop.
	if envList.Count != 3 || len(envList.Items) != 3 {
		t.Fatalf("env list count = %d, items = %d, want 3 and 3", envList.Count, len(envList.Items))
	}
	for i, e := range envList.Items {
		if e.DisplayOrder != i {
			t.Fatalf("env %q display_order = %d, want %d", e.Name, e.DisplayOrder, i)
		}
	}

	// Reorder the whole set through the CLI, then read it back.
	reordered := run("env", "reorder", "--org", org.Id, "--project", project.Id,
		strings.Join([]string{envs[2].Id, envs[0].Id, envs[1].Id}, ","), "-o", "json")
	decode(reordered, &envList)
	if len(envList.Items) != 3 {
		t.Fatalf("reorder returned %d items, want 3", len(envList.Items))
	}
	if envList.Items[0].Id != envs[2].Id || envList.Items[0].DisplayOrder != 0 {
		t.Fatalf("reorder did not take: %+v", envList.Items)
	}

	// Folders.
	var folder row
	decode(run("folder", "create", "--org", org.Id, "--project", project.Id, "--path", "services/api", "-o", "json"), &folder)
	var folderList list
	decode(run("folder", "list", "--org", org.Id, "--project", project.Id, "-o", "json"), &folderList)
	if folderList.Count != 1 || folderList.Items[0].Path != "services/api" {
		t.Fatalf("folder list = %+v", folderList)
	}

	// Rename at every level, and read each one back.
	decode(run("org", "rename", org.Id, "--name", "hierarchy-demo-renamed", "-o", "json"), &org)
	if org.Name != "hierarchy-demo-renamed" {
		t.Fatalf("org rename returned %q", org.Name)
	}
	decode(run("project", "rename", "--org", org.Id, project.Id, "--name", "checkout-v2", "-o", "json"), &project)
	if project.Name != "checkout-v2" {
		t.Fatalf("project rename returned %q", project.Name)
	}
	var env row
	decode(run("env", "rename", "--org", org.Id, "--project", project.Id, envs[0].Id, "--name", "development", "-o", "json"), &env)
	if env.Name != "development" {
		t.Fatalf("env rename returned %q", env.Name)
	}
	decode(run("folder", "rename", "--org", org.Id, "--project", project.Id, folder.Id, "--path", "services/gateway", "-o", "json"), &folder)
	if folder.Path != "services/gateway" {
		t.Fatalf("folder rename returned %q", folder.Path)
	}

	var shown row
	decode(run("org", "show", org.Id, "-o", "json"), &shown)
	if shown.Name != "hierarchy-demo-renamed" {
		t.Fatalf("org show after rename = %q", shown.Name)
	}
	decode(run("project", "show", "--org", org.Id, project.Id, "-o", "json"), &shown)
	if shown.Name != "checkout-v2" {
		t.Fatalf("project show after rename = %q", shown.Name)
	}

	// Every rename left a durable trail entry with both names.
	for _, typ := range []string{
		"settings.org_renamed", "settings.project_renamed",
		"settings.environment_renamed", "settings.folder_renamed",
		"settings.environment_reordered",
	} {
		if n := queryInt(t, db, "SELECT COUNT(*) FROM audit_tenant_events WHERE type = '"+typ+"'"); n == 0 {
			t.Errorf("%s left no audit record", typ)
		}
	}

	// Reads at every level, through the CLI, so a wrong path or method in any
	// of these handlers cannot stay green.
	var orgList, projectList list
	decode(run("org", "list", "-o", "json"), &orgList)
	if orgList.Count == 0 {
		t.Fatal("org list returned nothing")
	}
	decode(run("project", "list", "--org", org.Id, "-o", "json"), &projectList)
	if projectList.Count != 1 || projectList.Items[0].Id != project.Id {
		t.Fatalf("project list = %+v", projectList)
	}
	var shownEnv, shownFolder row
	decode(run("env", "show", "--org", org.Id, "--project", project.Id, envs[0].Id, "-o", "json"), &shownEnv)
	if shownEnv.Id != envs[0].Id || shownEnv.Name != "development" {
		t.Fatalf("env show = %+v", shownEnv)
	}
	decode(run("folder", "show", "--org", org.Id, "--project", project.Id, folder.Id, "-o", "json"), &shownFolder)
	if shownFolder.Path != "services/gateway" {
		t.Fatalf("folder show = %+v", shownFolder)
	}

	// Project deletion carries the permission model's locked confirmation naming
	// the project. Exit 4 alone proves nothing here — a non-empty-parent conflict
	// is also exit 4 — so each case asserts WHICH REQUESTS it made. Remove the
	// confirmation guard and the first two cases fail on the request log, not on
	// the exit code.
	takeRequests()
	absent := ios()
	absent.Stdout = &strings.Builder{}
	if code := cli.Run(t.Context(), absent, []string{"project", "delete", "--org", org.Id, project.Id}); code != cli.ExitRefused {
		t.Fatalf("delete without --confirm exited %d, want %d", code, cli.ExitRefused)
	}
	if got := takeRequests(); len(got) != 0 {
		t.Fatalf("delete without --confirm reached the server: %v", got)
	}

	stale := ios()
	stale.Stdout = &strings.Builder{}
	if code := cli.Run(t.Context(), stale, []string{
		"project", "delete", "--org", org.Id, project.Id, "--confirm", "checkout", // the pre-rename name
	}); code != cli.ExitRefused {
		t.Fatalf("delete with a stale --confirm exited %d, want %d", code, cli.ExitRefused)
	}
	got := takeRequests()
	if len(got) != 1 || !strings.HasPrefix(got[0], "GET ") {
		t.Fatalf("delete with a stale --confirm made %v, want exactly one GET (the name it compares against)", got)
	}

	// The correct name reaches the server — where deletes never cascade, so a
	// project still holding environments and a folder is refused THERE.
	blocked := ios()
	blocked.Stdout = &strings.Builder{}
	if code := cli.Run(t.Context(), blocked, []string{
		"project", "delete", "--org", org.Id, project.Id, "--confirm", project.Name,
	}); code == cli.ExitOK {
		t.Fatal("deleting a project that still holds environments succeeded")
	}
	if got := takeRequests(); len(got) != 2 || !strings.HasPrefix(got[0], "GET ") || !strings.HasPrefix(got[1], "DELETE ") {
		t.Fatalf("delete with the right name made %v, want GET then DELETE", got)
	}

	// Empty it through the CLI — successful deletes at every level, which nothing
	// else in this suite exercises end to end — then the project delete succeeds.
	for _, e := range envList.Items {
		if code := cli.Run(t.Context(), delIO(ios), []string{
			"env", "delete", "--org", org.Id, "--project", project.Id, e.Id,
		}); code != cli.ExitOK {
			t.Fatalf("env delete %s exited %d", e.Id, code)
		}
	}
	if code := cli.Run(t.Context(), delIO(ios), []string{
		"folder", "delete", "--org", org.Id, "--project", project.Id, folder.Id,
	}); code != cli.ExitOK {
		t.Fatal("folder delete failed")
	}
	takeRequests()
	if code := cli.Run(t.Context(), delIO(ios), []string{
		"project", "delete", "--org", org.Id, project.Id, "--confirm", project.Name,
	}); code != cli.ExitOK {
		t.Fatal("deleting the now-empty project failed")
	}
	if got := takeRequests(); len(got) != 2 || !strings.HasPrefix(got[0], "GET ") || !strings.HasPrefix(got[1], "DELETE ") {
		t.Fatalf("the successful delete made %v, want GET then DELETE", got)
	}
	var afterDelete list
	decode(run("project", "list", "--org", org.Id, "-o", "json"), &afterDelete)
	if afterDelete.Count != 0 {
		t.Fatalf("the project survived its own delete: %+v", afterDelete)
	}
}

// delIO is a throwaway IO whose stdout is discarded — the delete verbs report on
// stderr and return no document.
func delIO(ios func() cli.IO) cli.IO {
	io := ios()
	io.Stdout = &strings.Builder{}
	return io
}
