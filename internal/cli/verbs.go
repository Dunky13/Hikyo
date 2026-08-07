package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/disclose"
)

// The v1 verb table this slice ships. The full taxonomy is closed by the
// api-cli-surface ADR; what is here is the machinery plus the verbs the first
// slice needs, and each remaining family lands with its own ticket against
// this same dispatcher.
//
// The CLI is a frozen surface from the first stable release: no verb or flag
// is removed or repurposed, `-o json` shapes are additive-only, exit-code
// meanings are stable. Golden snapshots in CI are what make that a check
// rather than a promise.

// IO is the run's streams and environment, injected so every verb is
// testable without touching the process.
type IO struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Env     Env
	Workdir string
	// ReadPassword reads a secret from the controlling terminal with echo
	// off. Injected for tests; nil means the real terminal.
	ReadPassword func(prompt string) (string, error)
	// OpenTerminal backs the print triad's interactive leg.
	OpenTerminal func() (io.WriteCloser, error)
}

// Run dispatches one invocation and returns its exit code.
func Run(ctx context.Context, io IO, args []string) int {
	if len(args) == 0 {
		Usage(io.Stderr)
		return ExitUsage
	}
	verb, rest := args[0], args[1:]
	var err error
	switch verb {
	case "login":
		err = runLogin(ctx, io, rest)
	case "logout":
		err = runLogout(ctx, io, rest)
	case "whoami":
		err = runWhoami(ctx, io, rest)
	case "account":
		err = runAccount(ctx, io, rest)
	case "context":
		err = runContext(ctx, io, rest)
	case "org":
		err = runOrg(ctx, io, rest)
	default:
		fmt.Fprintf(io.Stderr, "wenv: unknown command %q\n\n", verb)
		Usage(io.Stderr)
		return ExitUsage
	}
	return Report(io.Stderr, err)
}

// Usage is the frozen help text. Its exact bytes are a committed golden
// snapshot: help output is part of the CLI's stable surface, and a diff to it
// is reviewed like a spec change.
func Usage(w io.Writer) {
	fmt.Fprint(w, `wenv - environment and secret management

authentication:
  wenv login <instance-url> --local [--as USER]   terminal-native local login
  wenv logout [--instance REF]                    revoke the stored session
  wenv whoami [--instance REF] [-o table|json]    describe the stored session

accounts:
  wenv account establish-credential --instance <url|ref> [--as USER]

contexts:
  wenv context create <name> --instance <url|ref> [--org O] [--project P] [--env E]
  wenv context list [-o table|json]
  wenv context show <name> [-o table|json]
  wenv context delete <name>
  wenv context delete --instance <ref>            forget a trust-store entry

organisations:
  wenv org list [-o table|json]
  wenv org show <org> [-o table|json]
  wenv org create --name <name>

target resolution, per dimension, first hit wins:
  --instance/--org/--project/--env, then WENV_*, then ./.wenv.json, then --context

exit codes:
  0 success   1 internal   2 usage   3 authentication   4 refused
  5 not found (also unauthorized - indistinguishable by design)   6 unavailable
`)
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

func runLogin(ctx context.Context, ios IO, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(ios.Stderr)
	local := fs.Bool("local", false, "terminal-native local login (password prompted, never argv)")
	device := fs.Bool("device", false, "RFC 8628 device-code flow")
	as := fs.String("as", "", "username to log in as")
	name := fs.String("name", "", "local reference to record this instance under (default: its host)")
	trustFile := fs.String("trust-file", "", "provisioned trust bundle (the CI path)")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}

	st, err := NewState(ios.Env)
	if err != nil {
		return err
	}

	// Transport dispatch. The loopback browser handoff is the ADR's primary
	// transport and the device flow its headless fallback; both need the
	// instance's own login page, which arrives with the browser session
	// surface (#54). Refusing by name is the point: a silent fallback to the
	// local floor would skip a ceremony the operator asked for.
	switch {
	case *device:
		return failf(ExitRefused,
			"`login --device` is not served by this build. The device-code flow lands with the browser login surface; "+
				"use `login --local` for the local floor in the meantime")
	case !*local:
		return failf(ExitRefused,
			"browser handoff login is not served by this build. It lands with the browser login surface; "+
				"pass --local to use the terminal-native local floor, which an installation can never remove")
	}

	if len(positional) == 0 {
		return failf(ExitUsage, "usage: wenv login <instance-url> --local --as <username>")
	}
	target := positional[0]

	entry, err := establish(ios, st, target, *name, *trustFile)
	if err != nil {
		return err
	}

	client, err := NewClient(entry, "")
	if err != nil {
		return err
	}
	meta, err := client.Meta(ctx)
	if err != nil {
		return err
	}
	if err := CheckRevision(meta, "localLogin"); err != nil {
		return err
	}
	if !slices.Contains(meta.ProtocolCapabilities, "local-password") {
		return failf(ExitRefused,
			"%s does not serve the local-password flow (it advertises: %s)",
			entry.Origin, strings.Join(meta.ProtocolCapabilities, ", "))
	}

	username := *as
	if username == "" {
		return failf(ExitUsage, "--as <username> is required for --local")
	}
	// No secret ever transits argv, in either direction: the password is
	// prompted from the controlling terminal with echo off, so it is absent
	// from `ps`, /proc/*/cmdline and shell history.
	password, err := ios.readPassword(fmt.Sprintf("Password for %s at %s: ", username, entry.Origin))
	if err != nil {
		return err
	}

	var result apigen.LoginResult
	err = client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/local/login",
		apigen.LocalLoginRequest{Username: username, Password: password}, &result)
	if err != nil {
		return err
	}

	if err := st.PutSession(SessionArtifact{
		Instance:  entry.Name,
		Origin:    entry.Origin,
		Token:     result.SessionToken,
		SessionID: result.Session.Id,
		Principal: result.Principal.Id,
		ExpiresAt: result.Session.AbsoluteExpiresAt.Format("2006-01-02T15:04:05Z"),
	}); err != nil {
		return err
	}

	// The artifact itself never reaches stdout: it is stored, and what the
	// human gets is a receipt.
	fmt.Fprintf(ios.Stderr, "logged in to %s as %s (session %s, idle expiry %s)\n",
		entry.Origin, username, result.Session.Id,
		result.Session.IdleExpiresAt.Format("2006-01-02 15:04 MST"))
	return nil
}

// establish records an instance in the trust store by one of the two
// permitted acts, and only those two.
func establish(ios IO, st *State, target, name, trustFile string) (TrustEntry, error) {
	store := st.Trust()

	// Provisioned establishment: trust arrives through the same protected
	// channel as the credential. No terminal is involved and none is needed —
	// an attacker who cannot read that channel cannot redirect the credential,
	// and one who can already holds it.
	if bundlePath := firstNonEmpty(trustFile, ios.Env.Getenv("WENV_TRUST_BUNDLE")); bundlePath != "" {
		raw, err := os.ReadFile(bundlePath)
		if err != nil {
			return TrustEntry{}, failf(ExitRefused, "reading the trust bundle: %v", err)
		}
		var bundle TrustBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			return TrustEntry{}, failf(ExitRefused, "trust bundle %s is not valid JSON: %v", bundlePath, err)
		}
		origin, err := CanonicalOrigin(bundle.Origin)
		if err != nil {
			return TrustEntry{}, err
		}
		entry := TrustEntry{Name: firstNonEmpty(name, bundle.Name), Origin: origin, SPKIPin: bundle.SPKIPin}
		if entry.Name == "" {
			return TrustEntry{}, failf(ExitRefused, "trust bundle %s names no instance reference", bundlePath)
		}
		if err := store.Put(entry); err != nil {
			return TrustEntry{}, err
		}
		return entry, nil
	}

	// A bare reference (not a URL) must already be established. This is the
	// rule with teeth: a repository file can name a reference, and if it is
	// not in the local store the CLI refuses and names the missing
	// provisioning step. It does not prompt-to-trust mid-command.
	if !strings.Contains(target, "://") {
		return store.Lookup(target)
	}

	origin, err := CanonicalOrigin(target)
	if err != nil {
		return TrustEntry{}, err
	}
	if entry, err := store.Lookup(originReference(origin, name)); err == nil {
		return entry, nil
	}

	// Interactive establishment. It REQUIRES a terminal and refuses non-TTY
	// invocation outright: there is no silent trust-on-first-use, because the
	// whole point is that a human looked at the fingerprint.
	pin, err := FetchIdentity(origin)
	if err != nil {
		return TrustEntry{}, err
	}
	entry := TrustEntry{Name: originReference(origin, name), Origin: origin, SPKIPin: pin}
	prompt := fmt.Sprintf(
		"Establish trust for a new instance?\n\n    origin:      %s\n    certificate: %s\n\nRecord it",
		origin, shortPin(pin))
	ok, err := disclose.Confirm(prompt, disclose.Options{OpenTerminal: ios.OpenTerminal})
	if err != nil {
		return TrustEntry{}, failf(ExitRefused,
			"establishing an instance requires an interactive terminal so a human can confirm the certificate identity. "+
				"For an automated context, provision a trust bundle with --trust-file or WENV_TRUST_BUNDLE")
	}
	if !ok {
		return TrustEntry{}, failf(ExitRefused, "establishment declined")
	}
	if err := store.Put(entry); err != nil {
		return TrustEntry{}, err
	}
	return entry, nil
}

func originReference(origin, name string) string {
	if name != "" {
		return name
	}
	return strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
}

// ---------------------------------------------------------------------------
// logout / whoami
// ---------------------------------------------------------------------------

func runLogout(ctx context.Context, ios IO, args []string) error {
	st, flags, err := parseCommon("logout", ios, args, nil)
	if err != nil {
		return err
	}
	client, artifact, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/logout", nil, nil); err != nil {
		// A session the server has already forgotten is still worth clearing
		// locally: leaving a dead artifact on disk is how "logged out" becomes
		// a lie the next command tells.
		var ce *Error
		if asCLIError(err, &ce) && ce.Code == ExitAuth {
			_ = st.DeleteSession(artifact.Instance)
		}
		return err
	}
	if err := st.DeleteSession(artifact.Instance); err != nil {
		return err
	}
	fmt.Fprintf(ios.Stderr, "logged out of %s\n", artifact.Origin)
	return nil
}

func runWhoami(ctx context.Context, ios IO, args []string) error {
	var format string
	st, flags, err := parseCommon("whoami", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	var who apigen.WhoAmI
	if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/auth/whoami", nil, &who); err != nil {
		return err
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"PRINCIPAL", "KIND", "ARTIFACT", "METHOD", "FACTORS", "IDLE EXPIRY"},
		Rows: [][]string{{
			who.Principal.Id, string(who.Principal.Kind), who.Session.Artifact,
			who.Session.Assurance.Method, strings.Join(who.Session.Assurance.Factors, ","),
			who.Session.IdleExpiresAt.Format("2006-01-02 15:04 MST"),
		}},
		JSON: who,
	})
}

// ---------------------------------------------------------------------------
// account
// ---------------------------------------------------------------------------

// runAccount consumes a credential-establishment authority.
//
// Spelling note: the account verb family is fixed by the api-cli-surface ADR
// (`session`, `factor`, `recovery-codes`); `establish-credential` is the
// spelling this slice adds to it, because the bootstrap path needs a terminal
// way to consume the authority `admin create` mints and the browser path that
// would otherwise carry it is #54's. It joins the EXISTING family under the
// existing grammar - no new verb family, no new output class - and #54
// confirms or renames it before the freeze.
func runAccount(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 || args[0] != "establish-credential" {
		return failf(ExitUsage, "usage: wenv account establish-credential --instance <url|ref> [--as USER]")
	}
	var (
		as        string
		trustFile string
	)
	st, flags, err := parseCommon("account establish-credential", ios, args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&as, "as", "", "the username the authority was minted for (display only)")
		fs.StringVar(&trustFile, "trust-file", "", "provisioned trust bundle")
	})
	if err != nil {
		return err
	}
	target := flags.Instance
	if target == "" {
		target = ios.Env.Getenv("WENV_INSTANCE")
	}
	if target == "" {
		return failf(ExitUsage, "--instance <url|ref> is required")
	}
	entry, err := establish(ios, st, target, "", trustFile)
	if err != nil {
		return err
	}
	client, err := NewClient(entry, "")
	if err != nil {
		return err
	}
	meta, err := client.Meta(ctx)
	if err != nil {
		return err
	}
	if err := CheckRevision(meta, "establishCredential"); err != nil {
		return err
	}

	// Both secrets are prompted from the controlling terminal: the authority
	// is display-once material and the password is a credential, and neither
	// may transit argv, an environment variable, or a pipe a repository script
	// could feed.
	authority, err := ios.readPassword(fmt.Sprintf("Credential-establishment authority for %s: ", entry.Origin))
	if err != nil {
		return err
	}
	password, err := ios.readPassword("New password (minimum 12 characters): ")
	if err != nil {
		return err
	}
	confirm, err := ios.readPassword("Repeat the password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return failf(ExitRefused, "the two passwords do not match")
	}

	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/credential/establish",
		apigen.EstablishCredentialRequest{Authority: authority, Password: password}, nil); err != nil {
		return err
	}
	// No session, no assurance, no window - by design. Say so, because a user
	// who expects to be logged in now would otherwise read the silence as a
	// failure.
	fmt.Fprintf(ios.Stderr,
		"credential established at %s. It creates no session: log in with\n    wenv login %s --local --as %s\n",
		entry.Origin, entry.Origin, firstNonEmpty(as, "<username>"))
	return nil
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

func runContext(_ context.Context, ios IO, args []string) error {
	if len(args) == 0 {
		return failf(ExitUsage, "usage: wenv context create|list|show|delete")
	}
	st, err := NewState(ios.Env)
	if err != nil {
		return err
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "create":
		fs := flag.NewFlagSet("context create", flag.ContinueOnError)
		fs.SetOutput(ios.Stderr)
		instance := fs.String("instance", "", "instance URL (establishes trust) or an established reference")
		org := fs.String("org", "", "organisation")
		project := fs.String("project", "", "project")
		environment := fs.String("env", "", "environment")
		trustFile := fs.String("trust-file", "", "provisioned trust bundle")
		positional, err := parseInterspersed(fs, rest)
		if err != nil {
			return err
		}
		name := first(positional)
		if name == "" || *instance == "" {
			return failf(ExitUsage, "usage: wenv context create <name> --instance <url|ref>")
		}
		entry, err := establish(ios, st, *instance, "", *trustFile)
		if err != nil {
			return err
		}
		return st.PutContext(Context{
			Name: name, Instance: entry.Name, Org: *org, Project: *project, Env: *environment,
		})

	case "list":
		fs := flag.NewFlagSet("context list", flag.ContinueOnError)
		fs.SetOutput(ios.Stderr)
		format := fs.String("o", "table", "output format")
		if _, err := parseInterspersed(fs, rest); err != nil {
			return err
		}
		f, err := ParseFormat(*format)
		if err != nil {
			return err
		}
		all, err := st.Contexts()
		if err != nil {
			return err
		}
		names := sortedKeys(all)
		rows := make([][]string, 0, len(names))
		list := make([]Context, 0, len(names))
		for _, n := range names {
			c := all[n]
			rows = append(rows, []string{c.Name, c.Instance, c.Org, c.Project, c.Env})
			list = append(list, c)
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"NAME", "INSTANCE", "ORG", "PROJECT", "ENV"},
			Rows:    rows,
			JSON:    map[string]any{"items": list, "count": len(list)},
		})

	case "show":
		fs := flag.NewFlagSet("context show", flag.ContinueOnError)
		fs.SetOutput(ios.Stderr)
		format := fs.String("o", "table", "output format")
		positional, err := parseInterspersed(fs, rest)
		if err != nil {
			return err
		}
		f, err := ParseFormat(*format)
		if err != nil {
			return err
		}
		name := first(positional)
		if name == "" {
			return failf(ExitUsage, "usage: wenv context show <name>")
		}
		all, err := st.Contexts()
		if err != nil {
			return err
		}
		c, ok := all[name]
		if !ok {
			return failf(ExitNotFound, "no context named %q", name)
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"NAME", "INSTANCE", "ORG", "PROJECT", "ENV"},
			Rows:    [][]string{{c.Name, c.Instance, c.Org, c.Project, c.Env}},
			JSON:    c,
		})

	case "delete":
		fs := flag.NewFlagSet("context delete", flag.ContinueOnError)
		fs.SetOutput(ios.Stderr)
		instance := fs.String("instance", "", "forget a trust-store entry instead of a context")
		positional, err := parseInterspersed(fs, rest)
		if err != nil {
			return err
		}
		if *instance != "" {
			return st.Trust().Delete(*instance)
		}
		name := first(positional)
		if name == "" {
			return failf(ExitUsage, "usage: wenv context delete <name> | --instance <ref>")
		}
		return st.DeleteContext(name)

	default:
		return failf(ExitUsage, "unknown context verb %q: use create, list, show or delete", sub)
	}
}

// ---------------------------------------------------------------------------
// org
// ---------------------------------------------------------------------------

func runOrg(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 {
		return failf(ExitUsage, "usage: wenv org list|show|create")
	}
	sub, rest := args[0], args[1:]

	var (
		format  string
		orgName string
	)
	st, flags, err := parseCommon("org "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" {
			fs.StringVar(&orgName, "name", "", "organisation name")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		var list apigen.OrgList
		if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/orgs", nil, &list); err != nil {
			return err
		}
		rows := make([][]string, 0, len(list.Items))
		for _, o := range list.Items {
			rows = append(rows, []string{o.Id, o.Name, boolString(o.Active), o.CreatedAt.Format("2006-01-02")})
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ID", "NAME", "ACTIVE", "CREATED"},
			Rows:    rows,
			JSON:    list,
		})

	case "show":
		id := flags.positional
		if id == "" {
			return failf(ExitUsage, "usage: wenv org show <org>")
		}
		var org apigen.Org
		if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/orgs/"+id, nil, &org); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ID", "NAME", "ACTIVE", "CREATED"},
			Rows:    [][]string{{org.Id, org.Name, boolString(org.Active), org.CreatedAt.Format("2006-01-02")}},
			JSON:    org,
		})

	case "create":
		if orgName == "" {
			return failf(ExitUsage, "usage: wenv org create --name <name>")
		}
		var org apigen.Org
		if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/orgs",
			apigen.CreateOrgRequest{Name: orgName}, &org); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ID", "NAME", "ACTIVE", "CREATED"},
			Rows:    [][]string{{org.Id, org.Name, boolString(org.Active), org.CreatedAt.Format("2006-01-02")}},
			JSON:    org,
		})

	default:
		return failf(ExitUsage, "unknown org verb %q: use list, show or create", sub)
	}
}

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

type commonFlags struct {
	Flags
	positional string
}

// parseCommon parses the per-dimension flags every server-mediated verb takes.
func parseCommon(name string, ios IO, args []string, extra func(*flag.FlagSet)) (*State, commonFlags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(ios.Stderr)
	var c commonFlags
	fs.StringVar(&c.Context, "context", "", "named context to select for this invocation")
	fs.StringVar(&c.Instance, "instance", "", "instance reference")
	fs.StringVar(&c.Org, "org", "", "organisation")
	fs.StringVar(&c.Project, "project", "", "project")
	fs.StringVar(&c.Env, "env", "", "environment")
	if extra != nil {
		extra(fs)
	}
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, commonFlags{}, err
	}
	c.positional = first(positional)
	st, err := NewState(ios.Env)
	if err != nil {
		return nil, commonFlags{}, err
	}
	return st, c, nil
}

// authenticatedClient resolves the instance and its stored artifact.
//
// The artifact is presented only to the origin it was established against —
// the record carries that origin, and a mismatch is a hard refusal rather
// than a best-effort send.
func authenticatedClient(st *State, ios IO, flags commonFlags) (*Client, SessionArtifact, error) {
	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return nil, SessionArtifact{}, err
	}
	instance, err := resolved.Require(DimInstance)
	if err != nil {
		// Exactly one established instance is not an ambiguity, so falling
		// back to it is not a silent assumption — it is the only reading. Two
		// or more IS an ambiguity, and ambiguity is a hard error naming what
		// was missing, never a default.
		//
		// The fallback is the TRUST STORE rather than the session file, so
		// that after a logout the answer is "you are not logged in" (exit 3)
		// rather than "no instance" (exit 2). The distinction matters to a
		// script deciding whether to re-authenticate.
		entries, serr := st.Trust().Load()
		if serr != nil {
			return nil, SessionArtifact{}, serr
		}
		if len(entries) != 1 {
			return nil, SessionArtifact{}, err
		}
		for k := range entries {
			instance = k
		}
	}
	entry, err := st.Trust().Lookup(instance)
	if err != nil {
		return nil, SessionArtifact{}, err
	}
	sessions, err := st.Sessions()
	if err != nil {
		return nil, SessionArtifact{}, err
	}
	artifact, ok := sessions[instance]
	if !ok {
		return nil, SessionArtifact{}, failf(ExitAuth,
			"no session for instance %q: run `wenv login <url> --local --as <user>`", instance)
	}
	if artifact.Origin != entry.Origin {
		return nil, SessionArtifact{}, failf(ExitRefused,
			"the stored session for %q was established against %s, but the trust store now records %s; log in again",
			instance, artifact.Origin, entry.Origin)
	}
	client, err := NewClient(entry, artifact.Token)
	if err != nil {
		return nil, SessionArtifact{}, err
	}
	// The disclosure echo: the fully resolved target, to stderr, before
	// acting — including which precedence level supplied each dimension.
	if echo := resolved.Echo(); echo != "" {
		fmt.Fprintf(ios.Stderr, "target: %s [origin %s, artifact human-session %s]\n",
			echo, entry.Origin, artifact.Principal)
	}
	return client, artifact, nil
}

func (ios IO) readPassword(prompt string) (string, error) {
	if ios.ReadPassword != nil {
		return ios.ReadPassword(prompt)
	}
	return readTerminalPassword(prompt)
}

func first(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func boolString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// sortedKeys gives list output a stable order, which is what makes the
// golden fixtures meaningful: map iteration order would make the same state
// render differently on every run.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
