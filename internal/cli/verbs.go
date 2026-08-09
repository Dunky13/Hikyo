package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
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
	case "project":
		err = runProject(ctx, io, rest)
	case "env":
		err = runEnv(ctx, io, rest)
	case "folder":
		err = runFolder(ctx, io, rest)
	case "instance-config":
		err = runInstanceConfig(ctx, io, rest)
	case "doctor":
		err = runDoctor(ctx, io, rest)
	case "access":
		err = runAccess(ctx, io, rest)
	case "project-settings":
		err = runProjectSettings(ctx, io, rest)
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
  wenv account factor enrol-totp [--output-file PATH | --dangerously-print]
  wenv account factor confirm-totp
  wenv account factor step-up
  wenv account passkey enrol|list|remove          browser-only; refused on the terminal
  wenv account recovery-codes regenerate [--output-file PATH | --dangerously-print]
  wenv account recovery begin --instance <url|ref> --as USER [--output-file PATH]
  wenv account reset-credential <principal> [--output-file PATH | --dangerously-print]

contexts:
  wenv context create <name> --instance <url|ref> [--org O] [--project P] [--env E]
  wenv context list [-o table|json]
  wenv context show <name> [-o table|json]
  wenv context delete <name>
  wenv context delete --instance <ref>            forget a trust-store entry

diagnostics:
  wenv doctor [--instance REF] [-o table|json]     report server-authoritative provider health

hierarchy:
  wenv org list [-o table|json]
  wenv org show <org> [-o table|json]
  wenv org create --name <name>
  wenv org rename <org> --name <new-name>
  wenv org delete <org>
  wenv project list|show|create|rename|delete      --org selects the organisation
  wenv project create --name <name>
  wenv project rename <project> --name <new-name>
  wenv project delete <project> --confirm <project-name>   irreversible: shreds the key
  wenv env list|show|create|rename|reorder|delete   --org/--project select the project
  wenv env create --name <name>
  wenv env rename <env> --name <new-name>
  wenv env reorder <env-id,env-id,...>             the whole ordered set, once each
  wenv folder list|show|create|rename|delete       --org/--project select the project
  wenv folder create --path <path>
  wenv folder rename <folder> --path <new-path>

instance configuration:
  wenv instance-config provider create --kind saml --name <name> --entity-id <entityID> \
      (--metadata-file <xml> | --metadata-url <url>)
  wenv instance-config provider list|show|update|disable|remove
  wenv instance-config provider refresh-metadata <name>
  wenv instance-config saml-sp-key list|rotate
  wenv instance-config saml-sp-key retire|compromise-retire <fingerprint>

access:
  wenv access grant list [--org O] [--project P] [--instance-scope] [-o table|json]
  wenv access grant add --principal <id> --capability <atom>
  wenv access grant remove --principal <id> --capability <atom>
  wenv access grant template --principal <id> --template <name>
  wenv access member list [--org O] [--project P] [-o table|json]
  wenv access member remove --principal <id>
  wenv project-settings get --env E [-o table|json]
  wenv project-settings set --env E [--protected true|false] [--reauth-window-seconds N|inherit]

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

	token, err := cliSessionToken(result.SessionToken)
	if err != nil {
		return err
	}
	if err := st.PutSession(SessionArtifact{
		Instance:  entry.Name,
		Origin:    entry.Origin,
		Token:     token,
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
		// If the caller named an explicit URL, the bundle must agree with it.
		// Silently using the bundle's origin instead would let a provisioned
		// file redirect a command whose target the operator typed by hand —
		// the credential would still be correctly bound to that origin, but
		// to the wrong one.
		if err := requireSameOrigin(target, entry.Origin); err != nil {
			return TrustEntry{}, err
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
		// An already-established reference must still match the origin the
		// caller named. Returning it unchecked would present the credential
		// to whatever origin that reference happens to record now, which is
		// not the one on the command line.
		if oerr := requireSameOrigin(target, entry.Origin); oerr != nil {
			return TrustEntry{}, oerr
		}
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

// requireSameOrigin refuses when the caller named an explicit URL and the
// resolved entry points somewhere else. A bare reference (no scheme) names no
// origin, so there is nothing to compare and nothing to refuse.
func requireSameOrigin(target, resolved string) error {
	if !strings.Contains(target, "://") {
		return nil
	}
	wanted, err := CanonicalOrigin(target)
	if err != nil {
		return err
	}
	if wanted != resolved {
		return failf(ExitRefused,
			"you named %s, but that instance is established as %s. Refusing rather than presenting a credential "+
				"to an origin you did not ask for; remove the entry deliberately if the move is legitimate",
			wanted, resolved)
	}
	return nil
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
	if len(args) == 0 {
		return failf(ExitUsage, "usage: wenv account establish-credential|factor|passkey|recovery-codes|recovery|reset-credential ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "establish-credential":
		return runEstablishCredential(ctx, ios, rest)
	case "factor":
		return runFactor(ctx, ios, rest)
	case "passkey":
		return runPasskey(rest)
	case "recovery-codes":
		return runRecoveryCodes(ctx, ios, rest)
	case "recovery":
		return runRecovery(ctx, ios, rest)
	case "reset-credential":
		return runResetCredential(ctx, ios, rest)
	default:
		return failf(ExitUsage, "unknown account verb %q: use establish-credential, factor, passkey, recovery-codes, recovery or reset-credential", sub)
	}
}

// runResetCredential is the network administrator-issued reset: a credential-reset
// holder mints a credential-establishment authority for a target, returned once
// and transmitted out of band. An instance-capability target has no network path
// and is refused uniformly (like a nonexistent target, B2) - break-glass only,
// via `wenv admin reset-credential` on the host.
func runResetCredential(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return failf(ExitUsage, "usage: wenv account reset-credential <principal> [--output-file PATH | --dangerously-print]")
	}
	principal := args[0]
	var outputFile string
	var dangerous bool
	st, flags, err := parseCommon("account reset-credential", ios, args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&outputFile, "output-file", "", "write the authority to a file this command creates (0600)")
		fs.BoolVar(&dangerous, "dangerously-print", false, "print the authority to stdout")
	})
	if err != nil {
		return err
	}
	deliver := disclose.Options{OutputFile: outputFile, DangerouslyPrint: dangerous, Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}
	if err := disclose.Preflight(deliver); err != nil {
		return failf(ExitRefused, "the reset authority has nowhere to go: %v", err)
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	var result apigen.CredentialResetResult
	if err := client.Do(ctx, http.MethodPost,
		api.PathPrefix+"/accounts/"+url.PathEscape(principal)+"/credential-reset", nil, &result); err != nil {
		return err
	}
	if _, err := disclose.Emit(
		fmt.Sprintf("credential-establishment authority for %s (single-use)", principal),
		result.Authority, deliver); err != nil {
		return failf(ExitRefused, "disclosing the reset authority: %v", err)
	}
	fmt.Fprintf(ios.Stderr,
		"credential reset for %s; its sessions are revoked. Hand the authority above to the account holder out of band.\n", principal)
	return nil
}

// runPasskey refuses by name. A passkey ceremony needs an authenticator
// transport (CTAP/WebAuthn) that a terminal does not have, so the CLI serves
// the refusal rather than pretending: the verbs exist so the surface is
// discoverable and the message points at the only place they work — the
// browser. It reaches no server and touches no state, exactly like the
// `login --device` refusal.
func runPasskey(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "enrol", "list", "remove":
		return failf(ExitRefused,
			"`account passkey %s` is not served on the terminal: a passkey ceremony needs an authenticator transport a terminal does not have. "+
				"Manage passkeys from the browser session surface; use `account factor` for TOTP, which the terminal can carry", sub)
	default:
		return failf(ExitUsage, "unknown passkey verb %q: use enrol, list or remove (all browser-only)", sub)
	}
}

func runEstablishCredential(ctx context.Context, ios IO, args []string) error {
	var (
		as        string
		trustFile string
	)
	st, flags, err := parseCommon("account establish-credential", ios, args, func(fs *flag.FlagSet) {
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
// account factor / recovery-codes / recovery (#54)
// ---------------------------------------------------------------------------
//
// The account-security mutations (confirm, step-up, regenerate) reissue or
// rotate the acting session, so each returns a NEW token the CLI must persist
// in place of the old one — the previous token is dead the instant the server
// answers. Display-once material (the otpauth seed, the recovery codes, the
// recovery authority) goes through the print triad, never ordinary stdout.

func runFactor(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 {
		return failf(ExitUsage, "usage: wenv account factor enrol-totp|confirm-totp|step-up")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "enrol-totp":
		return runFactorEnrolTOTP(ctx, ios, rest)
	case "confirm-totp":
		return runFactorConfirmTOTP(ctx, ios, rest)
	case "step-up":
		return runFactorStepUp(ctx, ios, rest)
	default:
		return failf(ExitUsage, "unknown factor verb %q: use enrol-totp, confirm-totp or step-up", sub)
	}
}

// runFactorEnrolTOTP stages a pending enrolment and discloses the otpauth URI
// once through the print triad. It does not reissue the session — confirm-totp
// does — so it persists no token.
func runFactorEnrolTOTP(ctx context.Context, ios IO, args []string) error {
	var outputFile string
	var dangerous bool
	st, flags, err := parseCommon("account factor enrol-totp", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&outputFile, "output-file", "", "write the otpauth URI to a file this command creates (0600)")
		fs.BoolVar(&dangerous, "dangerously-print", false, "print the otpauth URI to stdout (publishes the seed to whatever captures it)")
	})
	if err != nil {
		return err
	}
	deliver := disclose.Options{OutputFile: outputFile, DangerouslyPrint: dangerous, Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}
	if err := disclose.Preflight(deliver); err != nil {
		return failf(ExitRefused, "the otpauth URI has nowhere to go: %v", err)
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	password, err := ios.readPassword("Password (to authorize enrolment): ")
	if err != nil {
		return err
	}
	var start apigen.TotpEnrolStartResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/totp/enrol/start",
		apigen.TotpEnrolStartRequest{Password: password}, &start); err != nil {
		return err
	}
	if _, err := disclose.Emit("otpauth provisioning URI", start.OtpauthUri, deliver); err != nil {
		return failf(ExitRefused, "disclosing the otpauth URI: %v", err)
	}
	fmt.Fprintf(ios.Stderr, "TOTP enrolment staged. Scan the URI, then confirm with\n    wenv account factor confirm-totp\n")
	return nil
}

// runFactorConfirmTOTP completes enrolment and persists the reissued session.
func runFactorConfirmTOTP(ctx context.Context, ios IO, args []string) error {
	st, flags, err := parseCommon("account factor confirm-totp", ios, args, nil)
	if err != nil {
		return err
	}
	client, artifact, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	code, err := ios.readPassword("Enter the code from your authenticator to confirm: ")
	if err != nil {
		return err
	}
	var result apigen.LoginResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/totp/enrol/confirm",
		apigen.TotpCodeRequest{Code: code}, &result); err != nil {
		return err
	}
	if err := persistRotatedSession(st, artifact, result); err != nil {
		return err
	}
	fmt.Fprintf(ios.Stderr, "TOTP enrolled. Step up to present it with\n    wenv account factor step-up\n")
	return nil
}

// runFactorStepUp elevates the acting session and persists the rotated token.
func runFactorStepUp(ctx context.Context, ios IO, args []string) error {
	st, flags, err := parseCommon("account factor step-up", ios, args, nil)
	if err != nil {
		return err
	}
	client, artifact, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	code, err := ios.readPassword("Enter the code from your authenticator: ")
	if err != nil {
		return err
	}
	var result apigen.LoginResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/totp/step-up",
		apigen.TotpCodeRequest{Code: code}, &result); err != nil {
		return err
	}
	if err := persistRotatedSession(st, artifact, result); err != nil {
		return err
	}
	fmt.Fprintf(ios.Stderr, "session elevated: factors now %s\n",
		strings.Join(result.Session.Assurance.Factors, ", "))
	return nil
}

func runRecoveryCodes(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 || args[0] != "regenerate" {
		return failf(ExitUsage, "usage: wenv account recovery-codes regenerate")
	}
	var outputFile string
	var dangerous bool
	st, flags, err := parseCommon("account recovery-codes regenerate", ios, args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&outputFile, "output-file", "", "write the codes to a file this command creates (0600)")
		fs.BoolVar(&dangerous, "dangerously-print", false, "print the codes to stdout")
	})
	if err != nil {
		return err
	}
	deliver := disclose.Options{OutputFile: outputFile, DangerouslyPrint: dangerous, Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}
	if err := disclose.Preflight(deliver); err != nil {
		return failf(ExitRefused, "the recovery codes have nowhere to go: %v", err)
	}
	client, artifact, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	proof, err := ios.readPassword("Account-security proof (your TOTP code, or password if no factor): ")
	if err != nil {
		return err
	}
	var result apigen.RecoveryCodesResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/recovery-codes/regenerate",
		apigen.RecoveryProofRequest{Proof: proof}, &result); err != nil {
		return err
	}
	if _, err := disclose.Emit("recovery codes (single-use)", strings.Join(result.RecoveryCodes, "\n"), deliver); err != nil {
		return failf(ExitRefused, "disclosing the recovery codes: %v", err)
	}
	if err := persistRotatedSession(st, artifact, result.Login); err != nil {
		return err
	}
	fmt.Fprintf(ios.Stderr, "recovery codes regenerated; the previous batch is now void\n")
	return nil
}

// runRecovery is the pre-auth break-in-glass path: consume a code for a
// credential-establishment authority, then establish a new password with it.
func runRecovery(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 || args[0] != "begin" {
		return failf(ExitUsage, "usage: wenv account recovery begin --instance <url|ref> --as <username>")
	}
	var (
		as         string
		trustFile  string
		outputFile string
		dangerous  bool
	)
	st, flags, err := parseCommon("account recovery begin", ios, args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&as, "as", "", "the username to recover")
		fs.StringVar(&trustFile, "trust-file", "", "provisioned trust bundle")
		fs.StringVar(&outputFile, "output-file", "", "write the authority to a file this command creates (0600)")
		fs.BoolVar(&dangerous, "dangerously-print", false, "print the authority to stdout")
	})
	if err != nil {
		return err
	}
	if as == "" {
		return failf(ExitUsage, "--as <username> is required")
	}
	target := flags.Instance
	if target == "" {
		target = ios.Env.Getenv("WENV_INSTANCE")
	}
	if target == "" {
		return failf(ExitUsage, "--instance <url|ref> is required")
	}
	deliver := disclose.Options{OutputFile: outputFile, DangerouslyPrint: dangerous, Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}
	if err := disclose.Preflight(deliver); err != nil {
		return failf(ExitRefused, "the authority has nowhere to go: %v", err)
	}
	entry, err := establish(ios, st, target, "", trustFile)
	if err != nil {
		return err
	}
	client, err := NewClient(entry, "")
	if err != nil {
		return err
	}
	code, err := ios.readPassword(fmt.Sprintf("Recovery code for %s at %s: ", as, entry.Origin))
	if err != nil {
		return err
	}
	var result apigen.RecoveryBeginResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/recovery/begin",
		apigen.RecoveryBeginRequest{Username: as, Code: code}, &result); err != nil {
		return err
	}
	if _, err := disclose.Emit("credential-establishment authority", result.Authority, deliver); err != nil {
		return failf(ExitRefused, "disclosing the authority: %v", err)
	}
	fmt.Fprintf(ios.Stderr,
		"recovery authority issued. It creates no session: establish a new password with\n    wenv account establish-credential --instance %s --as %s\n",
		entry.Origin, as)
	return nil
}

// persistRotatedSession replaces the stored artifact's token after an
// account-security mutation or step-up rotates it. The old token is already
// dead server-side, so a failure to persist here strands the caller — hence it
// is surfaced, not swallowed.
func persistRotatedSession(st *State, artifact SessionArtifact, r apigen.LoginResult) error {
	token, err := cliSessionToken(r.SessionToken)
	if err != nil {
		return err
	}
	artifact.Token = token
	artifact.SessionID = r.Session.Id
	artifact.ExpiresAt = r.Session.AbsoluteExpiresAt.Format("2006-01-02T15:04:05Z")
	return st.PutSession(artifact)
}

// cliSessionToken derefs the token the server returns to a CLI caller. A CLI
// artifact always carries its token in the body — it has no cookie channel — so
// a nil or empty token is a contract break worth surfacing, not a silent empty
// store that would strand the next request unauthenticated.
func cliSessionToken(t *string) (string, error) {
	if t == nil || *t == "" {
		return "", fmt.Errorf("server returned no session token for a CLI session")
	}
	return *t, nil
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
	sub, rest, err := subverb("org", args, "list", "show", "create", "rename", "delete")
	if err != nil {
		return err
	}

	var (
		format  string
		orgName string
	)
	st, flags, err := parseCommon("org "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
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
	// Syntax before resolution, exactly as the project/env/folder families do it
	// (internal/cli/hierarchy.go): an unknown subverb, a missing name or a stray
	// positional is usage (2) whether or not a session exists.
	switch sub {
	case "show", "rename", "delete":
		// Arity and flag agreement only. Whether a target is AVAILABLE is a
		// resolution question, not a syntax one — `--org`, WENV_ORG, a pin file
		// and a context may each supply it — so it is asked after resolution, by
		// addressed(), exactly as the other three families ask it.
		if err := flags.checkTarget("org "+sub, DimOrg, flags.Org); err != nil {
			return err
		}
	default:
		if err := flags.checkNoPositionals("org " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "create" && orgName == "":
		return failf(ExitUsage, "usage: wenv org create --name <name>")
	case sub == "rename" && orgName == "":
		return failf(ExitUsage, "usage: wenv org rename <org> --name <new-name>")
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
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
		id, err := addressed(resolved, DimOrg, flags.positional(), "org show")
		if err != nil {
			return err
		}
		var org apigen.Org
		if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/orgs/"+url.PathEscape(id), nil, &org); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ID", "NAME", "ACTIVE", "CREATED"},
			Rows:    [][]string{{org.Id, org.Name, boolString(org.Active), org.CreatedAt.Format("2006-01-02")}},
			JSON:    org,
		})

	case "create":
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

	case "rename":
		id, err := addressed(resolved, DimOrg, flags.positional(), "org rename")
		if err != nil {
			return err
		}
		var org apigen.Org
		if err := client.Do(ctx, http.MethodPatch, api.PathPrefix+"/orgs/"+url.PathEscape(id),
			apigen.RenameRequest{Name: orgName}, &org); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ID", "NAME", "ACTIVE", "CREATED"},
			Rows:    [][]string{{org.Id, org.Name, boolString(org.Active), org.CreatedAt.Format("2006-01-02")}},
			JSON:    org,
		})

	case "delete":
		id, err := addressed(resolved, DimOrg, flags.positional(), "org delete")
		if err != nil {
			return err
		}
		if err := client.Do(ctx, http.MethodDelete, api.PathPrefix+"/orgs/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted organisation %s\n", id)
		return nil

	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "wenv org: unhandled subverb %q", sub)
}

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

type commonFlags struct {
	Flags
	// positionals is EVERY positional argument, not just the first. Keeping only
	// the first is how `folder delete fld_real typo` silently acts on fld_real:
	// the extra word is a mistake the caller wants to hear about, and a delete
	// is the wrong place to guess.
	positionals []string
}

// positional is the first positional argument, or "" when there is none.
func (c commonFlags) positional() string { return first(c.positionals) }

// checkTarget and checkNoPositionals are the syntax half of addressing a verb.
// Both run BEFORE any target resolution or session lookup, so an exit code does
// not depend on whether the caller happens to be logged in.
//
// Every hierarchy subverb calls exactly one of them, from a switch the subverb
// gate already made exhaustive: a verb either takes one object or takes none,
// and an argument the CLI would silently drop is a mistake the caller wants to
// hear about — especially on a delete.
//
// checkTarget refuses a stray extra positional and a positional that
// contradicts the matching selector flag. The contradiction is checked against
// the FLAG only — a context or pin file naming a different object is the
// resolution model working as designed (an explicit argument overrides it), and
// erroring there would break the whole point of per-dimension precedence.
func (c commonFlags) checkTarget(verb string, dim Dimension, flagValue string) error {
	if len(c.positionals) > 1 {
		return failf(ExitUsage, "usage: wenv %s takes one %s, got %d: %s",
			verb, dim, len(c.positionals), strings.Join(c.positionals, " "))
	}
	if p := c.positional(); p != "" && flagValue != "" && p != flagValue {
		return failf(ExitUsage,
			"wenv %s names %s %q but --%s says %q — refusing rather than picking one",
			verb, dim, p, dim, flagValue)
	}
	return nil
}

// checkNoPositionals is checkTarget's counterpart for the verbs that address no
// object — `list` and `create`, which take their subject from selector flags.
// Without it `folder list stray` and `project create stray --name x` parse
// happily and drop the word.
func (c commonFlags) checkNoPositionals(verb string) error {
	if len(c.positionals) > 0 {
		return failf(ExitUsage, "usage: wenv %s takes no positional arguments, got: %s",
			verb, strings.Join(c.positionals, " "))
	}
	return nil
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
	c.positionals = positional
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
	client, artifact, _, err := authenticatedTarget(st, ios, flags)
	return client, artifact, err
}

// authenticatedTarget is authenticatedClient plus the resolved target, for the
// verbs that address a scope rather than the instance. The resolution is the
// same one either way — the hierarchy verbs must not invent a second
// precedence chain.
func authenticatedTarget(st *State, ios IO, flags commonFlags) (*Client, SessionArtifact, Resolved, error) {
	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return nil, SessionArtifact{}, Resolved{}, err
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
			return nil, SessionArtifact{}, Resolved{}, serr
		}
		if len(entries) != 1 {
			return nil, SessionArtifact{}, Resolved{}, err
		}
		for k := range entries {
			instance = k
		}
	}
	entry, err := st.Trust().Lookup(instance)
	if err != nil {
		return nil, SessionArtifact{}, Resolved{}, err
	}
	sessions, err := st.Sessions()
	if err != nil {
		return nil, SessionArtifact{}, Resolved{}, err
	}
	artifact, ok := sessions[instance]
	if !ok {
		return nil, SessionArtifact{}, Resolved{}, failf(ExitAuth,
			"no session for instance %q: run `wenv login <url> --local --as <user>`", instance)
	}
	if artifact.Origin != entry.Origin {
		return nil, SessionArtifact{}, Resolved{}, failf(ExitRefused,
			"the stored session for %q was established against %s, but the trust store now records %s; log in again",
			instance, artifact.Origin, entry.Origin)
	}
	client, err := NewClient(entry, artifact.Token)
	if err != nil {
		return nil, SessionArtifact{}, Resolved{}, err
	}
	// The disclosure echo: the fully resolved target, to stderr, before
	// acting — including which precedence level supplied each dimension.
	if echo := resolved.Echo(); echo != "" {
		fmt.Fprintf(ios.Stderr, "target: %s [origin %s, artifact human-session %s]\n",
			echo, entry.Origin, artifact.Principal)
	}
	return client, artifact, resolved, nil
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
