package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

// The machine-identity verbs (#61): service accounts, their credentials and
// the instance lifetime controls.
//
// TWO THINGS THIS FILE MUST NEVER GROW.
//
// There is no `--token` flag, anywhere, in either direction. A secret in
// argv is visible in `ps`, in /proc/<pid>/cmdline, in process listings and in
// shell history; the run-wrapper's one clean property — that shell history
// stays free of secret material — holds only if the flag does not exist to be
// misused. A workload receives its credential through `--token-file` or
// HIKYO_TOKEN and nothing else.
//
// There is no verb that prints an existing credential. `credential list`
// renders metadata because metadata is all the API returns; a value reaches
// the terminal exactly once, at mint, through the print triad.

func runServiceAccount(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("sa", args, "list", "create", "delete", "credential", "binding")
	if err != nil {
		return err
	}
	if sub == "credential" {
		return runServiceAccountCredential(ctx, ios, rest)
	}
	// `binding` creates a federated `(issuer, subject)` binding (#62). It has no
	// `list` and no `delete` of its own: a binding IS a credential row, so
	// `sa credential list` already shows it and `sa credential revoke` already
	// kills it. Two verb families over the same rows would be two places for the
	// never-return-a-value rule and the revoke formula to drift.
	if sub == "binding" {
		return runServiceAccountBinding(ctx, ios, rest)
	}

	var format, name, kind, id string
	st, flags, err := parseCommon("sa "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" {
			fs.StringVar(&name, "name", "", "the service account's name, unique within the project")
			fs.StringVar(&kind, "kind", "", "workload or automation - declared at creation and immutable")
		}
		if sub == "delete" {
			fs.StringVar(&id, "id", "", "the service account to delete")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax before resolution and before any session lookup, so an exit code
	// never depends on login state.
	if err := flags.checkNoPositionals("sa " + sub); err != nil {
		return err
	}
	switch {
	case sub == "create" && (name == "" || kind == ""):
		return failf(ExitUsage, "usage: hikyo sa create --name <name> --kind workload|automation")
	case sub == "delete" && id == "":
		return failf(ExitUsage, "usage: hikyo sa delete --id <id>")
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := serviceAccountPath(resolved)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		var out apigen.ServiceAccountList
		if err := client.Do(ctx, http.MethodGet, base, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, serviceAccountTable(out))
	case "create":
		var out apigen.ServiceAccount
		body := apigen.CreateServiceAccountRequest{Name: name, Kind: apigen.ServiceAccountKind(kind)}
		if err := client.Do(ctx, http.MethodPost, base, body, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, serviceAccountTable(apigen.ServiceAccountList{
			Items: []apigen.ServiceAccount{out}, Count: 1,
		}))
	default:
		// Deletion revokes every credential and releases every grant in one
		// transaction. It is deliberately not gated on disclosure rights.
		return client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(id), nil, nil)
	}
}

func runServiceAccountCredential(ctx context.Context, ios IO, args []string) (returnErr error) {
	sub, rest, err := subverb("sa credential", args, "list", "mint", "rotate", "revoke")
	if err != nil {
		return err
	}

	var (
		format, saID, credID, outputFile string
		lifetime                         string
		indefinite, dangerous            bool
	)
	st, flags, err := parseCommon("sa credential "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.StringVar(&saID, "sa", "", "the service account")
		if sub == "revoke" || sub == "rotate" {
			fs.StringVar(&credID, "id", "", "the credential to revoke")
		}
		if sub == "mint" || sub == "rotate" {
			fs.StringVar(&lifetime, "lifetime", "", "finite lifetime, e.g. 720h; empty means the instance default")
			fs.BoolVar(&indefinite, "indefinite", false,
				"mint a credential with no expiry - refused unless the instance opted in")
			// The print triad. There is no --token flag: a minted value goes
			// to the controlling terminal, to a file this command creates
			// O_EXCL at 0600, or to stdout under an explicit flag whose name
			// is the warning.
			fs.StringVar(&outputFile, "output-file", "",
				"write the credential to a file this command creates (0600)")
			fs.BoolVar(&dangerous, "dangerously-print", false,
				"print the credential to stdout - and to whatever collects your stdout")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("sa credential " + sub); err != nil {
		return err
	}
	if saID == "" {
		return failf(ExitUsage, "usage: hikyo sa credential %s --sa <id> ...", sub)
	}
	if (sub == "revoke" || sub == "rotate") && credID == "" {
		return failf(ExitUsage, "usage: hikyo sa credential %s --sa <id> --id <credential-id>", sub)
	}
	var want apigen.MintCredentialRequest
	if sub == "mint" || sub == "rotate" {
		if indefinite && lifetime != "" {
			return failf(ExitUsage,
				"hikyo sa credential %s: --indefinite and --lifetime name two different lifetimes; choose one", sub)
		}
		if indefinite {
			yes := true
			want.Indefinite = &yes
		}
		if lifetime != "" {
			d, err := time.ParseDuration(lifetime)
			if err != nil || d <= 0 {
				return failf(ExitUsage, "hikyo sa credential %s: --lifetime must be a positive duration, e.g. 720h", sub)
			}
			secs := int(d / time.Second)
			want.LifetimeSeconds = &secs
		}
	}

	// mint and rotate share the whole body: rotation IS a mint plus a revoke
	// of the predecessor, which is the ADR's overlap-based rotation rather
	// than a distinct authorization act.
	//
	// Prepare runs HERE — before target resolution, any network call, or mint.
	// The reserved destination is the exact destination later written.
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout,
	}
	var sink *disclose.PreparedSink
	if sub == "mint" || sub == "rotate" {
		sink, err = ios.prepareDisclosure(deliver)
		if err != nil {
			return failf(ExitRefused, "the credential has nowhere to go: %v", err)
		}
		defer sink.AbortOnReturn(&returnErr)
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := serviceAccountPath(resolved)
	if err != nil {
		return err
	}
	credentials := base + "/" + url.PathEscape(saID) + "/credentials"

	switch sub {
	case "list":
		var out apigen.MachineCredentialList
		if err := client.Do(ctx, http.MethodGet, credentials, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, credentialTable(out))
	case "revoke":
		return client.Do(ctx, http.MethodDelete, credentials+"/"+url.PathEscape(credID), nil, nil)
	}

	var out apigen.MintCredentialResult
	if err := client.Do(ctx, http.MethodPost, credentials, want, &out); err != nil {
		return err
	}
	if _, err := sink.WriteOnce("hikyo machine credential (shown once)", out.Value); err != nil {
		return failf(ExitRefused, "disclosing the credential: %v", err)
	}
	if out.Clamped {
		fmt.Fprintf(ios.Stderr,
			"note: the instance lifetime ceiling shortened this credential; it expires at %s\n",
			renderExpiry(out.Credential))
	}
	if sub == "rotate" {
		// The revoke comes AFTER the new value has been delivered. If it
		// fails the operator holds two live credentials, which is the safe
		// direction and the intended steady state of an overlap rotation.
		if err := client.Do(ctx, http.MethodDelete, credentials+"/"+url.PathEscape(credID), nil, nil); err != nil {
			fmt.Fprintf(ios.Stderr,
				"warning: the replacement was minted but revoking %s failed: %v\n"+
					"    both credentials are live; revoke the old one with\n"+
					"    hikyo sa credential revoke --sa %s --id %s\n", credID, err, saID, credID)
			return err
		}
	}
	return Render(ios.Stdout, f, credentialTable(apigen.MachineCredentialList{
		Items: []apigen.MachineCredential{out.Credential}, Count: 1,
	}))
}

func runCredentialPolicy(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("instance-config credential-policy", args, "get", "set")
	if err != nil {
		return err
	}
	var (
		format, maxLifetime, allowIndefinite, maxLive string
		confirm                                       bool
	)
	st, flags, err := parseCommon("instance-config credential-policy "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "set" {
			// String tri-state rather than typed flags: an omitted control
			// must mean "unchanged", and a bool defaulting to false would
			// silently withdraw the indefinite opt-in on every call that did
			// not mention it.
			fs.StringVar(&maxLifetime, "max-lifetime", "", "the instance ceiling on a finite credential, e.g. 2160h")
			fs.StringVar(&allowIndefinite, "allow-indefinite", "", "true or false - the separate opt-in, default off")
			fs.StringVar(&maxLive, "max-live-credentials", "", "concurrent live credentials per service account")
			fs.BoolVar(&confirm, "confirm", false, "acknowledge the affected credentials a tightening enumerates")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("instance-config credential-policy " + sub); err != nil {
		return err
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	path := api.PathPrefix + "/instance/credential-policy"

	var current apigen.CredentialPolicy
	if err := client.Do(ctx, http.MethodGet, path, nil, &current); err != nil {
		return err
	}
	if sub == "get" {
		return Render(ios.Stdout, f, policyTable(current))
	}

	// PUT is a full replacement, so an omitted control is read back from the
	// current policy rather than defaulted — the same read-then-overlay the
	// project-settings knob uses, for the same reason.
	body := apigen.SetCredentialPolicyRequest{
		MaxFiniteLifetimeSeconds: current.MaxFiniteLifetimeSeconds,
		AllowIndefinite:          current.AllowIndefinite,
		MaxLiveCredentials:       current.MaxLiveCredentials,
	}
	if maxLifetime != "" {
		d, err := time.ParseDuration(maxLifetime)
		if err != nil || d <= 0 {
			return failf(ExitUsage, "--max-lifetime must be a positive duration, e.g. 2160h")
		}
		body.MaxFiniteLifetimeSeconds = int(d / time.Second)
	}
	if allowIndefinite != "" {
		v, err := strconv.ParseBool(allowIndefinite)
		if err != nil {
			return failf(ExitUsage, "--allow-indefinite must be true or false")
		}
		body.AllowIndefinite = v
	}
	if maxLive != "" {
		n, err := strconv.Atoi(maxLive)
		if err != nil || n < 1 {
			return failf(ExitUsage, "--max-live-credentials must be a positive integer")
		}
		body.MaxLiveCredentials = n
	}
	if confirm {
		body.Confirm = &confirm
	}
	var out apigen.CredentialPolicyResult
	if err := client.Do(ctx, http.MethodPut, path, body, &out); err != nil {
		return err
	}
	if err := Render(ios.Stdout, f, policyResultTable(out)); err != nil {
		return err
	}
	if !out.Applied {
		// The preview. Nothing was written, so the exit code says so: a
		// script that treated a two-phase tightening as done would believe a
		// ceiling it never set.
		for _, a := range out.Affected {
			fmt.Fprintf(ios.Stderr, "  %s (%s): %s\n", a.Id, a.ServiceAccountId, a.Reason)
		}
		return failf(ExitRefused,
			"this change affects %d live credential(s), listed above. Nothing was written.\n"+
				"    Re-run with --confirm to apply it.", len(out.Affected))
	}
	return nil
}

// serviceAccountPath builds the project-scoped collection route. Service
// accounts are project-owned, so an org without a project is a usage error
// rather than a wider query.
func serviceAccountPath(resolved Resolved) (string, error) {
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return "", err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return "", err
	}
	return api.PathPrefix + "/orgs/" + url.PathEscape(org) +
		"/projects/" + url.PathEscape(project) + "/service-accounts", nil
}

func serviceAccountTable(list apigen.ServiceAccountList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, sa := range list.Items {
		rows = append(rows, []string{
			sa.Id, sa.Name, string(sa.Kind), strconv.Itoa(sa.LiveCredentials), sa.PrincipalId,
		})
	}
	return Table{
		Columns: []string{"ID", "NAME", "KIND", "LIVE", "PRINCIPAL"},
		Rows:    rows,
		JSON:    list,
	}
}

func credentialTable(list apigen.MachineCredentialList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, c := range list.Items {
		rows = append(rows, []string{
			c.Id, credentialIdentity(c), string(c.Kind), renderExpiry(c), credentialStatus(c),
		})
	}
	return Table{
		// No VALUE column, and there is no data to fill one: the API returns
		// metadata, and a credential value is shown once at mint.
		//
		// The second column is IDENTITY rather than PREFIX because the two kinds
		// identify themselves differently: a bearer credential by its non-secret
		// prefix hint, a federated binding by the `(issuer, subject)` it names.
		// One column, because an operator scanning this list is asking the same
		// question of both — which of these is which.
		Columns: []string{"ID", "IDENTITY", "KIND", "EXPIRES", "STATUS"},
		Rows:    rows,
		JSON:    list,
	}
}

// renderExpiry states `indefinite` as a word, never as a distant date: it is
// a distinct typed value and rendering it as a timestamp would invite the
// reading that a big enough number is the same thing.
func renderExpiry(c apigen.MachineCredential) string {
	if c.Lifetime == apigen.Indefinite || c.ExpiresAt == nil {
		return "indefinite"
	}
	return c.ExpiresAt.UTC().Format(time.RFC3339)
}

// credentialIdentity renders whichever identifier the credential's kind has.
// Neither is secret: a prefix hint is a few characters of a 256-bit value, and
// an `(issuer, subject)` pair is a public external identity.
func credentialIdentity(c apigen.MachineCredential) string {
	if c.PrefixHint != nil {
		return *c.PrefixHint
	}
	if c.Subject != nil {
		return *c.Subject
	}
	// Unreachable through the API — the shape CHECKs make one of the two total —
	// so an empty cell here would be a silent claim that the row has no
	// identity at all.
	return "-"
}

func credentialStatus(c apigen.MachineCredential) string {
	switch {
	case c.RevokedAt != nil:
		return "revoked"
	case c.ExpiringSoon:
		return "expiring-soon"
	default:
		return "live"
	}
}

func policyTable(p apigen.CredentialPolicy) Table {
	return Table{
		Columns: []string{"MAX LIFETIME", "ALLOW INDEFINITE", "MAX LIVE PER ACCOUNT"},
		Rows: [][]string{{
			(time.Duration(p.MaxFiniteLifetimeSeconds) * time.Second).String(),
			strconv.FormatBool(p.AllowIndefinite),
			strconv.Itoa(p.MaxLiveCredentials),
		}},
		JSON: p,
	}
}

func policyResultTable(r apigen.CredentialPolicyResult) Table {
	t := policyTable(r.Policy)
	t.JSON = r
	return t
}

// machineToken resolves the credential a workload presents. The ADR fixes
// exactly two channels and forbids a third:
//
//	--token-file <path>   the file the operator placed (systemd
//	                      LoadCredentialEncrypted, a Kubernetes Secret mount)
//	HIKYO_TOKEN            the environment variable
//
// There is no --token flag. A secret in argv is readable by every process on
// the host through `ps` and /proc/<pid>/cmdline, and it lands in shell
// history; the run-wrapper's one clean property is that history stays free of
// secret material, and it holds only if the flag does not exist.
//
// When BOTH are populated --token-file wins and the collision warns LOUDLY.
// A silent precedence rule on a credential is exactly the quiet ambiguity the
// fail-loud principle exists to prevent: the operator who set both believes
// one of them is in use and has a 50% chance of being right about which.
func machineToken(ios IO, tokenFile string) (string, error) {
	env := ios.Env.Getenv("HIKYO_TOKEN")
	if tokenFile == "" {
		return env, nil
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", failf(ExitUsage, "hikyo: reading --token-file %s: %v", tokenFile, err)
	}
	// Trailing newline only: the mint writes the value plus one newline so a
	// script can read the file directly, and an operator's editor may add
	// another. Interior whitespace is NOT stripped — a value with a space in
	// it is not a hikyo artifact, and quietly repairing it would hide a
	// truncated or concatenated file.
	token := strings.Trim(string(raw), "\r\n")
	if token == "" {
		return "", failf(ExitUsage, "hikyo: --token-file %s is empty", tokenFile)
	}
	if env != "" && env != token {
		fmt.Fprintf(ios.Stderr,
			"WARNING: both --token-file and HIKYO_TOKEN are set and they differ.\n"+
				"    --token-file %s wins; HIKYO_TOKEN is ignored for this invocation.\n"+
				"    Unset one of them: a credential chosen by a precedence rule nobody\n"+
				"    read is a credential nobody knows they are using.\n", tokenFile)
	}
	return token, nil
}
