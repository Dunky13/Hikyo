package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

// The multi-instance CLI families (#71, multi-instance ADR § Parity and the
// CLI), joining the API/CLI ADR's closed noun-verb taxonomy under its existing
// grammar:
//
//	remote add|list|show|remove
//	remote-credential create|list|show|revoke
//
// `remote rename` is deliberately ABSENT. The amendment's verb list for this
// family is the four above; the display name is the one mutable field and it
// is reachable through the API and the UI, where parity holds because the API
// is public surface. Adding a fifth verb here would widen a closed list to
// save one round trip.
//
// `remote add` is INTERACTIVE-ONLY: it requires a terminal for the fingerprint
// confirmation and for the credential paste. There is deliberately no
// non-interactive form in v1 — scripting fleet directory setup is a named
// post-v1 candidate, gated on a design that preserves the pin confirmation and
// the no-argv-secret rule.

const remotesPath = api.PathPrefix + "/instance/remotes"
const connectionsPath = api.PathPrefix + "/instance/connections"

func runRemote(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("remote", args, "add", "list", "show", "remove")
	if err != nil {
		return err
	}

	var format string
	st, flags, err := parseCommon("remote "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	positional := flags.positionals

	switch sub {
	case "add":
		if len(positional) != 2 {
			return failf(ExitUsage, "usage: hikyo remote add <name> <url>")
		}
		return addRemote(ctx, ios, st, flags, f, positional[0], positional[1])
	case "list":
		if len(positional) != 0 {
			return failf(ExitUsage, "usage: hikyo remote list [-o table|json]")
		}
	default:
		if len(positional) != 1 {
			return failf(ExitUsage, "usage: hikyo remote %s <name>", sub)
		}
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		var out apigen.RemoteList
		if err := client.Do(ctx, http.MethodGet, remotesPath, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, remoteTable(out))
	case "show":
		var out apigen.Remote
		if err := client.Do(ctx, http.MethodGet, remotesPath+"/"+url.PathEscape(positional[0]), nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, remoteTable(apigen.RemoteList{Items: []apigen.Remote{out}, Count: 1}))
	default:
		// A TYPED-NAME confirmation (ADR § Parity), because removal destroys
		// the stored credential and the snapshot with the entry, and re-adding
		// costs the whole ceremony again on both instances.
		ok, err := disclose.ConfirmName(
			fmt.Sprintf("removing remote %q destroys its stored credential and its snapshot.\n"+
				"the URL and pin are immutable, so re-adding means the full ceremony again.", positional[0]),
			positional[0],
			disclose.Options{Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal})
		if err != nil {
			return failf(ExitRefused, "confirming the removal: %v", err)
		}
		if !ok {
			return failf(ExitRefused, "hikyo remote remove: the name was not typed back; nothing was removed")
		}
		if err := client.Do(ctx, http.MethodDelete, remotesPath+"/"+url.PathEscape(positional[0]), nil, nil); err != nil {
			return err
		}
		// Said EVERY time, because it is the thing operators get wrong:
		// destroying the local copy is not revocation.
		fmt.Fprintf(ios.Stderr,
			"note: the serving instance's credential is STILL VALID until it is revoked there.\n"+
				"    on that instance, run: hikyo remote-credential revoke --id <connection-id>\n")
		return nil
	}
}

// addRemote is the ceremony. Order is the ADR's and it is load-bearing:
// connect, DISPLAY THE FINGERPRINT AND TAKE THE HUMAN'S CONFIRMATION, read the
// pre-auth meta endpoint over that pinned connection to confirm the target
// speaks this protocol at a revision that can serve a directory, then take the
// credential — and only then hand all of it to the server, which performs the
// one authenticated fetch that decides whether the entry exists at all.
//
// Every step before the paste can refuse without a secret having been typed,
// which is why the paste is last.
func addRemote(ctx context.Context, ios IO, st *State, flags commonFlags, f Format, name, rawURL string) error {
	origin, err := CanonicalOrigin(rawURL)
	if err != nil {
		return failf(ExitUsage, "hikyo remote add: %v", err)
	}
	// HTTPS ONLY, INDEPENDENTLY OF THE GENERAL CLI'S LOOPBACK EXCEPTION.
	// CanonicalOrigin admits http because a loopback ORIGIN is a legitimate
	// thing for other verbs to address, and because the workspace allowlist
	// stores origins that may be plaintext. A REMOTE URL is neither: the ADR
	// makes the directory channel https-and-pinned, the credential is written
	// onto that wire, and there is no fingerprint to confirm without TLS. Left
	// to the general rule, `hikyo remote add peer http://127.0.0.1:8080`
	// confirmed a BLANK fingerprint, read meta in the clear, and asked the
	// human to paste a directory credential — the server's own
	// ValidateRemoteURL then refused the whole thing, one secret too late.
	if !strings.HasPrefix(origin, "https://") {
		return failf(ExitUsage, "hikyo remote add: a remote URL must be https, got %q\n"+
			"    the directory channel is TLS with a pinned key; there is no fingerprint to "+
			"confirm without it, and the credential would cross an unencrypted wire.", rawURL)
	}
	deliver := disclose.Options{Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}

	pin, err := FetchIdentity(origin)
	if err != nil {
		return failf(ExitRefused, "hikyo remote add: connecting to %s: %v", origin, err)
	}
	if pin == "" {
		// Belt to the braces above. A blank fingerprint is not something a
		// human can meaningfully confirm, and displaying one teaches them that
		// confirming blanks is normal.
		return failf(ExitRefused, "hikyo remote add: %s presented no pinnable key; nothing was stored", origin)
	}
	// The fingerprint goes to the TERMINAL and the answer comes back from it,
	// so a log-capturing pipe sees neither the key being trusted nor the
	// intent to trust it.
	ok, err := disclose.Confirm(
		fmt.Sprintf("%s presents key fingerprint\n    %s\ntrust it?", origin, pin), deliver)
	if err != nil {
		return failf(ExitRefused, "hikyo remote add: %v (this command is interactive-only)", err)
	}
	if !ok {
		return failf(ExitRefused, "hikyo remote add: fingerprint not confirmed; nothing was stored")
	}

	// The PRE-AUTH META READ, before the credential is asked for. It is the
	// ADR's order and the order is the point: a human who has just confirmed a
	// fingerprint must not be asked to paste a directory credential into
	// something that has not yet proven it speaks this protocol at a revision
	// that can serve the directory at all.
	//
	// It runs over the PINNED connection the human just confirmed — the same
	// client construction every other verb uses, with the pin from this
	// ceremony rather than from the trust store — so the bytes read here come
	// from the key that was displayed, not from whatever answers that name next.
	// Unreachable and incompatible are both loud refusals; neither degrades.
	peer, err := NewClient(TrustEntry{Name: name, Origin: origin, SPKIPin: pin}, "")
	if err != nil {
		return err
	}
	meta, err := peer.Meta(ctx)
	if err != nil {
		return failf(ExitRefused,
			"hikyo remote add: %s did not answer the meta endpoint, so it has not shown it speaks this protocol: %v\n"+
				"    nothing was stored, and no credential was asked for.", origin, err)
	}
	if err := CheckRevision(meta, "serveDirectory"); err != nil {
		return failf(ExitRefused,
			"hikyo remote add: %s is not a compatible peer: %v\n"+
				"    nothing was stored, and no credential was asked for.", origin, err)
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}

	// The credential is READ FROM THE TERMINAL, never from a flag: there is no
	// --token anywhere in this CLI, because argv is world-readable on a shared
	// host and lands in shell history besides.
	// ios.readPassword, not ios.ReadPassword: the field's contract is "nil
	// means the real terminal", and reading the field directly made the ONLY
	// uninjected path — every real invocation — refuse itself. Every other verb
	// in this CLI goes through the accessor; this one had quietly opted out.
	credential, err := ios.readPassword("paste the directory credential minted on " + origin + ": ")
	if err != nil {
		return failf(ExitRefused, "hikyo remote add: reading the credential: %v", err)
	}
	if credential == "" {
		return failf(ExitUsage, "hikyo remote add: no credential was entered")
	}

	var out apigen.Remote
	body := apigen.AddRemoteRequest{
		Name: name, Url: origin, SpkiPin: pin, Credential: credential,
	}
	if err := client.Do(ctx, http.MethodPost, remotesPath, body, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, remoteTable(apigen.RemoteList{Items: []apigen.Remote{out}, Count: 1}))
}

func runRemoteCredential(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("remote-credential", args, "create", "list", "show", "revoke")
	if err != nil {
		return err
	}

	var (
		format, label, id, lifetime, outputFile string
		indefinite, dangerous                   bool
	)
	st, flags, err := parseCommon("remote-credential "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" {
			fs.StringVar(&label, "label", "", "names the intended peer, for the audit trail")
			fs.StringVar(&lifetime, "lifetime", "", "finite lifetime, e.g. 720h; empty means the instance default")
			fs.BoolVar(&indefinite, "indefinite", false,
				"mint with no expiry - refused unless the instance opted in")
			// The print triad, identical to every other display-once mint.
			// There is no --token flag anywhere in this CLI.
			fs.StringVar(&outputFile, "output-file", "",
				"write the credential to a file this command creates (0600)")
			fs.BoolVar(&dangerous, "dangerously-print", false,
				"print the credential to stdout - and to whatever collects your stdout")
		}
		if sub == "show" || sub == "revoke" {
			fs.StringVar(&id, "id", "", "the connection credential")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("remote-credential " + sub); err != nil {
		return err
	}
	switch {
	case sub == "create" && label == "":
		return failf(ExitUsage, "usage: hikyo remote-credential create --label <peer-name>")
	case (sub == "show" || sub == "revoke") && id == "":
		return failf(ExitUsage, "usage: hikyo remote-credential %s --id <connection-id>", sub)
	}

	var want apigen.MintInstanceConnectionRequest
	want.Label = label
	if sub == "create" {
		if indefinite && lifetime != "" {
			return failf(ExitUsage,
				"hikyo remote-credential create: --indefinite and --lifetime name two different lifetimes; choose one")
		}
		if indefinite {
			yes := true
			want.Indefinite = &yes
		}
		if lifetime != "" {
			d, err := time.ParseDuration(lifetime)
			if err != nil || d <= 0 {
				return failf(ExitUsage,
					"hikyo remote-credential create: --lifetime must be a positive duration, e.g. 720h")
			}
			secs := int(d / time.Second)
			want.LifetimeSeconds = &secs
		}
	}

	// Preflight BEFORE the mint, for the reason every display-once path
	// preflights: a credential minted with nowhere to put it has been
	// destroyed and the side effect performed, because the server will never
	// hand it back.
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal,
	}
	if sub == "create" {
		if err := disclose.Preflight(deliver); err != nil {
			return failf(ExitRefused, "the credential has nowhere to go: %v", err)
		}
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		var out apigen.InstanceConnectionList
		if err := client.Do(ctx, http.MethodGet, connectionsPath, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, connectionTable(out))
	case "show":
		var out apigen.InstanceConnection
		if err := client.Do(ctx, http.MethodGet, connectionsPath+"/"+url.PathEscape(id), nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, connectionTable(apigen.InstanceConnectionList{
			Items: []apigen.InstanceConnection{out}, Count: 1,
		}))
	case "revoke":
		return client.Do(ctx, http.MethodDelete, connectionsPath+"/"+url.PathEscape(id), nil, nil)
	}

	var out apigen.MintedInstanceConnection
	if err := client.Do(ctx, http.MethodPost, connectionsPath, want, &out); err != nil {
		return err
	}
	if _, err := disclose.Emit("hikyo directory credential (shown once)", out.Value, deliver); err != nil {
		return failf(ExitRefused, "disclosing the credential: %v", err)
	}
	if out.Clamped {
		fmt.Fprintf(ios.Stderr,
			"note: the instance lifetime ceiling shortened this credential\n")
	}
	return Render(ios.Stdout, f, connectionTable(apigen.InstanceConnectionList{
		Items: []apigen.InstanceConnection{out.Connection}, Count: 1,
	}))
}

func remoteTable(l apigen.RemoteList) Table {
	rows := make([][]string, 0, len(l.Items))
	for _, r := range l.Items {
		state := string(r.State)
		if r.Stale && r.StaleForSeconds != nil {
			// The card's own sentence, in the terminal's vocabulary: the state
			// and its age together, never a stale listing presented as current.
			state += " (" + humanAge(*r.StaleForSeconds) + " old)"
		}
		rows = append(rows, []string{
			r.Name, r.Url, state, derefString(r.Version),
			countOrDash(r.OrgCount), countOrDash(r.ProjectCount),
		})
	}
	return Table{
		Columns: []string{"NAME", "URL", "STATE", "VERSION", "ORGS", "PROJECTS"},
		Rows:    rows,
		JSON:    l,
	}
}

func connectionTable(l apigen.InstanceConnectionList) Table {
	rows := make([][]string, 0, len(l.Items))
	for _, c := range l.Items {
		status := "revoked"
		if c.Live {
			status = "live"
		}
		expires := "never"
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.Format(time.RFC3339)
		}
		used := "never"
		if c.LastUsedAt != nil {
			used = c.LastUsedAt.Format(time.RFC3339)
		}
		rows = append(rows, []string{c.Id, c.Label, c.PrefixHint, status, expires, used})
	}
	return Table{
		Columns: []string{"ID", "LABEL", "PREFIX", "STATUS", "EXPIRES", "LAST USED"},
		Rows:    rows,
		JSON:    l,
	}
}

func humanAge(seconds int) string {
	switch {
	case seconds < 60:
		return strconv.Itoa(seconds) + "s"
	case seconds < 3600:
		return strconv.Itoa(seconds/60) + "m"
	case seconds < 86400:
		return strconv.Itoa(seconds/3600) + "h"
	default:
		return strconv.Itoa(seconds/86400) + "d"
	}
}

func derefString(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func countOrDash(n *int) string {
	if n == nil {
		return "-"
	}
	return strconv.Itoa(*n)
}
