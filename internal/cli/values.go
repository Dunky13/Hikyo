package cli

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Dunky13/hikyo/api/apigen"
	"github.com/Dunky13/hikyo/internal/disclose"
)

// The value verbs (#50): `hikyo values get|set|diff|copy`.
//
// `get`, `set` and `diff` are the api-cli-surface ADR's closed v1 spellings
// for this noun; `--clear` is the flat-model ADR's own declared additive join
// for clearing to `absent`. `copy` joins the family as a declared additive
// spelling under the same grammar, pre-freeze, exactly as #48's `rename` and
// #49's `create` did: copy-to and bulk-apply are locked OPERATIONS with no
// spelling of their own, and a surface where the API can copy and the CLI
// cannot would make every scripted fill a hand-rolled get/set pair — which is
// precisely the plaintext-through-argv path the output grammar forbids.
//
// NO SECRET EVER REACHES ARGV, in either direction:
//
//   - inbound, `values set` takes its value from a no-echo terminal prompt,
//     from stdin (`--stdin`), or from a file the caller names
//     (`--value-file`). There is no `--value` flag and there will not be one:
//     a value on the command line transits `ps`, `/proc/*/cmdline` and shell
//     history before it ever reaches the server.
//   - outbound, plaintext goes through the print triad — controlling terminal
//     after confirmation, `--output-file` (O_EXCL, 0600), or an explicit
//     `--dangerously-print` — never to stdout by accident. `config` values are
//     not secret and print normally; the triad guards `secret` disclosure.
//
// valuesSetUsage is the one spelling of where a value may come from.
const valuesSetUsage = "usage: hikyo values set <KEY> (--stdin | --value-file PATH | interactive prompt) [--clear]"

var valueColumns = []string{"KEY", "CLASS", "PRESENCE", "VALUE"}

// runValues is the `values` family.
func runValues(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("values", args, "list", "get", "set", "declare", "diff", "copy", "import")
	if err != nil {
		return err
	}
	// `values import` is its own verb in every way that matters — a strict,
	// human-only, per-environment batch write with a precondition — so it takes
	// its own flag set rather than sharing this one's. It rides the `values`
	// family because the api-cli-surface ADR spells it `values import` and the
	// noun-verb taxonomy is closed.
	if sub == "import" {
		return runValuesImport(ctx, ios, rest)
	}

	var format, valueFile, left, right, source, destinations, keyNames, environments string
	var clear, reveal, stdin, dangerous, confirmProtected bool
	var outputFile string
	st, flags, err := parseCommon("values "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "list" || sub == "get" || sub == "diff" {
			fs.BoolVar(&reveal, "reveal", false,
				"disclose `secret` plaintext; audited per key, and refused without the reveal capability")
		}
		if sub == "list" || sub == "get" || sub == "diff" {
			// The print triad for the reveal paths. `get` delivers one revealed
			// secret; `list` and `diff` deliver the WHOLE rendered output (it may
			// contain revealed secrets), so the same three flags guard all three.
			fs.StringVar(&outputFile, "output-file", "",
				"write the revealed output to a file this command creates (0600)")
			fs.BoolVar(&dangerous, "dangerously-print", false, "print the revealed output to stdout")
		}
		if sub == "declare" {
			fs.StringVar(&environments, "envs", "",
				"the environments to give this key a first value in, comma-separated")
		}
		if sub == "set" || sub == "declare" {
			fs.BoolVar(&stdin, "stdin", false, "read the value from stdin")
			fs.StringVar(&valueFile, "value-file", "", "read the value from a file the caller names")
		}
		if sub == "set" {
			fs.BoolVar(&clear, "clear", false, "clear the value to `absent`")
		}
		if sub == "diff" {
			fs.StringVar(&left, "left", "", "the left environment")
			fs.StringVar(&right, "right", "", "the right environment")
		}
		if sub == "copy" {
			fs.StringVar(&source, "from", "", "the source environment")
			fs.StringVar(&destinations, "to", "", "destination environments, comma-separated")
			fs.StringVar(&keyNames, "keys", "", "key names to copy, comma-separated")
			fs.BoolVar(&confirmProtected, "confirm-protected", false,
				"confirm a protected destination explicitly")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax first, before target resolution or session lookup, so a malformed
	// invocation answers the same exit code whether or not the caller is
	// logged in.
	switch sub {
	case "get", "set", "declare":
		if err := flags.checkTarget("values "+sub, "key", ""); err != nil {
			return err
		}
		if flags.positional() == "" {
			return failf(ExitUsage, "usage: hikyo values %s <KEY>", sub)
		}
	default:
		if err := flags.checkNoPositionals("values " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "diff" && (left == "" || right == ""):
		return failf(ExitUsage, "usage: hikyo values diff --left <env> --right <env> [--reveal]")
	case sub == "diff" && left == right:
		return failf(ExitUsage, "hikyo values diff compares two DIFFERENT environments")
	case sub == "copy" && (source == "" || destinations == "" || keyNames == ""):
		return failf(ExitUsage,
			"usage: hikyo values copy --from <env> --to <env,env> --keys <KEY,KEY> [--confirm-protected]")
	case sub == "set" && clear && (stdin || valueFile != ""):
		return failf(ExitUsage, "hikyo values set --clear takes no value")
	case sub == "declare" && environments == "":
		return failf(ExitUsage,
			"usage: hikyo values declare <KEY> --envs <env,env,env> (--stdin | --value-file PATH)")
	}

	// The value is read BEFORE the request is built and before the session is
	// touched, so a caller who mistypes the source of their value is told so
	// without a round trip carrying it.
	var value string
	if sub == "declare" || (sub == "set" && !clear) {
		value, err = readValue(ios, stdin, valueFile, flags.positional())
		if err != nil {
			return err
		}
	}

	// A revealing list or diff discloses its ENTIRE rendered output (it may carry
	// revealed secrets), so the print triad is checked BEFORE the request goes
	// out: a caller with nowhere to put the plaintext is refused before the
	// server ever reveals it, never after — the same pre-act preflight the
	// display-once ceremonies use. (`get` preflights per cell after the response,
	// because a config cell prints without the triad; list and diff cannot cheaply
	// separate the two, so they guard the whole output up front.)
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal,
	}
	if reveal && (sub == "list" || sub == "diff") {
		if err := disclose.Preflight(deliver); err != nil {
			return failf(ExitRefused, "the values have nowhere to go: %v", err)
		}
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		base, err := environmentValuesBase(project, resolved, flags, "values list")
		if err != nil {
			return err
		}
		var list apigen.ValueList
		if reveal {
			err = client.Do(ctx, http.MethodPost, base+"/reveal", nil, &list)
		} else {
			err = client.Do(ctx, http.MethodGet, base, nil, &list)
		}
		if err != nil {
			return err
		}
		if reveal {
			return emitRendered(f, valueTable(list), "revealed values", deliver)
		}
		return Render(ios.Stdout, f, valueTable(list))

	case "get":
		base, err := environmentValuesBase(project, resolved, flags, "values get")
		if err != nil {
			return err
		}
		target := base + "/" + url.PathEscape(flags.positional())
		var cell apigen.ValueCell
		if reveal {
			err = client.Do(ctx, http.MethodPost, target+"/reveal", nil, &cell)
		} else {
			err = client.Do(ctx, http.MethodGet, target, nil, &cell)
		}
		if err != nil {
			return err
		}
		return renderCell(ios, f, cell, outputFile, dangerous)

	case "set":
		base, err := environmentValuesBase(project, resolved, flags, "values set")
		if err != nil {
			return err
		}
		target := base + "/" + url.PathEscape(flags.positional())
		if clear {
			if err := client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(ios.Stderr, "cleared %s\n", flags.positional())
			return nil
		}
		var cell apigen.ValueCell
		if err := client.Do(ctx, http.MethodPut, target,
			apigen.SetValueRequest{Value: value}, &cell); err != nil {
			return err
		}
		return Render(ios.Stdout, f, valueTable(apigen.ValueList{Items: []apigen.ValueCell{cell}, Count: 1}))

	case "declare":
		// Declare-into-environments: ONE supplied plaintext into several
		// environments, authorized per destination and all-or-nothing. The
		// environments are named explicitly rather than taken from the target
		// resolution, because this verb addresses several of them at once.
		var list apigen.ValueList
		if err := client.Do(ctx, http.MethodPost, project+"/values/declare", apigen.DeclareValuesRequest{
			Key: flags.positional(), EnvironmentIds: splitList(environments), Value: value,
		}, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, valueTable(list))

	case "diff":
		var out apigen.ValueDiff
		if reveal {
			err = client.Do(ctx, http.MethodPost, project+"/values/diff/reveal",
				apigen.RevealDiffRequest{Left: left, Right: right}, &out)
		} else {
			err = client.Do(ctx, http.MethodGet,
				project+"/values/diff?left="+url.QueryEscape(left)+"&right="+url.QueryEscape(right), nil, &out)
		}
		if err != nil {
			return err
		}
		if reveal {
			return emitRendered(f, diffTable(out), "revealed value diff", deliver)
		}
		return Render(ios.Stdout, f, diffTable(out))

	case "copy":
		body := apigen.CopyValuesRequest{
			SourceEnvironmentId:       source,
			Keys:                      splitList(keyNames),
			DestinationEnvironmentIds: splitList(destinations),
		}
		if confirmProtected {
			body.ConfirmProtected = &confirmProtected
		}
		var result apigen.CopyValuesResult
		if err := client.Do(ctx, http.MethodPost, project+"/values/copy", body, &result); err != nil {
			return err
		}
		rows := make([][]string, 0, len(result.Copied))
		for _, c := range result.Copied {
			rows = append(rows, []string{c.Key, c.DestinationEnvironmentId})
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"KEY", "DESTINATION"}, Rows: rows, JSON: result,
		})
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo values: unhandled subverb %q", sub)
}

// environmentValuesBase addresses the environment a value lives in. The
// environment is required explicitly (or through `--env` / a context):
// guessing it is how a value lands in the wrong environment, which for this
// noun is the whole class of incident the tool exists to prevent.
func environmentValuesBase(project string, resolved Resolved, flags commonFlags, verb string) (string, error) {
	env, err := addressed(resolved, DimEnv, flags.Env, verb)
	if err != nil {
		return "", err
	}
	return project + "/environments/" + url.PathEscape(env) + "/values", nil
}

// readValue takes the plaintext from stdin, from a named file, or from a
// no-echo terminal prompt — never from argv.
//
// A malformed invocation (both sources, or no source available) is ExitUsage.
// A source that IS chosen but fails to READ — stdin, the named file, or the
// terminal — is an I/O/environment failure, not a usage error: it is reported
// as a bare error, which Report maps to the same bucket the trust store and
// state files use when their reads fail.
func readValue(ios IO, stdin bool, valueFile, keyName string) (string, error) {
	switch {
	case stdin && valueFile != "":
		return "", failf(ExitUsage, "hikyo values set takes --stdin or --value-file, not both")
	case stdin:
		raw, err := io.ReadAll(ios.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading the value from stdin: %w", err)
		}
		// One trailing newline is the shell's, not the operator's: `echo x |`
		// would otherwise store "x\n". Any other whitespace is the server's to
		// normalize, and it does.
		return strings.TrimSuffix(string(raw), "\n"), nil
	case valueFile != "":
		raw, err := os.ReadFile(valueFile)
		if err != nil {
			return "", fmt.Errorf("reading the value from %s: %w", valueFile, err)
		}
		return strings.TrimSuffix(string(raw), "\n"), nil
	case ios.ReadPassword == nil:
		return "", failf(ExitUsage, valuesSetUsage)
	default:
		value, err := ios.ReadPassword(fmt.Sprintf("value for %s: ", keyName))
		if err != nil {
			return "", fmt.Errorf("reading the value: %w", err)
		}
		return value, nil
	}
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// presenceWord renders the two-state presence model, and only ever those two
// words. There is no third one to render.
func presenceWord(set bool) string {
	if set {
		return "set"
	}
	return "absent"
}

// cellValue is what a table cell shows. A `secret` that was not revealed
// shows nothing at all rather than a placeholder that could be mistaken for
// the value.
func cellValue(c apigen.ValueCell) string {
	if c.Value == nil {
		return ""
	}
	return *c.Value
}

func valueTable(list apigen.ValueList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, c := range list.Items {
		rows = append(rows, []string{
			c.Name, string(c.Classification), presenceWord(c.Set), cellValue(c),
		})
	}
	return Table{Columns: valueColumns, Rows: rows, JSON: list}
}

func diffTable(d apigen.ValueDiff) Table {
	rows := make([][]string, 0, len(d.Items))
	for _, row := range d.Items {
		verdict := "unknown"
		switch {
		case row.Equal == nil:
			// Both sides `set`, at least one unreadable: whether two secrets
			// match is itself material, so it is not answered either way.
			verdict = "gated"
		case *row.Equal:
			verdict = "same"
		default:
			verdict = "different"
		}
		rows = append(rows, []string{
			row.Name, string(row.Classification), verdict,
			presenceWord(row.Left.Set) + " " + cellValue(row.Left),
			presenceWord(row.Right.Set) + " " + cellValue(row.Right),
		})
	}
	return Table{
		Columns: []string{"KEY", "CLASS", "VERDICT", "LEFT", "RIGHT"},
		Rows:    rows, JSON: d,
	}
}

// emitRendered delivers output that may contain revealed `secret` plaintext
// through the print triad: it renders to a buffer and hands the whole thing to
// disclose.Emit, so a revealing list or diff never reaches stdout except under
// the triad's own rules. Preflight has already run before the request, so a
// refusal here is the rare check/write race, not the common case.
func emitRendered(f Format, t Table, label string, deliver disclose.Options) error {
	var buf bytes.Buffer
	if err := Render(&buf, f, t); err != nil {
		return err
	}
	if _, err := disclose.Emit(label, strings.TrimRight(buf.String(), "\n"), deliver); err != nil {
		return failf(ExitRefused, "disclosing the values: %v", err)
	}
	return nil
}

// renderCell prints one cell. A revealed `secret` goes through the print
// triad; everything else is ordinary output.
func renderCell(ios IO, f Format, cell apigen.ValueCell, outputFile string, dangerous bool) error {
	secret := cell.Classification == apigen.Secret
	if !secret || !cell.Revealed {
		return Render(ios.Stdout, f, valueTable(apigen.ValueList{Items: []apigen.ValueCell{cell}, Count: 1}))
	}
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal,
	}
	if err := disclose.Preflight(deliver); err != nil {
		return failf(ExitRefused, "the value has nowhere to go: %v", err)
	}
	if _, err := disclose.Emit("value of "+cell.Name, cellValue(cell), deliver); err != nil {
		return failf(ExitRefused, "disclosing the value: %v", err)
	}
	return nil
}
