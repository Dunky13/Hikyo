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
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
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
	sub, rest, err := subverb("values", args,
		"list", "get", "set", "declare", "diff", "copy", "import", "publish", "export", "pending")
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
	var versions string
	var revision int64
	var clear, reveal, stdin, dangerous, confirmProtected bool
	var outputFile string
	st, flags, err := parseCommon("values "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "list" || sub == "get" || sub == "diff" || sub == "export" {
			fs.BoolVar(&reveal, "reveal", false,
				"disclose `secret` plaintext; audited per key, and refused without the reveal capability")
		}
		if sub == "publish" {
			fs.StringVar(&versions, "versions", "",
				"the pending-change version ids to publish, comma-separated")
		}
		if sub == "export" {
			fs.Int64Var(&revision, "revision", 0,
				"the revision to export; omitted means the latest")
		}
		if sub == "list" || sub == "get" || sub == "diff" || sub == "export" {
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
	case sub == "publish" && versions == "":
		return failf(ExitUsage, "usage: hikyo values publish --versions <id,id> [--env <env>]")
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
	if reveal && (sub == "list" || sub == "diff" || sub == "export") {
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
		// Both directions STAGE (#51). What comes back is the immutable version
		// id a later `values publish` names, not a cell: nothing delivers yet,
		// and rendering a cell here would say otherwise.
		var staged apigen.PendingChange
		if clear {
			if err := client.Do(ctx, http.MethodDelete, target, nil, &staged); err != nil {
				return err
			}
		} else if err := client.Do(ctx, http.MethodPut, target,
			apigen.SetValueRequest{Value: value}, &staged); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "staged %s (%s); publish it with: hikyo values publish --versions %s\n",
			staged.Name, staged.Operation, staged.VersionId)
		return Render(ios.Stdout, f, pendingTable(staged))

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
	case "publish":
		// SELECTIVE by construction: the verb takes version ids, not key
		// names. A publish carries exactly the drafts it names plus whatever
		// key-group closure requires, and the result says which was which.
		base, err := environmentBase(project, resolved, flags, "values publish")
		if err != nil {
			return err
		}
		var result apigen.PublishResult
		if err := client.Do(ctx, http.MethodPost, base+"/publish",
			apigen.PublishRequest{VersionIds: splitList(versions)}, &result); err != nil {
			return err
		}
		return Render(ios.Stdout, f, publishTable(result))

	case "pending":
		// The caller's own working state for one environment, plus the
		// write-presence marker for everybody else's. It is what supplies the
		// version ids `values publish` names.
		base, err := environmentBase(project, resolved, flags, "values pending")
		if err != nil {
			return err
		}
		var signals apigen.EnvironmentSignals
		if err := client.Do(ctx, http.MethodGet, base+"/signals", nil, &signals); err != nil {
			return err
		}
		return Render(ios.Stdout, f, signalsTable(signals))

	case "export":
		// The one bulk-disclosure verb, and what "fetch resolved" actually is:
		// it reads a COMMITTED SNAPSHOT, never live values.
		base, err := environmentBase(project, resolved, flags, "values export")
		if err != nil {
			return err
		}
		body := apigen.ExportValuesRequest{}
		if reveal {
			body.Reveal = &reveal
		}
		if revision > 0 {
			body.Revision = &revision
		}
		var out apigen.ExportedValues
		if err := client.Do(ctx, http.MethodPost, base+"/values/export", body, &out); err != nil {
			return err
		}
		if reveal {
			return emitRendered(f, exportTable(out), "exported values", deliver)
		}
		return Render(ios.Stdout, f, exportTable(out))
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo values: unhandled subverb %q", sub)
}

// environmentBase addresses one environment. The environment is required
// explicitly (or through `--env` / a context) for the same reason
// environmentValuesBase requires it: guessing it is how a publish lands in the
// wrong environment.
func environmentBase(project string, resolved Resolved, flags commonFlags, verb string) (string, error) {
	env, err := addressed(resolved, DimEnv, flags.Env, verb)
	if err != nil {
		return "", err
	}
	return project + "/environments/" + url.PathEscape(env), nil
}

func pendingTable(c apigen.PendingChange) Table {
	return Table{
		Columns: []string{"KEY", "CLASS", "OPERATION", "VERSION", "STAGED FROM"},
		Rows: [][]string{{
			c.Name, string(c.Classification), string(c.Operation), c.VersionId,
			strconv.FormatInt(c.StagedFromRevision, 10),
		}},
		JSON: c,
	}
}

func publishTable(r apigen.PublishResult) Table {
	rows := make([][]string, 0, len(r.Environments))
	for _, env := range r.Environments {
		rows = append(rows, []string{
			env.EnvironmentId,
			strconv.FormatInt(env.Revision, 10),
			strconv.Itoa(len(env.ChangedKeys)),
			env.ChangeToken,
		})
	}
	return Table{
		Columns: []string{"ENVIRONMENT", "REVISION", "CHANGED", "CHANGE TOKEN"},
		Rows:    rows, JSON: r,
	}
}

func signalsTable(s apigen.EnvironmentSignals) Table {
	rows := make([][]string, 0, len(s.Cells))
	for _, cell := range s.Cells {
		pending := ""
		if cell.PendingVersionId != nil {
			pending = *cell.PendingVersionId
		}
		others := ""
		if cell.PendingByOthers {
			others = "yes"
		}
		changed := ""
		if cell.ChangedInRevision != nil {
			changed = strconv.FormatInt(*cell.ChangedInRevision, 10)
		}
		rows = append(rows, []string{cell.Name, string(cell.Classification), pending, others, changed})
	}
	return Table{
		Columns: []string{"KEY", "CLASS", "PENDING VERSION", "OTHERS PENDING", "CHANGED IN"},
		Rows:    rows, JSON: s,
	}
}

func exportTable(e apigen.ExportedValues) Table {
	rows := make([][]string, 0, len(e.Items))
	for _, item := range e.Items {
		// A value is printed only where the server says it was REVEALED. An
		// unrevealed `secret` prints nothing rather than an empty string a
		// reader could not tell from an empty value.
		value := ""
		if item.Value != nil {
			value = *item.Value
		}
		rows = append(rows, []string{item.Name, string(item.Classification), value})
	}
	return Table{Columns: []string{"KEY", "CLASS", "VALUE"}, Rows: rows, JSON: e}
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
