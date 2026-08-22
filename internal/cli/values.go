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
	"github.com/Hikyo-Org/hikyo/internal/dotenv"
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
func runValues(ctx context.Context, ios IO, args []string) (returnErr error) {
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

	var format, exportFormat, valueFile, left, right, source, destinations, keyNames, environments string
	var versions, previewToken, confirmedProtectedEnvironments, acknowledge string
	var revision int64
	var clear, reveal, stdin, dangerous, confirmProtected bool
	var outputFile string
	st, flags, err := parseCommon("values "+sub, ios, rest, func(fs *flag.FlagSet) {
		// `export` is an export PATH, so its payload encoding is `--format`
		// (api-cli-surface ADR: `--format` names the payload on export paths, `-o`
		// names the envelope on browse paths). Every other verb here is a browse
		// path and takes `-o`.
		if sub == "export" {
			fs.StringVar(&exportFormat, "format", "table", "payload format: table, json, or dotenv")
		} else {
			fs.StringVar(&format, "o", "table", "output format: table or json")
		}
		if sub == "list" || sub == "get" || sub == "diff" || sub == "export" {
			fs.BoolVar(&reveal, "reveal", false,
				"disclose `secret` plaintext; audited per key, and refused without the reveal capability")
		}
		if sub == "publish" {
			fs.StringVar(&versions, "versions", "",
				"the pending-change version ids to publish, comma-separated")
			fs.StringVar(&previewToken, "preview-token", "",
				"the exact-input token returned by a restore preview")
			fs.StringVar(&confirmedProtectedEnvironments, "confirm-protected", "",
				"exact protected environment ids reviewed by machine automation, comma-separated")
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
			fs.StringVar(&acknowledge, "acknowledge", "",
				"secret-scanning keep-as-config token(s) from a prior warning, comma-separated")
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
	// `export` carries the extra `dotenv` payload format; everything else is the
	// two-value envelope. dotenv is resolved in the export case below.
	dotenvExport := sub == "export" && exportFormat == "dotenv"
	var f Format
	if sub == "export" {
		if !dotenvExport {
			f, err = ParseFormat(exportFormat)
		}
	} else {
		f, err = ParseFormat(format)
	}
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
	// revealed secrets), so the print-triad destination is reserved BEFORE the request goes
	// out: a caller with nowhere to put the plaintext is refused before the
	// server ever reveals it. (`get` prepares per cell after the response,
	// because a config cell prints without the triad; list and diff cannot cheaply
	// separate the two, so they guard the whole output up front.)
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout,
	}
	var sink *disclose.PreparedSink
	if reveal && (sub == "list" || sub == "diff" || sub == "export") {
		sink, err = ios.prepareDisclosure(deliver)
		if err != nil {
			return failf(ExitRefused, "the values have nowhere to go: %v", err)
		}
		defer sink.AbortOnReturn(&returnErr)
	}

	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}
	// ceremony wraps a disclosure in the reauthentication ceremony over the
	// environments it discloses in (reveal_window.go): the call is made, and on
	// the server's refusal a window is opened by inline TOTP and the call made
	// once more. Non-revealing reads never go through it.
	// The enumerated unit a browser handoff binds, resolved only when one is
	// needed: the secret keys the act opens in the environment (all of them,
	// or the named subset).
	unit := func(names []string) func(context.Context, string) ([]string, error) {
		return func(ctx context.Context, env string) ([]string, error) {
			return keyIDsOf(ctx, client, project, env, apigen.KeyClassificationSecret, names)
		}
	}
	ceremony := func(envs []string, d disclosure, attempt func() error) error {
		return withRevealCeremony(ctx, client, st, ios, artifact, project, envs, d, attempt)
	}

	switch sub {
	case "list":
		base, err := environmentValuesBase(project, resolved, flags, "values list")
		if err != nil {
			return err
		}
		var list apigen.ValueList
		if reveal {
			err = ceremony([]string{resolved.Get(DimEnv)}, disclosure{purpose: "reveal", keys: unit(nil)}, func() error {
				return client.Do(ctx, http.MethodPost, base+"/reveal", nil, &list)
			})
		} else {
			err = client.Do(ctx, http.MethodGet, base, nil, &list)
		}
		if err != nil {
			return err
		}
		if reveal {
			return emitRendered(f, valueTable(list), "revealed values", sink)
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
			err = ceremony([]string{resolved.Get(DimEnv)}, disclosure{purpose: "reveal", keys: unit([]string{flags.positional()})}, func() error {
				return client.Do(ctx, http.MethodPost, target+"/reveal", nil, &cell)
			})
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
			apigen.SetValueRequest{Value: value, Acknowledgements: acksPtr(acknowledge)}, &staged); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "staged %s (%s); publish it with: hikyo values publish --versions %s\n",
			staged.Name, staged.Operation, staged.VersionId)
		warnFindings(ios, staged.Findings)
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
		warnFindings(ios, list.Findings)
		return Render(ios.Stdout, f, valueTable(list))

	case "diff":
		var out apigen.ValueDiff
		if reveal {
			err = ceremony([]string{left, right}, disclosure{purpose: "reveal", keys: unit(nil)}, func() error {
				return client.Do(ctx, http.MethodPost, project+"/values/diff/reveal",
					apigen.RevealDiffRequest{Left: left, Right: right}, &out)
			})
		} else {
			err = client.Do(ctx, http.MethodGet,
				project+"/values/diff?left="+url.QueryEscape(left)+"&right="+url.QueryEscape(right), nil, &out)
		}
		if err != nil {
			return err
		}
		if reveal {
			return emitRendered(f, diffTable(out), "revealed value diff", sink)
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
		// A copy that carries secret material opens it under the source
		// environment's reveal guard (values service: the reveal conjunct
		// consumes the session's window over the SOURCE); a config-only copy
		// is refused by nothing here and therefore never prompts.
		if err := ceremony([]string{source}, disclosure{purpose: "copy", keys: unit(splitList(keyNames))}, func() error {
			return client.Do(ctx, http.MethodPost, project+"/values/copy", body, &result)
		}); err != nil {
			return err
		}
		warnFindings(ios, result.Findings)
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
		environment, err := addressed(resolved, DimEnv, flags.Env, "values publish")
		if err != nil {
			return err
		}
		base := project + "/environments/" + url.PathEscape(environment)
		var result apigen.PublishResult
		body := apigen.PublishRequest{VersionIds: splitList(versions)}
		if previewToken != "" {
			body.PreviewToken = &previewToken
		}
		if confirmedProtectedEnvironments != "" {
			body.ConfirmedProtectedEnvironments = publishProtectedIDs(confirmedProtectedEnvironments)
		}
		if err := client.Do(ctx, http.MethodPost, base+"/publish",
			body, &result); err != nil {
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
		exportEnv := resolved.Get(DimEnv)
		// An export's unit is the secret keys of the REVISION it covers, not
		// of the current list: a key added, deleted or reclassified since then
		// would otherwise make the consent set differ from the exported set
		// (api-cli-surface ADR line 144, "the full key set the export covers").
		exportUnit := func(ctx context.Context, env string) ([]string, error) {
			return exportSecretKeyIDs(ctx, client, project, base, env, revision)
		}
		if err := ceremony([]string{exportEnv}, disclosure{purpose: "reveal", keys: exportUnit}, func() error {
			return client.Do(ctx, http.MethodPost, base+"/values/export", body, &out)
		}); err != nil {
			return err
		}
		if dotenvExport {
			return exportDotenv(ios, out, reveal, sink)
		}
		if reveal {
			return emitRendered(f, exportTable(out), "exported values", sink)
		}
		return Render(ios.Stdout, f, exportTable(out))
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo values: unhandled subverb %q", sub)
}

// exportDotenv renders an export as `NAME=value` lines through
// internal/compose's raw encoder, so the escaping is byte-identical to what the
// Compose renderer would deliver. Secrets appear only under `--reveal` (the
// server returns their plaintext then, and the output goes through the print
// triad because it may carry secret material); without `--reveal` every secret
// is omitted and their count is reported on stderr. Values are written through
// internal/dotenv's quoting encoder, so what `values import --from-dotenv`
// reads back is byte-exact (surrounding whitespace, quotes, `#`, newlines).
func exportDotenv(ios IO, out apigen.ExportedValues, reveal bool, sink *disclose.PreparedSink) error {
	var rows []dotenv.Entry
	omitted := 0
	for _, item := range out.Items {
		if item.Value == nil {
			// An unrevealed secret is omitted and counted; an unset key simply has
			// no line.
			if item.Classification == apigen.KeyClassificationSecret {
				omitted++
			}
			continue
		}
		rows = append(rows, dotenv.Entry{Key: item.Name, Value: *item.Value})
	}
	content, refusals, err := dotenv.Encode(rows)
	if err != nil {
		return failf(ExitInternal, "encoding the dotenv export: %v", err)
	}
	if len(refusals) > 0 {
		names := make([]string, 0, len(refusals))
		for _, r := range refusals {
			names = append(names, fmt.Sprintf("%s (%s)", r.Key, r.Reason))
		}
		return failf(ExitRefused,
			"hikyo values export --format dotenv: %s cannot be represented as a dotenv line; export as json instead",
			strings.Join(names, ", "))
	}
	body := strings.TrimRight(string(content), "\n")
	if reveal {
		if _, err := sink.WriteOnce("exported values (dotenv)", body); err != nil {
			return failf(ExitRefused, "disclosing the values: %v", err)
		}
	} else if _, err := ios.Stdout.Write(content); err != nil {
		return err
	}
	if omitted > 0 {
		fmt.Fprintf(ios.Stderr, "omitted %d secret(s); re-run with --reveal to include them\n", omitted)
	}
	return nil
}

func publishProtectedIDs(raw string) *[]apigen.ID {
	names := splitList(raw)
	confirmed := make([]apigen.ID, 0, len(names))
	for _, envID := range names {
		confirmed = append(confirmed, apigen.ID(envID))
	}
	return &confirmed
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
	default:
		value, err := ios.readPassword(fmt.Sprintf("value for %s: ", keyName))
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
// PreparedSink.WriteOnce, so a revealing list or diff never reaches stdout
// except under the triad's own rules. The destination was reserved before the
// request, so this writes to exactly the destination that admitted the act.
func emitRendered(f Format, t Table, label string, sink *disclose.PreparedSink) error {
	var buf bytes.Buffer
	if err := Render(&buf, f, t); err != nil {
		return err
	}
	if _, err := sink.WriteOnce(label, strings.TrimRight(buf.String(), "\n")); err != nil {
		return failf(ExitRefused, "disclosing the values: %v", err)
	}
	return nil
}

// renderCell prints one cell. A revealed `secret` goes through the print
// triad; everything else is ordinary output.
func renderCell(ios IO, f Format, cell apigen.ValueCell, outputFile string, dangerous bool) (returnErr error) {
	secret := cell.Classification == apigen.KeyClassificationSecret
	if !secret || !cell.Revealed {
		return Render(ios.Stdout, f, valueTable(apigen.ValueList{Items: []apigen.ValueCell{cell}, Count: 1}))
	}
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout,
	}
	sink, err := ios.prepareDisclosure(deliver)
	if err != nil {
		return failf(ExitRefused, "the value has nowhere to go: %v", err)
	}
	defer sink.AbortOnReturn(&returnErr)
	if _, err := sink.WriteOnce("value of "+cell.Name, cellValue(cell)); err != nil {
		return failf(ExitRefused, "disclosing the value: %v", err)
	}
	return nil
}

// keyIDsOf resolves the enumerated unit of a disclosure in one environment:
// the ids of its keys of one classification (all of them, or the named
// subset). It reads the non-revealing list, which discloses nothing; the ids
// are what the browser ceremony binds and what the disclosure then consumes.
func keyIDsOf(ctx context.Context, client *Client, projectBase, env string, class apigen.KeyClassification, names []string) ([]string, error) {
	var list apigen.ValueList
	if err := client.Do(ctx, http.MethodGet, projectBase+"/environments/"+url.PathEscape(env)+"/values", nil, &list); err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var out []string
	for _, cell := range list.Items {
		if cell.Classification != class {
			continue
		}
		if len(wanted) > 0 && !wanted[cell.Name] {
			continue
		}
		out = append(out, string(cell.KeyId))
	}
	return out, nil
}

// exportSecretKeyIDs resolves an export's unit from the revision it covers:
// the non-revealing export names the secret keys of that revision, and the
// project catalogue maps names to ids. A key the catalogue no longer holds
// cannot be bound and refuses by name rather than consenting to a narrower
// set than the export would open.
func exportSecretKeyIDs(ctx context.Context, client *Client, projectBase, envBase, env string, revision int64) ([]string, error) {
	body := apigen.ExportValuesRequest{}
	if revision > 0 {
		body.Revision = &revision
	}
	var covered apigen.ExportedValues
	if err := client.Do(ctx, http.MethodPost, envBase+"/values/export", body, &covered); err != nil {
		return nil, err
	}
	var catalogue apigen.KeyList
	if err := client.Do(ctx, http.MethodGet, projectBase+"/keys", nil, &catalogue); err != nil {
		return nil, err
	}
	ids := map[string]string{}
	for _, k := range catalogue.Items {
		ids[string(k.Name)] = string(k.Id)
	}
	var out, missing []string
	for _, item := range covered.Items {
		if item.Classification != apigen.KeyClassificationSecret {
			continue
		}
		id, ok := ids[string(item.Name)]
		if !ok {
			missing = append(missing, string(item.Name))
			continue
		}
		out = append(out, id)
	}
	if len(missing) > 0 {
		return nil, failf(ExitRefused, "the export covers secret key(s) the catalogue no longer declares (%s); a ceremony cannot be bound to them - export the current revision, or reveal in the browser", strings.Join(missing, ", "))
	}
	return out, nil
}
