package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
	"github.com/Hikyo-Org/hikyo/internal/dotenv"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// runDefinitions is the reviewable definitions Git flow. Check deliberately
// owns a 0/1/2 contract distinct from the CLI-wide exit taxonomy: 1 means
// drift, and every actual check error maps to 2.
func runDefinitions(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("definitions", args, "export", "check", "plan", "apply", "scaffold")
	if err != nil {
		return err
	}
	// `scaffold` is a PURE LOCAL TRANSFORM (source-of-truth ADR § Onboarding
	// under a closed schema): it reads only the file it is given, contacts no
	// server, and holds no authority — so it never constructs a client or touches
	// a session, and is handled here before any target resolution.
	if sub == "scaffold" {
		return runDefinitionsScaffold(ios, rest)
	}
	if sub == "check" {
		if err := runDefinitionsVerb(ctx, ios, sub, rest); err != nil {
			var outcome *silentExit
			if asSilentExit(err, &outcome) {
				return outcome
			}
			return &Error{Code: ExitUsage, Err: err}
		}
		return nil
	}
	return runDefinitionsVerb(ctx, ios, sub, rest)
}

func asSilentExit(err error, out **silentExit) bool {
	return errors.As(err, out)
}

func runDefinitionsVerb(ctx context.Context, ios IO, sub string, args []string) error {
	var format, file, outputFile, planID, commit, ref, actor, acknowledge string
	var portable, allowDelete bool
	st, flags, err := parseCommon("definitions "+sub, ios, args, func(fs *flag.FlagSet) {
		if sub == "check" || sub == "plan" || sub == "apply" {
			fs.StringVar(&format, "o", "table", "output format: table or json")
		}
		if sub == "check" || sub == "plan" || sub == "apply" {
			fs.StringVar(&file, "file", "", "canonical definitions bundle")
		}
		if sub == "export" {
			fs.BoolVar(&portable, "portable", false, "strip server-owned ids and the base revision")
			fs.StringVar(&outputFile, "output-file", "", "create this file with the canonical bundle bytes")
		}
		// Surface-2 override tokens: `plan` scans the bundle before it persists,
		// `apply` re-scans on ruleset-snapshot skew (#74 SS3).
		if sub == "plan" || sub == "apply" {
			ackFlag(fs, &acknowledge)
		}
		if sub == "apply" {
			fs.StringVar(&planID, "plan", "", "immutable definitions plan id")
			fs.BoolVar(&allowDelete, "allow-delete", false, "accept the concrete deletions shown by the plan")
			fs.StringVar(&commit, "commit", "", "source commit label")
			fs.StringVar(&ref, "ref", "", "source ref label")
			fs.StringVar(&actor, "actor", "", "source automation actor label")
		}
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("definitions " + sub); err != nil {
		return err
	}
	switch {
	case (sub == "check" || sub == "plan") && file == "":
		return failf(ExitUsage, "usage: hikyo definitions %s --file PATH [-o table|json]", sub)
	case sub == "apply" && planID == "":
		return failf(ExitUsage, "usage: hikyo definitions apply --plan ID [--file PATH] [--allow-delete]")
	}

	var f Format
	if sub != "export" {
		f, err = ParseFormat(format)
		if err != nil {
			return err
		}
	}

	var canonical []byte
	if file != "" {
		canonical, _, err = readDefinitionsBundle(file)
		if err != nil {
			return err
		}
	}
	if sub == "export" && outputFile != "" {
		if err := disclose.Preflight(disclose.Options{OutputFile: outputFile}); err != nil {
			return failf(ExitRefused, "writing the definitions bundle: %v", err)
		}
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	base += "/definitions"

	switch sub {
	case "export":
		params := url.Values{}
		if portable {
			params.Set("portable", "true")
		}
		path := base + "/export"
		if query := params.Encode(); query != "" {
			path += "?" + query
		}
		var raw []byte
		if err := client.Do(ctx, http.MethodGet, path, nil, &raw); err != nil {
			return err
		}
		if outputFile == "" {
			_, err = ios.Stdout.Write(raw)
			return err
		}
		if _, err := disclose.Emit("definitions bundle", strings.TrimSuffix(string(raw), "\n"), disclose.Options{OutputFile: outputFile}); err != nil {
			return failf(ExitRefused, "writing the definitions bundle: %v", err)
		}
		if pathInsideGitWorktree(outputFile) {
			fmt.Fprintf(ios.Stderr, "warning: %s is inside a Git worktree; review the exported definitions before committing it\n", outputFile)
		}
		return nil

	case "check":
		var result apigen.DefinitionsCheckResult
		if err := client.Do(ctx, http.MethodPost, base+"/check", json.RawMessage(canonical), &result); err != nil {
			return err
		}
		if err := Render(ios.Stdout, f, definitionsCheckTable(result)); err != nil {
			return err
		}
		// Non-blocking secret-scanning warnings (#74 SS3): check is a dry-run, so
		// findings ride the success response to stderr and never change the drift
		// exit contract. They warn that a `plan` would be refused.
		checkFindings(ios, result.Findings)
		if result.State != apigen.Equal {
			return &silentExit{Code: 1}
		}
		return nil

	case "plan":
		path := base + "/plans"
		if acks := splitList(acknowledge); len(acks) > 0 {
			path += "?acknowledge=" + url.QueryEscape(strings.Join(acks, ","))
		}
		var result apigen.DefinitionsPlanResponse
		if err := client.Do(ctx, http.MethodPost, path, json.RawMessage(canonical), &result); err != nil {
			return err
		}
		return Render(ios.Stdout, f, definitionsPlanTable(result))

	case "apply":
		body := apigen.ApplyDefinitionsPlanRequest{AllowDelete: allowDelete}
		body.Commit, body.Ref, body.Actor = optional(commit), optional(ref), optional(actor)
		body.Acknowledgements = acksPtr(acknowledge)
		if file != "" {
			_, digest, err := readDefinitionsBundle(file)
			if err != nil {
				return err
			}
			body.Digest = &digest
		}
		var result apigen.ApplyDefinitionsPlanResult
		if err := client.Do(ctx, http.MethodPost, base+"/plans/"+url.PathEscape(planID)+"/apply", body, &result); err != nil {
			return err
		}
		return Render(ios.Stdout, f, definitionsApplyTable(result))
	}
	return failf(ExitInternal, "hikyo definitions: unhandled subverb %q", sub)
}

// scaffoldTODO is the reviewer marker every scaffolded key carries. It rides
// the key's `description` because a bundle is JSON — there is no comment channel
// — and it is echoed to stderr per run so the marker cannot pass silently
// (source-of-truth ADR: scaffold "refuses to be silent about it").
const scaffoldTODO = "TODO: classify"

// runDefinitionsScaffold turns a plaintext `.env` into an ADDITIVE definitions
// bundle on stdout, offline. Every key is emitted as `config` with a
// string-typed declaration and a `# TODO: classify` marker: scaffold never
// contacted a server, so it cannot know classification and must not guess
// (source-of-truth ADR § Onboarding under a closed schema). The output is
// additive (no base_revision), so the user reviews it, commits it, and applies
// it, after which `values import` runs strict against an already-declared
// schema.
func runDefinitionsScaffold(ios IO, args []string) error {
	fs := flag.NewFlagSet("definitions scaffold", flag.ContinueOnError)
	fs.SetOutput(ios.Stderr)
	from := fs.String("from", "", "the .env file to scaffold a definitions bundle from")
	if err := fs.Parse(args); err != nil {
		return &Error{Code: ExitUsage, Err: err}
	}
	if fs.NArg() > 0 {
		return failf(ExitUsage, "hikyo definitions scaffold takes no positional arguments, got: %s", strings.Join(fs.Args(), " "))
	}
	if *from == "" {
		return failf(ExitUsage, "usage: hikyo definitions scaffold --from <.env>")
	}
	raw, err := os.ReadFile(*from)
	if err != nil {
		return failf(ExitUsage, "reading %s: %v", *from, err)
	}
	entries, err := dotenv.Parse(raw)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}

	bundle := definitions.Bundle{Keys: make([]definitions.Key, 0, len(entries))}
	for _, e := range entries {
		bundle.Keys = append(bundle.Keys, definitions.Key{
			Name:           e.Key,
			Classification: string(schema.Config),
			Description:    scaffoldTODO,
			Declaration:    schema.Declaration{Rule: &schema.Rule{Type: schema.TypeString}},
			RequiredIn:     definitions.Presence{Mode: string(schema.PresenceNone)},
			ForbiddenIn:    definitions.Presence{Mode: string(schema.PresenceNone)},
		})
	}
	normalized, err := definitions.Normalize(bundle)
	if err != nil {
		return failf(ExitInternal, "%v", err)
	}
	out, err := definitions.Encode(normalized)
	if err != nil {
		return failf(ExitInternal, "%v", err)
	}
	if _, err := ios.Stdout.Write(out); err != nil {
		return err
	}
	fmt.Fprintf(ios.Stderr,
		"scaffold: %d keys emitted as config — review and classify before apply (# %s)\n",
		len(entries), scaffoldTODO)
	return nil
}

func readDefinitionsBundle(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", failf(ExitUsage, "reading definitions bundle %s: %v", path, err)
	}
	bundle, err := definitions.Parse(raw)
	if err != nil {
		return nil, "", failf(ExitRefused, "%v", err)
	}
	canonical, err := definitions.Encode(bundle)
	if err != nil {
		return nil, "", err
	}
	digest, err := definitions.Digest(bundle)
	if err != nil {
		return nil, "", err
	}
	return canonical, digest, nil
}

func definitionsCheckTable(result apigen.DefinitionsCheckResult) Table {
	rows := [][]string{{"state", string(result.State)}, {"base_revision", revisionPointer(result.BaseRevision)}, {"current_revision", strconv.FormatInt(result.CurrentRevision, 10)}}
	rows = append(rows, definitionsDiffRows(result.Differences)...)
	return Table{Columns: []string{"FIELD", "VALUE"}, Rows: rows, JSON: result}
}

func definitionsPlanTable(result apigen.DefinitionsPlanResponse) Table {
	p := result.Plan
	rows := [][]string{
		{"plan_id", p.Id}, {"digest", p.Digest}, {"base_revision", revisionPointer(p.BaseRevision)},
		{"current_revision", strconv.FormatInt(p.CurrentRevision, 10)}, {"additive", strconv.FormatBool(p.Additive)},
		{"expires_at", p.ExpiresAt.Format(time.RFC3339)},
		{"protected_environments", strings.Join(p.ProtectedEnvironments, ",")},
		{"deletions_present", strconv.FormatBool(p.DeletionsPresent)},
	}
	rows = append(rows, planDiffRows(p.Diff)...)
	for _, name := range p.RevealRequired {
		rows = append(rows, []string{"reveal_required", name})
	}
	return Table{Columns: []string{"FIELD", "VALUE"}, Rows: rows, JSON: result}
}

func definitionsApplyTable(result apigen.ApplyDefinitionsPlanResult) Table {
	return Table{
		Columns: []string{"FIELD", "VALUE"},
		Rows:    [][]string{{"plan_id", result.PlanId}, {"revision", strconv.FormatInt(result.Revision, 10)}, {"published", strings.Join(result.Published, ",")}},
		JSON:    result,
	}
}

func definitionsDiffRows(diff apigen.DefinitionsDiff) [][]string {
	rows := kindDiffRows("environment", diff.Environments)
	rows = append(rows, kindDiffRows("key_group", diff.KeyGroups)...)
	rows = append(rows, kindDiffRows("key", diff.Keys)...)
	for _, name := range diff.RevealRequired {
		rows = append(rows, []string{"reveal_required", name})
	}
	return rows
}

func planDiffRows(diff apigen.DefinitionsPlanDiff) [][]string {
	rows := kindDiffRows("environment", diff.Environments)
	rows = append(rows, kindDiffRows("key_group", diff.KeyGroups)...)
	rows = append(rows, kindDiffRows("key", diff.Keys)...)
	for _, deletion := range diff.KeyDeletions {
		rows = append(rows, []string{"delete_key_impact", deletion.Name + " (live in " + strings.Join(deletion.LiveIn, ",") + ")"})
	}
	for _, deletion := range diff.EnvDeletions {
		rows = append(rows, []string{"delete_environment_impact", fmt.Sprintf("%s (%d live occurrences)", deletion.Name, deletion.Occurrences)})
	}
	return rows
}

func kindDiffRows(kind string, diff apigen.DefinitionsKindDiff) [][]string {
	var rows [][]string
	for _, name := range diff.Creates {
		rows = append(rows, []string{kind + " create", name})
	}
	for _, name := range diff.Updates {
		rows = append(rows, []string{kind + " update", name})
	}
	for _, rename := range diff.Renames {
		rows = append(rows, []string{kind + " rename", rename.From + " -> " + rename.To})
	}
	for _, name := range diff.Deletes {
		rows = append(rows, []string{kind + " delete", name})
	}
	return rows
}

func revisionPointer(revision *int64) string {
	if revision == nil {
		return ""
	}
	return strconv.FormatInt(*revision, 10)
}

func pathInsideGitWorktree(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	dir := filepath.Dir(abs)
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
