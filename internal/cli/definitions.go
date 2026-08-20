package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

// runDefinitions is the reviewable definitions Git flow. Check deliberately
// owns a 0/1/2 contract distinct from the CLI-wide exit taxonomy: 1 means
// drift, and every actual check error maps to 2.
func runDefinitions(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("definitions", args, "export", "check", "plan", "apply")
	if err != nil {
		return err
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
	status, ok := err.(*silentExit)
	if ok {
		*out = status
	}
	return ok
}

func runDefinitionsVerb(ctx context.Context, ios IO, sub string, args []string) error {
	var format, file, outputFile, planID, commit, ref, actor string
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
		if result.State != apigen.Equal {
			return &silentExit{Code: 1}
		}
		return nil

	case "plan":
		var result apigen.DefinitionsPlanResponse
		if err := client.Do(ctx, http.MethodPost, base+"/plans", json.RawMessage(canonical), &result); err != nil {
			return err
		}
		return Render(ios.Stdout, f, definitionsPlanTable(result))

	case "apply":
		body := apigen.ApplyDefinitionsPlanRequest{AllowDelete: allowDelete}
		body.Commit, body.Ref, body.Actor = optional(commit), optional(ref), optional(actor)
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
		{"expires_at", p.ExpiresAt.Format("2006-01-02T15:04:05Z")},
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
