package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
	"github.com/Hikyo-Org/hikyo/internal/importer"
)

// The interactive import wizard's CLI surface (import-paths ADR § Entry modes).
// `hikyo import` with no source arguments on a TTY enters it. The engine lives in
// internal/importer and is I/O-agnostic; this file supplies the impure surface —
// the terminal, the connector reads, the environment list and the server
// presence read — and drives artifact emission for the multi-environment plan
// the engine returns.

// runImportWizard resolves the target project (which must pre-exist), then walks
// the interactive session under the aggregate session deadline and emits the
// project's artifacts.
func runImportWizard(ctx context.Context, ios IO, c commonFlags, outDir string) error {
	st, err := NewState(ios.Env)
	if err != nil {
		return err
	}
	client, _, resolved, err := authenticatedTarget(st, ios, c)
	if err != nil {
		return err
	}
	projectBasePath, err := projectBase(resolved)
	if err != nil {
		return err
	}
	projectID, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}

	// The whole session runs under the aggregate wall-clock bound; each connector
	// read and each presence read inherits it.
	ctx, cancel := context.WithTimeout(ctx, importer.SessionDeadline)
	defer cancel()

	host := &cliWizardHost{
		terminalPrompter: newTerminalPrompter(ios),
		ctx:              ctx, client: client, projectBase: projectBasePath,
	}
	plan, err := importer.Wizard(host, projectID)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}
	// The session may have paused on a prompt past its deadline without any
	// network call observing the expiry (a create-only session makes no read
	// after the source). Refuse before emitting rather than write artifacts a
	// stale session authored.
	if err := ctx.Err(); err != nil {
		return failf(ExitRefused, "the import session exceeded its %s deadline before emitting artifacts", importer.SessionDeadline)
	}
	valuesPaths, err := writeProjectArtifacts(ios, outDir, plan)
	if err != nil {
		return err
	}
	return reportProject(ios, plan, outDir, host.sourceFiles, valuesPaths)
}

// cliWizardHost is the impure WizardHost the engine calls. It never prints an
// artifact to stdout — prompts go to stderr through the prompter, and the values
// files go through the secret-file discipline in writeProjectArtifacts.
type cliWizardHost struct {
	*terminalPrompter
	ctx         context.Context
	client      *Client
	projectBase string
	// sourceFiles are the export files read this session, for the
	// plaintext-still-on-disk warning. Live reads contribute none.
	sourceFiles []string
}

// ReadSource performs one connector read for a gathered selector, mapping the
// wizard's Selector onto the same Run/RunLive the flag mode uses.
func (h *cliWizardHost) ReadSource(source string, sel importer.Selector) (importer.SourceRead, error) {
	if sel.Live {
		res, err := importer.RunLive(h.ctx, source, importer.LiveInput{
			Context: sel.Context, Namespace: sel.Namespace, Name: sel.Name,
			Mount: sel.Mount, Path: sel.Path, KVVersion: sel.KVVersion,
		})
		if err != nil {
			return importer.SourceRead{}, err
		}
		return importer.SourceRead{Result: res, EnvSlug: sel.EnvSlug}, nil
	}
	in, err := importer.ReadExport(sel.File)
	if err != nil {
		return importer.SourceRead{}, err
	}
	in.EnvSlug = sel.EnvSlug
	res, err := importer.Run(h.ctx, source, in)
	if err != nil {
		return importer.SourceRead{}, err
	}
	h.sourceFiles = append(h.sourceFiles, sel.File)
	return importer.SourceRead{Result: res, FileDigest: importer.Digest(in.Data), EnvSlug: sel.EnvSlug}, nil
}

// ExistingEnvironments lists the project's environments the actor can read.
func (h *cliWizardHost) ExistingEnvironments() ([]importer.NamedEnv, error) {
	var list apigen.EnvironmentList
	if err := h.client.Do(h.ctx, http.MethodGet, h.projectBase+"/environments", nil, &list); err != nil {
		return nil, err
	}
	out := make([]importer.NamedEnv, 0, len(list.Items))
	for _, e := range list.Items {
		out = append(out, importer.NamedEnv{ID: string(e.Id), Name: e.Name})
	}
	return out, nil
}

// Presence reads the server's occurrence answer for one existing environment.
func (h *cliWizardHost) Presence(envID string, candidates []importer.PlannedCandidate) (importer.ServerState, error) {
	var occurrences apigen.ValueOccurrenceList
	if err := h.client.Do(h.ctx, http.MethodPost,
		h.projectBase+"/environments/"+url.PathEscape(envID)+"/values/occurrences",
		apigen.ValueOccurrencesRequest{Candidates: wireImportCandidates(candidates)}, &occurrences); err != nil {
		return importer.ServerState{}, err
	}
	return importer.ServerState{
		Environment:         envID,
		DefinitionsRevision: occurrences.DefinitionsRevision,
		Keys:                occurrenceKeys(occurrences),
	}, nil
}

// occurrenceKeys turns the server's occurrence list into the planner's per-key
// state. Shared with flag mode so the two cannot read the response differently.
func occurrenceKeys(occurrences apigen.ValueOccurrenceList) []importer.KeyState {
	keys := make([]importer.KeyState, 0, len(occurrences.Items))
	for _, k := range occurrences.Items {
		row := importer.KeyState{Name: k.Name, Declared: k.Declared, Set: k.Set, Token: k.Token}
		if k.KeyId != nil {
			row.ID = *k.KeyId
		}
		if k.Classification != nil {
			row.Classification = string(*k.Classification)
		}
		if k.DeclaredType != nil {
			row.Type = *k.DeclaredType
		}
		keys = append(keys, row)
	}
	return keys
}

// runReplayMultiEnv replays a multi-environment template: it fans the one
// recorded source read over every environment the template names, reads presence
// per existing environment, and emits the one project-wide bundle and manifest
// plus a values file per environment. A conflict a wizard would have resolved is
// refused non-interactively by the planner.
func runReplayMultiEnv(ctx context.Context, ios IO, client *Client, projectBase, projectID, source string,
	result importer.Result, fileDigest, envSlug, sourcePath string, template *importer.Template,
	candidates []importer.PlannedCandidate, outDir string) error {
	in := importer.ProjectPlanInput{
		Source: source, Project: projectID, Template: template,
	}
	for _, envMap := range template.Environments {
		env := importer.EnvInput{
			Records: result.Records, Skipped: result.Skipped, Scope: result.Scope,
			FileDigest: fileDigest, SourceIdentity: result.Identity,
		}
		if envMap.Source != nil {
			env.EnvSlug = *envMap.Source
		} else {
			env.EnvSlug = envSlug
		}
		if envMap.Create {
			env.Create = true
			env.EnvName = envMap.Target
		} else {
			env.EnvID = envMap.Target
			var occurrences apigen.ValueOccurrenceList
			if err := client.Do(ctx, http.MethodPost,
				projectBase+"/environments/"+url.PathEscape(envMap.Target)+"/values/occurrences",
				apigen.ValueOccurrencesRequest{Candidates: wireImportCandidates(candidates)}, &occurrences); err != nil {
				return err
			}
			env.Keys = occurrenceKeys(occurrences)
			in.DefinitionsRevision = occurrences.DefinitionsRevision
		}
		in.Envs = append(in.Envs, env)
	}
	plan, err := importer.BuildProjectPlan(in)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}
	valuesPaths, err := writeProjectArtifacts(ios, outDir, plan)
	if err != nil {
		return err
	}
	var sources []string
	if sourcePath != "" {
		sources = []string{sourcePath}
	}
	return reportProject(ios, plan, outDir, sources, valuesPaths)
}

// ---------------------------------------------------------------------------
// Terminal prompter
// ---------------------------------------------------------------------------

// terminalPrompter is the importer.Prompter over the real terminal: prompts and
// notices go to stderr (stdout carries the artifact table alone), answers are
// read from stdin.
type terminalPrompter struct {
	in  *bufio.Reader
	out interface{ Write([]byte) (int, error) }
}

func newTerminalPrompter(ios IO) *terminalPrompter {
	return &terminalPrompter{in: bufio.NewReader(ios.Stdin), out: ios.Stderr}
}

func (p *terminalPrompter) Notice(msg string) { fmt.Fprintf(p.out, "%s\n", msg) }

func (p *terminalPrompter) Confirm(question string, def bool) (bool, error) {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(p.out, "%s %s ", question, hint)
	line, err := p.readLine()
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return def, nil
	}
}

func (p *terminalPrompter) Choose(question string, options []string, def int) (int, error) {
	fmt.Fprintf(p.out, "%s\n", question)
	for i, o := range options {
		fmt.Fprintf(p.out, "  %d) %s\n", i+1, o)
	}
	fmt.Fprintf(p.out, "choice [%d]: ", def+1)
	line, err := p.readLine()
	if err != nil {
		return 0, err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(options) {
		return 0, failf(ExitUsage, "%q is not one of the %d options", line, len(options))
	}
	return n - 1, nil
}

func (p *terminalPrompter) Line(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s] ", question, def)
	} else {
		fmt.Fprintf(p.out, "%s ", question)
	}
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def, nil
	}
	return line, nil
}

func (p *terminalPrompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", failf(ExitUsage, "the import wizard reached end of input before the session finished")
	}
	return line, nil
}

// ---------------------------------------------------------------------------
// Multi-environment artifact emission
// ---------------------------------------------------------------------------

// writeProjectArtifacts emits the three committable artifacts once and one
// values file per environment that writes anything. Every values path is
// reserved before anything is written, and the committable artifacts are
// created O_EXCL with a cleanup that covers every file this run created — a
// collision on any artifact must not leave a half-authored migration on disk.
func writeProjectArtifacts(ios IO, outDir string, plan *importer.ProjectPlan) (valuesPaths []string, returnErr error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, failf(ExitRefused, "preparing the output directory: %v", err)
	}

	type valuesTarget struct {
		path   string
		file   importer.ValuesFile
		envRef string
		sink   *disclose.PreparedSink
	}
	var valuesTargets []valuesTarget
	for _, env := range plan.Envs {
		if !env.HasValues {
			continue
		}
		ref := env.EnvID
		if env.Create {
			ref = env.EnvName
		}
		valuesTargets = append(valuesTargets, valuesTarget{
			path: filepath.Join(outDir, "values-"+ref+".json"), file: env.Values, envRef: ref,
		})
	}

	// Reserve every values path before writing anything. If a later
	// reservation or artifact fails, deferred aborts remove unused empty files.
	for i := range valuesTargets {
		vt := &valuesTargets[i]
		deliver := disclose.Options{OutputFile: vt.path, Stdout: ios.Stdout}
		sink, err := ios.prepareDisclosure(deliver)
		if err != nil {
			return nil, failf(ExitRefused, "the values file for %s has nowhere to go: %v", vt.envRef, err)
		}
		vt.sink = sink
		defer sink.AbortOnReturn(&returnErr)
	}

	bundleBody, err := definitions.Encode(plan.Bundle)
	if err != nil {
		return nil, err
	}
	mappingBody, err := importer.Encode(plan.Template)
	if err != nil {
		return nil, err
	}
	manifestBody, err := importer.Encode(plan.Manifest)
	if err != nil {
		return nil, err
	}

	var created []string
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	for _, artifact := range []struct {
		name string
		body []byte
	}{
		{bundleFile, bundleBody},
		{mappingFile, mappingBody},
		{manifestFile, manifestBody},
	} {
		path := filepath.Join(outDir, artifact.name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			cleanup()
			if errors.Is(err, fs.ErrExist) {
				return nil, failf(ExitRefused,
					"%s already exists: import never overwrites an artifact a human may have reviewed", path)
			}
			return nil, failf(ExitRefused, "writing %s: %v", path, err)
		}
		created = append(created, path)
		if _, err := f.Write(artifact.body); err != nil {
			f.Close()
			cleanup()
			return nil, failf(ExitRefused, "writing %s: %v", path, err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return nil, failf(ExitRefused, "writing %s: %v", path, err)
		}
	}

	valuesPaths = nil
	for _, vt := range valuesTargets {
		body, err := importer.Encode(vt.file)
		if err != nil {
			cleanup()
			return nil, err
		}
		if len(body) > importer.MaxFileBytes {
			cleanup()
			return nil, failf(ExitRefused,
				"the values file for %s would be %d bytes, exceeding the %d-byte per-file cap; split the import",
				vt.envRef, len(body), importer.MaxFileBytes)
		}
		if _, err := vt.sink.WriteOnce("values for "+vt.envRef, strings.TrimRight(string(body), "\n")); err != nil {
			cleanup()
			return nil, failf(ExitRefused, "writing the values file for %s: %v", vt.envRef, err)
		}
		// Track the emitted plaintext file so a LATER values-file failure removes
		// it too — a half-authored migration must not leave one environment's
		// plaintext on disk beside a missing sibling.
		created = append(created, vt.path)
		valuesPaths = append(valuesPaths, vt.path)
	}
	return valuesPaths, nil
}

// reportProject prints the session summary: renames, near misses, per-environment
// buckets, the artifact table, and the plaintext-still-on-disk warning.
func reportProject(ios IO, plan *importer.ProjectPlan, outDir string, sourceFiles, valuesPaths []string) error {
	w := ios.Stderr
	for _, r := range plan.Renames {
		fmt.Fprintf(w, "rename: %s -> %s (%s)\n",
			importer.QuoteName(r.From), importer.QuoteName(r.To), r.Transform)
	}
	for _, n := range plan.NearMisses {
		fmt.Fprintf(w, "near miss: %s is one edit from the declared key %s\n",
			importer.QuoteName(n.Imported), importer.QuoteName(n.Declared))
	}
	if len(plan.SkippedBySource) > 0 {
		fmt.Fprintf(w, "skipped at the source: %s\n", quoteImportNames(plan.SkippedBySource))
	}
	if len(plan.PlaintextHints) > 0 {
		fmt.Fprintf(w, "plaintext at the source (a classification HINT; nothing was downgraded): %s\n",
			quoteImportNames(plan.PlaintextHints))
	}
	if len(plan.AlreadyDeclared) > 0 {
		fmt.Fprintf(w, "already declared (not re-declared): %s\n", quoteImportNames(plan.AlreadyDeclared))
	}
	for _, env := range plan.Envs {
		ref := env.EnvName
		if ref == "" {
			ref = env.EnvID
		}
		verb := "existing"
		if env.Create {
			verb = "to create"
		}
		fmt.Fprintf(w, "environment %s (%s): %d new, %d already set\n", ref, verb, len(env.New), len(env.Set))
	}

	rows := [][]string{
		{"bundle", filepath.Join(outDir, bundleFile), "committable"},
		{"mapping", filepath.Join(outDir, mappingFile), "committable"},
		{"manifest", filepath.Join(outDir, manifestFile), "committable"},
	}
	for _, path := range valuesPaths {
		rows = append(rows, []string{"values", path, "NEVER commit"})
	}
	if err := Render(ios.Stdout, FormatTable, Table{
		Columns: []string{"ARTIFACT", "PATH", "HANDLING"}, Rows: rows,
	}); err != nil {
		return err
	}

	fmt.Fprintf(w, "\nnext: review the bundle, apply it with `definitions plan|apply`, then run\n"+
		"`hikyo values import` once per environment with its values file and the run manifest.\n\n")
	// Every plaintext file this session left on disk — the source exports it read
	// and the values files it emitted — is named so the human deletes them all.
	fmt.Fprintln(w, importer.PlaintextWarning("", append(append([]string{}, sourceFiles...), valuesPaths...)))
	return nil
}
