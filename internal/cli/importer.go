package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/definitions"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
	"github.com/Hikyo-Org/hikyo/internal/importer"
)

// `hikyo import` (#68, import-paths ADR § Grammar join).
//
// One new top-level verb under the ADR's declared amendment to the closed v1
// taxonomy. Human-only; client-local parity exemption; no new output classes —
// the emitted artifacts are files under the existing secret-file discipline,
// and nothing this verb prints is a secret value.
//
// THREE ENTRY MODES ARE SPECIFIED; TWO SHIP HERE. Flag mode and replay are
// below. The wizard (TTY, no source arguments) is not served by this build and
// refuses by name rather than hanging on a prompt that does not exist.
//
// EVERY IMPORT AUTHORS ARTIFACTS AND STOPS. There is no flag that turns
// two-phase off, and this file has no write path to the server at all: phase 2
// is `hikyo values import`, a separate invocation the human runs after
// reviewing what this produced.
//
// One flag spelling deviates from every other verb in this CLI, deliberately
// and per the spellings spec: the TARGET environment is `--environment`,
// because `--env <slug>` names the SOURCE-side slice inside an Infisical
// export. Reusing `--env` for the target here would make the one verb that
// addresses two environment namespaces spell them identically.

// importSourceList is the served `--from` set, rendered for usage text from
// the connector registry so the two cannot disagree.
var importSourceList = strings.Join(importer.Sources(), "|")

var importUsage = "usage: hikyo import --from <" + importSourceList + "> --project <p> --environment <e> " +
	"--file <path> [--env <slug>] [--out-dir <dir>]\n" +
	"       hikyo import --from k8s --live --namespace <ns> [--name <secret>] --project <p> --environment <e>\n" +
	"       hikyo import --from vault --live --mount <mount> [--path <prefix>] [--kv-version <1|2>] --project <p> --environment <e>\n" +
	"       hikyo import --mapping <mapping.json> [--file <path>] [--out-dir <dir>]"

// artifact file names inside --out-dir. Fixed, because the phase-2 commands
// name them and a reviewer reads them in a pull request.
const (
	bundleFile   = "definitions-bundle.json"
	mappingFile  = "mapping.json"
	manifestFile = "run-manifest.json"
)

func runImport(ctx context.Context, ios IO, args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(ios.Stderr)
	var c commonFlags
	fs.StringVar(&c.Context, "context", "", "named context to select for this invocation")
	fs.StringVar(&c.Instance, "instance", "", "instance reference")
	fs.StringVar(&c.Org, "org", "", "organisation")
	fs.StringVar(&c.Project, "project", "", "project")
	// NOT --env: see the file comment. --env is the SOURCE slice.
	environment := fs.String("environment", "", "the target environment (exactly one per invocation)")
	from := fs.String("from", "", "the source connector: "+importSourceList)
	file := fs.String("file", "", "the export file the source's own tooling produced")
	live := fs.Bool("live", false, "read the source through its ambient client configuration")
	namespace := fs.String("namespace", "", "Kubernetes source namespace")
	name := fs.String("name", "", "one Kubernetes Secret name")
	kubeContext := fs.String("kube-context", "", "Kubernetes kubeconfig context (current context by default)")
	mount := fs.String("mount", "", "Vault/OpenBao KV mount")
	pathPrefix := fs.String("path", "", "Vault/OpenBao path prefix")
	kvVersion := fs.Int("kv-version", 0, "Vault/OpenBao KV engine version (1 or 2; detected when omitted)")
	envSlug := fs.String("env", "", "the SOURCE environment slug inside the export (Infisical)")
	mapping := fs.String("mapping", "", "replay a recorded mapping template")
	outDir := fs.String("out-dir", ".", "where the emitted artifacts are written")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(positional) > 0 {
		return failf(ExitUsage, "hikyo import takes no positional arguments, got: %s", strings.Join(positional, " "))
	}
	c.Env = *environment
	explicitLive := *live

	// Mode selection. The no-arguments case is a HARD ERROR either way — never
	// a hung prompt — and the two halves differ only in which sentence is
	// useful: on a terminal the wizard is what the operator expected, and
	// saying "not served" is more use than repeating the flags at them.
	switch {
	case *from == "" && *mapping == "":
		if onTerminal(ios) {
			// Wizard: no source arguments on a TTY. The target project is resolved
			// from the ambient chain (it must pre-exist); the environments are
			// chosen interactively, so no --environment is required here.
			return runImportWizard(ctx, ios, c, *outDir)
		}
		return failf(ExitUsage, "hikyo import needs --from or --mapping (there is no terminal to prompt on).\n%s", importUsage)
	case *from != "" && *mapping != "":
		return failf(ExitUsage, "hikyo import takes --from or --mapping, not both")
	case *from != "" && !slices.Contains(importer.Sources(), *from):
		// Checked HERE, before the file is opened, so naming a source this
		// build does not serve answers the same way whether or not the export
		// happens to exist. `vault` is the live-and-file connector that lands
		// with #69, and it is the one an operator is most likely to try.
		return failf(ExitUsage, "hikyo import does not serve source %q: served sources are %s", *from, importSourceList)
	}
	if *from != "" {
		var missing []string
		if c.Project == "" {
			missing = append(missing, "--project")
		}
		if *environment == "" {
			missing = append(missing, "--environment")
		}
		if len(missing) > 0 {
			return failf(ExitRefused,
				"hikyo import --from requires an explicit target; missing %s (ambient context is not accepted for a committable migration)",
				strings.Join(missing, " and "))
		}
		switch {
		case *live && *file != "":
			return failf(ExitUsage, "hikyo import takes either --file or --live, not both")
		case !*live && *file == "":
			return failf(ExitUsage, "hikyo import --from requires either --file <path> or --live.\n%s", importUsage)
		case *live && *from != "k8s" && *from != "vault":
			return failf(ExitUsage, "hikyo import source %q is file-only in v1", *from)
		case *live && *from == "k8s" && *namespace == "":
			return failf(ExitUsage, "hikyo import --from k8s --live requires --namespace <namespace>")
		case *live && *from == "vault" && *mount == "":
			return failf(ExitUsage, "hikyo import --from vault --live requires --mount <mount>")
		case *kvVersion != 0 && *kvVersion != 1 && *kvVersion != 2:
			return failf(ExitUsage, "hikyo import --kv-version is neither 1 nor 2")
		}
		if *live && *from == "k8s" && (*mount != "" || *pathPrefix != "" || *kvVersion != 0 || *envSlug != "") {
			return failf(ExitUsage, "Kubernetes live mode does not take Vault/Infisical selectors")
		}
		if *live && *from == "vault" && (*namespace != "" || *name != "" || *kubeContext != "" || *envSlug != "") {
			return failf(ExitUsage, "Vault/OpenBao live mode does not take Kubernetes/Infisical selectors")
		}
		if !*live && (*namespace != "" || *name != "" || *kubeContext != "" || *mount != "" || *pathPrefix != "" || *kvVersion != 0) {
			return failf(ExitUsage, "file mode does not take live source selectors")
		}
	}
	var template *importer.Template
	var replayNames []string
	source := *from
	if *mapping != "" {
		// A replay's target comes from the template it replays, so naming a
		// different one on the command line is refused rather than silently
		// overridden: an artifact that records the choices and then watches a
		// flag override them is not a record.
		if c.Project != "" || *environment != "" || explicitLive || *namespace != "" || *name != "" ||
			*kubeContext != "" || *mount != "" || *pathPrefix != "" || *kvVersion != 0 || *envSlug != "" {
			return failf(ExitUsage,
				"hikyo import --mapping takes its target, mode and source selectors from the template; remove selector overrides")
		}
		raw, err := importer.ReadFile(*mapping)
		if err != nil {
			return failf(ExitUsage, "reading the mapping template: %v", err)
		}
		parsed, err := importer.ParseTemplate(raw)
		if err != nil {
			return failf(ExitRefused, "%v", err)
		}
		// A multi-environment template is a wizard session's artifact; the replay
		// fans the recorded source over every environment it names (§ multi-env
		// replay below). A single-environment template targets exactly one, the
		// way flag mode does.
		template = &parsed
		source = parsed.Source
		c.Project = parsed.Project
		if len(parsed.Environments) == 1 {
			c.Env = parsed.Environments[0].Target
		}
		*envSlug = parsed.Scope.EnvSlug
		if parsed.Scope.FileDigest == "" && (source == "k8s" || source == "vault") {
			if *file != "" {
				return failf(ExitUsage, "this mapping records live mode; remove --file")
			}
			*live = true
			*namespace = parsed.Scope.Namespace
			replayNames = append([]string{}, parsed.Scope.Names...)
			*mount = parsed.Scope.Mount
			*pathPrefix = parsed.Scope.PathPrefix
			*kvVersion = parsed.Scope.KVVersion
		} else if *file == "" {
			return failf(ExitUsage, "this mapping records file mode: pass --file <path>.\n%s", importUsage)
		}
	}

	// The foreign source is read BEFORE the Hikyo session is touched, so a
	// caller who names an invalid source or exceeds a connector bound hears
	// about it without a Hikyo round trip carrying anything.
	var in importer.Input
	var result importer.Result
	sourcePath := ""
	if *live {
		result, err = importer.RunLive(ctx, source, importer.LiveInput{
			Context: *kubeContext, Namespace: *namespace, Name: *name, Names: replayNames,
			Mount: *mount, Path: *pathPrefix, KVVersion: *kvVersion,
		})
	} else {
		in, err = importer.ReadExport(*file)
		if err != nil {
			return failf(ExitUsage, "reading the export: %v", err)
		}
		in.EnvSlug = *envSlug
		result, err = importer.Run(ctx, source, in)
		sourcePath = *file
	}
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}

	// The rename transform runs BEFORE the server is asked anything: the
	// presence read mints a token per candidate key, and it cannot do that
	// without knowing which names this run will propose.
	fileDigest := ""
	if !*live {
		fileDigest = importer.Digest(in.Data)
	}
	planIn := importer.PlanInput{
		Source: source, Records: result.Records, Skipped: result.Skipped,
		Scope: result.Scope, FileDigest: fileDigest, EnvSlug: *envSlug,
		SourceIdentity: result.Identity,
		Template:       template,
	}
	candidates, err := importer.PlannedCandidates(planIn)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}

	st, err := NewState(ios.Env)
	if err != nil {
		return err
	}
	client, _, resolved, err := authenticatedTarget(st, ios, c)
	if err != nil {
		return err
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}
	projectID, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}

	// Multi-environment replay fans the one recorded source read over every
	// environment the template names — presence varies per environment, the
	// bundle and manifest are one. A conflict the wizard would have resolved
	// interactively is refused here, non-interactively, by the planner.
	if template != nil && len(template.Environments) > 1 {
		return runReplayMultiEnv(ctx, ios, client, project, projectID, source, result, fileDigest,
			*envSlug, sourcePath, template, candidates, *outDir)
	}

	envID, err := addressed(resolved, DimEnv, "", "import --environment")
	if err != nil {
		return err
	}

	// Phase 1's only server contact: read-only,
	// `read@project AND read@environment`, no reveal, no comparison, no write.
	var occurrences apigen.ValueOccurrenceList
	if err := client.Do(ctx, http.MethodPost,
		project+"/environments/"+url.PathEscape(envID)+"/values/occurrences",
		apigen.ValueOccurrencesRequest{Candidates: wireImportCandidates(candidates)}, &occurrences); err != nil {
		return err
	}

	planIn.State = importer.ServerState{
		Project:             projectID,
		Environment:         envID,
		DefinitionsRevision: occurrences.DefinitionsRevision,
		Keys:                occurrenceKeys(occurrences),
	}

	plan, err := importer.BuildPlan(planIn)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}

	valuesPath, err := writeArtifacts(ios, *outDir, envID, plan)
	if err != nil {
		return err
	}
	return reportImport(ios, plan, result.Resolution, sourcePath, valuesPath, *outDir)
}

func wireImportCandidates(in []importer.PlannedCandidate) []apigen.ValueOccurrenceCandidate {
	out := make([]apigen.ValueOccurrenceCandidate, 0, len(in))
	for _, candidate := range in {
		out = append(out, apigen.ValueOccurrenceCandidate{
			Name:                   candidate.Name,
			IntendedClassification: apigen.KeyClassification(candidate.Classification),
			IntendedType:           apigen.ValueOccurrenceCandidateIntendedType(candidate.Type),
		})
	}
	return out
}

// writeArtifacts emits the four artifacts. The three committable ones are
// ordinary files; the values file is NOT committable and goes through the print
// triad's file leg — dirfd-parent-checked, O_EXCL, 0600 — which is the same
// discipline every other plaintext-bearing file in this CLI uses.
func writeArtifacts(ios IO, outDir, envID string, plan *importer.Plan) (string, error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", failf(ExitRefused, "preparing the output directory: %v", err)
	}
	valuesPath := ""
	// A run that writes nothing emits no values file. An empty one is an
	// artifact phase 2 refuses by construction, so an idempotent re-run would
	// end in a refusal for having correctly done nothing.
	if plan.HasValues {
		valuesPath = filepath.Join(outDir, "values-"+envID+".json")
	}
	var valuesBody []byte
	if valuesPath != "" {
		var err error
		valuesBody, err = importer.Encode(plan.Values)
		if err != nil {
			return "", err
		}
		if len(valuesBody) > importer.MaxFileBytes {
			return "", failf(ExitRefused,
				"the values file would be %d bytes, exceeding the %d-byte per-file cap that `values import` accepts; split the import or reduce the selection",
				len(valuesBody), importer.MaxFileBytes)
		}
	}

	// The values file is preflighted BEFORE anything is written: a run that
	// emits a bundle and then discovers it has nowhere to put the plaintext has
	// left half a migration on disk.
	deliver := disclose.Options{OutputFile: valuesPath, Stdout: ios.Stdout, OpenTerminal: ios.OpenTerminal}
	if valuesPath != "" {
		if err := disclose.Preflight(deliver); err != nil {
			return "", failf(ExitRefused, "the values file has nowhere to go: %v", err)
		}
	}

	// The committable artifacts are created O_EXCL, not Lstat-then-write. The
	// check-then-act version loses two ways: an attacker who wins the window
	// between the two swaps in a symlink and the write follows it into whatever
	// it points at, and a collision on the THIRD artifact leaves the first two
	// on disk as a half-authored migration. O_EXCL closes the first; removing
	// what this run created closes the second.
	var created []string
	cleanup := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	bundleBody, err := definitions.Encode(plan.Bundle)
	if err != nil {
		return "", err
	}
	mappingBody, err := importer.Encode(plan.Template)
	if err != nil {
		return "", err
	}
	manifestBody, err := importer.Encode(plan.Manifest)
	if err != nil {
		return "", err
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
				return "", failf(ExitRefused,
					"%s already exists: import never overwrites an artifact a human may have reviewed", path)
			}
			return "", failf(ExitRefused, "writing %s: %v", path, err)
		}
		created = append(created, path)
		if _, err := f.Write(artifact.body); err != nil {
			f.Close()
			cleanup()
			return "", failf(ExitRefused, "writing %s: %v", path, err)
		}
		if err := f.Close(); err != nil {
			cleanup()
			return "", failf(ExitRefused, "writing %s: %v", path, err)
		}
	}

	if valuesPath == "" {
		return "", nil
	}
	if _, err := disclose.Emit("values for "+envID, strings.TrimRight(string(valuesBody), "\n"), deliver); err != nil {
		cleanup()
		return "", failf(ExitRefused, "writing the values file: %v", err)
	}
	return valuesPath, nil
}

// reportImport prints what happened. Every rename is surfaced, every skipped
// key is named, and the run ends with the plaintext-still-on-disk warning.
func reportImport(ios IO, plan *importer.Plan, sourceResolution, sourcePath, valuesPath, outDir string) error {
	w := ios.Stderr
	if sourceResolution != "" {
		fmt.Fprintf(w, "source resolution: %s\n", sourceResolution)
	}
	for _, r := range plan.Renames {
		fmt.Fprintf(w, "rename: %s -> %s (%s)\n",
			importer.QuoteName(r.From), importer.QuoteName(r.To), r.Transform)
	}
	for _, n := range plan.NearMisses {
		fmt.Fprintf(w, "near miss: %s is one edit from the declared key %s\n",
			importer.QuoteName(n.Imported), importer.QuoteName(n.Declared))
	}
	if len(plan.SkippedBySource) > 0 {
		reason := "connector exclusions"
		switch plan.Template.Source {
		case "infisical":
			reason = "personal overrides"
		case "vault":
			reason = "deleted or destroyed latest versions"
		}
		fmt.Fprintf(w, "skipped at the source (%s): %s\n", reason, quoteImportNames(plan.SkippedBySource))
	}
	if len(plan.PlaintextHints) > 0 {
		fmt.Fprintf(w, "plaintext at the source (a classification HINT; nothing was downgraded): %s\n",
			quoteImportNames(plan.PlaintextHints))
	}
	if len(plan.AlreadyDeclared) > 0 {
		fmt.Fprintf(w, "already declared (not re-declared): %s\n", quoteImportNames(plan.AlreadyDeclared))
	}
	if len(plan.Set) > 0 {
		fmt.Fprintf(w, "already set, skipped by default: %s\n", quoteImportNames(plan.Set))
	}
	if len(plan.Overwritten) > 0 {
		fmt.Fprintf(w, "overwrite selected: %s\n", quoteImportNames(plan.Overwritten))
	}
	fmt.Fprintf(w, "%d new, %d already set; artifacts in %s\n", len(plan.New), len(plan.Set), outDir)

	rows := [][]string{
		{"bundle", filepath.Join(outDir, bundleFile), "committable"},
		{"mapping", filepath.Join(outDir, mappingFile), "committable"},
		{"manifest", filepath.Join(outDir, manifestFile), "committable"},
	}
	if valuesPath != "" {
		rows = append(rows, []string{"values", valuesPath, "NEVER commit"})
	}
	if err := Render(ios.Stdout, FormatTable, Table{
		Columns: []string{"ARTIFACT", "PATH", "HANDLING"}, Rows: rows,
	}); err != nil {
		return err
	}
	if valuesPath == "" {
		fmt.Fprintf(w, "\nno values file: all %d key(s) are already set in %s and were skipped. "+
			"Re-run with an --overwrite selection in the mapping template to replace them.\n\n",
			len(plan.Set), plan.Values.Environment)
		fmt.Fprintln(w, importer.PlaintextWarning(sourcePath, nil))
		return nil
	}
	fmt.Fprintf(w, "\nnext: review the bundle, apply it, then\n"+
		"  hikyo values import --env %s --file %s --manifest %s\n\n",
		plan.Values.Environment, valuesPath, filepath.Join(outDir, manifestFile))
	fmt.Fprintln(w, importer.PlaintextWarning(sourcePath, []string{valuesPath}))
	return nil
}

func quoteImportNames(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, name := range names {
		quoted = append(quoted, importer.QuoteName(name))
	}
	return strings.Join(quoted, ", ")
}

// onTerminal reports whether a controlling terminal exists. It is the same
// question disclose asks, asked the same way: stdout being a TTY proves
// neither presence nor intent, and /dev/tty is a different file.
func onTerminal(ios IO) bool {
	open := ios.OpenTerminal
	if open == nil {
		return false
	}
	tty, err := open()
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

// ---------------------------------------------------------------------------
// `hikyo values import` — phase 2
// ---------------------------------------------------------------------------

// validateImportArtifactTargets binds the plaintext artifact to both target
// dimensions phase 1 recorded, even when no manifest accompanies it.
func validateImportArtifactTargets(values importer.ValuesFile, project, env string) error {
	if values.Project != project {
		return failf(ExitRefused,
			"the values file was authored for project %s but this invocation targets %s",
			importer.QuoteName(values.Project), importer.QuoteName(project))
	}
	if values.Environment != env {
		return failf(ExitRefused,
			"the values file was authored for environment %s but this invocation targets %s",
			importer.QuoteName(values.Environment), importer.QuoteName(env))
	}
	return nil
}

// runValuesImport consumes one environment's values file. Strict, human-only,
// per environment: an undeclared key rejects the run by name, and the closed
// schema is not conceded on the import path — the largest imports are precisely
// the accumulated-typo case it exists to catch.
//
// `--manifest` is the one declared additive input. With it, the server
// re-evaluates phase 1's read formula and verifies the definitions revision and
// every written key's occurrence token inside the import's own transaction; any
// movement rejects those keys by name. Without it, the verb behaves exactly as
// locked.
func runValuesImport(ctx context.Context, ios IO, args []string) error {
	var valuesFile, manifestPath, overwrite, format string
	st, flags, err := parseCommon("values import", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.StringVar(&valuesFile, "file", "", "the values file an import authored")
		fs.StringVar(&manifestPath, "manifest", "", "the run manifest to verify as a precondition")
		fs.StringVar(&overwrite, "overwrite", "",
			"enumerated keys to overwrite where the environment already has a value, comma-separated")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("values import"); err != nil {
		return err
	}
	if valuesFile == "" {
		return failf(ExitUsage,
			"usage: hikyo values import --env <e> --file <values-file> [--manifest <run-manifest.json>] [--overwrite KEY,KEY]")
	}

	raw, err := importer.ReadFile(valuesFile)
	if err != nil {
		return failf(ExitUsage, "reading the values file: %v", err)
	}
	values, err := importer.ParseValuesFile(raw)
	if err != nil {
		return failf(ExitRefused, "%v", err)
	}

	body := apigen.ImportValuesRequest{}
	for _, e := range values.Entries {
		body.Entries = append(body.Entries, struct {
			Key   apigen.KeyName `json:"key"`
			Value string         `json:"value"`
		}{Key: e.Key, Value: e.Value})
	}
	if list := splitList(overwrite); len(list) > 0 {
		body.Overwrite = &list
	}
	if manifestPath != "" {
		rawManifest, err := importer.ReadFile(manifestPath)
		if err != nil {
			return failf(ExitUsage, "reading the run manifest: %v", err)
		}
		manifest, err := importer.ParseManifest(rawManifest)
		if err != nil {
			return failf(ExitRefused, "%v", err)
		}
		pre := apigen.ImportPrecondition{
			DefinitionsRevision: manifest.DefinitionsRevision,
			EnvironmentIds:      manifest.Target.Environments,
		}
		for _, o := range manifest.Occurrences {
			pre.Occurrences = append(pre.Occurrences, struct {
				EnvironmentId apigen.ID      `json:"environment_id"`
				Key           apigen.KeyName `json:"key"`
				Token         string         `json:"token"`
			}{EnvironmentId: o.Environment, Key: o.Key, Token: o.Token})
		}
		body.Precondition = &pre
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}
	env, err := addressed(resolved, DimEnv, flags.Env, "values import")
	if err != nil {
		return err
	}
	targetProject, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	// The values file binds both target dimensions even without a manifest.
	// Same environment ids and key names can exist in different projects; a
	// one-dimensional check would silently retarget reviewed plaintext.
	if err := validateImportArtifactTargets(values, targetProject, env); err != nil {
		return err
	}

	var result apigen.ImportValuesResult
	if err := client.Do(ctx, http.MethodPost,
		project+"/environments/"+url.PathEscape(env)+"/values/import", body, &result); err != nil {
		return err
	}
	warnFindings(ios, result.Findings)
	// The manifest's phase-completion marker is what lets a resumed migration
	// know where it stopped, so a run that completed says so. `applied` stays
	// false: that transition belongs to `definitions apply` (#70), which does
	// not exist, and claiming it here would be a marker for an act nobody
	// performed.
	if manifestPath != "" {
		if err := markImported(manifestPath, env); err != nil {
			fmt.Fprintf(ios.Stderr,
				"the import landed, but the run manifest could not be updated (%v); "+
					"a resumed migration will read it as not yet imported\n", err)
		}
	}
	if len(result.Skipped) > 0 {
		sorted := append([]string{}, result.Skipped...)
		sort.Strings(sorted)
		fmt.Fprintf(ios.Stderr,
			"skipped (already set; pass --overwrite to replace): %s\n", strings.Join(sorted, ", "))
	}
	fmt.Fprintf(ios.Stderr, "imported %d value(s); delete %s now that it has landed\n",
		len(result.Imported), valuesFile)
	rows := make([][]string, 0, len(result.Imported)+len(result.Skipped))
	for _, k := range result.Imported {
		rows = append(rows, []string{k, "imported"})
	}
	for _, k := range result.Skipped {
		rows = append(rows, []string{k, "skipped"})
	}
	return Render(ios.Stdout, f, Table{Columns: []string{"KEY", "OUTCOME"}, Rows: rows, JSON: result})
}

// markImported rewrites a run manifest with this environment's completion
// marker set. It re-parses and re-encodes rather than patching text, so the
// artifact stays exactly what ParseManifest accepts.
//
// A failure here is REPORTED, not raised: the import has committed, and turning
// a bookkeeping failure into a non-zero exit would tell a script the write did
// not happen when it did.
func markImported(path, envID string) error {
	return markImportedWithWriter(path, envID, func(f *os.File, raw []byte) error {
		_, err := f.Write(raw)
		return err
	})
}

func markImportedWithWriter(path, envID string, writeTemp func(*os.File, []byte) error) error {
	raw, err := importer.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	manifest, err := importer.ParseManifest(raw)
	if err != nil {
		return err
	}
	if manifest.PhaseCompletion.Imported == nil {
		manifest.PhaseCompletion.Imported = map[string]bool{}
	}
	manifest.PhaseCompletion.Imported[envID] = true
	updated, err := importer.Encode(manifest)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := writeTemp(tmp, updated); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keepTemp = false
	return nil
}
