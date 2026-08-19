package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/compose"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// The Compose delivery verbs (compose-integration ADR; #63): `hikyo run --`
// (path 1, exec wrapper) and `hikyo compose render|sync|doctor` (path 2,
// rendered env_file). Both are MACHINE-ONLY — the stored human session is never
// used — and both are thin wiring over internal/compose, which owns all the
// pure logic and filesystem primitives. Every use of a compose primitive sits
// behind a small helper here so the snapshot/generation format rework can be
// reconciled in one place per primitive.

const (
	composeConfigName = "hikyo-compose.yaml"
	// runGenerationKey names run's single snapshot "generation" in the
	// GenerationStamps map. It is outside the target-name grammar
	// (^[a-z][a-z0-9-]*$) so it can never collide with a real target named
	// "run".
	runGenerationKey = "__run__"
	// offlineMetaFile is the CLI-owned sidecar the offline path needs beyond the
	// compose snapshot payload: the AAD tuple LoadSnapshot takes as a parameter,
	// and the name→key_id map the per-key reconciliation records require.
	offlineMetaFile = "offline.meta.json"

	machineRevealOptIn = "secret plaintext requires the per-project machine-reveal opt-in and then a `reveal` grant; " +
		"in this build that opt-in is not exposed, so a machine credential cannot receive these secrets yet"
)

// ---------------------------------------------------------------------------
// hikyo run -- <command>
// ---------------------------------------------------------------------------

func runRun(ctx context.Context, ios IO, args []string) error {
	// The child's command and ITS flags sit after the first `--`. Split BEFORE
	// any flag parsing: flag.Parse would otherwise consume `--` and then eat the
	// child's own flags (`hikyo run -- mycmd --config-only`).
	sep := slices.Index(args, "--")
	if sep < 0 {
		return failf(ExitUsage, "usage: hikyo run [flags] -- <command> [args...]")
	}
	hikyoArgs, childArgs := args[:sep], args[sep+1:]
	if len(childArgs) == 0 {
		return failf(ExitUsage, "hikyo run: no command after `--`")
	}

	var (
		configOnly       bool
		allowOverrideRaw string
		projectDir       string
	)
	st, flags, err := parseCommon("run", ios, hikyoArgs, func(fs *flag.FlagSet) {
		fs.BoolVar(&configOnly, "config-only", false, "request the config-only projection: no secrets, a distinct authorized mode")
		fs.StringVar(&allowOverrideRaw, "allow-override", "", "comma-separated keys whose inherited value the fetched value may replace")
		fs.StringVar(&projectDir, "project-directory", "", "directory to look up hikyo-compose.yaml from (walks up); optional")
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("run"); err != nil {
		return err
	}
	allowOverride := splitCSV(allowOverrideRaw)

	cfg, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return err
	}
	client, entry, resolved, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "run")
	if err != nil {
		return err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)

	// The state dir exists only when a config file names this stack; run with no
	// config file writes nothing and holds nothing pending by construction.
	stateDir := ""
	if cfg != nil {
		stateDir = composeStateDir(st, composeSlug(cfg, org, project, env))
		// Flush-before-fetch (ops-spec § 6 ordering rule): pending offline
		// records reconcile BEFORE the fetch proceeds; a failure refuses the
		// fetch.
		if err := flushOffline(ctx, client, org, project, env, stateDir); err != nil {
			return err
		}
	}

	resp, ferr := fetchDelivery(ctx, client, org, project, env, configOnly, "")

	var (
		fetched map[string]string
		live    bool
	)
	if ferr != nil {
		f, herr := serveRunOffline(ios, cfg, stateDir, entry, org, project, env, configOnly, ferr)
		if herr != nil {
			return herr
		}
		fetched = f
	} else {
		// All-or-nothing (compose ADR § "Authorization"): a secret the principal
		// cannot reveal makes the whole delivery refuse BEFORE anything else. Not
		// reached under --config-only, whose projection carries no secrets.
		if !configOnly {
			if missing := unrevealedSecrets(resp.Keys); len(missing) > 0 {
				return failf(ExitRefused, "hikyo run: cannot deliver secret(s) %s — %s",
					strings.Join(missing, ", "), machineRevealOptIn)
			}
		}
		fetched = deliveredValues(resp.Keys)
		live = true
	}

	// Loader-control (compose ADR § "Loader-control keys"): refuse a
	// loader-control key the config's run block does not acknowledge by name.
	var ack []string
	if cfg != nil {
		ack = cfg.Run.AcknowledgeLoaderControl
	}
	if refused := compose.RefuseUnacknowledged(mapKeys(fetched), ack); len(refused) > 0 {
		return failf(ExitRefused, "hikyo run: refusing loader-control key(s) %s; acknowledge each by name in the config's `run.acknowledge_loader_control`",
			strings.Join(refused, ", "))
	}

	// Merge: fetched wins; a differing collision is a hard error unless named in
	// --allow-override (compose ADR § "Merge, collisions").
	merged, _, err := compose.MergeEnv(os.Environ(), fetched, allowOverride)
	if err != nil {
		return &Error{Code: ExitRefused, Err: err}
	}

	// ARG_MAX preflight (ops-spec § 6): the execve composite bound, refused loud
	// pre-exec rather than as E2BIG at the wrong layer.
	if total, ok := compose.ExecSizeOK(merged, childArgs, compose.DefaultArgMax()); !ok {
		return failf(ExitRefused, "hikyo run: the child environment plus argv is %d bytes, over the exec budget (ARG_MAX %d minus a 64 KiB margin); reduce the delivered set or shorten the command",
			total, compose.DefaultArgMax())
	}

	// Snapshot: after a LIVE delivering fetch and only when a config file exists.
	// Opt-in governs SERVING, not saving — a silent save failure is the silent
	// fallback the house forbids, so it is a hard error.
	if live && cfg != nil {
		if err := saveRunSnapshot(ios, cfg, stateDir, entry, org, project, env, configOnly, resp); err != nil {
			return failf(ExitInternal, "hikyo run: saving offline snapshot: %v", err)
		}
	}

	// Exec. 127 = not found, 126 = found-but-not-executable — the child-side
	// convention (exit.go), the only exits outside the closed set. On success
	// there is no hikyo process (unix syscall.Exec): the child's status is the
	// invocation's.
	command := childArgs[0]
	resolvedPath, lookErr := exec.LookPath(command)
	if lookErr != nil {
		return failf(ExitCommandNotFound, "hikyo run: %s: command not found", command)
	}
	if err := ios.exec(resolvedPath, childArgs, merged); err != nil {
		return failf(ExitCommandNotExecutable, "hikyo run: %s: %v", command, err)
	}
	// Unreachable on a real unix exec (the process image is replaced); reached
	// only through the injected test seam, which returns nil to signal capture.
	return nil
}

// serveRunOffline handles a failed run fetch: if it failed as UNAVAILABLE and
// the stack opted into offline serve, it opens the snapshot, prints the stale
// line, records one offline disclosure per key BEFORE returning the values, and
// returns them. Any other failure (or no opt-in) is surfaced unchanged.
func serveRunOffline(ios IO, cfg *compose.Config, stateDir string, entry TrustEntry, org, project, env string, configOnly bool, fetchErr error) (map[string]string, error) {
	if !isUnavailable(fetchErr) {
		return nil, fetchErr
	}
	if cfg == nil || !cfg.Snapshot.OfflineServe {
		fmt.Fprintln(ios.Stderr, "hikyo run: offline serve is not enabled for this stack; set snapshot.offline_serve: true in hikyo-compose.yaml to serve stale values during an outage")
		return nil, fetchErr
	}
	payload, meta, err := loadOfflineSnapshot(ios, cfg, stateDir, entry, org, project, env, configOnly)
	if err != nil {
		return nil, err
	}
	stamp := payload.GenerationStamps[runGenerationKey]
	if err := appendOfflineRecords(stateDir, payload.Rows, meta, stamp); err != nil {
		return nil, failf(ExitInternal, "hikyo run: recording offline disclosure: %v", err)
	}
	fmt.Fprintf(ios.Stderr, "serving stale from %s, generation %s\n", meta.AAD.IssuedAt, stamp)
	return rowsToValues(payload.Rows), nil
}

// saveRunSnapshot seals the delivered env plus one run "generation" stamp and
// persists the CLI offline sidecar beside it.
func saveRunSnapshot(ios IO, cfg *compose.Config, stateDir string, entry TrustEntry, org, project, env string, configOnly bool, resp apigen.DeliveryResponse) error {
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return err
	}
	rows := deliveredRows(resp.Keys)
	stamp := compose.TargetStamp(keys, canonicalRows(rows))
	payload := compose.SnapshotPayload{Rows: rows, GenerationStamps: map[string]string{runGenerationKey: stamp}}
	aad := buildDeliveryAAD(entry, org, project, env, resp, configOnly, cfg.TargetNames())
	if err := saveSnapshot(stateDir, keys, aad, payload); err != nil {
		return err
	}
	return saveOfflineMeta(stateDir, aad, resp.Keys)
}

// ---------------------------------------------------------------------------
// hikyo compose render|sync|doctor
// ---------------------------------------------------------------------------

func runCompose(ctx context.Context, ios IO, args []string) error {
	if len(args) == 0 {
		return failf(ExitUsage, "usage: hikyo compose render|sync|doctor")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "render":
		_, err := runComposeRender(ctx, ios, rest)
		return err
	case "sync":
		return runComposeSync(ctx, ios, rest)
	case "doctor":
		return runComposeDoctor(ctx, ios, rest)
	default:
		return failf(ExitUsage, "unknown compose verb %q: use render, sync or doctor", sub)
	}
}

func runComposeRender(ctx context.Context, ios IO, args []string) (bool, error) {
	var (
		configOnly bool
		projectDir string
	)
	st, flags, err := parseCommon("compose render", ios, args, func(fs *flag.FlagSet) {
		fs.BoolVar(&configOnly, "config-only", false, "request the config-only projection: no secrets")
		fs.StringVar(&projectDir, "project-directory", "", "directory to look up hikyo-compose.yaml from (walks up)")
	})
	if err != nil {
		return false, err
	}
	if err := flags.checkNoPositionals("compose render"); err != nil {
		return false, err
	}
	return composeRenderCore(ctx, ios, st, flags, projectDir, configOnly)
}

// composeRenderCore is the render pipeline, shared by `compose render` and the
// render step of `compose sync`. It returns whether any target's stamp moved,
// so sync knows whether to recreate.
func composeRenderCore(ctx context.Context, ios IO, st *State, flags commonFlags, projectDir string, configOnly bool) (bool, error) {
	cfg, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return false, err
	}
	if cfg == nil {
		return false, failf(ExitUsage, "hikyo compose render requires a %s (searched up from %s); the .hikyo.json pin file is not enough — the config carries the render targets",
			composeConfigName, startDir(ios, projectDir))
	}
	client, entry, resolved, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "compose")
	if err != nil {
		return false, err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)
	slug := composeSlug(cfg, org, project, env)
	stateDir := composeStateDir(st, slug)
	runtimeDir, err := composeRuntimeDir(ios, cfg, slug)
	if err != nil {
		return false, err
	}
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return false, err
	}

	w := compose.NewWriter(stateDir, nil)
	unlock, err := w.BeginRender()
	if err != nil {
		return false, failf(ExitRefused, "another hikyo compose process holds the lock for %s", slug)
	}
	defer unlock()

	// 1. Recover incomplete (torn) generations before anything reads them.
	if err := w.Recover(runtimeDir); err != nil {
		return false, failf(ExitInternal, "compose render: recover: %v", err)
	}
	// 2. Flush-before-fetch.
	if err := flushOffline(ctx, client, org, project, env, stateDir); err != nil {
		return false, err
	}
	// 3. Cursor: present it only when the three-part local test holds.
	currentStamps, err := compose.CurrentStamps(cfgDir)
	if err != nil {
		return false, failf(ExitRefused, "compose render: %v", err)
	}
	keyIDs := allTargetKeyIDs(cfg)
	present := eligibleCursor(stateDir, currentStamps, runtimeDir, env, configOnly, keyIDs)

	resp, ferr := fetchDelivery(ctx, client, org, project, env, configOnly, present)
	if ferr != nil {
		return composeRenderOffline(ctx, ios, w, cfg, cfgDir, stateDir, runtimeDir, keys, entry, org, project, env, configOnly, ferr)
	}
	if resp.Current {
		for _, t := range cfg.TargetNames() {
			fmt.Fprintf(ios.Stderr, "up to date (generation %s)\n", currentStamps[t])
		}
		return false, nil
	}
	return composeRenderApply(ios, w, cfg, cfgDir, stateDir, runtimeDir, keys, entry, org, project, env, configOnly, resp, currentStamps, keyIDs)
}

// composeRenderApply renders each target from a live full delivery. On ANY
// refusal it writes no generation and does not advance the cursor.
func composeRenderApply(ios IO, w *compose.Writer, cfg *compose.Config, cfgDir, stateDir, runtimeDir string, keys *crypto.LocalKeys, entry TrustEntry, org, project, env string, configOnly bool, resp apigen.DeliveryResponse, currentStamps map[string]string, keyIDs []string) (bool, error) {
	byID := deliveredByID(resp.Keys)

	type rendered struct {
		name    string
		stamp   string
		content []byte
		rows    []compose.SnapshotRow
	}
	var results []rendered
	var refusals []string

	for _, name := range cfg.TargetNames() {
		tgt := cfg.Targets[name]
		var rows []compose.Row
		var srows []compose.SnapshotRow
		var names []string
		for _, id := range tgt.Keys {
			k, ok := byID[id]
			if !ok {
				// A target key id the server did not deliver: at render time the
				// target cannot be rendered as declared, so refuse (the ADR's
				// doctor-time "id no longer exists" becomes a render-time refusal).
				refusals = append(refusals, fmt.Sprintf("%s: %s: key id was not delivered by the server", name, id))
				continue
			}
			if !configOnly && isUnrevealedSecret(k) {
				refusals = append(refusals, fmt.Sprintf("%s: %s: secret has no value — %s", name, k.Name, machineRevealOptIn))
				continue
			}
			val := valueOf(k)
			rows = append(rows, compose.Row{Name: k.Name, Value: val})
			srows = append(srows, compose.SnapshotRow{Name: k.Name, Classification: string(k.Classification), Value: val})
			names = append(names, k.Name)
		}
		for _, ln := range compose.RefuseUnacknowledged(names, tgt.AcknowledgeLoaderControl) {
			refusals = append(refusals, fmt.Sprintf("%s: %s: loader-control key not acknowledged (add it to this target's acknowledge_loader_control)", name, ln))
		}
		content, encRefusals, err := compose.EncodeRaw(rows)
		if err != nil {
			return false, failf(ExitInternal, "compose render: encode %s: %v", name, err)
		}
		for _, r := range encRefusals {
			refusals = append(refusals, fmt.Sprintf("%s: %s: %s", name, r.Key, r.Reason))
		}
		results = append(results, rendered{name: name, stamp: compose.TargetStamp(keys, content), content: content, rows: srows})
	}

	if len(refusals) > 0 {
		sort.Strings(refusals)
		return false, failf(ExitRefused, "hikyo compose render refused; no generation written, cursor not advanced:\n  %s", strings.Join(refusals, "\n  "))
	}

	// Write generations (idempotent — a no-op when present+complete, a rewrite
	// when a reboot lost the tmpfs copy), then the single stamp commit, then GC,
	// then snapshot + cursor.
	finalStamps := map[string]string{}
	var allRows []compose.SnapshotRow
	var lines []string
	moved := false
	for _, r := range results {
		finalStamps[r.name] = r.stamp
		allRows = append(allRows, r.rows...)
		if err := w.WriteGeneration(runtimeDir, r.stamp, map[string][]byte{r.name: r.content}); err != nil {
			return false, failf(ExitInternal, "compose render: write generation %s: %v", r.name, err)
		}
		if currentStamps[r.name] != r.stamp {
			moved = true
			lines = append(lines, fmt.Sprintf("rendered %s generation %s → %s", r.name, r.stamp, filepath.Join(runtimeDir, r.stamp, r.name+".env")))
		} else {
			lines = append(lines, fmt.Sprintf("unchanged %s generation %s", r.name, r.stamp))
		}
	}
	if err := w.CommitStamps(cfgDir, finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: commit stamps: %v", err)
	}
	if err := w.GC(runtimeDir, finalStamps, compose.DefaultGenerationsKept); err != nil {
		return false, failf(ExitInternal, "compose render: gc: %v", err)
	}

	// Snapshot BEFORE cursor: a snapshot is a harmless cache, but a cursor saved
	// without a snapshot could read "current" after a reboot with nothing to
	// serve. If the cursor save fails the snapshot still stands and the next
	// render does a full fetch.
	aad := buildDeliveryAAD(entry, org, project, env, resp, configOnly, cfg.TargetNames())
	if err := saveSnapshot(stateDir, keys, aad, compose.SnapshotPayload{Rows: allRows, GenerationStamps: finalStamps}); err != nil {
		return false, failf(ExitInternal, "compose render: save snapshot: %v", err)
	}
	if err := saveOfflineMeta(stateDir, aad, resp.Keys); err != nil {
		return false, failf(ExitInternal, "compose render: save offline metadata: %v", err)
	}
	if err := saveCursor(stateDir, resp, env, configOnly, keyIDs, finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: save cursor: %v", err)
	}

	for _, l := range lines {
		fmt.Fprintln(ios.Stderr, l)
	}
	return moved, nil
}

// composeRenderOffline renders each target from the last snapshot when the
// server is unreachable and the stack opted in.
func composeRenderOffline(ctx context.Context, ios IO, w *compose.Writer, cfg *compose.Config, cfgDir, stateDir, runtimeDir string, keys *crypto.LocalKeys, entry TrustEntry, org, project, env string, configOnly bool, fetchErr error) (bool, error) {
	_ = ctx
	if !isUnavailable(fetchErr) {
		return false, fetchErr
	}
	if !cfg.Snapshot.OfflineServe {
		fmt.Fprintln(ios.Stderr, "hikyo compose render: offline serve is not enabled for this stack; set snapshot.offline_serve: true to render from the last snapshot during an outage")
		return false, fetchErr
	}
	payload, meta, err := loadOfflineSnapshot(ios, cfg, stateDir, entry, org, project, env, configOnly)
	if err != nil {
		return false, err
	}
	byID := map[string]compose.SnapshotRow{}
	nameToID := meta.KeyIDs
	// Snapshot rows are keyed by name; the sidecar carries name→key_id.
	rowByName := map[string]compose.SnapshotRow{}
	for _, r := range payload.Rows {
		rowByName[r.Name] = r
	}
	for name, id := range nameToID {
		if r, ok := rowByName[name]; ok {
			byID[id] = r
		}
	}

	type rendered struct {
		name    string
		stamp   string
		content []byte
		rows    []compose.SnapshotRow
		ids     []string
	}
	var results []rendered
	var refusals []string
	for _, name := range cfg.TargetNames() {
		tgt := cfg.Targets[name]
		stamp, ok := payload.GenerationStamps[name]
		if !ok {
			refusals = append(refusals, fmt.Sprintf("%s: no stamp in the last snapshot", name))
			continue
		}
		var rows []compose.Row
		var srows []compose.SnapshotRow
		var ids []string
		for _, id := range tgt.Keys {
			r, ok := byID[id]
			if !ok {
				refusals = append(refusals, fmt.Sprintf("%s: %s: not present in the last snapshot", name, id))
				continue
			}
			rows = append(rows, compose.Row{Name: r.Name, Value: r.Value})
			srows = append(srows, r)
			ids = append(ids, id)
		}
		content, encRefusals, err := compose.EncodeRaw(rows)
		if err != nil {
			return false, failf(ExitInternal, "compose render: encode %s: %v", name, err)
		}
		for _, rr := range encRefusals {
			refusals = append(refusals, fmt.Sprintf("%s: %s: %s", name, rr.Key, rr.Reason))
		}
		results = append(results, rendered{name: name, stamp: stamp, content: content, rows: srows, ids: ids})
	}
	if len(refusals) > 0 {
		sort.Strings(refusals)
		return false, failf(ExitRefused, "hikyo compose render (offline) refused; no generation written:\n  %s", strings.Join(refusals, "\n  "))
	}

	// One offline record per served key, fsynced BEFORE any generation is
	// written, then the generations, then the stamp commit and GC.
	var records []compose.OfflineRecord
	for _, r := range results {
		for i, sr := range r.rows {
			id, err := compose.NewRecordID()
			if err != nil {
				return false, failf(ExitInternal, "compose render: record id: %v", err)
			}
			records = append(records, compose.OfflineRecord{
				RecordID: id, KeyID: r.ids[i], KeyName: sr.Name, Classification: sr.Classification,
				OccurredAt: ios.now().UTC().Format(time.RFC3339), CredentialID: meta.AAD.CredentialID,
				Generation: r.stamp, ServedFrom: meta.AAD.IssuedAt,
			})
		}
	}
	if err := compose.Append(stateDir, records); err != nil {
		return false, failf(ExitInternal, "compose render: recording offline disclosure: %v", err)
	}

	currentStamps, err := compose.CurrentStamps(cfgDir)
	if err != nil {
		return false, failf(ExitRefused, "compose render: %v", err)
	}
	finalStamps := map[string]string{}
	var lines []string
	moved := false
	for _, r := range results {
		finalStamps[r.name] = r.stamp
		if err := w.WriteGeneration(runtimeDir, r.stamp, map[string][]byte{r.name: r.content}); err != nil {
			return false, failf(ExitInternal, "compose render: write generation %s: %v", r.name, err)
		}
		fmt.Fprintf(ios.Stderr, "serving stale from %s, generation %s\n", meta.AAD.IssuedAt, r.stamp)
		if currentStamps[r.name] != r.stamp {
			moved = true
			lines = append(lines, fmt.Sprintf("rendered %s generation %s → %s", r.name, r.stamp, filepath.Join(runtimeDir, r.stamp, r.name+".env")))
		} else {
			lines = append(lines, fmt.Sprintf("unchanged %s generation %s", r.name, r.stamp))
		}
	}
	if err := w.CommitStamps(cfgDir, finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: commit stamps: %v", err)
	}
	if err := w.GC(runtimeDir, finalStamps, compose.DefaultGenerationsKept); err != nil {
		return false, failf(ExitInternal, "compose render: gc: %v", err)
	}
	for _, l := range lines {
		fmt.Fprintln(ios.Stderr, l)
	}
	return moved, nil
}

// ---------------------------------------------------------------------------
// hikyo compose sync
// ---------------------------------------------------------------------------

func runComposeSync(ctx context.Context, ios IO, args []string) error {
	var projectDir string
	st, flags, err := parseCommon("compose sync", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&projectDir, "project-directory", "", "directory to look up hikyo-compose.yaml from (walks up)")
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("compose sync"); err != nil {
		return err
	}

	// (1) Doctor checks run BEFORE the first render; any error finding refuses
	// without rendering. Findings go to stderr — stdout stays empty.
	findings, err := composeDoctorGather(ctx, ios, st, flags, projectDir)
	if err != nil {
		return err
	}
	if hasErrorFinding(findings) {
		renderComposeFindings(ios.Stderr, FormatTable, findings)
		return failf(ExitRefused, "hikyo compose sync: doctor found errors; not rendering")
	}

	// (2) Render (conditional).
	moved, err := composeRenderCore(ctx, ios, st, flags, projectDir, false)
	if err != nil {
		return err
	}
	if !moved {
		return nil
	}

	// (3) A stamp moved: recreate through docker compose up -d in the project dir.
	_, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return err
	}
	return dockerComposeUp(ctx, ios, cfgDir)
}

func dockerComposeUp(ctx context.Context, ios IO, projectDir string) error {
	bin, found := dockerBinary(ios)
	if !found {
		return failf(ExitRefused, "hikyo compose sync: docker not found on PATH; install Docker Compose or set HIKYO_COMPOSE_DOCKER")
	}
	cmd := exec.CommandContext(ctx, bin, "compose", "up", "-d")
	cmd.Dir = projectDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = ios.Stdout
	cmd.Stderr = ios.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return failf(ExitInternal, "hikyo compose sync: `docker compose up -d` exited %d", ee.ExitCode())
		}
		return failf(ExitInternal, "hikyo compose sync: `docker compose up -d`: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// hikyo compose doctor
// ---------------------------------------------------------------------------

func runComposeDoctor(ctx context.Context, ios IO, args []string) error {
	var (
		format     string
		projectDir string
	)
	st, flags, err := parseCommon("compose doctor", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.StringVar(&projectDir, "project-directory", "", "directory to look up hikyo-compose.yaml from (walks up)")
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("compose doctor"); err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	findings, err := composeDoctorGather(ctx, ios, st, flags, projectDir)
	if err != nil {
		return err
	}
	renderComposeFindings(ios.Stdout, f, findings)
	if hasErrorFinding(findings) {
		return failf(ExitRefused, "hikyo compose doctor found errors")
	}
	return nil
}

// composeDoctorGather assembles every input compose.Doctor needs — docker
// version/config, the raw compose file, managed stamps, generation state, file
// modes, and server agreement via a conditional fetch — and returns the merged
// finding list.
func composeDoctorGather(ctx context.Context, ios IO, st *State, flags commonFlags, projectDir string) ([]compose.Finding, error) {
	cfg, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, failf(ExitUsage, "hikyo compose doctor requires a %s (searched up from %s)", composeConfigName, startDir(ios, projectDir))
	}
	client, _, resolved, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "compose")
	if err != nil {
		return nil, err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)
	slug := composeSlug(cfg, org, project, env)
	stateDir := composeStateDir(st, slug)
	runtimeDir, rerr := composeRuntimeDir(ios, cfg, slug)

	var findings []compose.Finding

	// Docker version + resolved config.
	dockerFindings, version, resolvedConfig := doctorDocker(ctx, ios, cfgDir)
	findings = append(findings, dockerFindings...)

	managed, err := compose.CurrentStamps(cfgDir)
	if err != nil {
		return nil, failf(ExitRefused, "compose doctor: %v", err)
	}

	in := compose.DoctorInput{
		ComposeVersion: version,
		Config:         resolvedConfig,
		RawComposeYAML: doctorRawCompose(ios, cfgDir),
		ManagedStamps:  managed,
		ConfigTargets:  cfg.Targets,
		ExistingKeyIDs: doctorExistingKeyIDs(ctx, client, org, project, cfg),
		StateEntries:   doctorStateEntries(stateDir),
		TokenFile:      doctorTokenFile(flags.TokenFile),

		SystemdInvocation:       ios.Env.Getenv("INVOCATION_ID") != "",
		TokenFromCredentialsDir: tokenFromCredentialsDir(ios, flags.TokenFile),
	}
	if rerr == nil {
		in.RuntimeDir = runtimeDir
	}

	findings = append(findings, compose.Doctor(in)...)
	// A docker_missing finding makes the version check redundant; drop the
	// compose.Doctor floor finding so the two do not both fire for one cause.
	if hasCode(findings, "docker_missing") {
		findings = dropCode(findings, "compose_version_below_floor")
	}

	findings = append(findings, doctorServerAgreement(ctx, client, stateDir, managed, runtimeDir, org, project, env, allTargetKeyIDs(cfg))...)

	sortFindings(findings)
	return findings, nil
}

// doctorDocker runs `docker compose version --short` and `docker compose config
// --format json`. A missing docker binary is the docker_missing error finding
// and leaves version/config empty.
func doctorDocker(ctx context.Context, ios IO, cfgDir string) ([]compose.Finding, string, *compose.ComposeConfig) {
	bin, found := dockerBinary(ios)
	if !found {
		return []compose.Finding{{Severity: compose.SeverityError, Code: "docker_missing",
			Message: "docker not found on PATH and HIKYO_COMPOSE_DOCKER is unset; path 2 needs Docker Compose ≥ 2.30"}}, "", nil
	}
	version, err := runCapture(ctx, ios, bin, cfgDir, "compose", "version", "--short")
	if err != nil {
		return []compose.Finding{{Severity: compose.SeverityError, Code: "docker_missing",
			Message: fmt.Sprintf("`docker compose version` failed: %v", err)}}, "", nil
	}
	var cfg *compose.ComposeConfig
	if raw, err := runCapture(ctx, ios, bin, cfgDir, "compose", "config", "--format", "json"); err == nil {
		if parsed, perr := compose.ParseComposeConfig([]byte(raw)); perr == nil {
			cfg = parsed
		}
	}
	return nil, strings.TrimSpace(version), cfg
}

// doctorServerAgreement performs a conditional fetch presenting the stored
// cursor when eligible, so no plaintext crosses the wire on a "current" answer.
func doctorServerAgreement(ctx context.Context, client *Client, stateDir string, managed map[string]string, runtimeDir, org, project, env string, keyIDs []string) []compose.Finding {
	present := eligibleCursor(stateDir, managed, runtimeDir, env, false, keyIDs)
	if present == "" {
		// No eligible cursor: either never rendered, or the local render is gone.
		// A full fetch would be a disclosure, so doctor does not do one.
		return []compose.Finding{{Severity: compose.SeverityError, Code: "never_rendered",
			Message: "no eligible cursor: this box has not rendered, or its render is gone; run `hikyo compose render`"}}
	}
	resp, err := fetchDelivery(ctx, client, org, project, env, false, present)
	if err != nil {
		if isUnavailable(err) {
			return []compose.Finding{{Severity: compose.SeverityWarn, Code: "server_unreachable",
				Message: fmt.Sprintf("could not reach the server to confirm agreement: %v", err)}}
		}
		return []compose.Finding{{Severity: compose.SeverityError, Code: "server_unreachable",
			Message: fmt.Sprintf("the server refused the agreement check: %v", err)}}
	}
	if !resp.Current {
		return []compose.Finding{{Severity: compose.SeverityError, Code: "server_manifest_drift",
			Message: "the server's current manifest is not the one this box rendered — run `hikyo compose render`"}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// machine-only target resolution
// ---------------------------------------------------------------------------

// resolveMachineTarget resolves the target, folds any hikyo-compose.yaml
// dimensions in (a disagreement with an already-resolved dimension is a hard
// error), and REQUIRES a machine credential. It never falls back to the stored
// human session — that path is a refusal in this build.
func resolveMachineTarget(st *State, ios IO, flags commonFlags, cfg *compose.Config, cfgPath, verb string) (*Client, TrustEntry, Resolved, error) {
	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, err
	}
	if cfg != nil {
		for _, d := range []struct {
			dim Dimension
			val string
		}{{DimOrg, cfg.Org}, {DimProject, cfg.Project}, {DimEnv, cfg.Environment}} {
			if err := foldConfigDim(&resolved, d.dim, d.val, cfgPath); err != nil {
				return nil, TrustEntry{}, Resolved{}, err
			}
		}
	}

	entry, err := machineEntry(st, resolved, cfg)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, err
	}
	for _, d := range []Dimension{DimOrg, DimProject, DimEnv} {
		if _, err := resolved.Require(d); err != nil {
			return nil, TrustEntry{}, Resolved{}, err
		}
	}

	token, err := machineToken(ios, flags.TokenFile)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, err
	}
	if token == "" {
		return nil, TrustEntry{}, Resolved{}, failf(ExitAuth,
			"hikyo %s accepts only a machine credential (--token-file or HIKYO_TOKEN); the --use-human-session path is not in this build", verb)
	}
	client, err := NewClient(entry, token)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, err
	}
	if echo := resolved.Echo(); echo != "" {
		fmt.Fprintf(ios.Stderr, "target: %s [origin %s, artifact machine-credential]\n", echo, entry.Origin)
	}
	return client, entry, resolved, nil
}

// foldConfigDim fills an unresolved dimension from the config, or refuses when
// the config disagrees with an already-resolved one, naming both sources.
func foldConfigDim(r *Resolved, dim Dimension, cfgVal, cfgPath string) error {
	cfgVal = strings.TrimSpace(cfgVal)
	if cfgVal == "" {
		return nil
	}
	if cur := r.Values[dim]; cur != "" {
		if cur != cfgVal {
			return failf(ExitUsage, "hikyo compose: %s is %q (from %s) but %q (from %s) — refusing rather than picking one",
				dim, cur, r.Sources[dim], cfgVal, cfgPath)
		}
		return nil
	}
	r.Values[dim] = cfgVal
	r.Sources[dim] = SourceConfig
	return nil
}

// machineEntry resolves the trust entry the credential is presented to. The
// machine path NEVER establishes trust interactively: an origin the config
// names must already be provisioned in the local store.
func machineEntry(st *State, resolved Resolved, cfg *compose.Config) (TrustEntry, error) {
	var cfgOrigin string
	if cfg != nil && strings.TrimSpace(cfg.Instance) != "" {
		o, err := CanonicalOrigin(cfg.Instance)
		if err != nil {
			return TrustEntry{}, err
		}
		cfgOrigin = o
	}

	instance := resolved.Get(DimInstance)
	if instance == "" {
		if cfgOrigin != "" {
			entry, err := lookupByOrigin(st, cfgOrigin)
			if err != nil {
				return TrustEntry{}, err
			}
			resolved.Values[DimInstance] = entry.Name
			resolved.Sources[DimInstance] = SourceConfig
			return entry, nil
		}
		// Exactly one established instance is the only reading; two or more is an
		// ambiguity, never a default.
		entries, serr := st.Trust().Load()
		if serr != nil {
			return TrustEntry{}, serr
		}
		if len(entries) != 1 {
			_, err := resolved.Require(DimInstance)
			return TrustEntry{}, err
		}
		for k := range entries {
			instance = k
		}
		resolved.Values[DimInstance] = instance
		resolved.Sources[DimInstance] = SourceContext
	}

	entry, err := st.Trust().Lookup(instance)
	if err != nil {
		return TrustEntry{}, err
	}
	if cfgOrigin != "" && entry.Origin != cfgOrigin {
		return TrustEntry{}, failf(ExitUsage,
			"instance %q resolves to origin %s but %s names %s — refusing rather than picking one",
			instance, entry.Origin, composeConfigName, cfgOrigin)
	}
	return entry, nil
}

func lookupByOrigin(st *State, origin string) (TrustEntry, error) {
	entries, err := st.Trust().Load()
	if err != nil {
		return TrustEntry{}, err
	}
	for _, e := range entries {
		if e.Origin == origin {
			return e, nil
		}
	}
	return TrustEntry{}, failf(ExitRefused,
		"%s names instance %s, which is not in the local trust store; provision it with `hikyo context create --instance %s` or --trust-file (the machine path never establishes trust interactively)",
		composeConfigName, origin, origin)
}

// ---------------------------------------------------------------------------
// delivery transport
// ---------------------------------------------------------------------------

func deliveryPath(org, project, env string) string {
	return api.PathPrefix + "/orgs/" + url.PathEscape(org) +
		"/projects/" + url.PathEscape(project) +
		"/environments/" + url.PathEscape(env) + "/delivery"
}

func fetchDelivery(ctx context.Context, client *Client, org, project, env string, configOnly bool, cursor string) (apigen.DeliveryResponse, error) {
	q := url.Values{}
	if configOnly {
		q.Set("config_only", "true")
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	path := deliveryPath(org, project, env)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var resp apigen.DeliveryResponse
	if err := client.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return apigen.DeliveryResponse{}, err
	}
	return resp, nil
}

// flushOffline reconciles buffered offline records before a fetch (ops-spec § 6
// ordering rule). Records chunk to the server's 1000-per-call limit; the files
// are marked flushed only after every chunk is accepted, so a mid-run failure
// re-sends idempotently rather than dropping evidence.
func flushOffline(ctx context.Context, client *Client, org, project, env, stateDir string) error {
	if stateDir == "" {
		return nil
	}
	records, files, err := compose.Pending(stateDir)
	if err != nil {
		return failf(ExitInternal, "reading pending offline records: %v", err)
	}
	if len(records) == 0 {
		return nil
	}
	path := deliveryPath(org, project, env) + "/offline-records"
	const batch = 1000
	for i := 0; i < len(records); i += batch {
		end := min(i+batch, len(records))
		body := apigen.ReconcileOfflineRecordsRequest{Records: toAPIRecords(records[i:end])}
		if err := client.Do(ctx, http.MethodPost, path, body, nil); err != nil {
			return err // refuses the fetch: ExitUnavailable or the server's mapped code
		}
	}
	if err := compose.MarkFlushed(files); err != nil {
		return failf(ExitInternal, "marking offline records flushed: %v", err)
	}
	return nil
}

func toAPIRecords(recs []compose.OfflineRecord) []apigen.OfflineDeliveryRecord {
	out := make([]apigen.OfflineDeliveryRecord, 0, len(recs))
	for _, r := range recs {
		occ, _ := time.Parse(time.RFC3339, r.OccurredAt)
		served, _ := time.Parse(time.RFC3339, r.ServedFrom)
		out = append(out, apigen.OfflineDeliveryRecord{
			RecordId: r.RecordID, KeyId: r.KeyID, KeyName: r.KeyName,
			Classification: apigen.KeyClassification(r.Classification),
			OccurredAt:     occ, ServedFrom: served,
			CredentialId: r.CredentialID, Generation: r.Generation,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// snapshot / cursor / offline-meta helpers (thin wrappers over internal/compose)
// ---------------------------------------------------------------------------

// offlineMeta is the CLI-owned sidecar the offline path needs beyond the
// compose snapshot payload: the AAD tuple LoadSnapshot takes as a parameter, and
// the name→key_id map the per-key reconciliation records require. Kept in the
// CLI layer deliberately — the compose snapshot format is being reworked to be
// self-describing; saveOfflineMeta/loadOfflineMeta are the one place to
// reconcile when it lands.
type offlineMeta struct {
	AAD    crypto.SnapshotAAD `json:"aad"`
	KeyIDs map[string]string  `json:"key_ids"`
}

func saveSnapshot(stateDir string, keys *crypto.LocalKeys, aad crypto.SnapshotAAD, payload compose.SnapshotPayload) error {
	return compose.SaveSnapshot(stateDir, keys, aad, payload)
}

func saveOfflineMeta(stateDir string, aad crypto.SnapshotAAD, keys []apigen.DeliveredKey) error {
	ids := make(map[string]string, len(keys))
	for _, k := range keys {
		ids[k.Name] = k.KeyId
	}
	data, err := json.Marshal(offlineMeta{AAD: aad, KeyIDs: ids})
	if err != nil {
		return fmt.Errorf("marshal offline metadata: %w", err)
	}
	return writeFileAtomic0600(filepath.Join(stateDir, offlineMetaFile), data)
}

func loadOfflineMeta(stateDir string) (offlineMeta, bool, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, offlineMetaFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return offlineMeta{}, false, nil
		}
		return offlineMeta{}, false, err
	}
	var m offlineMeta
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return offlineMeta{}, false, fmt.Errorf("parse offline metadata: %w", err)
	}
	return m, true, nil
}

// loadOfflineSnapshot opens the persisted snapshot for offline serve. It
// cross-checks the sidecar's context-derivable AAD fields against the current
// invocation, so a snapshot is not merely self-consistent but still belongs to
// THIS stack, then opens it under the persisted AAD.
func loadOfflineSnapshot(ios IO, cfg *compose.Config, stateDir string, entry TrustEntry, org, project, env string, configOnly bool) (compose.SnapshotPayload, offlineMeta, error) {
	var zero compose.SnapshotPayload
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return zero, offlineMeta{}, err
	}
	meta, ok, err := loadOfflineMeta(stateDir)
	if err != nil {
		return zero, offlineMeta{}, failf(ExitRefused, "offline serve: %v", err)
	}
	if !ok {
		return zero, offlineMeta{}, failf(ExitRefused, "offline serve is enabled but no snapshot has been saved for this stack yet")
	}
	if meta.AAD.InstanceOrigin != entry.Origin || meta.AAD.OrgID != org || meta.AAD.ProjectID != project ||
		meta.AAD.EnvironmentID != env || meta.AAD.ConfigOnly != configOnly {
		return zero, offlineMeta{}, failf(ExitRefused, "offline snapshot belongs to a different context (origin/org/project/env/config-only mismatch) and will not be served")
	}
	payload, _, err := compose.LoadSnapshot(stateDir, keys, meta.AAD, ios.now(), cfg.SnapshotMaxAge())
	if err != nil {
		if errors.Is(err, compose.ErrSnapshotExpired) || errors.Is(err, compose.ErrSnapshotRollback) || errors.Is(err, crypto.ErrDecrypt) {
			return zero, offlineMeta{}, failf(ExitRefused,
				"offline serve refused: snapshot issued %s, expires %s — past the maximum stale age (%s) or otherwise unusable (%v)",
				meta.AAD.IssuedAt, meta.AAD.ExpiresAt, cfg.SnapshotMaxAge(), err)
		}
		return zero, offlineMeta{}, failf(ExitRefused, "offline serve: %v", err)
	}
	return payload, meta, nil
}

func saveCursor(stateDir string, resp apigen.DeliveryResponse, env string, configOnly bool, keyIDs []string, stamps map[string]string) error {
	pinGen := ""
	if resp.PinnedRevision != nil {
		pinGen = strconv.FormatInt(*resp.PinnedRevision, 10)
	}
	return compose.SaveCursor(stateDir, compose.CursorState{
		Cursor: resp.Cursor, CredentialID: resp.CredentialId, Environment: env,
		ConfigOnly: configOnly, TargetIDsHash: compose.HashTargetIDs(keyIDs),
		PinGeneration: pinGen, GenerationStamps: stamps,
	})
}

// eligibleCursor returns the stored cursor when the three-part local test holds,
// or "". The credential id compared is the cursor's own last-fetch value: the
// live server credential id is not known pre-fetch, and the server re-binds the
// cursor to the presenting credential anyway (a mismatch just yields a full
// fetch, never a wrong "current").
func eligibleCursor(stateDir string, currentStamps map[string]string, runtimeDir, env string, configOnly bool, keyIDs []string) string {
	state, err := compose.LoadCursor(stateDir)
	if err != nil || state == nil {
		return ""
	}
	c, ok := compose.EligibleCursor(state, currentStamps, runtimeDir, state.CredentialID, env, configOnly, keyIDs)
	if !ok {
		return ""
	}
	return c
}

func appendOfflineRecords(stateDir string, rows []compose.SnapshotRow, meta offlineMeta, generation string) error {
	if len(rows) == 0 {
		return nil
	}
	recs := make([]compose.OfflineRecord, 0, len(rows))
	for _, r := range rows {
		id, err := compose.NewRecordID()
		if err != nil {
			return err
		}
		recs = append(recs, compose.OfflineRecord{
			RecordID: id, KeyID: meta.KeyIDs[r.Name], KeyName: r.Name, Classification: r.Classification,
			OccurredAt: time.Now().UTC().Format(time.RFC3339), CredentialID: meta.AAD.CredentialID,
			Generation: generation, ServedFrom: meta.AAD.IssuedAt,
		})
	}
	return compose.Append(stateDir, recs)
}

// ---------------------------------------------------------------------------
// path / config discovery
// ---------------------------------------------------------------------------

func startDir(ios IO, projectDir string) string {
	if strings.TrimSpace(projectDir) != "" {
		return projectDir
	}
	return ios.Workdir
}

// findComposeConfig walks up from startDir looking for hikyo-compose.yaml.
func findComposeConfig(startDir string) (*compose.Config, string, error) {
	dir := startDir
	for {
		candidate := filepath.Join(dir, composeConfigName)
		raw, err := os.ReadFile(candidate)
		switch {
		case err == nil:
			cfg, perr := compose.ParseConfig(raw)
			if perr != nil {
				return nil, "", failf(ExitRefused, "%s: %v", candidate, perr)
			}
			return cfg, dir, nil
		case !errors.Is(err, os.ErrNotExist):
			return nil, "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir || strings.TrimSpace(parent) == "" {
			return nil, "", nil
		}
		dir = parent
	}
}

func composeSlug(cfg *compose.Config, org, project, env string) string {
	if cfg != nil && strings.TrimSpace(cfg.Slug) != "" {
		return cfg.Slug
	}
	return org + "-" + project + "-" + env
}

func composeStateDir(st *State, slug string) string {
	return filepath.Join(st.Dir(), "compose", slug)
}

// composeRuntimeDir resolves the tmpfs runtime directory (ops-spec § 6):
// config runtime_dir, else /run/hikyo/<slug> as root, else
// $XDG_RUNTIME_DIR/hikyo/<slug>. No runtime dir and not root is a usage error
// naming runtime_dir rather than a silent guess.
func composeRuntimeDir(ios IO, cfg *compose.Config, slug string) (string, error) {
	if cfg != nil && strings.TrimSpace(cfg.RuntimeDir) != "" {
		return cfg.RuntimeDir, nil
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/run/hikyo", slug), nil
	}
	if xdg := ios.Env.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "hikyo", slug), nil
	}
	return "", failf(ExitUsage,
		"no runtime directory: not root and XDG_RUNTIME_DIR is unset. Set `runtime_dir` in %s, or run under a session with XDG_RUNTIME_DIR", composeConfigName)
}

func loadLocalKeys(stateDir string) (*crypto.LocalKeys, error) {
	keys, err := crypto.LoadOrCreateLocalKey(stateDir)
	if err != nil {
		return nil, failf(ExitRefused, "compose: local key: %v", err)
	}
	return keys, nil
}

// ---------------------------------------------------------------------------
// doctor input gathering
// ---------------------------------------------------------------------------

// doctorRawCompose reads the raw compose file so ${HIKYO_GEN_*:?} is visible
// (the resolved config discards the required form). COMPOSE_FILE wins when set;
// otherwise the first conventional name found in the project dir.
func doctorRawCompose(ios IO, cfgDir string) string {
	if cf := ios.Env.Getenv("COMPOSE_FILE"); cf != "" {
		path := cf
		if !filepath.IsAbs(path) {
			path = filepath.Join(cfgDir, path)
		}
		if b, err := os.ReadFile(path); err == nil {
			return string(b)
		}
		return ""
	}
	for _, name := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
		if b, err := os.ReadFile(filepath.Join(cfgDir, name)); err == nil {
			return string(b)
		}
	}
	return ""
}

// doctorExistingKeyIDs reads the project key catalogue for the target_key_missing
// check. A workload credential deliberately CANNOT enumerate the catalogue (it
// reads values through delivery, not the catalogue), so a 404/403 there is not a
// drift signal — it means the check is not answerable from this credential. In
// that case the configured target key ids are treated as existing, making the
// check a no-op rather than flagging every id as missing. When the catalogue IS
// readable, the real set drives the check.
func doctorExistingKeyIDs(ctx context.Context, client *Client, org, project string, cfg *compose.Config) map[string]bool {
	var list apigen.KeyList
	path := api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project) + "/keys"
	if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
		out := map[string]bool{}
		for _, id := range allTargetKeyIDs(cfg) {
			out[id] = true
		}
		return out
	}
	out := make(map[string]bool, len(list.Items))
	for _, k := range list.Items {
		out[k.Id] = true
	}
	return out
}

func doctorStateEntries(stateDir string) []compose.StateEntry {
	var entries []compose.StateEntry
	_ = filepath.WalkDir(stateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		entries = append(entries, compose.StateEntry{
			Path: path, Perm: info.Mode(), IsDir: d.IsDir(), OwnedByEUID: ownedByEUID(info),
		})
		return nil
	})
	return entries
}

func doctorTokenFile(tokenFile string) *compose.FileMode {
	if tokenFile == "" {
		return nil
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		return nil
	}
	return &compose.FileMode{Perm: info.Mode(), OwnedByEUID: ownedByEUID(info)}
}

func tokenFromCredentialsDir(ios IO, tokenFile string) bool {
	dir := ios.Env.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" || tokenFile == "" {
		return false
	}
	abs, err := filepath.Abs(tokenFile)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dir, abs)
	return err == nil && !strings.HasPrefix(rel, "..")
}

// ---------------------------------------------------------------------------
// doctor rendering
// ---------------------------------------------------------------------------

type composeFinding struct {
	Status  string `json:"status"`
	Check   string `json:"check"`
	Message string `json:"message"`
}

type composeDoctorReport struct {
	Status   string           `json:"status"`
	Findings []composeFinding `json:"findings"`
}

func renderComposeFindings(w io.Writer, f Format, findings []compose.Finding) {
	report := composeDoctorReport{Status: "ok", Findings: []composeFinding{}}
	rows := make([][]string, 0, len(findings))
	for _, fd := range findings {
		report.Findings = append(report.Findings, composeFinding{Status: string(fd.Severity), Check: fd.Code, Message: fd.Message})
		rows = append(rows, []string{string(fd.Severity), fd.Code, fd.Message})
		switch fd.Severity {
		case compose.SeverityError:
			report.Status = "error"
		case compose.SeverityWarn:
			if report.Status == "ok" {
				report.Status = "warning"
			}
		}
	}
	if len(rows) == 0 {
		rows = append(rows, []string{"ok", "compose", "no findings"})
	}
	_ = Render(w, f, Table{Columns: []string{"STATUS", "CHECK", "MESSAGE"}, Rows: rows, JSON: report})
}

// ---------------------------------------------------------------------------
// docker seam + capture
// ---------------------------------------------------------------------------

// dockerBinary resolves the docker executable. HIKYO_COMPOSE_DOCKER overrides
// PATH resolution — the test seam, documented in the handoff/package doc only,
// deliberately kept out of the help text.
func dockerBinary(ios IO) (string, bool) {
	if v := ios.Env.Getenv("HIKYO_COMPOSE_DOCKER"); v != "" {
		return v, true
	}
	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", false
	}
	return bin, true
}

func runCapture(ctx context.Context, ios IO, bin, dir string, args ...string) (string, error) {
	_ = ios
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

// ---------------------------------------------------------------------------
// small pure helpers
// ---------------------------------------------------------------------------

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func isUnavailable(err error) bool {
	var ce *Error
	return asCLIError(err, &ce) && ce.Code == ExitUnavailable
}

func unrevealedSecrets(keys []apigen.DeliveredKey) []string {
	var missing []string
	for _, k := range keys {
		if isUnrevealedSecret(k) {
			missing = append(missing, k.Name)
		}
	}
	sort.Strings(missing)
	return missing
}

func isUnrevealedSecret(k apigen.DeliveredKey) bool {
	return k.Presence == apigen.DeliveredKeyPresenceSet &&
		k.Classification == apigen.KeyClassificationSecret && k.Value == nil
}

func valueOf(k apigen.DeliveredKey) string {
	if k.Value == nil {
		return ""
	}
	return *k.Value
}

func deliveredValues(keys []apigen.DeliveredKey) map[string]string {
	out := map[string]string{}
	for _, k := range keys {
		if k.Value != nil {
			out[k.Name] = *k.Value
		}
	}
	return out
}

func deliveredRows(keys []apigen.DeliveredKey) []compose.SnapshotRow {
	var rows []compose.SnapshotRow
	for _, k := range keys {
		if k.Value == nil {
			continue
		}
		rows = append(rows, compose.SnapshotRow{Name: k.Name, Classification: string(k.Classification), Value: *k.Value})
	}
	return rows
}

func deliveredByID(keys []apigen.DeliveredKey) map[string]apigen.DeliveredKey {
	m := make(map[string]apigen.DeliveredKey, len(keys))
	for _, k := range keys {
		m[k.KeyId] = k
	}
	return m
}

func rowsToValues(rows []compose.SnapshotRow) map[string]string {
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		out[r.Name] = r.Value
	}
	return out
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func canonicalRows(rows []compose.SnapshotRow) []byte {
	sorted := append([]compose.SnapshotRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	data, _ := json.Marshal(sorted)
	return data
}

func allTargetKeyIDs(cfg *compose.Config) []string {
	set := map[string]struct{}{}
	for _, t := range cfg.Targets {
		for _, id := range t.Keys {
			set[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func buildDeliveryAAD(entry TrustEntry, org, project, env string, resp apigen.DeliveryResponse, configOnly bool, targetNames []string) crypto.SnapshotAAD {
	rev := int64(resp.SchemaRevision)
	pinned := resp.PinnedRevision != nil
	if pinned {
		rev = *resp.PinnedRevision
	}
	names := append([]string(nil), targetNames...)
	sort.Strings(names)
	return crypto.SnapshotAAD{
		InstanceOrigin: entry.Origin,
		OrgID:          org, ProjectID: project, EnvironmentID: env,
		CredentialID: resp.CredentialId, Revision: rev, Pinned: pinned,
		Projection: deliveryProjection(resp.Keys), ConfigOnly: configOnly,
		TargetNames: names,
		IssuedAt:    resp.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   resp.SnapshotExpiresAt.UTC().Format(time.RFC3339),
	}
}

// deliveryProjection is the authorized projection recorded in the snapshot AAD,
// derived from what was delivered: `read` always, plus `reveal` when any
// delivered secret carried a value (the values-export rule mirrored). One
// function so the derivation cannot drift between save sites.
func deliveryProjection(keys []apigen.DeliveredKey) []string {
	proj := []string{"read"}
	for _, k := range keys {
		if k.Classification == apigen.KeyClassificationSecret && k.Value != nil {
			proj = append(proj, "reveal")
			break
		}
	}
	return proj
}

func hasErrorFinding(findings []compose.Finding) bool {
	return hasSeverity(findings, compose.SeverityError)
}

func hasSeverity(findings []compose.Finding, sev compose.Severity) bool {
	for _, f := range findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func hasCode(findings []compose.Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func dropCode(findings []compose.Finding, code string) []compose.Finding {
	out := findings[:0]
	for _, f := range findings {
		if f.Code != code {
			out = append(out, f)
		}
	}
	return out
}

func sortFindings(findings []compose.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Message < findings[j].Message
	})
}

// writeFileAtomic0600 writes data to a temp file in the same dir and renames it
// into place (0600), creating the directory 0700 if needed.
func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}
