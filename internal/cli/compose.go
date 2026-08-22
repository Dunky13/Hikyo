package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
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
//
// Test seam: HIKYO_COMPOSE_DOCKER overrides the resolved `docker` executable for
// `compose sync|doctor`. It is deliberately kept out of the help text — not part
// of the CLI's stable surface, only a test/override hook — documented here and
// in the api-cli-spellings "Compose delivery" section.

const (
	composeConfigName = "hikyo-compose.yaml"
	// runGenerationKey names run's single snapshot "generation" in the
	// GenerationStamps map. It is outside the target-name grammar
	// (^[a-z][a-z0-9-]*$) so it can never collide with a real target named
	// "run".
	runGenerationKey = "__run__"

	// credentialFingerprintDomain domain-separates the LOCAL credential
	// fingerprint that binds BOTH the cursor and the offline snapshot to the
	// presented token (compose ADR § Cursor rules; R1-3). It is a purely local
	// identity: swapping tokens changes the fingerprint and invalidates the cursor
	// before it is presented and refuses the old snapshot by name at load. The
	// bytes are frozen — changing them would pointlessly invalidate live cursors.
	credentialFingerprintDomain = "hikyo-cursor-cred-v1\x00"

	machineRevealOptIn = "secret plaintext requires the project's machine-reveal opt-in and then a `reveal` grant on this principal: " +
		"`hikyo project-settings machine-reveal set --enabled true` (project-settings and reveal, second factor), " +
		"then `hikyo access grant add --principal <mch_...> --capability reveal --env <env>`; or run with --config-only"
)

// credentialFingerprint is the local, offline-derivable identity of the
// presented credential: hex(sha256(domain ‖ token))[:32] (compose ADR § Cursor
// rules — "the stored cursor is bound to credential identity"). ONE helper for
// every save-site and compare-site so they cannot drift — it binds BOTH the
// cursor AND the offline snapshot's credential (R1-3), so a rotated token
// refuses the old snapshot by name even fully offline. The server-asserted
// credential_id (a different value) remains authenticated metadata in the AAD.
func credentialFingerprint(token string) string {
	sum := sha256.Sum256([]byte(credentialFingerprintDomain + token))
	return hex.EncodeToString(sum[:])[:32]
}

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
		useHumanSession  bool
		allowOverrideRaw string
		projectDir       string
	)
	st, flags, err := parseCommon("run", ios, hikyoArgs, func(fs *flag.FlagSet) {
		fs.BoolVar(&configOnly, "config-only", false, "request the config-only projection: no secrets, a distinct authorized mode")
		fs.BoolVar(&useHumanSession, "use-human-session", false, "the locked #18 exception: run under the stored human session, gated by a TTY, an enumerated confirmation, and a live disclosure window")
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

	// The single narrow #18 exception, restated exactly (api-cli-surface ADR line
	// 96): `run` — and only `run` — may use the stored human session, and only
	// when ALL of the flag, a TTY, an enumerated confirmation, and the bound
	// reauth ceremony hold. `render` and `sync` have no human path, so this branch
	// lives here rather than in resolveMachineTarget.
	if useHumanSession {
		if flags.Auth == "machine" {
			return failf(ExitRefused, "hikyo run --use-human-session conflicts with --auth=machine")
		}
		flags.Auth = "human"
		return runHumanSession(ctx, ios, st, flags, cfg, childArgs, configOnly, allowOverride)
	}
	client, entry, resolved, token, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "run")
	if err != nil {
		return err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)

	// The state dir exists only when a config file names this stack; run with no
	// config file writes nothing and holds nothing pending by construction.
	stateDir := ""
	var snapshotBinding crypto.SnapshotBinding
	if cfg != nil {
		slug, serr := composeSlug(cfg, org, project, env)
		if serr != nil {
			return serr
		}
		stateDir = composeStateDir(st, slug)
		snapshotBinding, serr = newSnapshotBinding(stateDir, entry, org, project, env, token, configOnly, []string{runGenerationKey})
		if serr != nil {
			return failf(ExitRefused, "hikyo run: snapshot binding: %v", serr)
		}
		// Flush-before-fetch (ops-spec § 6 ordering rule): pending offline
		// records reconcile BEFORE the fetch proceeds; a failure refuses the
		// fetch.
		if err := flushOffline(ctx, client, org, project, env, stateDir); err != nil {
			return err
		}
	}

	// Loader-control acknowledgement (compose ADR § "Loader-control keys"): the
	// config's run block acknowledges by name. Resolved before the fetch so the
	// offline path can refuse a loader-control key BEFORE it appends any offline
	// record (finding 6).
	var ack []string
	if cfg != nil {
		ack = cfg.Run.AcknowledgeLoaderControl
	}

	resp, ferr := fetchDelivery(ctx, client, org, project, env, configOnly, ack, "")

	var (
		fetched map[string]string
		live    bool
	)
	if ferr != nil {
		f, herr := serveRunOffline(ios, cfg, stateDir, snapshotBinding, ack, ferr)
		if herr != nil {
			return herr
		}
		fetched = f
	} else {
		if cfg != nil {
			snapshotBinding, err = bindSnapshotDelivery(snapshotBinding, resp)
			if err != nil {
				return failf(ExitRefused, "hikyo run: snapshot binding: %v", err)
			}
		}
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

	// Loader-control refusal for the LIVE path (the offline path already checked
	// pre-append inside serveRunOffline).
	if refused := compose.RefuseUnacknowledged(mapKeys(fetched), ack); len(refused) > 0 {
		return failf(ExitRefused, "hikyo run: refusing loader-control key(s) %s; acknowledge each by name in the config's `run.acknowledge_loader_control`",
			strings.Join(refused, ", "))
	}

	// Merge: fetched wins; a differing collision is a hard error unless named in
	// --allow-override (compose ADR § "Merge, collisions"). The base is the
	// SANITIZED parent environment — HIKYO_TOKEN (the workload credential) never
	// reaches the child (finding 1).
	merged, _, err := compose.MergeEnv(sanitizedEnviron(), fetched, allowOverride)
	if err != nil {
		return &Error{Code: ExitRefused, Err: err}
	}

	// ARG_MAX preflight (ops-spec § 6): the execve composite bound, refused loud
	// pre-exec rather than as E2BIG at the wrong layer.
	if ok, detail := compose.ExecPreflight(merged, childArgs, compose.DefaultArgMax()); !ok {
		return failf(ExitRefused, "hikyo run: %s; reduce the delivered set or shorten the command", detail)
	}

	// Snapshot: after a LIVE delivering fetch and only when a config file exists.
	// Opt-in governs SERVING, not saving — a silent save failure is the silent
	// fallback the house forbids, so it is a hard error.
	if live && cfg != nil {
		if err := saveRunSnapshot(stateDir, snapshotBinding, resp); err != nil {
			return failf(ExitInternal, "hikyo run: saving offline snapshot: %v", err)
		}
	}

	// Exec. 127 = not found, 126 = found-but-not-executable — the child-side
	// convention (exit.go), the only exits outside the closed set. On success
	// there is no hikyo process (unix syscall.Exec): the child's status is the
	// invocation's.
	command := childArgs[0]
	resolvedPath, cerr := resolveChildCommand(command)
	if cerr != nil {
		return cerr
	}
	if err := ios.exec(resolvedPath, childArgs, merged); err != nil {
		return failf(ExitCommandNotExecutable, "hikyo run: %s: %v", command, err)
	}
	// Unreachable on a real unix exec (the process image is replaced); reached
	// only through the injected test seam, which returns nil to signal capture.
	return nil
}

// runHumanSession implements the locked #18 exception for `hikyo run`. All four
// conditions must hold before the child is launched:
//
//  1. the --use-human-session flag (the caller is here, so it is set);
//  2. stderr is a TTY — an ADDITIONAL refusal, never the control (ADR line 96):
//     a human session driving a non-interactive process is refused;
//  3. an enumerated confirmation — the environment and the exact key names to be
//     injected, printed to the controlling terminal, answered y/N there;
//  4. the bound reauth ceremony — a live disclosure window for the environment,
//     opened inline by the TOTP ceremony where the window allows it. Required
//     under --config-only too: the four conditions are locked as a set.
//
// The offline snapshot machinery is deliberately NOT reached on this path: a
// human-session snapshot served offline later would bypass the machine-only rule
// the delivery model rests on, so a human-session run never saves one.
func runHumanSession(ctx context.Context, ios IO, st *State, flags commonFlags, cfg *compose.Config, childArgs []string, configOnly bool, allowOverride []string) error {
	// (2) TTY gate, first: a refusal that needs no session and no server. Both
	// halves are required by name: a controlling terminal (the confirmation and
	// the code are read there) AND stderr being a TTY (the locked condition -
	// a human session driving a process whose stderr is captured is refused).
	terminalSession, terminalErr := ios.terminalSession()
	if terminalErr != nil {
		return failf(ExitRefused,
			"hikyo run --use-human-session requires a controlling terminal for the confirmation and reauth ceremony: %v", terminalErr)
	}
	if ios.StderrIsTerminal == nil || !ios.StderrIsTerminal() {
		return failf(ExitRefused,
			"hikyo run --use-human-session requires stderr to be a terminal; a captured stderr means a non-interactive process, which the human-session exception refuses")
	}

	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	session, err := requireHumanSession("hikyo run --use-human-session", artifact)
	if err != nil {
		return err
	}
	if cfg != nil {
		for _, d := range []struct {
			dim Dimension
			val string
		}{{DimOrg, cfg.Org}, {DimProject, cfg.Project}, {DimEnv, cfg.Environment}} {
			if err := foldConfigDim(&resolved, d.dim, d.val, composeConfigName); err != nil {
				return err
			}
		}
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}
	org, env := resolved.Get(DimOrg), resolved.Get(DimEnv)
	if echo := resolved.Echo(); echo != "" {
		fmt.Fprintf(ios.Stderr, "target: %s [origin %s, artifact human-session]\n", echo, session.Origin)
	}

	// (4) Bound reauth ceremony: a live disclosure window over the environment,
	// opened inline (TOTP) where the environment's window allows it; a
	// 0-window environment is refused with the browser path named. Required
	// under --config-only too: the exception's four conditions are locked
	// without a projection carve-out (api-cli-surface ADR).
	if err := ensureRevealWindow(ctx, client, st, ios, &session, project, env,
		// The unit is what the run will inject: the environment's secret keys
		// for the full projection, its config keys under --config-only - the
		// exception's "enumerated environment/key-set" named as the act is.
		disclosure{purpose: "reveal", keys: func(ctx context.Context, env string) ([]string, error) {
			class := apigen.KeyClassificationSecret
			if configOnly {
				class = apigen.KeyClassificationConfig
			}
			return keyIDsOf(ctx, client, project, env, class, nil)
		}},
		failf(ExitAuth, "a live disclosure window is required: run the reveal ceremony first")); err != nil {
		return err
	}

	resp, err := fetchDelivery(ctx, client, org, resolved.Get(DimProject), env, configOnly, nil, "")
	if err != nil {
		return err
	}
	if !configOnly {
		if missing := unrevealedSecrets(resp.Keys); len(missing) > 0 {
			return failf(ExitRefused, "hikyo run: cannot deliver secret(s) %s — %s",
				strings.Join(missing, ", "), machineRevealOptIn)
		}
	}
	fetched := deliveredValues(resp.Keys)

	// (3) Enumerated confirmation on the controlling terminal.
	names := mapKeys(fetched)
	sort.Strings(names)
	prompt := fmt.Sprintf("About to inject %d value(s) into environment %s and exec %q:\n  %s\nProceed",
		len(names), env, childArgs[0], strings.Join(names, "\n  "))
	ok, err := terminalSession.ConfirmEnumerated(prompt)
	if err != nil {
		return failf(ExitRefused, "reading the confirmation: %v", err)
	}
	if !ok {
		return failf(ExitRefused, "hikyo run --use-human-session: declined at the confirmation")
	}

	if refused := compose.RefuseUnacknowledged(mapKeys(fetched), runLoaderControlAck(cfg)); len(refused) > 0 {
		return failf(ExitRefused, "hikyo run: refusing loader-control key(s) %s; acknowledge each by name in the config's `run.acknowledge_loader_control`",
			strings.Join(refused, ", "))
	}
	merged, _, err := compose.MergeEnv(sanitizedEnviron(), fetched, allowOverride)
	if err != nil {
		return &Error{Code: ExitRefused, Err: err}
	}
	if ok, detail := compose.ExecPreflight(merged, childArgs, compose.DefaultArgMax()); !ok {
		return failf(ExitRefused, "hikyo run: %s; reduce the delivered set or shorten the command", detail)
	}
	command := childArgs[0]
	resolvedPath, cerr := resolveChildCommand(command)
	if cerr != nil {
		return cerr
	}
	if err := ios.exec(resolvedPath, childArgs, merged); err != nil {
		return failf(ExitCommandNotExecutable, "hikyo run: %s: %v", command, err)
	}
	return nil
}

// runLoaderControlAck is the loader-control acknowledgement in force for a run,
// from the config's run block (empty when there is no config).
func runLoaderControlAck(cfg *compose.Config) []string {
	if cfg == nil {
		return nil
	}
	return cfg.Run.AcknowledgeLoaderControl
}

// serveRunOffline handles a failed run fetch: if it failed as UNAVAILABLE and
// the stack opted into offline serve, it opens the snapshot, refuses any
// unacknowledged loader-control key (finding 6, BEFORE any record is written),
// records one offline disclosure per key BEFORE returning the values, prints the
// stale line, and returns them. Any other failure (or no opt-in) is surfaced
// unchanged. The snapshot is bound to run's identity: TargetNames ["__run__"],
// so a render snapshot cannot be served here (finding 3).
func serveRunOffline(ios IO, cfg *compose.Config, stateDir string, binding crypto.SnapshotBinding, ack []string, fetchErr error) (map[string]string, error) {
	if !isUnavailable(fetchErr) {
		return nil, fetchErr
	}
	if cfg == nil || !cfg.Snapshot.OfflineServe {
		fmt.Fprintln(ios.Stderr, "hikyo run: offline serve is not enabled for this stack; set snapshot.offline_serve: true in hikyo-compose.yaml to serve stale values during an outage")
		return nil, fetchErr
	}
	payload, binding, err := loadOfflineSnapshot(ios, cfg, binding)
	if err != nil {
		return nil, err
	}
	// Loader-control BEFORE any disclosure record is written (finding 6): an
	// unacknowledged loader-control key is refused even when serving stale.
	if refused := compose.RefuseUnacknowledged(rowNames(payload.Rows), ack); len(refused) > 0 {
		return nil, failf(ExitRefused, "hikyo run: refusing loader-control key(s) %s; acknowledge each by name in the config's `run.acknowledge_loader_control`",
			strings.Join(refused, ", "))
	}
	stamp := payload.GenerationStamps[runGenerationKey]
	if err := appendOfflineRecords(ios, stateDir, payload.Rows, binding, stamp); err != nil {
		return nil, failf(ExitInternal, "hikyo run: recording offline disclosure: %v", err)
	}
	aad, err := binding.AAD()
	if err != nil {
		return nil, failf(ExitInternal, "hikyo run: reading offline snapshot binding: %v", err)
	}
	fmt.Fprintf(ios.Stderr, "serving stale from %s, generation %s\n", aad.IssuedAt, stamp)
	return rowsToValues(payload.Rows), nil
}

// saveRunSnapshot seals the delivered env plus one run "generation" stamp. The
// snapshot's TargetNames is ["__run__"] (run holds no render target), so
// ContextMatches refuses a render snapshot for run and vice versa (finding 3),
// and its credential binding is the fingerprint of the presented token (R1-3),
// authenticated in the header — no separate credential record on disk.
func saveRunSnapshot(stateDir string, binding crypto.SnapshotBinding, resp apigen.DeliveryResponse) error {
	if _, err := binding.CanonicalAAD(); err != nil {
		return err
	}
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return err
	}
	rows := deliveredRows(resp.Keys)
	// run's "generation" stamp is over the canonical row set, keyed to the
	// run generation key (TargetStamp does not grammar-check the name — only
	// WriteGeneration does — so the __run__ sentinel is legal here).
	stamp := compose.TargetStamp(keys, runGenerationKey, canonicalRows(rows))
	payload := compose.SnapshotPayload{Rows: rows, GenerationStamps: map[string]string{runGenerationKey: stamp}}
	return saveSnapshot(keys, binding, payload)
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
	moved, _, err := composeRenderCore(ctx, ios, st, flags, projectDir, configOnly)
	return moved, err
}

// renderPaths carries the resolved project/state directories out of a render so
// `compose sync` can drive its apply-pending marker without re-resolving (which
// would echo the target line twice).
type renderPaths struct {
	cfgDir   string
	stateDir string
}

// composeRenderCore is the render pipeline, shared by `compose render` and the
// render step of `compose sync`. It returns whether any target's stamp moved
// (so sync knows whether to recreate) and the resolved paths.
func composeRenderCore(ctx context.Context, ios IO, st *State, flags commonFlags, projectDir string, configOnly bool) (bool, renderPaths, error) {
	cfg, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return false, renderPaths{}, err
	}
	if cfg == nil {
		return false, renderPaths{}, failf(ExitUsage, "hikyo compose render requires a %s (searched up from %s); the .hikyo.json pin file is not enough — the config carries the render targets",
			composeConfigName, startDir(ios, projectDir))
	}
	client, entry, resolved, token, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "compose")
	if err != nil {
		return false, renderPaths{}, err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)
	slug, err := composeSlug(cfg, org, project, env)
	if err != nil {
		return false, renderPaths{}, err
	}
	stateDir := composeStateDir(st, slug)
	rp := renderPaths{cfgDir: cfgDir, stateDir: stateDir}
	snapshotBinding, err := newSnapshotBinding(stateDir, entry, org, project, env, token, configOnly, cfg.TargetNames())
	if err != nil {
		return false, rp, failf(ExitRefused, "compose render: snapshot binding: %v", err)
	}
	runtimeDir, explicitRuntime, err := composeRuntimeDir(ios, cfg, slug)
	if err != nil {
		return false, rp, err
	}
	// The DEFAULT runtime dir MUST be tmpfs-backed or render refuses (compose ADR
	// § Where plaintext lives; ops-spec § 6). An EXPLICIT runtime_dir is the
	// operator's accepted disposition (doctor reports `runtime_not_tmpfs` but the
	// renderer does not block) — the orchestrator's binding call for finding 2.
	if !explicitRuntime {
		if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
			return false, rp, failf(ExitInternal, "compose render: create runtime dir: %v", err)
		}
		if ok, terr := compose.IsTmpfs(runtimeDir); terr != nil {
			return false, rp, failf(ExitInternal, "compose render: checking runtime dir filesystem: %v", terr)
		} else if !ok {
			return false, rp, failf(ExitRefused, "compose render: default runtime dir %s is not backed by tmpfs; rendered plaintext must live only on tmpfs — set an explicit `runtime_dir` on tmpfs in %s", runtimeDir, composeConfigName)
		}
	}
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return false, rp, err
	}

	w := compose.NewWriter(stateDir, nil)
	lock, err := w.BeginRender(cfgDir)
	if err != nil {
		return false, rp, failf(ExitRefused, "another hikyo compose process holds the lock for %s", slug)
	}
	defer lock.Close()

	// 1. Recover incomplete (torn) generations before anything reads them.
	if err := lock.Recover(runtimeDir); err != nil {
		return false, rp, failf(ExitInternal, "compose render: recover: %v", err)
	}
	// 2. Flush-before-fetch.
	if err := flushOffline(ctx, client, org, project, env, stateDir); err != nil {
		return false, rp, err
	}
	// 3. Cursor: present it only when the full local eligibility test holds.
	currentStamps, err := compose.CurrentStamps(cfgDir)
	if err != nil {
		return false, rp, failf(ExitRefused, "compose render: %v", err)
	}
	present := eligibleCursor(stateDir, cfg, currentStamps, runtimeDir, token, env, configOnly)

	// The acknowledgement in force for this render is the UNION of every target's
	// acknowledge_loader_control (#64 audit field). The server records it and
	// filters nothing; per-target refusal below stays client-side authoritative.
	resp, ferr := fetchDelivery(ctx, client, org, project, env, configOnly, renderAcknowledged(cfg), present)
	if ferr != nil {
		moved, err := composeRenderOffline(ctx, ios, lock, cfg, cfgDir, stateDir, runtimeDir, keys, snapshotBinding, configOnly, ferr)
		return moved, rp, err
	}
	if resp.Current {
		for _, t := range cfg.TargetNames() {
			fmt.Fprintf(ios.Stderr, "up to date (generation %s)\n", currentStamps[t])
		}
		return false, rp, nil
	}
	snapshotBinding, err = bindSnapshotDelivery(snapshotBinding, resp)
	if err != nil {
		return false, rp, failf(ExitRefused, "compose render: snapshot binding: %v", err)
	}
	moved, err := composeRenderApply(ios, lock, cfg, stateDir, runtimeDir, keys, snapshotBinding, token, env, configOnly, resp, currentStamps)
	return moved, rp, err
}

// composeRenderApply renders each target from a live full delivery. On ANY
// refusal it writes no generation and does not advance the cursor.
func composeRenderApply(ios IO, lock *compose.RenderLock, cfg *compose.Config, stateDir, runtimeDir string, keys *crypto.LocalKeys, binding crypto.SnapshotBinding, token, env string, configOnly bool, resp apigen.DeliveryResponse, currentStamps map[string]string) (bool, error) {
	if _, err := binding.CanonicalAAD(); err != nil {
		return false, failf(ExitRefused, "compose render: snapshot binding: %v", err)
	}
	plan, err := compose.BuildRenderPlan(liveRenderInput(cfg, configOnly, resp.Keys))
	if err != nil {
		return false, failf(ExitInternal, "compose render: %v", err)
	}
	if refusals := renderRefusalMessages(plan.Refusals); len(refusals) > 0 {
		return false, failf(ExitRefused, "hikyo compose render refused; no generation written, cursor not advanced:\n  %s", strings.Join(refusals, "\n  "))
	}

	// Write generations (idempotent — a no-op when present+complete, a rewrite
	// when a reboot lost the tmpfs copy). WriteGeneration computes each target's
	// stamp with the target bound into the domain (finding 5: two targets with
	// identical content get distinct stamps and distinct dirs). Then the single
	// stamp commit, then GC, then snapshot + cursor.
	finalStamps := map[string]string{}
	var allRows []compose.SnapshotRow
	var lines []string
	moved := false
	for _, target := range plan.Targets {
		allRows = append(allRows, target.SnapshotRows...)
		stamp, materialized, err := lock.WriteGeneration(runtimeDir, keys, target.Name, target.Content)
		if err != nil {
			return false, failf(ExitInternal, "compose render: write generation %s: %v", target.Name, err)
		}
		finalStamps[target.Name] = stamp
		// moved when the stamp changed OR the generation had to be re-materialised
		// (the tmpfs copy was lost): either way sync must re-apply (R1-10).
		if currentStamps[target.Name] != stamp || materialized {
			moved = true
			lines = append(lines, fmt.Sprintf("rendered %s generation %s → %s", target.Name, stamp, filepath.Join(runtimeDir, stamp, target.Name+".env")))
		} else {
			lines = append(lines, fmt.Sprintf("unchanged %s generation %s", target.Name, stamp))
		}
	}
	if err := lock.CommitStamps(finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: commit stamps: %v", err)
	}
	if err := lock.GC(runtimeDir, compose.DefaultGenerationsKept); err != nil {
		return false, failf(ExitInternal, "compose render: gc: %v", err)
	}

	// Snapshot BEFORE cursor: a snapshot is a harmless cache, but a cursor saved
	// without a snapshot could read "current" after a reboot with nothing to
	// serve. If the cursor save fails the snapshot still stands and the next
	// render does a full fetch.
	if err := saveSnapshot(keys, binding, compose.SnapshotPayload{Rows: allRows, GenerationStamps: finalStamps}); err != nil {
		return false, failf(ExitInternal, "compose render: save snapshot: %v", err)
	}
	if err := saveCursor(stateDir, cfg, resp, token, env, configOnly, finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: save cursor: %v", err)
	}

	for _, l := range lines {
		fmt.Fprintln(ios.Stderr, l)
	}
	return moved, nil
}

// composeRenderOffline renders each target from the last snapshot when the
// server is unreachable and the stack opted in. Row→key_id now comes from the
// sealed payload's rows (finding 3: no cleartext sidecar).
func composeRenderOffline(ctx context.Context, ios IO, lock *compose.RenderLock, cfg *compose.Config, cfgDir, stateDir, runtimeDir string, keys *crypto.LocalKeys, binding crypto.SnapshotBinding, configOnly bool, fetchErr error) (bool, error) {
	_ = ctx
	if !isUnavailable(fetchErr) {
		return false, fetchErr
	}
	if !cfg.Snapshot.OfflineServe {
		fmt.Fprintln(ios.Stderr, "hikyo compose render: offline serve is not enabled for this stack; set snapshot.offline_serve: true to render from the last snapshot during an outage")
		return false, fetchErr
	}
	payload, binding, err := loadOfflineSnapshot(ios, cfg, binding)
	if err != nil {
		return false, err
	}
	aad, err := binding.AAD()
	if err != nil {
		return false, failf(ExitInternal, "compose render: reading offline snapshot binding: %v", err)
	}
	plan, err := compose.BuildRenderPlan(offlineRenderInput(cfg, configOnly, payload.Rows))
	if err != nil {
		return false, failf(ExitInternal, "compose render: %v", err)
	}
	if refusals := renderRefusalMessages(plan.Refusals); len(refusals) > 0 {
		return false, failf(ExitRefused, "hikyo compose render (offline) refused; no generation written:\n  %s", strings.Join(refusals, "\n  "))
	}

	// One offline record per served key, fsynced BEFORE any generation is
	// written, then the generations, then the stamp commit and GC.
	var records []compose.OfflineRecord
	stamps := make(map[string]string, len(plan.Targets))
	for _, target := range plan.Targets {
		// The stamp is bound to the target name and must match the value
		// WriteGeneration computes after the disclosure record is durable.
		stamp := compose.TargetStamp(keys, target.Name, target.Content)
		stamps[target.Name] = stamp
		for _, row := range target.SnapshotRows {
			id, err := compose.NewRecordID()
			if err != nil {
				return false, failf(ExitInternal, "compose render: record id: %v", err)
			}
			records = append(records, compose.OfflineRecord{
				RecordID: id, KeyID: row.KeyID, KeyName: row.Name, Classification: row.Classification,
				OccurredAt: ios.now().UTC().Format(time.RFC3339), CredentialID: aad.CredentialID,
				Generation: stamp, ServedFrom: aad.IssuedAt,
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
	for _, target := range plan.Targets {
		stamp, materialized, err := lock.WriteGeneration(runtimeDir, keys, target.Name, target.Content)
		if err != nil {
			return false, failf(ExitInternal, "compose render: write generation %s: %v", target.Name, err)
		}
		if stamp != stamps[target.Name] {
			return false, failf(ExitInternal, "compose render: target %s stamp changed between planning and write", target.Name)
		}
		finalStamps[target.Name] = stamp
		fmt.Fprintf(ios.Stderr, "serving stale from %s, generation %s\n", aad.IssuedAt, stamp)
		// moved when the stamp changed OR the generation had to be re-materialised
		// (the tmpfs copy was lost): either way sync must re-apply (R1-10).
		if currentStamps[target.Name] != stamp || materialized {
			moved = true
			lines = append(lines, fmt.Sprintf("rendered %s generation %s → %s", target.Name, stamp, filepath.Join(runtimeDir, stamp, target.Name+".env")))
		} else {
			lines = append(lines, fmt.Sprintf("unchanged %s generation %s", target.Name, stamp))
		}
	}
	if err := lock.CommitStamps(finalStamps); err != nil {
		return false, failf(ExitInternal, "compose render: commit stamps: %v", err)
	}
	if err := lock.GC(runtimeDir, compose.DefaultGenerationsKept); err != nil {
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

	// (1) Doctor checks run BEFORE the first render; any BLOCKING error finding
	// refuses without rendering. Findings go to stderr — stdout stays empty. The
	// server-agreement family (`server_manifest_drift`, `never_rendered`,
	// `server_stamp_unknown`, `server_unreachable`) is DELIBERATELY EXCLUDED from
	// the gate: those describe exactly the staleness this sync is about to repair,
	// so gating on them would brick sync on every publish and every fresh box.
	// Sync's gate is the LOCAL integrity checks (version floor, format raw, stamp
	// grammar, token/state modes); the drift stays an error for the doctor VERB,
	// which reports rather than repairs (finding 11 — this is the interpretation
	// of the ADR "same checks" sentence offered for human disposition; see the
	// spellings § Compose delivery).
	findings, err := composeDoctorGather(ctx, ios, st, flags, projectDir, false)
	if err != nil {
		return err
	}
	if hasBlockingError(findings) {
		if rerr := renderComposeFindings(ios.Stderr, FormatTable, findings); rerr != nil {
			return failf(ExitInternal, "hikyo compose sync: rendering findings: %v", rerr)
		}
		return failf(ExitRefused, "hikyo compose sync: doctor found errors; not rendering")
	}

	// (2) Render (conditional).
	moved, rp, err := composeRenderCore(ctx, ios, st, flags, projectDir, false)
	if err != nil {
		return err
	}

	// (3) Apply through `docker compose up -d` when a stamp moved, OR when a prior
	// sync left an apply-pending marker (its docker call failed, or a reboot lost
	// the tmpfs generation and it was re-materialized): the marker forces a retry
	// even when nothing moved this time (finding 10). The marker is written BEFORE
	// docker and removed only after docker succeeds, so a failed apply is retried
	// on the next sync rather than left permanently stale.
	pending := applyPendingExists(rp.stateDir)
	if !moved && !pending {
		return nil
	}
	stamps, err := compose.CurrentStamps(rp.cfgDir)
	if err != nil {
		return failf(ExitRefused, "hikyo compose sync: %v", err)
	}
	if err := writeApplyPending(rp.stateDir, stamps); err != nil {
		return failf(ExitInternal, "hikyo compose sync: writing apply-pending marker: %v", err)
	}
	if err := dockerComposeUp(ctx, ios, rp.cfgDir); err != nil {
		return err // marker stays: the next sync retries the apply
	}
	if err := removeApplyPending(rp.stateDir); err != nil {
		return failf(ExitInternal, "hikyo compose sync: clearing apply-pending marker: %v", err)
	}
	return nil
}

func dockerComposeUp(ctx context.Context, ios IO, projectDir string) error {
	bin, found := dockerBinary(ios)
	if !found {
		return failf(ExitRefused, "hikyo compose sync: docker not found on PATH; install Docker Compose or set HIKYO_COMPOSE_DOCKER")
	}
	cmd := exec.CommandContext(ctx, bin, "compose", "up", "-d")
	cmd.Dir = projectDir
	cmd.Stdin = os.Stdin
	// `compose sync` is a delivery operation: nothing is printed on hikyo stdout
	// (output ADR). Docker's own stdout is diagnostic, so it is routed to hikyo
	// STDERR, keeping sync stdout empty (finding 14).
	cmd.Stdout = ios.Stderr
	cmd.Stderr = ios.Stderr
	// The workload credential never reaches a subprocess (finding 1).
	cmd.Env = sanitizedEnviron()
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return failf(ExitInternal, "hikyo compose sync: `docker compose up -d` exited %d", ee.ExitCode())
		}
		return failf(ExitInternal, "hikyo compose sync: `docker compose up -d`: %v", err)
	}
	return nil
}

const applyPendingFile = "apply-pending"

// applyPendingExists reports whether a prior sync left an unfinished apply.
func applyPendingExists(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, applyPendingFile))
	return err == nil
}

// writeApplyPending records the stamps to apply, atomically, BEFORE docker runs.
func writeApplyPending(stateDir string, stamps map[string]string) error {
	data, err := json.Marshal(stamps)
	if err != nil {
		return err
	}
	return writeFileAtomic0600(filepath.Join(stateDir, applyPendingFile), data)
}

// removeApplyPending clears the marker after a successful docker apply.
func removeApplyPending(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, applyPendingFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
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
	findings, err := composeDoctorGather(ctx, ios, st, flags, projectDir, true)
	if err != nil {
		return err
	}
	// Propagate a rendering failure as ExitInternal (finding 15): doctor must not
	// return success or its findings-derived refusal when its required output
	// never reached the caller.
	if rerr := renderComposeFindings(ios.Stdout, f, findings); rerr != nil {
		return failf(ExitInternal, "hikyo compose doctor: rendering findings: %v", rerr)
	}
	if hasErrorFinding(findings) {
		return failf(ExitRefused, "hikyo compose doctor found errors")
	}
	return nil
}

// composeDoctorGather assembles every input compose.Doctor needs — docker
// version/config, the raw compose file, managed stamps, generation state, file
// modes, and server agreement via a conditional fetch — and returns the merged
// finding list.
func composeDoctorGather(ctx context.Context, ios IO, st *State, flags commonFlags, projectDir string, includeServerAgreement bool) ([]compose.Finding, error) {
	cfg, cfgDir, err := findComposeConfig(startDir(ios, projectDir))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, failf(ExitUsage, "hikyo compose doctor requires a %s (searched up from %s)", composeConfigName, startDir(ios, projectDir))
	}
	client, _, resolved, token, err := resolveMachineTarget(st, ios, flags, cfg, cfgDir, "compose")
	if err != nil {
		return nil, err
	}
	org, project, env := resolved.Get(DimOrg), resolved.Get(DimProject), resolved.Get(DimEnv)
	slug, err := composeSlug(cfg, org, project, env)
	if err != nil {
		return nil, err
	}
	stateDir := composeStateDir(st, slug)
	runtimeDir, _, rerr := composeRuntimeDir(ios, cfg, slug)

	// Flush-before-fetch (ops-spec § 6): reconcile pending offline records BEFORE
	// any doctor network request (the catalogue and agreement fetches), so a POST
	// always precedes every GET (finding 9). A flush failure is a hard error.
	if err := flushOffline(ctx, client, org, project, env, stateDir); err != nil {
		return nil, err
	}

	var findings []compose.Finding

	// Docker version + resolved config.
	dockerFindings, version, resolvedConfig := doctorDocker(ctx, ios, cfgDir)
	findings = append(findings, dockerFindings...)

	managed, err := compose.CurrentStamps(cfgDir)
	if err != nil {
		return nil, failf(ExitRefused, "compose doctor: %v", err)
	}

	existingKeyIDs, catFinding := doctorExistingKeyIDs(ctx, client, org, project, cfg)
	if catFinding != nil {
		findings = append(findings, *catFinding)
	}
	stateEntries, scanFinding := doctorStateEntries(stateDir)
	if scanFinding != nil {
		findings = append(findings, *scanFinding)
	}

	in := compose.DoctorInput{
		ComposeVersion: version,
		Config:         resolvedConfig,
		RawComposeYAML: doctorRawCompose(ios, cfgDir),
		ManagedStamps:  managed,
		ConfigTargets:  cfg.Targets,
		ExistingKeyIDs: existingKeyIDs,
		StateEntries:   stateEntries,
		TokenFile:      doctorTokenFile(flags.TokenFile),

		SystemdInvocation:       ios.Env.Getenv("INVOCATION_ID") != "",
		TokenFromCredentialsDir: tokenFromCredentialsDir(ios, flags.TokenFile),
	}
	// runtime_dir must resolve; when it cannot (not root, no XDG_RUNTIME_DIR, no
	// explicit config), surface it as its own error and do not let the derived
	// runtime checks fire on an empty path (finding 12).
	runtimeResolved := rerr == nil
	if runtimeResolved {
		in.RuntimeDir = runtimeDir
		in.RuntimeTmpfs = doctorRuntimeTmpfs(runtimeDir)
	}

	// Server agreement: feed compose.Doctor the per-target server stamps it needs
	// (finding 4). The structural check then compares them against the managed
	// stamp and the label. Only the DOCTOR verb reaches the server; sync repairs
	// freshness and must not gate on it (finding 11).
	var serverStamps map[string]string
	var serverFindings []compose.Finding
	haveServerStamps := false
	if includeServerAgreement {
		serverStamps, serverFindings, haveServerStamps = doctorServerStamps(ctx, client, cfg, stateDir, managed, runtimeDir, org, project, env, token)
		in.ServerStamps = serverStamps
	}

	findings = append(findings, compose.Doctor(in)...)
	findings = append(findings, serverFindings...)

	// A docker_missing finding makes the version check redundant; drop the
	// compose.Doctor floor finding so the two do not both fire for one cause.
	if hasCode(findings, "docker_missing") {
		findings = dropCode(findings, "compose_version_below_floor")
	}
	if !runtimeResolved {
		findings = dropCode(findings, "runtime_not_tmpfs")
		findings = dropCode(findings, "runtime_dir_not_absolute")
		findings = append(findings, compose.Finding{Severity: compose.SeverityError, Code: "runtime_dir_unresolved",
			Message: fmt.Sprintf("could not resolve a runtime dir: %v", rerr)})
	}
	// server_stamp_unknown is compose.Doctor's honest "no server stamp to compare"
	// finding. Drop it whenever we deliberately did not (or could not) obtain the
	// server stamps — sync never fetches, and doctor's never_rendered /
	// server_unreachable / drift cases explain the gap directly.
	if !haveServerStamps {
		findings = dropCode(findings, "server_stamp_unknown")
	}

	sortFindings(findings)
	return findings, nil
}

// doctorDocker runs `docker compose version --short` and `docker compose config
// --format json`. A missing docker binary is docker_missing; a config invocation
// or JSON parse failure is docker_config_failed (fail closed — a nil config used
// to silently disable the service checks, finding 12).
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
	raw, cerr := runCapture(ctx, ios, bin, cfgDir, "compose", "config", "--format", "json")
	if cerr != nil {
		return []compose.Finding{{Severity: compose.SeverityError, Code: "docker_config_failed",
			Message: fmt.Sprintf("`docker compose config` failed: %v", cerr)}}, strings.TrimSpace(version), nil
	}
	parsed, perr := compose.ParseComposeConfig([]byte(raw))
	if perr != nil {
		return []compose.Finding{{Severity: compose.SeverityError, Code: "docker_config_failed",
			Message: fmt.Sprintf("could not parse `docker compose config` JSON: %v", perr)}}, strings.TrimSpace(version), nil
	}
	return nil, strings.TrimSpace(version), parsed
}

// doctorServerStamps performs the conditional agreement fetch and returns the
// per-target server stamps to feed compose.Doctor's structural check, plus any
// standalone findings. The bool reports whether server stamps were obtained (so
// the caller can drop the honest server_stamp_unknown when they were not).
func doctorServerStamps(ctx context.Context, client *Client, cfg *compose.Config, stateDir string, managed map[string]string, runtimeDir, org, project, env, token string) (map[string]string, []compose.Finding, bool) {
	present := eligibleCursor(stateDir, cfg, managed, runtimeDir, token, env, false)
	if present == "" {
		// No eligible cursor: never rendered, or the local render is gone. A full
		// fetch would be a disclosure, so doctor does not do one.
		return nil, []compose.Finding{{Severity: compose.SeverityError, Code: "never_rendered",
			Message: "no eligible cursor: this box has not rendered, or its render is gone; run `hikyo compose render`"}}, false
	}
	resp, err := fetchDelivery(ctx, client, org, project, env, false, renderAcknowledged(cfg), present)
	if err != nil {
		sev := compose.SeverityError
		msg := fmt.Sprintf("the server refused the agreement check: %v", err)
		if isUnavailable(err) {
			sev = compose.SeverityWarn
			msg = fmt.Sprintf("could not reach the server to confirm agreement: %v", err)
		}
		return nil, []compose.Finding{{Severity: sev, Code: "server_unreachable", Message: msg}}, false
	}
	if resp.Current {
		// The server agrees the presented cursor is current: our managed stamps ARE
		// the server's, no plaintext crossed the wire.
		return managed, nil, true
	}
	// Drift: the cursor is not current. We cannot always recompute the server's
	// per-target stamp (a read-only credential holds no secret plaintext), so
	// report the drift directly and leave the stamps unknown.
	return nil, []compose.Finding{{Severity: compose.SeverityError, Code: "server_manifest_drift",
		Message: "the server's current manifest is not the one this box rendered — run `hikyo compose render`"}}, false
}

// ---------------------------------------------------------------------------
// machine-only target resolution
// ---------------------------------------------------------------------------

// resolveMachineTarget resolves the target, folds any hikyo-compose.yaml
// dimensions in (a disagreement with an already-resolved dimension is a hard
// error), and REQUIRES a machine credential. It never falls back to the stored
// human session — that path is a refusal in this build.
func resolveMachineTarget(st *State, ios IO, flags commonFlags, cfg *compose.Config, cfgPath, verb string) (*Client, TrustEntry, Resolved, string, error) {
	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	if cfg != nil {
		for _, d := range []struct {
			dim Dimension
			val string
		}{{DimOrg, cfg.Org}, {DimProject, cfg.Project}, {DimEnv, cfg.Environment}} {
			if err := foldConfigDim(&resolved, d.dim, d.val, cfgPath); err != nil {
				return nil, TrustEntry{}, Resolved{}, "", err
			}
		}
	}
	if _, err := NewTenantScope(resolved); err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	kinds, err := authKindsFor(flags.operation)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	if !kinds.Allows(AuthKindMachineCredential) {
		return nil, TrustEntry{}, Resolved{}, "", failf(ExitRefused, "hikyo %s does not accept machine credentials", flags.operation)
	}
	if flags.Auth == "human" {
		hint := "this operation requires a machine credential"
		if flags.operation == "run" {
			hint = "pass --use-human-session for run's gated human-session exception"
		}
		return nil, TrustEntry{}, Resolved{}, "", failf(ExitRefused, "hikyo %s cannot use --auth=human: %s", flags.operation, hint)
	}

	entry, err := machineEntry(st, resolved, cfg)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	for _, d := range []Dimension{DimOrg, DimProject, DimEnv} {
		if _, err := resolved.Require(d); err != nil {
			return nil, TrustEntry{}, Resolved{}, "", err
		}
	}

	token, err := machineToken(ios, flags.TokenFile)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	if token == "" {
		// `run` has the single locked human-session exception; `render`/`sync` have
		// no human path at all (api-cli-surface ADR line 96).
		hint := "render and sync have no human path"
		if verb == "run" {
			hint = "pass --use-human-session to run under the stored human session (a TTY, an enumerated confirmation, and a live disclosure window are required)"
		}
		return nil, TrustEntry{}, Resolved{}, "", failf(ExitAuth,
			"hikyo %s accepts only a machine credential (--token-file or HIKYO_TOKEN); %s", verb, hint)
	}
	client, err := NewClient(entry, token)
	if err != nil {
		return nil, TrustEntry{}, Resolved{}, "", err
	}
	if echo := resolved.Echo(); echo != "" {
		fmt.Fprintf(ios.Stderr, "target: %s [origin %s, artifact machine-credential]\n", echo, entry.Origin)
	}
	return client, entry, resolved, token, nil
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

// renderAcknowledged is the sorted, deduped union of every target's
// acknowledge_loader_control — the loader-control acknowledgement in force for a
// render, sent on the fetch so the server's audit record carries it (#64).
func renderAcknowledged(cfg *compose.Config) []string {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, name := range cfg.TargetNames() {
		for _, k := range cfg.Targets[name].AcknowledgeLoaderControl {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func fetchDelivery(ctx context.Context, client *Client, org, project, env string, configOnly bool, acknowledged []string, cursor string) (apigen.DeliveryResponse, error) {
	q := url.Values{}
	if configOnly {
		// The wire term is `projection=config-only` (#64's server param); the CLI
		// flag stays `--config-only`. `full` is the default and is left implicit.
		q.Set("projection", "config-only")
	}
	// acknowledged_keys is sent AS PRESENTED so the server records which
	// loader-control acknowledgement was in force for this delivery (#64 audit
	// field). The server records and otherwise ignores it — client-side refusal
	// stays authoritative. style: form, explode: false ⇒ a single CSV member.
	if len(acknowledged) > 0 {
		q.Set("acknowledged_keys", strings.Join(acknowledged, ","))
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
	if err := compose.MarkFlushed(stateDir, files); err != nil {
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
// snapshot / cursor helpers (thin wrappers over internal/compose)
// ---------------------------------------------------------------------------

func saveSnapshot(keys *crypto.LocalKeys, binding crypto.SnapshotBinding, payload compose.SnapshotPayload) error {
	return compose.SaveSnapshot(keys, binding, payload)
}

// loadOfflineSnapshot opens the persisted snapshot under the validated binding
// the box constructed before the fetch: origin/org/project/env, config_only,
// mode target set, and the LOCAL fingerprint of the presented token. A rotated
// token refuses the old snapshot by name before decrypt work.
func loadOfflineSnapshot(ios IO, cfg *compose.Config, binding crypto.SnapshotBinding) (compose.SnapshotPayload, crypto.SnapshotBinding, error) {
	var zeroP compose.SnapshotPayload
	var zeroB crypto.SnapshotBinding
	if err := binding.ValidateScope(); err != nil {
		return zeroP, zeroB, err
	}
	stateDir, err := binding.StorageDir()
	if err != nil {
		return zeroP, zeroB, err
	}
	keys, err := loadLocalKeys(stateDir)
	if err != nil {
		return zeroP, zeroB, err
	}
	payload, storedBinding, err := compose.LoadSnapshot(keys, binding, ios.now(), cfg.SnapshotMaxAge())
	if err != nil {
		if errors.Is(err, compose.ErrSnapshotContext) {
			return zeroP, zeroB, failf(ExitRefused, "offline snapshot belongs to a different context and will not be served: %v", err)
		}
		if errors.Is(err, os.ErrNotExist) {
			return zeroP, zeroB, failf(ExitRefused, "offline serve is enabled but no snapshot has been saved for this stack yet")
		}
		if errors.Is(err, compose.ErrSnapshotExpired) || errors.Is(err, compose.ErrSnapshotRollback) || errors.Is(err, crypto.ErrDecrypt) {
			aad, aadErr := storedBinding.AAD()
			if aadErr != nil {
				return zeroP, zeroB, failf(ExitRefused, "offline serve refused: snapshot binding is unusable (%v)", err)
			}
			return zeroP, zeroB, failf(ExitRefused,
				"offline serve refused: snapshot issued %s, expires %s — past the maximum stale age (%s) or otherwise unusable (%v)",
				aad.IssuedAt, aad.ExpiresAt, cfg.SnapshotMaxAge(), err)
		}
		return zeroP, zeroB, failf(ExitRefused, "offline serve: %v", err)
	}
	return payload, storedBinding, nil
}

// newSnapshotBinding validates and owns the offline-known scope before any
// snapshot filesystem work. The same value is completed from a live delivery
// or matched against the stored delivery fields on an offline path.
func newSnapshotBinding(stateDir string, entry TrustEntry, org, project, env, token string, configOnly bool, targetNames []string) (crypto.SnapshotBinding, error) {
	return crypto.NewSnapshotBinding(crypto.SnapshotBindingScope{
		StorageDir:     stateDir,
		InstanceOrigin: entry.Origin,
		OrgID:          org, ProjectID: project, EnvironmentID: env,
		CredentialFingerprint: credentialFingerprint(token), ConfigOnly: configOnly,
		TargetNames: targetNames,
	})
}

// cursorBinding builds the eligibility binding. The credential identity is the
// LOCAL fingerprint of the PRESENTED token (finding 8) — not a stored value, so
// swapping tokens invalidates the cursor before it is presented. The env,
// config_only, and per-target key-id membership are local truth; the pinned
// revision and projection are server-asserted (unknowable pre-fetch, and the
// server re-binds anyway), so they come from the stored cursor when present.
func cursorBinding(cfg *compose.Config, token, env string, configOnly bool, stored *compose.CursorState) compose.CursorBinding {
	b := compose.CursorBinding{
		CredentialID: credentialFingerprint(token),
		Environment:  env,
		ConfigOnly:   configOnly,
		TargetKeyIDs: targetKeyIDs(cfg),
	}
	if stored != nil {
		b.PinnedRevision = stored.Binding.PinnedRevision
		b.Projection = stored.Binding.Projection
	}
	return b
}

// saveCursor persists the cursor with its full binding after a committed render.
func saveCursor(stateDir string, cfg *compose.Config, resp apigen.DeliveryResponse, token, env string, configOnly bool, stamps map[string]string) error {
	pinned := int64(0)
	if resp.PinnedRevision != nil {
		pinned = *resp.PinnedRevision
	}
	binding := compose.CursorBinding{
		CredentialID:   credentialFingerprint(token),
		Environment:    env,
		ConfigOnly:     configOnly,
		PinnedRevision: pinned,
		Projection:     deliveryProjection(resp.Keys),
		TargetKeyIDs:   targetKeyIDs(cfg),
	}
	return compose.SaveCursor(stateDir, compose.CursorState{
		Cursor: resp.Cursor, Binding: binding, GenerationStamps: stamps,
	})
}

// eligibleCursor returns the stored cursor iff the full local eligibility test
// holds against the currently presented token, env, mode, and target set.
func eligibleCursor(stateDir string, cfg *compose.Config, currentStamps map[string]string, runtimeDir, token, env string, configOnly bool) string {
	state, err := compose.LoadCursor(stateDir)
	if err != nil || state == nil {
		return ""
	}
	want := cursorBinding(cfg, token, env, configOnly, state)
	c, ok := compose.EligibleCursor(state, want, currentStamps, runtimeDir)
	if !ok {
		return ""
	}
	return c
}

// appendOfflineRecords writes one durable, fsynced disclosure record per served
// row BEFORE the plaintext is released (compose ADR § "Audit during offline
// serve"). KeyID travels inside the sealed payload's rows now.
func appendOfflineRecords(ios IO, stateDir string, rows []compose.SnapshotRow, binding crypto.SnapshotBinding, generation string) error {
	if len(rows) == 0 {
		return nil
	}
	aad, err := binding.AAD()
	if err != nil {
		return err
	}
	recs := make([]compose.OfflineRecord, 0, len(rows))
	for _, r := range rows {
		id, err := compose.NewRecordID()
		if err != nil {
			return err
		}
		recs = append(recs, compose.OfflineRecord{
			RecordID: id, KeyID: r.KeyID, KeyName: r.Name, Classification: r.Classification,
			OccurredAt: ios.now().UTC().Format(time.RFC3339), CredentialID: aad.CredentialID,
			Generation: generation, ServedFrom: aad.IssuedAt,
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

// composeIDGrammar is the repo's canonical resource-id grammar
// (api/openapi.yaml:8754 `^[a-z]{2,8}_[0-9a-fA-F-]{36}$`). There is no Go
// constant for it, so it is anchored here for the slug derivation.
var composeIDGrammar = regexp.MustCompile(`^[a-z]{2,8}_[0-9a-fA-F-]{36}$`)

// composeSlug derives the project slug. An explicit config slug (already
// grammar-checked as a path segment in ParseConfig) wins. Otherwise it is
// "<org>-<project>-<env>", but ONLY after validating each id against the repo id
// grammar so an unvalidated string cannot become a path segment (finding 2), and
// asserting containment so the derived state dir cannot escape.
func composeSlug(cfg *compose.Config, org, project, env string) (string, error) {
	if cfg != nil && strings.TrimSpace(cfg.Slug) != "" {
		return cfg.Slug, nil
	}
	for _, id := range []string{org, project, env} {
		if !composeIDGrammar.MatchString(id) {
			return "", failf(ExitUsage,
				"hikyo compose: cannot derive a project slug from %q — it is not a valid id (want %s); set an explicit `slug` in %s",
				id, composeIDGrammar.String(), composeConfigName)
		}
	}
	slug := org + "-" + project + "-" + env
	// Containment: the slug is a single path segment under the state dir, so a
	// join must not climb out of it (defence in depth over the grammar).
	if rel, err := filepath.Rel(".", slug); err != nil || rel != slug || strings.ContainsRune(slug, filepath.Separator) || strings.Contains(slug, "..") {
		return "", failf(ExitUsage, "hikyo compose: derived slug %q is not a safe path segment", slug)
	}
	return slug, nil
}

func composeStateDir(st *State, slug string) string {
	return filepath.Join(st.Dir(), "compose", slug)
}

// composeRuntimeDir resolves the tmpfs runtime directory (ops-spec § 6):
// config runtime_dir, else /run/hikyo/<slug> as root, else
// $XDG_RUNTIME_DIR/hikyo/<slug>. No runtime dir and not root is a usage error
// naming runtime_dir rather than a silent guess. The bool reports whether the
// path came from an EXPLICIT config runtime_dir (the operator's call on tmpfs)
// versus a derived DEFAULT (which the renderer requires to be tmpfs).
func composeRuntimeDir(ios IO, cfg *compose.Config, slug string) (string, bool, error) {
	if cfg != nil && strings.TrimSpace(cfg.RuntimeDir) != "" {
		return cfg.RuntimeDir, true, nil
	}
	if os.Geteuid() == 0 {
		return filepath.Join("/run/hikyo", slug), false, nil
	}
	if xdg := ios.Env.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		return filepath.Join(xdg, "hikyo", slug), false, nil
	}
	return "", false, failf(ExitUsage,
		"no runtime directory: not root and XDG_RUNTIME_DIR is unset. Set `runtime_dir` in %s, or run under a session with XDG_RUNTIME_DIR", composeConfigName)
}

// doctorRuntimeTmpfs reports whether the runtime dir (or its nearest existing
// ancestor, since the dir may not exist yet) is tmpfs-backed. On non-Linux
// IsTmpfs returns true, so this never falsely flags there.
func doctorRuntimeTmpfs(dir string) bool {
	for dir != "" {
		if ok, err := compose.IsTmpfs(dir); err == nil {
			return ok
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return true
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
// reads values through delivery, not the catalogue), so a UNIFORM not-found /
// unauthorized there (unauthorized ≡ nonexistent) is not a drift signal — it
// means the check is not answerable from this credential, and the configured ids
// are treated as existing (a no-op). Any OTHER failure — transport, 5xx, decode
// — is NOT swallowed: it fails closed as `catalogue_unavailable` (finding 12),
// while still treating the ids as existing so target_key_missing does not fire
// on an unknown set.
func doctorExistingKeyIDs(ctx context.Context, client *Client, org, project string, cfg *compose.Config) (map[string]bool, *compose.Finding) {
	allExist := func() map[string]bool {
		out := map[string]bool{}
		for _, id := range allTargetKeyIDs(cfg) {
			out[id] = true
		}
		return out
	}
	var list apigen.KeyList
	path := api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project) + "/keys"
	if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
		if isNotFound(err) {
			// Uniform 404/unauthorized: unanswerable from this credential, no-op.
			return allExist(), nil
		}
		return allExist(), &compose.Finding{Severity: compose.SeverityError, Code: "catalogue_unavailable",
			Message: fmt.Sprintf("could not read the key catalogue to confirm target key ids: %v", err)}
	}
	out := make(map[string]bool, len(list.Items))
	for _, k := range list.Items {
		out[k.Id] = true
	}
	return out, nil
}

// doctorStateEntries walks the client state dir for mode/ownership checks. A
// walk or stat error is NOT swallowed: it fails closed as `state_scan_failed`
// (finding 12) rather than silently reporting an incomplete tree.
func doctorStateEntries(stateDir string) ([]compose.StateEntry, *compose.Finding) {
	var entries []compose.StateEntry
	var scanErr error
	_ = filepath.WalkDir(stateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// A missing state dir is legitimate (nothing rendered yet); any other
			// walk error is a real scan failure.
			if errors.Is(err, os.ErrNotExist) && path == stateDir {
				return nil
			}
			scanErr = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			scanErr = fmt.Errorf("%s: %w", path, ierr)
			return nil
		}
		entries = append(entries, compose.StateEntry{
			Path: path, Perm: info.Mode(), IsDir: d.IsDir(), OwnedByEUID: ownedByEUID(info),
		})
		return nil
	})
	if scanErr != nil {
		return entries, &compose.Finding{Severity: compose.SeverityError, Code: "state_scan_failed",
			Message: fmt.Sprintf("could not fully scan the client state dir: %v", scanErr)}
	}
	return entries, nil
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

func renderComposeFindings(w io.Writer, f Format, findings []compose.Finding) error {
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
	return Render(w, f, Table{Columns: []string{"STATUS", "CHECK", "MESSAGE"}, Rows: rows, JSON: report})
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
	// The workload credential never reaches a subprocess (finding 1).
	cmd.Env = sanitizedEnviron()
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

func liveRenderInput(cfg *compose.Config, configOnly bool, keys []apigen.DeliveredKey) compose.RenderInput {
	rows := make([]compose.RenderSourceRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, compose.RenderSourceRow{
			KeyID: key.KeyId, Name: key.Name, Classification: string(key.Classification), Value: key.Value,
			UnrevealedSecret: !configOnly && isUnrevealedSecret(key),
		})
	}
	return renderInput(cfg, configOnly, compose.AbsentKeyRefuseNotDelivered, rows)
}

func offlineRenderInput(cfg *compose.Config, configOnly bool, rows []compose.SnapshotRow) compose.RenderInput {
	sourceRows := make([]compose.RenderSourceRow, 0, len(rows))
	for _, row := range rows {
		value := row.Value
		sourceRows = append(sourceRows, compose.RenderSourceRow{
			KeyID: row.KeyID, Name: row.Name, Classification: row.Classification, Value: &value,
		})
	}
	return renderInput(cfg, configOnly, compose.AbsentKeyRefuseNotInSnapshot, sourceRows)
}

func renderInput(cfg *compose.Config, configOnly bool, fullProjectionPolicy compose.AbsentKeyPolicy, rows []compose.RenderSourceRow) compose.RenderInput {
	projection := compose.RenderProjectionFull
	absentKeys := fullProjectionPolicy
	if configOnly {
		projection = compose.RenderProjectionConfigOnly
		absentKeys = compose.AbsentKeySkip
	}
	targets := make([]compose.RenderTarget, 0, len(cfg.Targets))
	for _, name := range cfg.TargetNames() {
		target := cfg.Targets[name]
		targets = append(targets, compose.RenderTarget{
			Name: name, KeyIDs: append([]string(nil), target.Keys...),
			AcknowledgeLoaderControl: append([]string(nil), target.AcknowledgeLoaderControl...),
		})
	}
	return compose.RenderInput{Projection: projection, AbsentKeys: absentKeys, Targets: targets, Rows: rows}
}

func renderRefusalMessages(refusals []compose.RenderRefusal) []string {
	messages := make([]string, 0, len(refusals))
	for _, refusal := range refusals {
		var detail string
		switch refusal.Kind {
		case compose.RenderRefusalKeyNotDelivered:
			detail = "key id was not delivered by the server"
		case compose.RenderRefusalKeyNotInSnapshot:
			detail = "not present in the last snapshot"
		case compose.RenderRefusalSecretUnrevealed:
			detail = "secret has no value — " + machineRevealOptIn
		case compose.RenderRefusalLoaderControl:
			detail = "loader-control key not acknowledged (add it to this target's acknowledge_loader_control)"
		case compose.RenderRefusalEncoding:
			detail = refusal.Reason
		default:
			detail = fmt.Sprintf("unknown render refusal %q", refusal.Kind)
		}
		messages = append(messages, fmt.Sprintf("%s: %s: %s", refusal.Target, refusal.Key, detail))
	}
	sort.Strings(messages)
	return messages
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
		rows = append(rows, compose.SnapshotRow{Name: k.Name, KeyID: k.KeyId, Classification: string(k.Classification), Value: *k.Value})
	}
	return rows
}

// rowNames returns the snapshot row names (for the loader-control check).
func rowNames(rows []compose.SnapshotRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
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

// targetKeyIDs is the per-target key-id membership map the cursor binds to
// (compose ADR § Cursor rules — membership is by immutable key id, per target).
func targetKeyIDs(cfg *compose.Config) map[string][]string {
	out := make(map[string][]string, len(cfg.Targets))
	for name, t := range cfg.Targets {
		out[name] = append([]string(nil), t.Keys...)
	}
	return out
}

// bindSnapshotDelivery completes the already-validated local snapshot scope
// with one live response. PinnedRevision is the resolved pin when the server
// served a pin, else 0 (unpinned "current") — it is NOT schema revision.
func bindSnapshotDelivery(binding crypto.SnapshotBinding, resp apigen.DeliveryResponse) (crypto.SnapshotBinding, error) {
	pinned := int64(0)
	if resp.PinnedRevision != nil {
		pinned = *resp.PinnedRevision
	}
	return binding.WithDelivery(crypto.SnapshotBindingDelivery{
		CredentialID:   resp.CredentialId,
		PinnedRevision: pinned,
		ChangeToken:    resp.ChangeToken,
		Projection:     deliveryProjection(resp.Keys),
		// RFC3339Nano (not RFC3339): the server issues at sub-second precision, and
		// second-truncation would make two fetches within the same wall-clock
		// second collide on the snapshot high-water mark (equal issuance, different
		// ChangeToken → refused as a rollback) even though the second is legitimate
		// forward progress — bricking a publish-then-sync inside one second. Nano
		// precision keeps distinct issuances distinct; a true rollback still has a
		// strictly-older instant and is still refused. RFC3339Nano is valid RFC3339
		// (fractional seconds are permitted), so the stale-line spelling holds.
		IssuedAt:  resp.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: resp.SnapshotExpiresAt.UTC().Format(time.RFC3339Nano),
	})
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

// syncRepairableCodes is the family sync's pre-render gate excludes: these are
// the findings sync's own render REPAIRS, not the local integrity it must not
// proceed past (finding 11). Two groups: the server-agreement freshness family
// (the staleness sync exists to reconcile), and the runtime-generation family
// (`generation_absent`/`generation_incomplete` — a wiped or torn tmpfs copy the
// render re-materialises, R1-10). Gating on either would brick sync on exactly
// the state it is invoked to fix (every publish, every fresh box, every reboot
// that lost the tmpfs).
var syncRepairableCodes = map[string]bool{
	"server_manifest_drift": true,
	"never_rendered":        true,
	"server_stamp_unknown":  true,
	"server_unreachable":    true,
	"generation_absent":     true,
	"generation_incomplete": true,
}

// hasBlockingError reports whether any error finding OUTSIDE the sync-repairable
// family is present — the set sync gates on before rendering.
func hasBlockingError(findings []compose.Finding) bool {
	for _, f := range findings {
		if f.Severity == compose.SeverityError && !syncRepairableCodes[f.Code] {
			return true
		}
	}
	return false
}

// isNotFound reports the uniform not-found/unauthorized response (unauthorized ≡
// nonexistent), the only catalogue answer doctor treats as "unanswerable".
func isNotFound(err error) bool {
	var ce *Error
	return asCLIError(err, &ce) && (ce.Code == ExitNotFound || ce.Code == ExitAuth)
}

// sanitizedEnviron returns the process environment with the workload credential
// (HIKYO_TOKEN) removed: it is the ONLY credential-transport env var (the token
// file is a flag, not an env var), and it must never reach the child or any
// subprocess the CLI spawns (finding 1). Building the child env from this — not
// os.Environ() — means the credential was never present, not stripped after.
//
// CREDENTIALS_DIRECTORY is deliberately NOT stripped (R1-1, accepted): it is a
// directory PATH, not a secret, and access to the files under it is per-open and
// uid-gated by systemd — so stripping the variable protects nothing, while
// stripping it would break a child that legitimately consumes its own systemd
// credentials.
func sanitizedEnviron() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, e := range src {
		if strings.HasPrefix(e, "HIKYO_TOKEN=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// resolveChildCommand resolves the command after `--`, distinguishing 127 (not
// found) from 126 (found but not executable). exec.LookPath alone is
// insufficient: for a BARE name it swallows a found-but-non-executable file as
// ErrNotFound (verified on darwin), so that case is detected by scanning PATH; a
// command containing a path separator is stat'd directly and LookPath surfaces
// fs.ErrPermission (finding 13).
//
// A command resolved ONLY via a relative PATH entry (`.` or any non-absolute
// dir) returns exec.ErrDot: Go deliberately refuses to run cwd-controlled code
// implicitly, and so do we — treat it as NOT FOUND (127), naming the relative
// entry, never execute it (NEW-1).
func resolveChildCommand(command string) (string, error) {
	path, err := exec.LookPath(command)
	if err == nil {
		return path, nil
	}
	if errors.Is(err, exec.ErrDot) {
		return "", failf(ExitCommandNotFound, "hikyo run: %s: resolved only via the relative PATH entry %q; refusing to execute cwd-controlled code — use an absolute path or a PATH of absolute directories", command, filepath.Dir(path))
	}
	if errors.Is(err, fs.ErrPermission) {
		return "", failf(ExitCommandNotExecutable, "hikyo run: %s: found but not executable", command)
	}
	if !strings.ContainsRune(command, filepath.Separator) && pathHasNonExecutable(command) {
		return "", failf(ExitCommandNotExecutable, "hikyo run: %s: found on PATH but not executable", command)
	}
	return "", failf(ExitCommandNotFound, "hikyo run: %s: command not found", command)
}

// pathHasNonExecutable reports whether a bare command name matches a regular
// file on PATH that lacks execute permission. It reads the PROCESS PATH (the
// same one exec.LookPath consulted), not an injected env, so the two agree.
func pathHasNonExecutable(command string) bool {
	// Windows has no 0o111 execute bit (executability is by extension via
	// PATHEXT), so this Unix-mode scan would misclassify; LookPath already
	// classifies correctly there.
	if runtime.GOOS == "windows" {
		return false
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "."
		}
		fi, err := os.Stat(filepath.Join(dir, command))
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.Mode().Perm()&0o111 == 0 {
			return true
		}
	}
	return false
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
