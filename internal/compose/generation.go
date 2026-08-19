package compose

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/gofrs/flock"
)

// Render generations, the stamp file, the per-project writer lock, and GC
// (compose-integration ADR § "Change propagation — render generations and the
// stamp", § "Generations, atomicity and locking").
//
// The invariant the whole design defends: VALUES AND STAMP CANNOT DISAGREE.
// Generation directories are immutable and named by the stamp, so there is no
// ordering between "write the values" and "write the stamp" to get wrong. The
// single mutable artifact is the stamp file, committed by one atomic rename.
//
// The writer lock is not a convention but an unforgeable guard: BeginRender
// returns a *RenderLock, and WriteGeneration / CommitStamps / Recover / GC are
// methods on it. A caller cannot mutate the runtime dir without holding the
// lock, because there is no other way to reach those verbs.
//
// DECISIONS taken here (brief-sanctioned, documented per the ADR's request):
//   - The stamp variables live in a managed block of <project dir>/.env
//     (Compose auto-loads only that file for interpolation), delimited by the
//     two markers below, one line per target: HIKYO_GEN_<TARGET>=v1-…
//   - Foreign lines are preserved byte-for-byte including their line endings
//     (LF or CRLF). The managed block's OWN lines are always written with LF —
//     it is generated, not hand-edited.
//   - One generation directory per TARGET per content: a render writes
//     <runtimeDir>/<stamp>/<target>.env, where <stamp> keys that target's
//     content. Every write/read under the runtime dir goes through an os.Root
//     confined to it, so a crafted stamp or target cannot escape the tree.

const (
	managedBegin = "# >>> hikyo compose (managed, do not edit) >>>"
	managedEnd   = "# <<< hikyo compose <<<"

	// stampVarPrefix precedes the upper-snake target name.
	stampVarPrefix = "HIKYO_GEN_"

	// completeMarker is written LAST in a generation directory; recovery treats
	// a directory lacking it as unreferenced whatever its age.
	completeMarker = ".complete"

	// lockName is the per-project writer lock file under the state dir.
	lockName = "lock"

	// targetContentDomain separates a stamp's per-target-content input from any
	// other message the stamp key might sign. It is a DIFFERENT layer from
	// crypto.Stamp's own "hikyo-stamp-v1\x00" prefix.
	targetContentDomain = "hikyo-target-content-v1\x00"

	// DefaultGenerationsKept is the retention beyond the current stamp
	// (ops-spec § 6: current + previous 3).
	DefaultGenerationsKept = 3
)

// TargetStamp is the stamp over one target's rendered content: the canonical
// per-target-content encoding fed to the keyed stamp. Keep the two domain
// prefixes in their two layers — this one here, crypto.Stamp's inside.
func TargetStamp(keys *crypto.LocalKeys, content []byte) string {
	buf := make([]byte, 0, len(targetContentDomain)+len(content))
	buf = append(buf, targetContentDomain...)
	buf = append(buf, content...)
	return keys.Stamp(buf)
}

// varName maps a target name to its stamp variable (HIKYO_GEN_<UPPER_SNAKE>).
func varName(target string) string {
	return stampVarPrefix + strings.ToUpper(strings.ReplaceAll(target, "-", "_"))
}

// targetFromVar reverses varName. Unambiguous because target names carry no '_'.
func targetFromVar(v string) (string, bool) {
	if !strings.HasPrefix(v, stampVarPrefix) {
		return "", false
	}
	return strings.ToLower(strings.ReplaceAll(v[len(stampVarPrefix):], "_", "-")), true
}

// Probe is the crash seam (mirrors service.DeliveryConformanceProbe). Production
// leaves it nil; tests inject an error to simulate a crash at a deterministic
// durability boundary and assert the recovery invariant.
type Probe interface {
	AfterGenerationDirCreated(stamp string) error
	BeforeGenerationComplete(stamp string) error
	BeforeStampRename() error
}

// Writer owns a per-project state directory and mints RenderLocks.
type Writer struct {
	stateDir string
	probe    Probe
}

// NewWriter returns a Writer over stateDir. probe is nil in production.
func NewWriter(stateDir string, probe Probe) *Writer {
	return &Writer{stateDir: stateDir, probe: probe}
}

// RenderLock is the held writer lock and the capability to mutate the runtime
// dir and the stamp file. It is returned by BeginRender and released by Close.
type RenderLock struct {
	w          *Writer
	projectDir string
	fl         *flock.Flock
}

// BeginRender takes the non-blocking per-project writer lock and returns a
// handle scoped to projectDir (whose managed .env block is the stamp file). A
// second holder fails fast — a crash releases the lock (the OS drops it on
// process death), unlike an O_EXCL lock file that would wedge forever.
func (w *Writer) BeginRender(projectDir string) (*RenderLock, error) {
	fl := flock.New(filepath.Join(w.stateDir, lockName))
	locked, err := fl.TryLock()
	if err != nil {
		return nil, fmt.Errorf("compose: acquire writer lock: %w", err)
	}
	if !locked {
		return nil, errors.New("compose: another hikyo compose process holds the lock")
	}
	// gofrs/flock creates the lock file with its own default perm; force 0600
	// so the file this code creates does not itself trip doctor's
	// state_dir_mode check.
	if err := os.Chmod(fl.Path(), 0o600); err != nil {
		_ = fl.Unlock()
		return nil, fmt.Errorf("compose: chmod lock file: %w", err)
	}
	return &RenderLock{w: w, projectDir: projectDir, fl: fl}, nil
}

// Close releases the writer lock.
func (rl *RenderLock) Close() error { return rl.fl.Unlock() }

// WriteGeneration writes an immutable generation directory
// <runtimeDir>/<stamp>/ holding one <target>.env (0600), fsynced, then a
// .complete marker written LAST, where <stamp> is computed here as
// TargetStamp(keys, content) — never supplied by the caller. The target name is
// grammar-validated and all I/O is directory-relative under an os.Root, so a
// crafted target or stamp cannot escape the runtime dir. It returns the stamp.
//
// An existing COMPLETE directory is re-verified: its <target>.env bytes must
// re-stamp to the same name (immutable-by-construction), else it is a hard
// error, not a silent trust or overwrite. An existing INCOMPLETE one is a torn
// write: removed and rewritten.
func (rl *RenderLock) WriteGeneration(runtimeDir string, keys *crypto.LocalKeys, target string, content []byte) (string, error) {
	if !targetNameGrammar.MatchString(target) {
		return "", fmt.Errorf("compose: refusing to write generation: invalid target name %q", target)
	}
	stamp := TargetStamp(keys, content)
	envName := target + ".env"

	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", fmt.Errorf("compose: create runtime dir: %w", err)
	}
	// Explicit 0700, not umask-dependent (ADR § Where plaintext lives).
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		return "", fmt.Errorf("compose: chmod runtime dir: %w", err)
	}
	root, err := os.OpenRoot(runtimeDir)
	if err != nil {
		return "", fmt.Errorf("compose: open runtime dir: %w", err)
	}
	defer root.Close()

	present, complete := generationStateRoot(root, stamp)
	if present && complete {
		existing, err := root.ReadFile(stamp + "/" + envName)
		if err != nil {
			return "", fmt.Errorf("compose: re-verify generation %s: %w", stamp, err)
		}
		if TargetStamp(keys, existing) != stamp {
			return "", fmt.Errorf("compose: existing generation %s content does not match its stamp; refusing", stamp)
		}
		return stamp, nil
	}
	if present && !complete {
		if err := root.RemoveAll(stamp); err != nil {
			return "", fmt.Errorf("compose: remove incomplete generation %s: %w", stamp, err)
		}
	}
	if err := root.Mkdir(stamp, 0o700); err != nil {
		return "", fmt.Errorf("compose: create generation dir: %w", err)
	}
	if err := root.Chmod(stamp, 0o700); err != nil {
		return "", fmt.Errorf("compose: chmod generation dir: %w", err)
	}
	if err := writeFileFsyncRoot(root, stamp+"/"+envName, content, 0o600); err != nil {
		return "", fmt.Errorf("compose: write %s: %w", envName, err)
	}
	if err := fsyncRootPath(root, stamp); err != nil {
		return "", fmt.Errorf("compose: fsync generation dir: %w", err)
	}

	// Crash seam: the generation dir exists but the runtime dir entry is not yet
	// fsynced. Recover/GC collect it and no cursor accepts it.
	if rl.w.probe != nil {
		if err := rl.w.probe.AfterGenerationDirCreated(stamp); err != nil {
			return "", err
		}
	}
	// Make the generation directory ENTRY durable in the runtime dir before the
	// stamp rename that will reference it (ADR § Generations, atomicity).
	if err := fsyncRootPath(root, "."); err != nil {
		return "", fmt.Errorf("compose: fsync runtime dir: %w", err)
	}

	// Crash seam: a failure here leaves the directory present-but-incomplete.
	if rl.w.probe != nil {
		if err := rl.w.probe.BeforeGenerationComplete(stamp); err != nil {
			return "", err
		}
	}
	if err := writeFileFsyncRoot(root, stamp+"/"+completeMarker, nil, 0o600); err != nil {
		return "", fmt.Errorf("compose: write completion marker: %w", err)
	}
	if err := fsyncRootPath(root, stamp); err != nil {
		return "", fmt.Errorf("compose: fsync generation dir after marker: %w", err)
	}
	return stamp, nil
}

// writeFileFsyncRoot writes name relative to root (truncating), chmods to perm
// explicitly (umask-independent), and fsyncs the file.
func writeFileFsyncRoot(root *os.Root, name string, data []byte, perm os.FileMode) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// generationStateRoot reports presence/completeness of a stamp dir under root.
func generationStateRoot(root *os.Root, stamp string) (present, complete bool) {
	if _, err := root.Stat(stamp); err != nil {
		return false, false
	}
	if _, err := root.Stat(stamp + "/" + completeMarker); err != nil {
		return true, false
	}
	return true, true
}

// GenerationState reports whether a generation directory is present and whether
// it carries its completion marker. It is a read-only check used by doctor and
// the cursor over a resolved, absolute runtime dir.
func GenerationState(runtimeDir, stamp string) (present, complete bool) {
	genDir := filepath.Join(runtimeDir, stamp)
	if _, err := os.Stat(genDir); err != nil {
		return false, false
	}
	if _, err := os.Stat(filepath.Join(genDir, completeMarker)); err != nil {
		return true, false
	}
	return true, true
}

// CommitStamps rewrites the managed block of <projectDir>/.env with the given
// per-target stamps and atomically renames it into place — the single commit
// point. The existing file is validated as carrying exactly one well-formed
// managed block BEFORE any rewrite; every non-managed line is preserved
// byte-for-byte; the file's mode and ownership are preserved (never widened),
// and a file that does not exist yet is created 0600.
func (rl *RenderLock) CommitStamps(stamps map[string]string) error {
	for t, s := range stamps {
		if err := crypto.ParseStamp(s); err != nil {
			return fmt.Errorf("compose: refusing to commit stamp for %q: %w", t, err)
		}
	}
	envPath := filepath.Join(rl.projectDir, ".env")
	raw, err := os.ReadFile(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("compose: read .env: %w", err)
	}
	// Validate the existing managed block is well-formed (single, no duplicate
	// markers/variables, terminated) before touching anything.
	if _, err := parseManagedBlock(raw); err != nil {
		return err
	}
	next, err := spliceManagedBlock(raw, renderManagedBlock(stamps))
	if err != nil {
		return err
	}

	// Crash seam: before the rename, .env still names the OLD stamps, and the
	// old generation is intact — values and stamp never disagree.
	if rl.w.probe != nil {
		if err := rl.w.probe.BeforeStampRename(); err != nil {
			return err
		}
	}
	if err := atomicWriteEnv(envPath, next); err != nil {
		return fmt.Errorf("compose: commit stamp file: %w", err)
	}
	return nil
}

// renderManagedBlock builds the managed block bytes (LF line endings), targets
// sorted for determinism.
func renderManagedBlock(stamps map[string]string) []byte {
	targets := make([]string, 0, len(stamps))
	for t := range stamps {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	var b strings.Builder
	b.WriteString(managedBegin)
	b.WriteByte('\n')
	for _, t := range targets {
		b.WriteString(varName(t))
		b.WriteByte('=')
		b.WriteString(stamps[t])
		b.WriteByte('\n')
	}
	b.WriteString(managedEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}

// locateManagedBlock finds THE single managed block in lines, refusing
// duplicate markers, a nested block, an end without a begin, and an
// unterminated block. Returns begin/end line indices, or (-1,-1) when absent.
func locateManagedBlock(lines [][]byte) (begin, end int, err error) {
	begin, end = -1, -1
	for i, ln := range lines {
		switch trimLineEnd(ln) {
		case managedBegin:
			if begin != -1 && end == -1 {
				return -1, -1, fmt.Errorf("compose: nested hikyo managed block in .env (line %d)", i+1)
			}
			if begin != -1 {
				return -1, -1, fmt.Errorf("compose: duplicate hikyo managed block in .env (line %d)", i+1)
			}
			begin = i
		case managedEnd:
			if begin == -1 {
				return -1, -1, fmt.Errorf("compose: hikyo managed-block end without a begin in .env (line %d)", i+1)
			}
			if end != -1 {
				return -1, -1, fmt.Errorf("compose: duplicate hikyo managed-block end in .env (line %d)", i+1)
			}
			end = i
		}
	}
	if begin != -1 && end == -1 {
		return -1, -1, errors.New("compose: unterminated hikyo managed block in .env")
	}
	return begin, end, nil
}

// parseManagedBlock validates and parses the managed block into a target→stamp
// map. A malformed structure, a duplicate variable, an unknown variable, or a
// malformed stamp is a HARD ERROR — never a default. No block yields an empty map.
func parseManagedBlock(raw []byte) (map[string]string, error) {
	lines := splitKeepEnds(raw)
	begin, end, err := locateManagedBlock(lines)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if begin == -1 {
		return out, nil
	}
	for _, ln := range lines[begin+1 : end] {
		content := trimLineEnd(ln)
		if content == "" {
			continue
		}
		key, val, ok := strings.Cut(content, "=")
		if !ok {
			return nil, fmt.Errorf("compose: malformed managed line %q in .env", content)
		}
		target, ok := targetFromVar(key)
		if !ok {
			return nil, fmt.Errorf("compose: unexpected variable %q in managed block", key)
		}
		if _, dup := out[target]; dup {
			return nil, fmt.Errorf("compose: duplicate variable %q in managed block", key)
		}
		if err := crypto.ParseStamp(val); err != nil {
			return nil, fmt.Errorf("compose: %w", err)
		}
		out[target] = val
	}
	return out, nil
}

// spliceManagedBlock replaces the single managed block in raw with block, or
// appends block. Foreign lines keep their exact bytes and terminators. It
// returns an error if raw's managed block is malformed.
func spliceManagedBlock(raw, block []byte) ([]byte, error) {
	lines := splitKeepEnds(raw)
	begin, end, err := locateManagedBlock(lines)
	if err != nil {
		return nil, err
	}
	if begin != -1 && end != -1 {
		var out []byte
		for _, ln := range lines[:begin] {
			out = append(out, ln...)
		}
		out = append(out, block...)
		for _, ln := range lines[end+1:] {
			out = append(out, ln...)
		}
		return out, nil
	}
	// Not present: append. Ensure a separating newline if the file does not end
	// with one.
	out := append([]byte(nil), raw...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, block...), nil
}

// splitKeepEnds splits into lines each INCLUDING its trailing '\n' (the last
// line may lack one). CRLF is preserved: the '\r' stays on the line.
func splitKeepEnds(b []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			lines = append(lines, b[start:i+1])
			start = i + 1
		}
	}
	if start < len(b) {
		lines = append(lines, b[start:])
	}
	return lines
}

// trimLineEnd returns the line content without its trailing "\r\n" or "\n".
func trimLineEnd(line []byte) string {
	s := string(line)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}

// CurrentStamps parses the managed block of <projectDir>/.env into a
// target→stamp map, with the same strict validation as parseManagedBlock. A
// file with no managed block yields an empty map.
func CurrentStamps(projectDir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(projectDir, ".env"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("compose: read .env: %w", err)
	}
	return parseManagedBlock(raw)
}

// Recover removes torn generation directories — those lacking their completion
// marker — under runtimeDir. Every top-level entry must be a valid stamp
// directory; a foreign entry is a hard error naming it. It is a method on the
// held lock, so it can only run under serialization.
func (rl *RenderLock) Recover(runtimeDir string) error {
	root, entries, err := openRuntimeEntries(runtimeDir)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	for _, e := range entries {
		name := e.Name()
		if err := crypto.ParseStamp(name); err != nil {
			return fmt.Errorf("compose: refusing to recover: foreign entry %q under runtime dir %s", name, runtimeDir)
		}
		if _, complete := generationStateRoot(root, name); !complete {
			if err := root.RemoveAll(name); err != nil {
				return fmt.Errorf("compose: recover remove %s: %w", name, err)
			}
		}
	}
	return nil
}

// GC removes generation directories not named by any current stamp beyond the
// `keep` most recent (by mtime). Current stamps are derived by reading the
// managed block itself, not trusted from a caller. It NEVER removes a current
// generation, removes INCOMPLETE directories regardless of age, and errors on a
// foreign entry. It is a method on the held lock.
func (rl *RenderLock) GC(runtimeDir string, keep int) error {
	currentStamps, err := CurrentStamps(rl.projectDir)
	if err != nil {
		return err
	}
	current := make(map[string]struct{}, len(currentStamps))
	for _, s := range currentStamps {
		current[s] = struct{}{}
	}

	root, entries, err := openRuntimeEntries(runtimeDir)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()

	type gen struct {
		name  string
		mtime int64
	}
	var superseded []gen
	for _, e := range entries {
		name := e.Name()
		if err := crypto.ParseStamp(name); err != nil {
			return fmt.Errorf("compose: refusing to gc: foreign entry %q under runtime dir %s", name, runtimeDir)
		}
		if _, isCurrent := current[name]; isCurrent {
			continue // never collect a current generation
		}
		if _, complete := generationStateRoot(root, name); !complete {
			if err := root.RemoveAll(name); err != nil {
				return fmt.Errorf("compose: gc remove incomplete %s: %w", name, err)
			}
			continue
		}
		info, err := e.Info()
		if err != nil {
			return fmt.Errorf("compose: gc stat %s: %w", name, err)
		}
		superseded = append(superseded, gen{name: name, mtime: info.ModTime().UnixNano()})
	}
	sort.Slice(superseded, func(i, j int) bool { return superseded[i].mtime > superseded[j].mtime })
	for i, g := range superseded {
		if i < keep {
			continue
		}
		if err := root.RemoveAll(g.name); err != nil {
			return fmt.Errorf("compose: gc remove %s: %w", g.name, err)
		}
	}
	return nil
}

// openRuntimeEntries opens runtimeDir as an os.Root and lists its top-level
// entries. A missing runtime dir returns (nil, nil, nil) — nothing to do.
func openRuntimeEntries(runtimeDir string) (*os.Root, []os.DirEntry, error) {
	root, err := os.OpenRoot(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("compose: open runtime dir: %w", err)
	}
	d, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, fmt.Errorf("compose: open runtime dir: %w", err)
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		root.Close()
		return nil, nil, fmt.Errorf("compose: list runtime dir: %w", err)
	}
	return root, entries, nil
}
