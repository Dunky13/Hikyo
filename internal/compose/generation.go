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
// DECISIONS taken here (brief-sanctioned, documented per the ADR's request):
//   - The stamp variables live in a managed block of <project dir>/.env
//     (Compose auto-loads only that file for interpolation), delimited by the
//     two markers below, one line per target: HIKYO_GEN_<TARGET>=v1-…
//   - Foreign lines are preserved byte-for-byte including their line endings
//     (LF or CRLF). The managed block's OWN lines are always written with LF —
//     it is generated, not hand-edited.
//   - Target name → variable: upper-snake, with '-' mapped to '_'. Target names
//     match ^[a-z][a-z0-9-]*$ so '_' in the variable can only have come from a
//     '-', making the reverse mapping unambiguous.

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
// point and assert the recovery invariant.
type Probe interface {
	BeforeGenerationComplete(stamp string) error
	BeforeStampRename() error
}

// Writer owns a per-project state directory and serializes render/sync/adopt
// through the writer lock.
type Writer struct {
	stateDir string
	probe    Probe
}

// NewWriter returns a Writer over stateDir. probe is nil in production.
func NewWriter(stateDir string, probe Probe) *Writer {
	return &Writer{stateDir: stateDir, probe: probe}
}

// BeginRender takes the non-blocking per-project writer lock. A second holder
// fails fast — a crash releases the lock (the OS drops it on process death),
// unlike an O_EXCL lock file that would wedge forever.
func (w *Writer) BeginRender() (unlock func(), err error) {
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
	return func() { _ = fl.Unlock() }, nil
}

// WriteGeneration writes an immutable generation directory <runtimeDir>/<stamp>/
// holding one <target>.env per entry (0600), fsynced, then a .complete marker
// written LAST. An existing COMPLETE directory is a no-op (content is identical
// by construction — the stamp keys the content). An existing INCOMPLETE one is
// a torn write: it is removed and rewritten.
func (w *Writer) WriteGeneration(runtimeDir, stamp string, files map[string][]byte) error {
	if err := crypto.ParseStamp(stamp); err != nil {
		return fmt.Errorf("compose: refusing to write generation: %w", err)
	}
	genDir := filepath.Join(runtimeDir, stamp)

	present, complete := GenerationState(runtimeDir, stamp)
	if present && complete {
		return nil
	}
	if present && !complete {
		if err := os.RemoveAll(genDir); err != nil {
			return fmt.Errorf("compose: remove incomplete generation %s: %w", stamp, err)
		}
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("compose: create runtime dir: %w", err)
	}
	// Explicit 0700, not umask-dependent (ADR § Where plaintext lives).
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("compose: chmod runtime dir: %w", err)
	}
	if err := os.Mkdir(genDir, 0o700); err != nil {
		return fmt.Errorf("compose: create generation dir: %w", err)
	}
	if err := os.Chmod(genDir, 0o700); err != nil {
		return fmt.Errorf("compose: chmod generation dir: %w", err)
	}

	// Deterministic order so the directory fsync sees a stable set.
	names := make([]string, 0, len(files))
	for t := range files {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		fp := filepath.Join(genDir, t+".env")
		if err := writeFileFsync(fp, files[t], 0o600); err != nil {
			return fmt.Errorf("compose: write %s.env: %w", t, err)
		}
	}
	if err := fsyncDir(genDir); err != nil {
		return fmt.Errorf("compose: fsync generation dir: %w", err)
	}

	// Crash seam: a failure here leaves the directory present-but-incomplete,
	// which Recover/GC collect and no cursor accepts.
	if w.probe != nil {
		if err := w.probe.BeforeGenerationComplete(stamp); err != nil {
			return err
		}
	}
	if err := writeFileFsync(filepath.Join(genDir, completeMarker), nil, 0o600); err != nil {
		return fmt.Errorf("compose: write completion marker: %w", err)
	}
	if err := fsyncDir(genDir); err != nil {
		return fmt.Errorf("compose: fsync generation dir after marker: %w", err)
	}
	return nil
}

// GenerationState reports whether a generation directory is present and whether
// it carries its completion marker.
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
// point. Every non-managed line is preserved byte-for-byte; the file may not
// exist yet.
func (w *Writer) CommitStamps(projectDir string, stamps map[string]string) error {
	for t, s := range stamps {
		if err := crypto.ParseStamp(s); err != nil {
			return fmt.Errorf("compose: refusing to commit stamp for %q: %w", t, err)
		}
	}
	envPath := filepath.Join(projectDir, ".env")
	raw, err := os.ReadFile(envPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("compose: read .env: %w", err)
	}
	next := spliceManagedBlock(raw, renderManagedBlock(stamps))

	// Crash seam: before the rename, .env still names the OLD stamps, and the
	// old generation is intact — values and stamp never disagree.
	if w.probe != nil {
		if err := w.probe.BeforeStampRename(); err != nil {
			return err
		}
	}
	if err := atomicWrite(envPath, next, 0o644); err != nil {
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

// spliceManagedBlock replaces an existing managed block in raw with block, or
// appends block. Foreign lines keep their exact bytes and terminators.
func spliceManagedBlock(raw, block []byte) []byte {
	lines := splitKeepEnds(raw)
	begin, end := -1, -1
	for i, ln := range lines {
		switch trimLineEnd(ln) {
		case managedBegin:
			if begin == -1 {
				begin = i
			}
		case managedEnd:
			if begin != -1 && end == -1 {
				end = i
			}
		}
	}
	if begin != -1 && end != -1 && end >= begin {
		var out []byte
		for _, ln := range lines[:begin] {
			out = append(out, ln...)
		}
		out = append(out, block...)
		for _, ln := range lines[end+1:] {
			out = append(out, ln...)
		}
		return out
	}
	// Not present: append. Ensure a separating newline if the file does not end
	// with one.
	out := append([]byte(nil), raw...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, block...)
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
// target→stamp map. Each stamp is grammar-checked; a malformed stamp is a HARD
// ERROR, never a default. A file with no managed block yields an empty map.
func CurrentStamps(projectDir string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(projectDir, ".env"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("compose: read .env: %w", err)
	}
	out := map[string]string{}
	inBlock := false
	for _, ln := range splitKeepEnds(raw) {
		content := trimLineEnd(ln)
		switch content {
		case managedBegin:
			inBlock = true
			continue
		case managedEnd:
			inBlock = false
			continue
		}
		if !inBlock {
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
		if err := crypto.ParseStamp(val); err != nil {
			return nil, fmt.Errorf("compose: %w", err)
		}
		out[target] = val
	}
	return out, nil
}

// Recover removes torn generation directories — those lacking their completion
// marker — under runtimeDir. It must be called under the writer lock.
func (w *Writer) Recover(runtimeDir string) error {
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("compose: recover: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, complete := GenerationState(runtimeDir, e.Name()); !complete {
			if err := os.RemoveAll(filepath.Join(runtimeDir, e.Name())); err != nil {
				return fmt.Errorf("compose: recover remove %s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// GC removes generation directories not named by any current stamp beyond the
// `keep` most recent (by mtime). It NEVER removes a current generation, and it
// removes INCOMPLETE directories regardless of age (torn writes are
// unreferenced). Must be called under the writer lock.
func (w *Writer) GC(runtimeDir string, currentStamps map[string]string, keep int) error {
	current := make(map[string]struct{}, len(currentStamps))
	for _, s := range currentStamps {
		current[s] = struct{}{}
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("compose: gc: %w", err)
	}

	type gen struct {
		name  string
		mtime int64
	}
	var superseded []gen
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if _, isCurrent := current[name]; isCurrent {
			continue // never collect a current generation
		}
		if _, complete := GenerationState(runtimeDir, name); !complete {
			// Incomplete and not current: remove regardless of age.
			if err := os.RemoveAll(filepath.Join(runtimeDir, name)); err != nil {
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
	// Keep the `keep` most recent superseded generations; remove the rest.
	sort.Slice(superseded, func(i, j int) bool { return superseded[i].mtime > superseded[j].mtime })
	for i, g := range superseded {
		if i < keep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(runtimeDir, g.name)); err != nil {
			return fmt.Errorf("compose: gc remove %s: %w", g.name, err)
		}
	}
	return nil
}
