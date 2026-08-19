package compose

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

func testKeys(t *testing.T) *crypto.LocalKeys {
	t.Helper()
	k, err := crypto.LoadOrCreateLocalKey(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	return k
}

// dirs returns a fresh state dir and runtime dir.
func dirs(t *testing.T) (state, runtime string) {
	t.Helper()
	base := t.TempDir()
	state = filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime = filepath.Join(base, "runtime")
	return state, runtime
}

func TestVarNameRoundTrip(t *testing.T) {
	for _, tc := range []struct{ target, varN string }{
		{"api", "HIKYO_GEN_API"},
		{"api-server", "HIKYO_GEN_API_SERVER"},
		{"a1-b2", "HIKYO_GEN_A1_B2"},
	} {
		if got := varName(tc.target); got != tc.varN {
			t.Errorf("varName(%q) = %q, want %q", tc.target, got, tc.varN)
		}
		back, ok := targetFromVar(tc.varN)
		if !ok || back != tc.target {
			t.Errorf("targetFromVar(%q) = %q,%v, want %q", tc.varN, back, ok, tc.target)
		}
	}
}

func TestWriteGenerationAndState(t *testing.T) {
	_, runtime := dirs(t)
	w := NewWriter(t.TempDir(), nil)
	keys := testKeys(t)
	stamp := TargetStamp(keys, []byte("API=1\n"))

	if p, c := GenerationState(runtime, stamp); p || c {
		t.Fatal("state should be absent before write")
	}
	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("API=1\n")}); err != nil {
		t.Fatal(err)
	}
	if p, c := GenerationState(runtime, stamp); !p || !c {
		t.Fatalf("state present=%v complete=%v, want both", p, c)
	}
	// File exists 0600, marker present.
	b, err := os.ReadFile(filepath.Join(runtime, stamp, "api.env"))
	if err != nil || string(b) != "API=1\n" {
		t.Fatalf("api.env = %q err=%v", b, err)
	}
	// Re-write is a no-op (idempotent).
	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("API=1\n")}); err != nil {
		t.Fatalf("idempotent rewrite: %v", err)
	}
}

func TestWriteGenerationRejectsBadStamp(t *testing.T) {
	_, runtime := dirs(t)
	w := NewWriter(t.TempDir(), nil)
	if err := w.WriteGeneration(runtime, "not-a-stamp", map[string][]byte{"api": {}}); err == nil {
		t.Fatal("expected rejection of a malformed stamp")
	}
}

// errProbe fails at a chosen seam.
type errProbe struct {
	failComplete bool
	failRename   bool
}

func (p errProbe) BeforeGenerationComplete(string) error {
	if p.failComplete {
		return errors.New("injected crash before .complete")
	}
	return nil
}
func (p errProbe) BeforeStampRename() error {
	if p.failRename {
		return errors.New("injected crash before rename")
	}
	return nil
}

func TestCrashBeforeCompleteLeavesUnreferenced(t *testing.T) {
	_, runtime := dirs(t)
	keys := testKeys(t)
	stamp := TargetStamp(keys, []byte("x"))
	w := NewWriter(t.TempDir(), errProbe{failComplete: true})

	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("x")}); err == nil {
		t.Fatal("expected injected error")
	}
	if p, c := GenerationState(runtime, stamp); !p || c {
		t.Fatalf("after crash: present=%v complete=%v, want present & incomplete", p, c)
	}
	// Recover removes the torn directory.
	if err := w.Recover(runtime); err != nil {
		t.Fatal(err)
	}
	if p, _ := GenerationState(runtime, stamp); p {
		t.Fatal("Recover should have removed the incomplete generation")
	}
}

func TestCrashBeforeRenameKeepsOldStamp(t *testing.T) {
	state, _ := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	oldStamp := TargetStamp(keys, []byte("v1"))
	newStamp := TargetStamp(keys, []byte("v2"))

	// Commit the old stamp cleanly.
	w := NewWriter(state, nil)
	if err := w.CommitStamps(projectDir, map[string]string{"api": oldStamp}); err != nil {
		t.Fatal(err)
	}
	// Now a crash before the rename must leave .env naming the OLD stamp.
	wc := NewWriter(state, errProbe{failRename: true})
	if err := wc.CommitStamps(projectDir, map[string]string{"api": newStamp}); err == nil {
		t.Fatal("expected injected rename error")
	}
	got, err := CurrentStamps(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if got["api"] != oldStamp {
		t.Fatalf("api stamp = %q, want the old %q (values and stamp must never disagree)", got["api"], oldStamp)
	}
}

func TestCommitStampsPreservesForeignLines(t *testing.T) {
	keys := testKeys(t)
	s1 := TargetStamp(keys, []byte("1"))
	s2 := TargetStamp(keys, []byte("2"))

	for _, nl := range []struct{ name, eol string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
		t.Run(nl.name, func(t *testing.T) {
			projectDir := t.TempDir()
			foreign := "FOO=bar" + nl.eol + "BAZ=qux" + nl.eol
			envPath := filepath.Join(projectDir, ".env")
			if err := os.WriteFile(envPath, []byte(foreign), 0o644); err != nil {
				t.Fatal(err)
			}
			w := NewWriter(t.TempDir(), nil)
			if err := w.CommitStamps(projectDir, map[string]string{"api": s1}); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(envPath)
			// Foreign prefix survives byte-for-byte, terminators included.
			if got := string(after[:len(foreign)]); got != foreign {
				t.Fatalf("foreign lines mangled:\n got %q\nwant %q", got, foreign)
			}
			// Re-commit with a new stamp replaces the block, foreign lines still exact.
			if err := w.CommitStamps(projectDir, map[string]string{"api": s2}); err != nil {
				t.Fatal(err)
			}
			after2, _ := os.ReadFile(envPath)
			if got := string(after2[:len(foreign)]); got != foreign {
				t.Fatalf("foreign lines mangled on rewrite:\n got %q\nwant %q", got, foreign)
			}
			stamps, err := CurrentStamps(projectDir)
			if err != nil || stamps["api"] != s2 {
				t.Fatalf("CurrentStamps = %v err=%v, want api=%s", stamps, err, s2)
			}
			// Exactly one managed block (no duplication).
			if n := countOccur(string(after2), managedBegin); n != 1 {
				t.Fatalf("managed block count = %d, want 1", n)
			}
		})
	}
}

func TestCommitStampsNoPriorEnv(t *testing.T) {
	projectDir := t.TempDir()
	keys := testKeys(t)
	s := TargetStamp(keys, []byte("x"))
	w := NewWriter(t.TempDir(), nil)
	if err := w.CommitStamps(projectDir, map[string]string{"api": s}); err != nil {
		t.Fatal(err)
	}
	got, err := CurrentStamps(projectDir)
	if err != nil || got["api"] != s {
		t.Fatalf("got %v err=%v", got, err)
	}
}

func TestCurrentStampsRejectsMalformed(t *testing.T) {
	projectDir := t.TempDir()
	env := managedBegin + "\nHIKYO_GEN_API=not-a-valid-stamp\n" + managedEnd + "\n"
	if err := os.WriteFile(filepath.Join(projectDir, ".env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CurrentStamps(projectDir); err == nil {
		t.Fatal("expected hard error on a malformed stamp in the managed block")
	}
}

func TestWriteGenerationDirModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are the unix leg")
	}
	_, runtime := dirs(t)
	w := NewWriter(t.TempDir(), nil)
	keys := testKeys(t)
	stamp := TargetStamp(keys, []byte("x"))
	// A hostile umask (masks owner-execute) must not make the dir untraversable:
	// without the explicit chmod, Mkdir(0700)&~0177 = 0600.
	old := setUmask(0o177)
	defer setUmask(old)
	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{runtime, filepath.Join(runtime, stamp)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %04o, want 0700", d, fi.Mode().Perm())
		}
	}
}

func TestBeginRenderLockFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are the unix leg")
	}
	state, _ := dirs(t)
	old := setUmask(0o022)
	defer setUmask(old)
	w := NewWriter(state, nil)
	unlock, err := w.BeginRender()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	fi, err := os.Stat(filepath.Join(state, lockName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file mode = %04o, want 0600 (doctor state_dir_mode expects it)", fi.Mode().Perm())
	}
}

func TestBeginRenderLockContention(t *testing.T) {
	state, _ := dirs(t)
	w1 := NewWriter(state, nil)
	unlock, err := w1.BeginRender()
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	w2 := NewWriter(state, nil)
	if _, err := w2.BeginRender(); err == nil {
		t.Fatal("second BeginRender should fail fast while the lock is held")
	}
	unlock()
	// After release the lock is available again.
	unlock2, err := w2.BeginRender()
	if err != nil {
		t.Fatalf("relock after release: %v", err)
	}
	unlock2()
}

func TestGCKeepsCurrentPlusThree(t *testing.T) {
	_, runtime := dirs(t)
	w := NewWriter(t.TempDir(), nil)
	keys := testKeys(t)

	// Six complete generations with increasing mtime; one is "current".
	stamps := make([]string, 6)
	for i := range stamps {
		stamps[i] = TargetStamp(keys, []byte{byte('a' + i)})
		if err := w.WriteGeneration(runtime, stamps[i], map[string][]byte{"api": {byte('a' + i)}}); err != nil {
			t.Fatal(err)
		}
		// Space out mtimes deterministically.
		mt := time.Unix(1_700_000_000+int64(i)*10, 0)
		if err := os.Chtimes(filepath.Join(runtime, stamps[i]), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	current := stamps[0] // oldest is current — must survive despite age
	if err := w.GC(runtime, map[string]string{"api": current}, DefaultGenerationsKept); err != nil {
		t.Fatal(err)
	}
	// Survivors: current (stamps[0]) + 3 most-recent superseded (stamps[5,4,3]).
	surv := map[string]bool{stamps[0]: true, stamps[5]: true, stamps[4]: true, stamps[3]: true}
	for i, s := range stamps {
		p, _ := GenerationState(runtime, s)
		if p != surv[s] {
			t.Errorf("stamp[%d] present=%v, want %v", i, p, surv[s])
		}
	}
}

func TestGCRemovesIncompleteRegardlessOfAge(t *testing.T) {
	_, runtime := dirs(t)
	keys := testKeys(t)
	w := NewWriter(t.TempDir(), errProbe{failComplete: true})
	torn := TargetStamp(keys, []byte("torn"))
	_ = w.WriteGeneration(runtime, torn, map[string][]byte{"api": []byte("torn")}) // fails at marker
	// Make it look ancient.
	old := time.Unix(1, 0)
	_ = os.Chtimes(filepath.Join(runtime, torn), old, old)

	wc := NewWriter(t.TempDir(), nil)
	if err := wc.GC(runtime, map[string]string{}, DefaultGenerationsKept); err != nil {
		t.Fatal(err)
	}
	if p, _ := GenerationState(runtime, torn); p {
		t.Fatal("GC must remove an incomplete generation regardless of age")
	}
}

func countOccur(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
