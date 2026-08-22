package compose

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

// begin acquires a RenderLock over a fresh state dir with the given projectDir.
func begin(t *testing.T, projectDir string, probe Probe) *RenderLock {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	rl, err := NewWriter(state, probe).BeginRender(projectDir)
	if err != nil {
		t.Fatalf("BeginRender: %v", err)
	}
	t.Cleanup(func() { rl.Close() })
	return rl
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
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	stamp := TargetStamp(keys, "api", []byte("API=1\n"))

	if p, c := GenerationState(rt, stamp); p || c {
		t.Fatal("state should be absent before write")
	}
	got, _, err := rl.WriteGeneration(rt, keys, "api", []byte("API=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != stamp {
		t.Fatalf("WriteGeneration stamp = %q, want %q", got, stamp)
	}
	if p, c := GenerationState(rt, stamp); !p || !c {
		t.Fatalf("state present=%v complete=%v, want both", p, c)
	}
	b, err := os.ReadFile(filepath.Join(rt, stamp, "api.env"))
	if err != nil || string(b) != "API=1\n" {
		t.Fatalf("api.env = %q err=%v", b, err)
	}
	// Re-write is a no-op (idempotent; content re-stamps to the same name).
	if _, _, err := rl.WriteGeneration(rt, keys, "api", []byte("API=1\n")); err != nil {
		t.Fatalf("idempotent rewrite: %v", err)
	}
}

func TestPublishMaterializesCommitsAndCollects(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	rl := begin(t, projectDir, nil)
	content := map[string][]byte{
		"api":    []byte("API=1\n"),
		"worker": []byte("WORKER=1\n"),
	}

	result, err := rl.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: content})
	if err != nil {
		t.Fatal(err)
	}
	wantStamps := map[string]string{
		"api":    TargetStamp(keys, "api", content["api"]),
		"worker": TargetStamp(keys, "worker", content["worker"]),
	}
	if !reflect.DeepEqual(result.Stamps, wantStamps) {
		t.Fatalf("Publish stamps = %v, want %v", result.Stamps, wantStamps)
	}
	if !reflect.DeepEqual(result.Materialized, map[string]bool{"api": true, "worker": true}) {
		t.Fatalf("Publish materialized = %v, want both targets", result.Materialized)
	}
	if !result.CandidateActive() || !result.GCComplete() {
		t.Fatalf("Publish phase=%s, want complete", result.Phase)
	}
	if !result.Recover.ActiveKnown || result.Recover.NeedsCleanup || !reflect.DeepEqual(result.Recover.ActiveStamps, wantStamps) || !reflect.DeepEqual(result.Recover.CandidateStamps, wantStamps) {
		t.Fatalf("Publish recovery = %+v, want active candidates and no cleanup", result.Recover)
	}
	gotStamps, err := CurrentStamps(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotStamps, wantStamps) {
		t.Fatalf("CurrentStamps = %v, want %v", gotStamps, wantStamps)
	}
	for target, stamp := range wantStamps {
		got, err := os.ReadFile(filepath.Join(rt, stamp, target+".env"))
		if err != nil || string(got) != string(content[target]) {
			t.Fatalf("%s generation = %q err=%v", target, got, err)
		}
	}
}

func TestWriteGenerationRejectsBadTarget(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	for _, bad := range []string{"../evil", "API", "a/b", "", ".."} {
		if _, _, err := rl.WriteGeneration(rt, keys, bad, []byte("x")); err == nil {
			t.Errorf("WriteGeneration(%q) accepted an invalid target name", bad)
		}
	}
}

// TestWriteGenerationExistingMismatch: a complete dir whose file bytes no longer
// re-stamp to its name is a hard error, not a silent trust.
func TestWriteGenerationExistingMismatch(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	stamp, _, err := rl.WriteGeneration(rt, keys, "api", []byte("API=1\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Tamper the stored file so it no longer matches its stamp.
	if err := os.WriteFile(filepath.Join(rt, stamp, "api.env"), []byte("API=EVIL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rl.WriteGeneration(rt, keys, "api", []byte("API=1\n")); err == nil {
		t.Fatal("expected a hard error re-verifying tampered generation content")
	}
}

// errProbe fails at a chosen seam.
type errProbe struct {
	failAfterCreate      bool
	failComplete         bool
	failAfterMaterialize bool
	failRename           bool
	failAfterCommit      bool
	failGC               bool
	failGCRemoval        string
}

func (p errProbe) AfterGenerationDirCreated(string) error {
	if p.failAfterCreate {
		return errors.New("injected crash after generation dir created")
	}
	return nil
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
func (p errProbe) AfterGenerationMaterialized(string, string) error {
	if p.failAfterMaterialize {
		return errors.New("injected crash after generation materialized")
	}
	return nil
}
func (p errProbe) AfterStampCommit() error {
	if p.failAfterCommit {
		return errors.New("injected crash after stamp commit")
	}
	return nil
}
func (p errProbe) BeforeGarbageCollection() error {
	if p.failGC {
		return errors.New("injected crash before gc")
	}
	return nil
}
func (p errProbe) BeforeGenerationRemoval(stamp string) error {
	if p.failGCRemoval == stamp {
		return errors.New("injected crash during gc removal")
	}
	return nil
}

func TestPublishMaterializeFailureKeepsPreviousActive(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	oldContent := []byte("API=old\n")
	oldStamp := TargetStamp(keys, "api", oldContent)
	seed := begin(t, projectDir, nil)
	if _, _, err := seed.WriteGeneration(rt, keys, "api", oldContent); err != nil {
		t.Fatal(err)
	}
	if err := seed.CommitStamps(map[string]string{"api": oldStamp}); err != nil {
		t.Fatal(err)
	}

	lock := begin(t, projectDir, errProbe{failAfterMaterialize: true})
	newContent := []byte("API=new\n")
	newStamp := TargetStamp(keys, "api", newContent)
	result, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": newContent}})
	if err == nil {
		t.Fatal("Publish should surface the injected materialization failure")
	}
	if result.CandidateActive() || result.GCComplete() {
		t.Fatalf("Publish phase=%s after materialization failure", result.Phase)
	}
	if !result.Materialized["api"] || !result.Recover.NeedsCleanup {
		t.Fatalf("Publish result = %+v, want materialized candidate needing cleanup", result)
	}
	if result.Recover.ActiveStamps["api"] != oldStamp || result.Recover.CandidateStamps["api"] != newStamp {
		t.Fatalf("Publish recovery = %+v, want old active and new candidate", result.Recover)
	}
	if present, complete := GenerationState(rt, newStamp); !present || !complete {
		t.Fatalf("candidate present=%v complete=%v, want recoverable complete candidate", present, complete)
	}
}

func TestPublishPostCommitFailureReportsCandidateActive(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	lock := begin(t, projectDir, errProbe{failAfterCommit: true})
	content := []byte("API=new\n")
	stamp := TargetStamp(keys, "api", content)

	result, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": content}})
	if err == nil {
		t.Fatal("Publish should surface the injected post-commit failure")
	}
	if !result.CandidateActive() || result.GCComplete() {
		t.Fatalf("Publish phase=%s after post-commit failure", result.Phase)
	}
	if !result.Recover.NeedsCleanup || result.Recover.ActiveStamps["api"] != stamp {
		t.Fatalf("Publish recovery = %+v, want committed candidate active and cleanup pending", result.Recover)
	}
	got, err := CurrentStamps(projectDir)
	if err != nil || got["api"] != stamp {
		t.Fatalf("CurrentStamps = %v err=%v, want committed %s", got, err, stamp)
	}
}

func TestPublishStampSwitchFailureKeepsPreviousActive(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	oldContent := []byte("API=old\n")
	oldStamp := TargetStamp(keys, "api", oldContent)
	seed := begin(t, projectDir, nil)
	if _, _, err := seed.WriteGeneration(rt, keys, "api", oldContent); err != nil {
		t.Fatal(err)
	}
	if err := seed.CommitStamps(map[string]string{"api": oldStamp}); err != nil {
		t.Fatal(err)
	}

	lock := begin(t, projectDir, errProbe{failRename: true})
	newContent := []byte("API=new\n")
	newStamp := TargetStamp(keys, "api", newContent)
	result, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": newContent}})
	if err == nil {
		t.Fatal("Publish should surface the injected stamp-switch failure")
	}
	if result.CandidateActive() || result.GCComplete() {
		t.Fatalf("Publish phase=%s after stamp-switch failure", result.Phase)
	}
	if !result.Recover.ActiveKnown || !result.Recover.NeedsCleanup || result.Recover.ActiveStamps["api"] != oldStamp || result.Recover.CandidateStamps["api"] != newStamp {
		t.Fatalf("Publish recovery = %+v, want old active and new recoverable candidate", result.Recover)
	}
	got, err := CurrentStamps(projectDir)
	if err != nil || got["api"] != oldStamp {
		t.Fatalf("CurrentStamps = %v err=%v, want previous %s", got, err, oldStamp)
	}
}

func TestPublishGCFailureNeverRemovesActiveGeneration(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	lock := begin(t, projectDir, errProbe{failGC: true})
	content := []byte("API=new\n")
	stamp := TargetStamp(keys, "api", content)

	result, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": content}})
	if err == nil {
		t.Fatal("Publish should surface the injected GC failure")
	}
	if !result.CandidateActive() || result.GCComplete() {
		t.Fatalf("Publish phase=%s after GC failure", result.Phase)
	}
	if !result.Recover.NeedsCleanup || result.Recover.ActiveStamps["api"] != stamp {
		t.Fatalf("Publish recovery = %+v, want active generation retained", result.Recover)
	}
	if present, complete := GenerationState(rt, stamp); !present || !complete {
		t.Fatalf("active generation present=%v complete=%v after GC failure", present, complete)
	}
}

func TestCrashAfterDirCreatedLeavesUnreferenced(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), errProbe{failAfterCreate: true})
	stamp := TargetStamp(keys, "api", []byte("x"))
	if _, _, err := rl.WriteGeneration(rt, keys, "api", []byte("x")); err == nil {
		t.Fatal("expected injected error")
	}
	if p, c := GenerationState(rt, stamp); !p || c {
		t.Fatalf("after crash: present=%v complete=%v, want present & incomplete", p, c)
	}
	if err := rl.Recover(rt); err != nil {
		t.Fatal(err)
	}
	if p, _ := GenerationState(rt, stamp); p {
		t.Fatal("Recover should have removed the incomplete generation")
	}
}

func TestCrashBeforeCompleteLeavesUnreferenced(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), errProbe{failComplete: true})
	stamp := TargetStamp(keys, "api", []byte("x"))
	if _, _, err := rl.WriteGeneration(rt, keys, "api", []byte("x")); err == nil {
		t.Fatal("expected injected error")
	}
	if p, c := GenerationState(rt, stamp); !p || c {
		t.Fatalf("after crash: present=%v complete=%v, want present & incomplete", p, c)
	}
	if err := rl.Recover(rt); err != nil {
		t.Fatal(err)
	}
	if p, _ := GenerationState(rt, stamp); p {
		t.Fatal("Recover should have removed the incomplete generation")
	}
}

func TestRecoverRefusesForeignEntry(t *testing.T) {
	_, rt := dirs(t)
	rl := begin(t, t.TempDir(), nil)
	if err := os.MkdirAll(filepath.Join(rt, "not-a-stamp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rl.Recover(rt); err == nil {
		t.Fatal("Recover must refuse a foreign entry under the runtime dir")
	}
}

func TestCrashBeforeRenameKeepsOldStamp(t *testing.T) {
	projectDir := t.TempDir()
	keys := testKeys(t)
	oldStamp := TargetStamp(keys, "api", []byte("v1"))
	newStamp := TargetStamp(keys, "api", []byte("v2"))

	rl := begin(t, projectDir, nil)
	if err := rl.CommitStamps(map[string]string{"api": oldStamp}); err != nil {
		t.Fatal(err)
	}
	// A crash before the rename must leave .env naming the OLD stamp.
	rlc := begin(t, projectDir, errProbe{failRename: true})
	if err := rlc.CommitStamps(map[string]string{"api": newStamp}); err == nil {
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
	s1 := TargetStamp(keys, "api", []byte("1"))
	s2 := TargetStamp(keys, "api", []byte("2"))

	for _, nl := range []struct{ name, eol string }{{"LF", "\n"}, {"CRLF", "\r\n"}} {
		t.Run(nl.name, func(t *testing.T) {
			projectDir := t.TempDir()
			foreign := "FOO=bar" + nl.eol + "BAZ=qux" + nl.eol
			envPath := filepath.Join(projectDir, ".env")
			if err := os.WriteFile(envPath, []byte(foreign), 0o600); err != nil {
				t.Fatal(err)
			}
			rl := begin(t, projectDir, nil)
			if err := rl.CommitStamps(map[string]string{"api": s1}); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(envPath)
			if got := string(after[:len(foreign)]); got != foreign {
				t.Fatalf("foreign lines mangled:\n got %q\nwant %q", got, foreign)
			}
			if err := rl.CommitStamps(map[string]string{"api": s2}); err != nil {
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
			if n := countOccur(string(after2), managedBegin); n != 1 {
				t.Fatalf("managed block count = %d, want 1", n)
			}
		})
	}
}

// TestCommitStampsPreservesMode: a pre-existing 0600 secret-bearing .env is not
// widened by the commit (#5), under hostile umasks.
func TestCommitStampsPreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are the unix leg")
	}
	keys := testKeys(t)
	s := TargetStamp(keys, "api", []byte("x"))
	for _, um := range []int{0o077, 0o022} {
		old := setUmask(um)
		projectDir := t.TempDir()
		envPath := filepath.Join(projectDir, ".env")
		if err := os.WriteFile(envPath, []byte("SECRET=plaintext\n"), 0o600); err != nil {
			setUmask(old)
			t.Fatal(err)
		}
		if err := os.Chmod(envPath, 0o600); err != nil {
			setUmask(old)
			t.Fatal(err)
		}
		rl := begin(t, projectDir, nil)
		if err := rl.CommitStamps(map[string]string{"api": s}); err != nil {
			setUmask(old)
			t.Fatal(err)
		}
		fi, err := os.Stat(envPath)
		setUmask(old)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("umask %04o: .env mode = %04o, want 0600 (never widened)", um, fi.Mode().Perm())
		}
	}
}

// TestCommitStampsNewFileIs0600: a fresh combined .env is created 0600.
func TestCommitStampsNewFileIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are the unix leg")
	}
	old := setUmask(0o022)
	defer setUmask(old)
	projectDir := t.TempDir()
	keys := testKeys(t)
	s := TargetStamp(keys, "api", []byte("x"))
	rl := begin(t, projectDir, nil)
	if err := rl.CommitStamps(map[string]string{"api": s}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(projectDir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("new .env mode = %04o, want 0600", fi.Mode().Perm())
	}
}

func TestCommitStampsNoPriorEnv(t *testing.T) {
	projectDir := t.TempDir()
	keys := testKeys(t)
	s := TargetStamp(keys, "api", []byte("x"))
	rl := begin(t, projectDir, nil)
	if err := rl.CommitStamps(map[string]string{"api": s}); err != nil {
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
	if err := os.WriteFile(filepath.Join(projectDir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CurrentStamps(projectDir); err == nil {
		t.Fatal("expected hard error on a malformed stamp in the managed block")
	}
}

// TestManagedBlockMalformations: duplicate markers, nested/unterminated blocks,
// and duplicate variables are all hard errors before any rewrite (#13).
func TestManagedBlockMalformations(t *testing.T) {
	keys := testKeys(t)
	s := TargetStamp(keys, "api", []byte("x"))
	valid := "HIKYO_GEN_API=" + s
	cases := map[string]string{
		"duplicate-block":       managedBegin + "\n" + valid + "\n" + managedEnd + "\n" + managedBegin + "\n" + valid + "\n" + managedEnd + "\n",
		"nested-block":          managedBegin + "\n" + managedBegin + "\n" + valid + "\n" + managedEnd + "\n",
		"unterminated":          managedBegin + "\n" + valid + "\n",
		"end-without-begin":     valid + "\n" + managedEnd + "\n",
		"duplicate-variable":    managedBegin + "\n" + valid + "\n" + valid + "\n" + managedEnd + "\n",
		"duplicate-end-markers": managedBegin + "\n" + valid + "\n" + managedEnd + "\n" + managedEnd + "\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			projectDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(projectDir, ".env"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := CurrentStamps(projectDir); err == nil {
				t.Errorf("CurrentStamps accepted a malformed managed block")
			}
			rl := begin(t, projectDir, nil)
			if err := rl.CommitStamps(map[string]string{"api": s}); err == nil {
				t.Errorf("CommitStamps rewrote over a malformed managed block")
			}
		})
	}
}

func TestWriteGenerationDirModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are the unix leg")
	}
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	old := setUmask(0o177)
	defer setUmask(old)
	stamp, _, err := rl.WriteGeneration(rt, keys, "api", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{rt, filepath.Join(rt, stamp)} {
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
	rl, err := NewWriter(state, nil).BeginRender(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
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
	rl, err := w1.BeginRender(t.TempDir())
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	w2 := NewWriter(state, nil)
	if _, err := w2.BeginRender(t.TempDir()); err == nil {
		t.Fatal("second BeginRender should fail fast while the lock is held")
	}
	rl.Close()
	rl2, err := w2.BeginRender(t.TempDir())
	if err != nil {
		t.Fatalf("relock after release: %v", err)
	}
	rl2.Close()
}

func TestGCKeepsCurrentPlusThree(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	rl := begin(t, projectDir, nil)

	// Six complete generations of target "api" with increasing mtime.
	stamps := make([]string, 6)
	for i := range stamps {
		s, _, err := rl.WriteGeneration(rt, keys, "api", []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		stamps[i] = s
		mt := time.Unix(1_700_000_000+int64(i)*10, 0)
		if err := os.Chtimes(filepath.Join(rt, stamps[i]), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	current := stamps[0] // oldest is current — must survive despite age
	if err := rl.CommitStamps(map[string]string{"api": current}); err != nil {
		t.Fatal(err)
	}
	if err := rl.GC(rt, DefaultGenerationsKept); err != nil {
		t.Fatal(err)
	}
	surv := map[string]bool{stamps[0]: true, stamps[5]: true, stamps[4]: true, stamps[3]: true}
	for i, s := range stamps {
		p, _ := GenerationState(rt, s)
		if p != surv[s] {
			t.Errorf("stamp[%d] present=%v, want %v", i, p, surv[s])
		}
	}
}

func TestGCKeepsPreviousGenerationsPerTarget(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	rl := begin(t, projectDir, nil)

	apiOld, _, err := rl.WriteGeneration(rt, keys, "api", []byte("api-old"))
	if err != nil {
		t.Fatal(err)
	}
	apiCurrent, _, err := rl.WriteGeneration(rt, keys, "api", []byte("api-current"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(rt, apiOld), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}

	worker := make([]string, 5)
	for i := range worker {
		worker[i], _, err = rl.WriteGeneration(rt, keys, "worker", []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		mt := time.Unix(100+int64(i), 0)
		if err := os.Chtimes(filepath.Join(rt, worker[i]), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	if err := rl.CommitStamps(map[string]string{"api": apiCurrent, "worker": worker[4]}); err != nil {
		t.Fatal(err)
	}
	if err := rl.GC(rt, DefaultGenerationsKept); err != nil {
		t.Fatal(err)
	}

	if present, complete := GenerationState(rt, apiOld); !present || !complete {
		t.Fatalf("api previous generation present=%v complete=%v, want retained independently of worker history", present, complete)
	}
	workerPrevious := 0
	for _, stamp := range worker[:4] {
		if present, _ := GenerationState(rt, stamp); present {
			workerPrevious++
		}
	}
	if workerPrevious != DefaultGenerationsKept {
		t.Fatalf("worker previous generations = %d, want %d", workerPrevious, DefaultGenerationsKept)
	}
}

func TestPublishGCPartialFailureKeepsActiveAndReportsCleanup(t *testing.T) {
	_, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	seed := begin(t, projectDir, nil)
	stamps := make([]string, 6)
	for i := range stamps {
		stamp, _, err := seed.WriteGeneration(rt, keys, "api", []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		stamps[i] = stamp
		mt := time.Unix(100+int64(i), 0)
		if err := os.Chtimes(filepath.Join(rt, stamp), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	if err := seed.CommitStamps(map[string]string{"api": stamps[4]}); err != nil {
		t.Fatal(err)
	}

	lock := begin(t, projectDir, errProbe{failGCRemoval: stamps[0]})
	result, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": []byte("f")}})
	if err == nil {
		t.Fatal("Publish should surface the injected partial GC failure")
	}
	if !result.CandidateActive() || result.GCComplete() || !result.Recover.NeedsCleanup {
		t.Fatalf("Publish result = %+v, want committed active state with cleanup pending", result)
	}
	if present, complete := GenerationState(rt, stamps[5]); !present || !complete {
		t.Fatalf("active generation present=%v complete=%v after partial GC failure", present, complete)
	}
	if present, _ := GenerationState(rt, stamps[1]); present {
		t.Fatal("first over-retention generation should be removed before injected failure")
	}
	if present, complete := GenerationState(rt, stamps[0]); !present || !complete {
		t.Fatalf("failed-removal generation present=%v complete=%v, want recoverable", present, complete)
	}
}

func TestPublishRecoversTornGenerationAfterLockRestart(t *testing.T) {
	state, rt := dirs(t)
	projectDir := t.TempDir()
	keys := testKeys(t)
	content := []byte("API=restart\n")
	stamp := TargetStamp(keys, "api", content)
	first, err := NewWriter(state, errProbe{failComplete: true}).BeginRender(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	result, err := first.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": content}})
	if err == nil || result.CandidateActive() {
		t.Fatalf("first Publish result=%+v err=%v, want torn pre-switch failure", result, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if present, complete := GenerationState(rt, stamp); !present || complete {
		t.Fatalf("torn candidate present=%v complete=%v before restart recovery", present, complete)
	}

	restarted, err := NewWriter(state, nil).BeginRender(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Recover(rt); err != nil {
		t.Fatal(err)
	}
	result, err = restarted.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": content}})
	if err != nil || result.Phase != PublishPhaseComplete || !result.Materialized["api"] {
		t.Fatalf("restart Publish result=%+v err=%v, want complete re-materialization", result, err)
	}
}

func TestGCRemovesIncompleteRegardlessOfAge(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), errProbe{failComplete: true})
	torn := TargetStamp(keys, "api", []byte("torn"))
	_, _, _ = rl.WriteGeneration(rt, keys, "api", []byte("torn")) // fails at marker
	old := time.Unix(1, 0)
	_ = os.Chtimes(filepath.Join(rt, torn), old, old)

	// GC via a fresh lock over an empty project (no current stamps).
	rlc := begin(t, t.TempDir(), nil)
	if err := rlc.GC(rt, DefaultGenerationsKept); err != nil {
		t.Fatal(err)
	}
	if p, _ := GenerationState(rt, torn); p {
		t.Fatal("GC must remove an incomplete generation regardless of age")
	}
}

func TestGCRefusesForeignEntry(t *testing.T) {
	_, rt := dirs(t)
	rl := begin(t, t.TempDir(), nil)
	if err := os.MkdirAll(filepath.Join(rt, "junk"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rl.GC(rt, DefaultGenerationsKept); err == nil {
		t.Fatal("GC must refuse a foreign entry under the runtime dir")
	}
}

// TestTwoTargetsSameContentDistinctGenerations: two DIFFERENT targets rendering
// byte-identical content must get DIFFERENT stamps (target name is bound into
// the stamp), so each writes and re-verifies its own <target>.env (NEW-1).
func TestTwoTargetsSameContentDistinctGenerations(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	content := []byte("SHARED=1\n")

	sApi, _, err := rl.WriteGeneration(rt, keys, "api", content)
	if err != nil {
		t.Fatal(err)
	}
	sWorker, _, err := rl.WriteGeneration(rt, keys, "worker", content)
	if err != nil {
		t.Fatalf("second target with identical content must render: %v", err)
	}
	if sApi == sWorker {
		t.Fatal("identical content across distinct targets produced the same stamp")
	}
	if b, err := os.ReadFile(filepath.Join(rt, sApi, "api.env")); err != nil || string(b) != string(content) {
		t.Fatalf("api.env = %q err=%v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(rt, sWorker, "worker.env")); err != nil || string(b) != string(content) {
		t.Fatalf("worker.env = %q err=%v", b, err)
	}
	// Idempotent re-render of each still verifies against its own directory.
	if _, _, err := rl.WriteGeneration(rt, keys, "api", content); err != nil {
		t.Fatalf("api re-render: %v", err)
	}
	if _, _, err := rl.WriteGeneration(rt, keys, "worker", content); err != nil {
		t.Fatalf("worker re-render: %v", err)
	}
}

// TestWriteGenerationRefusesSymlinkedRuntimeDir: the runtime dir itself being a
// symlink is refused before any write (#6).
func TestWriteGenerationRefusesSymlinkedRuntimeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics are the unix leg")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "runtime")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	if _, _, err := rl.WriteGeneration(link, keys, "api", []byte("x")); err == nil {
		t.Fatal("WriteGeneration must refuse a symlinked runtime dir")
	}
}

func TestWriteGenerationAcceptsExistingPlainRuntimeDir(t *testing.T) {
	_, rt := dirs(t)
	if err := os.Mkdir(rt, 0o755); err != nil {
		t.Fatal(err)
	}
	keys := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	if _, _, err := rl.WriteGeneration(rt, keys, "api", []byte("x")); err != nil {
		t.Fatalf("WriteGeneration with existing plain runtime dir: %v", err)
	}
	info, err := os.Stat(rt)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("runtime dir mode = %04o, want 0700", info.Mode().Perm())
	}
}

// TestRenderLockRefusedAfterClose: every verb is spent once the lock is
// released, and a second Close is refused too (#11).
func TestRenderLockRefusedAfterClose(t *testing.T) {
	_, rt := dirs(t)
	keys := testKeys(t)
	projectDir := t.TempDir()
	// A fresh state dir + lock we control the lifetime of (no t.Cleanup Close).
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := NewWriter(state, nil).BeginRender(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); !errors.Is(err, errLockReleased) {
		t.Errorf("second Close err = %v, want errLockReleased", err)
	}
	if _, _, err := lock.WriteGeneration(rt, keys, "api", []byte("x")); !errors.Is(err, errLockReleased) {
		t.Errorf("WriteGeneration after Close err = %v, want errLockReleased", err)
	}
	if err := lock.CommitStamps(map[string]string{"api": TargetStamp(keys, "api", []byte("x"))}); !errors.Is(err, errLockReleased) {
		t.Errorf("CommitStamps after Close err = %v, want errLockReleased", err)
	}
	if err := lock.Recover(rt); !errors.Is(err, errLockReleased) {
		t.Errorf("Recover after Close err = %v, want errLockReleased", err)
	}
	if err := lock.GC(rt, DefaultGenerationsKept); !errors.Is(err, errLockReleased) {
		t.Errorf("GC after Close err = %v, want errLockReleased", err)
	}
	if _, err := lock.Publish(PublishPlan{RuntimeDir: rt, Keys: keys, Targets: map[string][]byte{"api": []byte("x")}}); !errors.Is(err, errLockReleased) {
		t.Errorf("Publish after Close err = %v, want errLockReleased", err)
	}
}

// TestRecoverGCRefuseStampNamedNonDirectory: a top-level entry whose NAME is a
// valid stamp but which is not a directory (a file, or a symlink — DirEntry.IsDir
// does not follow) is a hard error for both Recover and GC (#11).
func TestRecoverGCRefuseStampNamedNonDirectory(t *testing.T) {
	keys := testKeys(t)
	stampName := TargetStamp(keys, "api", []byte("x"))
	for _, verb := range []string{"recover", "gc"} {
		t.Run(verb, func(t *testing.T) {
			_, rt := dirs(t)
			if err := os.MkdirAll(rt, 0o700); err != nil {
				t.Fatal(err)
			}
			// A regular file named exactly like a valid stamp.
			if err := os.WriteFile(filepath.Join(rt, stampName), []byte("not a dir"), 0o600); err != nil {
				t.Fatal(err)
			}
			rl := begin(t, t.TempDir(), nil)
			var err error
			if verb == "recover" {
				err = rl.Recover(rt)
			} else {
				err = rl.GC(rt, DefaultGenerationsKept)
			}
			if err == nil {
				t.Fatalf("%s must refuse a stamp-named non-directory entry", verb)
			}
		})
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
