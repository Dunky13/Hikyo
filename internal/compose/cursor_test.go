package compose

import (
	"path/filepath"
	"runtime"
	"testing"
)

func cursorSetup(t *testing.T) (state, runtime string) {
	t.Helper()
	base := t.TempDir()
	state = filepath.Join(base, "state")
	if err := osMkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime = filepath.Join(base, "runtime")
	return state, runtime
}

func baseBinding() CursorBinding {
	return CursorBinding{
		CredentialID:   "cred_1",
		Environment:    "env_1",
		ConfigOnly:     false,
		PinnedRevision: 0,
		Projection:     []string{"read", "reveal"},
		TargetKeyIDs:   map[string][]string{"api": {"key_1", "key_2"}},
	}
}

// buildEligible writes a complete generation and returns a cursor bound to it.
func buildEligible(t *testing.T, runtime string) (CursorState, CursorBinding, map[string]string) {
	t.Helper()
	k := testKeys(t)
	rl := begin(t, t.TempDir(), nil)
	stamp, err := rl.WriteGeneration(runtime, k, "api", []byte("api-content"))
	if err != nil {
		t.Fatal(err)
	}
	binding := baseBinding()
	current := map[string]string{"api": stamp}
	cs := CursorState{
		Cursor:           "v1:abc",
		Binding:          binding,
		GenerationStamps: map[string]string{"api": stamp},
	}
	return cs, binding, current
}

func TestEligibleCursorHappyPath(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, binding, current := buildEligible(t, runtime)
	got, ok := EligibleCursor(&cs, binding, current, runtime)
	if !ok || got != "v1:abc" {
		t.Fatalf("EligibleCursor = %q,%v, want v1:abc,true", got, ok)
	}
	// Reordered projection / key ids still eligible (canonicalized).
	perm := binding
	perm.Projection = []string{"reveal", "read"}
	perm.TargetKeyIDs = map[string][]string{"api": {"key_2", "key_1"}}
	if _, ok := EligibleCursor(&cs, perm, current, runtime); !ok {
		t.Error("reordered binding lists should still be eligible")
	}
}

func TestEligibleCursorBindingMismatches(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, binding, current := buildEligible(t, runtime)
	if _, ok := EligibleCursor(&cs, binding, current, runtime); !ok {
		t.Fatal("precondition: base should be eligible")
	}
	for name, mut := range map[string]func(*CursorBinding){
		"credential":      func(b *CursorBinding) { b.CredentialID = "cred_OTHER" },
		"environment":     func(b *CursorBinding) { b.Environment = "env_OTHER" },
		"config_only":     func(b *CursorBinding) { b.ConfigOnly = true },
		"pinned_revision": func(b *CursorBinding) { b.PinnedRevision = 5 },
		"projection":      func(b *CursorBinding) { b.Projection = []string{"read"} },
		"key-added":       func(b *CursorBinding) { b.TargetKeyIDs = map[string][]string{"api": {"key_1", "key_2", "key_3"}} },
		"key-removed":     func(b *CursorBinding) { b.TargetKeyIDs = map[string][]string{"api": {"key_1"}} },
		"target-added": func(b *CursorBinding) {
			b.TargetKeyIDs = map[string][]string{"api": {"key_1", "key_2"}, "worker": {"key_9"}}
		},
		"target-removed": func(b *CursorBinding) { b.TargetKeyIDs = map[string][]string{} },
	} {
		want := binding
		want.Projection = append([]string(nil), binding.Projection...)
		want.TargetKeyIDs = map[string][]string{"api": {"key_1", "key_2"}}
		mut(&want)
		if _, ok := EligibleCursor(&cs, want, current, runtime); ok {
			t.Errorf("%s mismatch should invalidate", name)
		}
	}
}

func TestEligibleCursorGenerationTests(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, binding, current := buildEligible(t, runtime)

	// Managed-block stamp differs from the cursor's → ineligible.
	drift := map[string]string{"api": "v1-" + hex32()}
	if _, ok := EligibleCursor(&cs, binding, drift, runtime); ok {
		t.Error("stamp drift vs managed block should invalidate")
	}

	// Generation present-but-incomplete → ineligible.
	stamp := cs.GenerationStamps["api"]
	if err := removeFile(filepath.Join(runtime, stamp, completeMarker)); err != nil {
		t.Fatal(err)
	}
	if _, ok := EligibleCursor(&cs, binding, current, runtime); ok {
		t.Error("incomplete generation should invalidate")
	}
}

// TestEligibleCursorMissingEnvFile: complete generation but the <target>.env
// file is gone → ineligible (the render is not actually there).
func TestEligibleCursorMissingEnvFile(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, binding, current := buildEligible(t, runtime)
	stamp := cs.GenerationStamps["api"]
	if err := removeFile(filepath.Join(runtime, stamp, "api.env")); err != nil {
		t.Fatal(err)
	}
	if _, ok := EligibleCursor(&cs, binding, current, runtime); ok {
		t.Error("missing <target>.env should invalidate")
	}
}

// TestEligibleCursorRejectsExtraCurrentStamp: an EXTRA target in the
// managed-block stamps that the cursor was not issued for makes the sets unequal
// → ineligible (#2, exact set equality both ways).
func TestEligibleCursorRejectsExtraCurrentStamp(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, binding, current := buildEligible(t, runtime)
	current["worker"] = "v1-" + hex32() // a target the cursor never covered
	if _, ok := EligibleCursor(&cs, binding, current, runtime); ok {
		t.Error("an extra managed-block stamp must invalidate the cursor")
	}
}

// TestEligibleCursorRejectsNonRegularTargetFile: <target>.env being a directory
// or a symlink (not a regular file) invalidates the cursor — the render is not
// actually a plain env file (#2).
func TestEligibleCursorRejectsNonRegularTargetFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink case is the unix leg")
	}
	t.Run("directory", func(t *testing.T) {
		_, rt := cursorSetup(t)
		cs, binding, current := buildEligible(t, rt)
		stamp := cs.GenerationStamps["api"]
		envPath := filepath.Join(rt, stamp, "api.env")
		if err := removeFile(envPath); err != nil {
			t.Fatal(err)
		}
		if err := osMkdir(envPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, ok := EligibleCursor(&cs, binding, current, rt); ok {
			t.Error("a directory in place of <target>.env must invalidate")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		_, rt := cursorSetup(t)
		cs, binding, current := buildEligible(t, rt)
		stamp := cs.GenerationStamps["api"]
		envPath := filepath.Join(rt, stamp, "api.env")
		target := filepath.Join(rt, stamp, "real.env")
		if err := osWriteFile(target, []byte("api-content"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeFile(envPath); err != nil {
			t.Fatal(err)
		}
		if err := osSymlink("real.env", envPath); err != nil {
			t.Fatal(err)
		}
		if _, ok := EligibleCursor(&cs, binding, current, rt); ok {
			t.Error("a symlink in place of <target>.env must invalidate")
		}
	})
}

func TestSaveLoadCursorRoundTrip(t *testing.T) {
	state, runtime := cursorSetup(t)
	cs, _, _ := buildEligible(t, runtime)
	if err := SaveCursor(state, cs); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(state)
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.Cursor != cs.Cursor || !got.Binding.Equal(cs.Binding) {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestLoadCursorMissingIsNil(t *testing.T) {
	state, _ := cursorSetup(t)
	got, err := LoadCursor(state)
	if err != nil || got != nil {
		t.Fatalf("missing cursor should be nil,nil: %v %v", got, err)
	}
}
