package compose

import (
	"path/filepath"
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

// buildEligible writes a complete generation and returns a cursor bound to it.
func buildEligible(t *testing.T, runtime string) (CursorState, map[string]string) {
	t.Helper()
	k := testKeys(t)
	stamp := TargetStamp(k, []byte("api-content"))
	w := NewWriter(t.TempDir(), nil)
	if err := w.WriteGeneration(runtime, stamp, map[string][]byte{"api": []byte("api-content")}); err != nil {
		t.Fatal(err)
	}
	current := map[string]string{"api": stamp}
	cs := CursorState{
		Cursor:           "v1:abc",
		CredentialID:     "cred_1",
		Environment:      "env_1",
		ConfigOnly:       false,
		TargetIDsHash:    HashTargetIDs([]string{"key_1", "key_2"}),
		GenerationStamps: map[string]string{"api": stamp},
	}
	return cs, current
}

func TestEligibleCursorHappyPath(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, current := buildEligible(t, runtime)
	got, ok := EligibleCursor(&cs, current, runtime, "cred_1", "env_1", false, []string{"key_1", "key_2"})
	if !ok || got != "v1:abc" {
		t.Fatalf("EligibleCursor = %q,%v, want v1:abc,true", got, ok)
	}
}

func TestEligibleCursorBindingMismatches(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, current := buildEligible(t, runtime)
	base := func() (string, bool) {
		return EligibleCursor(&cs, current, runtime, "cred_1", "env_1", false, []string{"key_1", "key_2"})
	}
	if _, ok := base(); !ok {
		t.Fatal("precondition: base should be eligible")
	}
	// Each binding change invalidates.
	if _, ok := EligibleCursor(&cs, current, runtime, "cred_OTHER", "env_1", false, []string{"key_1", "key_2"}); ok {
		t.Error("credential mismatch should invalidate")
	}
	if _, ok := EligibleCursor(&cs, current, runtime, "cred_1", "env_OTHER", false, []string{"key_1", "key_2"}); ok {
		t.Error("environment mismatch should invalidate")
	}
	if _, ok := EligibleCursor(&cs, current, runtime, "cred_1", "env_1", true, []string{"key_1", "key_2"}); ok {
		t.Error("config_only mismatch should invalidate")
	}
	if _, ok := EligibleCursor(&cs, current, runtime, "cred_1", "env_1", false, []string{"key_1"}); ok {
		t.Error("target set change should invalidate")
	}
}

func TestEligibleCursorGenerationTests(t *testing.T) {
	_, runtime := cursorSetup(t)
	cs, current := buildEligible(t, runtime)
	ids := []string{"key_1", "key_2"}

	// Managed-block stamp differs from the cursor's → ineligible.
	drift := map[string]string{"api": "v1-" + hex32()}
	if _, ok := EligibleCursor(&cs, drift, runtime, "cred_1", "env_1", false, ids); ok {
		t.Error("stamp drift vs managed block should invalidate")
	}

	// Generation present-but-incomplete → ineligible (torn write / reboot).
	incompleteStamp := cs.GenerationStamps["api"]
	// Remove the completion marker to simulate an incomplete generation.
	marker := filepath.Join(runtime, incompleteStamp, completeMarker)
	if err := removeFile(marker); err != nil {
		t.Fatal(err)
	}
	if _, ok := EligibleCursor(&cs, current, runtime, "cred_1", "env_1", false, ids); ok {
		t.Error("incomplete generation should invalidate")
	}
}

func TestSaveLoadCursorRoundTrip(t *testing.T) {
	state, runtime := cursorSetup(t)
	cs, _ := buildEligible(t, runtime)
	if err := SaveCursor(state, cs); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCursor(state)
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.Cursor != cs.Cursor || got.TargetIDsHash != cs.TargetIDsHash {
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

func TestHashTargetIDsOrderIndependent(t *testing.T) {
	if HashTargetIDs([]string{"a", "b"}) != HashTargetIDs([]string{"b", "a"}) {
		t.Error("hash must be order-independent")
	}
	if HashTargetIDs([]string{"a", "b"}) == HashTargetIDs([]string{"a", "c"}) {
		t.Error("different sets must differ")
	}
	// Injectivity across the boundary.
	if HashTargetIDs([]string{"ab", "c"}) == HashTargetIDs([]string{"a", "bc"}) {
		t.Error("length-prefixing must keep the hash injective")
	}
}
