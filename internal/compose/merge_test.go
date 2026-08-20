package compose

import (
	"reflect"
	"strings"
	"testing"
)

func TestMergeEnvFetchedWins(t *testing.T) {
	inherited := []string{"PATH=/usr/bin", "DATABASE_URL=old", "HOME=/root"}
	fetched := map[string]string{"DATABASE_URL": "old", "API_KEY": "k"}
	// DATABASE_URL identical → no-op; API_KEY appended.
	out, collisions, err := MergeEnv(inherited, fetched, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(collisions) != 0 {
		t.Fatalf("unexpected collisions: %v", collisions)
	}
	want := []string{"PATH=/usr/bin", "DATABASE_URL=old", "HOME=/root", "API_KEY=k"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("out = %v, want %v", out, want)
	}
}

func TestMergeEnvDifferingValueHardError(t *testing.T) {
	inherited := []string{"DATABASE_URL=stale"}
	fetched := map[string]string{"DATABASE_URL": "fresh"}
	_, _, err := MergeEnv(inherited, fetched, nil)
	if err == nil {
		t.Fatal("expected hard error on differing collision")
	}
}

func TestMergeEnvOverrideEscapeHatch(t *testing.T) {
	inherited := []string{"DATABASE_URL=stale"}
	fetched := map[string]string{"DATABASE_URL": "fresh"}
	out, collisions, err := MergeEnv(inherited, fetched, []string{"DATABASE_URL"})
	if err != nil {
		t.Fatalf("override should not error: %v", err)
	}
	if len(collisions) != 1 || collisions[0].Key != "DATABASE_URL" {
		t.Fatalf("collision = %v", collisions)
	}
	if !reflect.DeepEqual(out, []string{"DATABASE_URL=fresh"}) {
		t.Errorf("out = %v; fetched must win", out)
	}
}

// TestMergeEnvNeverLeaksValues: neither the error nor the Collision result may
// contain either colliding value — only key names (#16).
func TestMergeEnvNeverLeaksValues(t *testing.T) {
	const inheritedVal = "INHERITED-SECRET-VALUE"
	const fetchedVal = "FETCHED-SECRET-VALUE"
	inherited := []string{"DATABASE_URL=" + inheritedVal}
	fetched := map[string]string{"DATABASE_URL": fetchedVal}

	// Hard-error path.
	if _, _, err := MergeEnv(inherited, fetched, nil); err == nil {
		t.Fatal("expected hard error")
	} else if s := err.Error(); strings.Contains(s, inheritedVal) || strings.Contains(s, fetchedVal) {
		t.Errorf("error string leaks a value: %q", s)
	}

	// Allowed-override path: the Collision struct carries no value fields.
	_, collisions, err := MergeEnv(inherited, fetched, []string{"DATABASE_URL"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range collisions {
		if s := reflect.ValueOf(c); s.NumField() != 1 {
			t.Errorf("Collision has %d fields, want 1 (key only)", s.NumField())
		}
	}
}

func TestMergeEnvSortedAppendAndStableOrder(t *testing.T) {
	inherited := []string{"Z=1", "A=2"}
	fetched := map[string]string{"M": "m", "B": "b"}
	out, _, err := MergeEnv(inherited, fetched, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Z=1", "A=2", "B=b", "M=m"} // inherited order stable, fetched sorted
	if !reflect.DeepEqual(out, want) {
		t.Errorf("out = %v, want %v", out, want)
	}
}
