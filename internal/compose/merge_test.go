package compose

import (
	"reflect"
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
	if len(collisions) != 1 || collisions[0].Key != "DATABASE_URL" || collisions[0].FetchedVal != "fresh" {
		t.Fatalf("collision = %v", collisions)
	}
	if !reflect.DeepEqual(out, []string{"DATABASE_URL=fresh"}) {
		t.Errorf("out = %v; fetched must win", out)
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
