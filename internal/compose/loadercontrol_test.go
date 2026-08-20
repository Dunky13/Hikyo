package compose

import (
	"reflect"
	"testing"
)

// The baseline is pinned verbatim in its single home, internal/delivery
// (TestLoaderControlBaselinePinned there). These tests cover the compose-facing
// re-export and the refusal helper that live in this package.

func TestIsLoaderControl(t *testing.T) {
	cases := map[string]bool{
		"PATH":            true,
		"LD_PRELOAD":      true,
		"LD_LIBRARY_PATH": true,
		"GIT_SSH_COMMAND": true,
		"NODE_OPTIONS":    true,
		"path":            false, // case-sensitive
		"Path":            false,
		"MY_PATH":         false,
		"DATABASE_URL":    false,
		"LD":              false, // prefix requires the underscore
		"GITHUB_TOKEN":    false, // not GIT_
	}
	for name, want := range cases {
		if got := IsLoaderControl(name); got != want {
			t.Errorf("IsLoaderControl(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestRefuseUnacknowledged(t *testing.T) {
	names := []string{"DATABASE_URL", "PATH", "LD_PRELOAD", "NODE_OPTIONS", "SAFE"}
	refused := RefuseUnacknowledged(names, []string{"PATH"})
	want := []string{"LD_PRELOAD", "NODE_OPTIONS"} // sorted, PATH acknowledged
	if !reflect.DeepEqual(refused, want) {
		t.Errorf("refused = %v, want %v", refused, want)
	}
	if r := RefuseUnacknowledged([]string{"SAFE", "DATABASE_URL"}, nil); r != nil {
		t.Errorf("no loader-control keys should refuse nothing, got %v", r)
	}
}
