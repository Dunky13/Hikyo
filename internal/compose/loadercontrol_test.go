package compose

import (
	"reflect"
	"sort"
	"testing"
)

// loaderControlPinned is the ADR's baseline verbatim. Shrinking the production
// list (loaderControlExact + prefixes) fails this test — #25 may extend, not
// silently shrink.
var loaderControlPinnedExact = []string{
	"PATH", "IFS", "ENV", "BASH_ENV", "SHELLOPTS", "NODE_OPTIONS",
	"PYTHONSTARTUP", "PYTHONPATH", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
	"NODE_EXTRA_CA_CERTS",
}

func TestLoaderControlBaselinePinned(t *testing.T) {
	got := make([]string, 0, len(loaderControlExact))
	for k := range loaderControlExact {
		got = append(got, k)
	}
	sort.Strings(got)
	want := append([]string(nil), loaderControlPinnedExact...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("exact baseline drifted.\n got: %v\nwant: %v", got, want)
	}
	if !reflect.DeepEqual(loaderControlPrefixes, []string{"LD_", "GIT_"}) {
		t.Errorf("prefix baseline drifted: %v", loaderControlPrefixes)
	}
}

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
