package delivery

import (
	"reflect"
	"slices"
	"testing"
)

// loaderControlPinnedExact is the ADR's exact-match baseline verbatim.
// Shrinking the production list (loaderControlExact + prefixes) fails this test
// — #25 may extend, never silently shrink. This is the single home of the pin
// now that internal/compose delegates to this package.
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
	want := append([]string(nil), loaderControlPinnedExact...)
	slices.Sort(got)
	slices.Sort(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("exact baseline drifted.\n got: %v\nwant: %v", got, want)
	}
	if !reflect.DeepEqual(loaderControlPrefixes, []string{"LD_", "GIT_"}) {
		t.Errorf("prefix baseline drifted: %v", loaderControlPrefixes)
	}
}

func TestIsLoaderControlKey(t *testing.T) {
	for _, name := range []string{
		"PATH", "IFS", "NODE_OPTIONS", "CLASSPATH", "NODE_EXTRA_CA_CERTS",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "GIT_SSH", "GIT_EXTERNAL_DIFF",
	} {
		if !IsLoaderControlKey(name) {
			t.Errorf("%q should be a loader-control key", name)
		}
	}
	for _, name := range []string{
		"API_KEY", "DB_URL", "PATHOLOGY",
		// GITHUB_TOKEN begins "GITH", not "GIT_" — the prefix requires the
		// underscore boundary, so it is NOT a loader-control key. LDAP_URL
		// likewise is not "LD_".
		"GITHUB_TOKEN", "MY_PATH", "LDAP_URL",
	} {
		if IsLoaderControlKey(name) {
			t.Errorf("%q should not be a loader-control key", name)
		}
	}
}

func TestUnacknowledgedClean(t *testing.T) {
	refused, extra := Unacknowledged([]string{"API_KEY", "DB_URL"}, nil)
	if len(refused) != 0 || len(extra) != 0 {
		t.Fatalf("clean mapping refused=%v extra=%v", refused, extra)
	}
}

func TestUnacknowledgedRefusesUnacked(t *testing.T) {
	refused, extra := Unacknowledged([]string{"API_KEY", "PATH", "LD_PRELOAD"}, nil)
	want := []string{"LD_PRELOAD", "PATH"}
	if !reflect.DeepEqual(refused, want) {
		t.Fatalf("refused = %v, want %v", refused, want)
	}
	if len(extra) != 0 {
		t.Fatalf("extra = %v, want none", extra)
	}
}

func TestUnacknowledgedExactAcceptance(t *testing.T) {
	// Exactly the mapped baseline keys acknowledged → clean.
	refused, extra := Unacknowledged(
		[]string{"API_KEY", "PATH", "LD_PRELOAD"},
		[]string{"PATH", "LD_PRELOAD"},
	)
	if len(refused) != 0 || len(extra) != 0 {
		t.Fatalf("exact acknowledgement should pass: refused=%v extra=%v", refused, extra)
	}
}

func TestUnacknowledgedExtraAckIsRefusal(t *testing.T) {
	// Acknowledging a baseline key that is not mapped is an over-broad grant.
	refused, extra := Unacknowledged(
		[]string{"PATH"},
		[]string{"PATH", "NODE_OPTIONS"},
	)
	if len(refused) != 0 {
		t.Fatalf("refused = %v, want none", refused)
	}
	if !reflect.DeepEqual(extra, []string{"NODE_OPTIONS"}) {
		t.Fatalf("extra = %v, want [NODE_OPTIONS]", extra)
	}
}

func TestUnacknowledgedMappedNonLoaderAckIsRefusal(t *testing.T) {
	// mapping [PATH, API_KEY] acknowledging [PATH, API_KEY]: API_KEY is mapped
	// but is not a loader-control key, so acknowledging it is a latent grant —
	// set equality with the mapped loader-control subset ({PATH}) fails.
	refused, extra := Unacknowledged(
		[]string{"PATH", "API_KEY"},
		[]string{"PATH", "API_KEY"},
	)
	if len(refused) != 0 {
		t.Fatalf("refused = %v, want none", refused)
	}
	if !reflect.DeepEqual(extra, []string{"API_KEY"}) {
		t.Fatalf("extra = %v, want [API_KEY]", extra)
	}
}

func TestUnacknowledgedDuplicateAckIsRefusal(t *testing.T) {
	// A repeated acknowledgement is not the exact mapped loader-control set.
	refused, extra := Unacknowledged(
		[]string{"PATH"},
		[]string{"PATH", "PATH"},
	)
	if len(refused) != 0 {
		t.Fatalf("refused = %v, want none", refused)
	}
	if !reflect.DeepEqual(extra, []string{"PATH"}) {
		t.Fatalf("extra = %v, want [PATH] (duplicate)", extra)
	}
}

func TestUnacknowledgedPartialAck(t *testing.T) {
	// PATH acknowledged, LD_PRELOAD not → LD_PRELOAD still refused.
	refused, extra := Unacknowledged(
		[]string{"PATH", "LD_PRELOAD"},
		[]string{"PATH"},
	)
	if !reflect.DeepEqual(refused, []string{"LD_PRELOAD"}) {
		t.Fatalf("refused = %v, want [LD_PRELOAD]", refused)
	}
	if len(extra) != 0 {
		t.Fatalf("extra = %v, want none", extra)
	}
}
