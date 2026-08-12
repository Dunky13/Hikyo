package main

import "testing"

func TestVersionStringUsesReleaseMetadata(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = oldVersion, oldCommit, oldDate })

	version = "0.2.0-rc.1"
	commit = "0123456789abcdef"
	buildDate = "2026-08-07T07:00:00Z"

	want := "hikyo 0.2.0-rc.1 (0123456789abcdef, 2026-08-07T07:00:00Z)"
	if got := versionString(); got != want {
		t.Fatalf("versionString() = %q, want %q", got, want)
	}
}

func TestVersionStringMarksDevelopmentBuild(t *testing.T) {
	oldVersion, oldCommit, oldDate := version, commit, buildDate
	t.Cleanup(func() { version, commit, buildDate = oldVersion, oldCommit, oldDate })

	version, commit, buildDate = "dev", "unknown", "unknown"
	if got := versionString(); got != "hikyo dev" {
		t.Fatalf("versionString() = %q, want %q", got, "hikyo dev")
	}
}
