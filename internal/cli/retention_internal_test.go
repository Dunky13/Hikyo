package cli

import (
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func TestOrgRetentionRequestModes(t *testing.T) {
	bounded, err := orgRetentionRequest("720h", 7, false)
	if err != nil {
		t.Fatal(err)
	}
	if bounded.Mode != apigen.RetentionPolicyModeKeepIfEither || bounded.MaxAgeSeconds == nil || *bounded.MaxAgeSeconds != 2592000 || bounded.LastRevisions == nil || *bounded.LastRevisions != 7 {
		t.Fatalf("bounded request = %#v", bounded)
	}
	unlimited, err := orgRetentionRequest("", 0, true)
	if err != nil || unlimited.Mode != apigen.RetentionPolicyModeUnlimited {
		t.Fatalf("unlimited request = %#v, %v", unlimited, err)
	}
	if _, err := orgRetentionRequest("1h", 1, true); err == nil {
		t.Fatal("unlimited and bounded flags were accepted together")
	}
}

func TestProjectRetentionRequestModes(t *testing.T) {
	bounded, err := projectRetentionRequest("24h", 3, false)
	if err != nil {
		t.Fatal(err)
	}
	if bounded.Inherited || bounded.MaxAgeSeconds == nil || *bounded.MaxAgeSeconds != 86400 || bounded.LastRevisions == nil || *bounded.LastRevisions != 3 {
		t.Fatalf("bounded request = %#v", bounded)
	}
	inherited, err := projectRetentionRequest("", 0, true)
	if err != nil || !inherited.Inherited {
		t.Fatalf("inherited request = %#v, %v", inherited, err)
	}
	if _, err := projectRetentionRequest("500ms", 1, false); err == nil {
		t.Fatal("sub-second duration was accepted")
	}
}
