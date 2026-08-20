package scanning

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// TestVendoringRecord is part of SS1: the vendoring record is complete and
// matches the committed snapshot — the pinned SHA-256 of the gitleaks TOML and
// the retained MIT LICENSE equal the files actually in the tree, so a silent
// edit of either fails here. (Computing the digest in a _test.go file is fine;
// the runtime package still imports no hash primitive — see TestNoHashPrimitiveImport.)
func TestVendoringRecord(t *testing.T) {
	if gitleaksUpstream == "" || gitleaksTag == "" || gitleaksCommit == "" || gitleaksSourcePath == "" {
		t.Fatal("vendoring record incomplete")
	}
	if len(gitleaksCommit) != 40 {
		t.Fatalf("gitleaks commit %q is not a 40-char sha", gitleaksCommit)
	}

	assertFileSHA(t, "rules/vendor/gitleaks.toml", vendorTOMLSHA256)
	assertFileSHA(t, "rules/vendor/LICENSE", vendorLicenseSHA256)
}

func assertFileSHA(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s sha256 = %s; pinned %s", path, got, want)
	}
}
