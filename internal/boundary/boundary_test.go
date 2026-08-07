// Package boundary enforces the import direction fixed in the
// system-architecture ADR: internal/store is importable only by
// internal/service (and store's own subpackages plus the wiring layer);
// handlers never import store; store never imports upward.
package boundary

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/Dunky13/wenv"

// storeImporters is the exact allowlist of packages permitted to import
// internal/store or its subpackages. Additions here are architecture
// decisions, not conveniences.
var storeImporters = map[string]bool{
	module + "/internal/service":         true,
	module + "/internal/app":             true, // construction wiring only
	module + "/internal/authz":           true, // the resolution surface (store/authn) only — see authnImporters
	module + "/internal/store":           true,
	module + "/internal/store/authn":     true,
	module + "/internal/store/tx":        true,
	module + "/internal/store/migrate":   true,
	module + "/internal/store/keyring":   true, // crypto.KeyStore implementation
	module + "/internal/store/sqlitegen": true,
	module + "/internal/store/pggen":     true,
	module + "/internal/conformance":     true, // cross-engine test harness
	module + "/internal/isolation":       true, // probe harness (#44)
}

// authnImporters is the stricter allowlist for the authorization package's
// resolution surface (tenant-isolation ADR § bootstrap carve-out): the reads
// authorize() needs in order to mint a proof. Only the authorization package
// consumes it and only the transaction package constructs it (per
// transaction attempt); the isolation probe harness instruments it in tests.
var authnImporters = map[string]bool{
	module + "/internal/authz":       true,
	module + "/internal/store/authn": true,
	module + "/internal/store/tx":    true,
	module + "/internal/isolation":   true, // query-count instrumentation (tests only)
}

// forbidden direct edges: importer prefix -> banned import prefix.
var forbidden = []struct{ importer, imports, why string }{
	{module + "/internal/server", module + "/internal/store", "handlers cannot reach the datastore directly"},
	{module + "/internal/server", module + "/internal/authz", "handlers extract artifacts only; authorization happens in the service transaction"},
	{module + "/internal/authz", module + "/internal/service", "the chokepoint never imports upward"},
	{module + "/internal/authz", module + "/internal/server", "the chokepoint never imports the HTTP layer"},
	{module + "/internal/service", module + "/internal/store/pggen", "generated queries take chain values as plain arguments: go through the store's proof-bound binding layer"},
	{module + "/internal/service", module + "/internal/store/sqlitegen", "generated queries take chain values as plain arguments: go through the store's proof-bound binding layer"},
	{module + "/internal/store", module + "/internal/service", "dependency direction is service→store"},
	{module + "/internal/store", module + "/internal/server", "store never imports the HTTP layer"},
	{module + "/cmd/", module + "/internal/store", "main wires through internal/app, not store"},
	{module + "/internal/config", module + "/internal/", "config is a leaf package"},
	{module + "/internal/crypto", module + "/internal/", "crypto is a leaf package: persistence arrives through its KeyStore interface"},
}

// Crypto chokepoint (encryption ADR CI invariant 12, placed by the
// system-architecture ADR § Encryption boundary): no import of a
// cryptographic primitive package outside the envelope package, and age
// nowhere outside the backup package. crypto/sha256 and crypto/subtle stay
// unrestricted — hashing verifiers is not envelope encryption.
var cryptoPrimitiveImporters = map[string]bool{
	module + "/internal/crypto": true,
	// internal/crypto/backup joins when the backup ticket lands.
}

var cryptoPrimitivePrefixes = []string{
	"golang.org/x/crypto/",
	"crypto/cipher",
	"crypto/aes",
	"crypto/hkdf",
	"crypto/hmac",
}

var ageImporters = map[string]bool{
	module + "/internal/crypto/backup": true, // sole age importer, future ticket
}

type pkg struct {
	ImportPath   string
	Imports      []string
	TestImports  []string
	XTestImports []string
}

func loadPackages(t *testing.T) []pkg {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", module+"/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}
	return pkgs
}

// allImports covers production and test imports alike — a test file in
// internal/server reaching into store is the same boundary breach.
func allImports(p pkg) []string {
	out := make([]string, 0, len(p.Imports)+len(p.TestImports)+len(p.XTestImports))
	out = append(out, p.Imports...)
	out = append(out, p.TestImports...)
	out = append(out, p.XTestImports...)
	return out
}

func TestStoreImportAllowlist(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, imp := range allImports(p) {
			if imp == module+"/internal/store" || strings.HasPrefix(imp, module+"/internal/store/") {
				if !storeImporters[p.ImportPath] {
					t.Errorf("%s imports %s: not on the store-importer allowlist", p.ImportPath, imp)
				}
			}
		}
	}
}

func TestCryptoChokepoint(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, imp := range allImports(p) {
			for _, prefix := range cryptoPrimitivePrefixes {
				if strings.HasPrefix(imp, prefix) && !cryptoPrimitiveImporters[p.ImportPath] {
					t.Errorf("%s imports %s: cryptographic primitives are confined to internal/crypto", p.ImportPath, imp)
				}
			}
			if (imp == "filippo.io/age" || strings.HasPrefix(imp, "filippo.io/age/")) && !ageImporters[p.ImportPath] {
				t.Errorf("%s imports %s: age is confined to internal/crypto/backup", p.ImportPath, imp)
			}
		}
	}
}

func TestForbiddenEdges(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, rule := range forbidden {
			if !strings.HasPrefix(p.ImportPath, rule.importer) {
				continue
			}
			for _, imp := range allImports(p) {
				if strings.HasPrefix(imp, rule.imports) {
					t.Errorf("%s imports %s: %s", p.ImportPath, imp, rule.why)
				}
			}
		}
	}
}

// TestAuthnImportAllowlist enforces the resolution surface's boundary in
// both directions: only the packages on authnImporters may import it, and it
// itself builds on generated queries and the domain vocabulary only — never
// the repository layer (which would create a cycle through authz) and never
// anything upward.
func TestAuthnImportAllowlist(t *testing.T) {
	authn := module + "/internal/store/authn"
	allowedImports := map[string]bool{
		module + "/internal/domain":          true,
		module + "/internal/store/sqlitegen": true,
		module + "/internal/store/pggen":     true,
		// The audit vocabulary (leaf), for the denial writer — the surface's
		// single write path (audit-model ADR amendment part 4).
		module + "/internal/audit": true,
	}
	for _, p := range loadPackages(t) {
		for _, imp := range allImports(p) {
			if imp == authn && !authnImporters[p.ImportPath] {
				t.Errorf("%s imports %s: not on the authn-importer allowlist", p.ImportPath, imp)
			}
			if p.ImportPath == authn && strings.HasPrefix(imp, module+"/") && !allowedImports[imp] {
				t.Errorf("%s imports %s: the resolution surface builds on generated queries and domain only", p.ImportPath, imp)
			}
		}
	}
}
