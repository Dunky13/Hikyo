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

const module = "github.com/Hikyo-Org/hikyo"

// ImportConfinement declares the packages that may import one or more external
// dependency module paths. DependencyPrefixes match either the module path
// itself or a subpackage path, never a merely similar string.
type ImportConfinement struct {
	Name               string
	DependencyPrefixes []string
	AllowedImporters   []string
}

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
	module + "/internal/store/auditrow":  true, // shared audit Row→params mapping
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

// protocolImportConfinements checks the actual third-party libraries, not the
// Hikyo wrappers that consume them. The human-auth ADR owns OIDC, OAuth2, and
// WebAuthn confinement; the machine-identities ADR owns oidcfed's direct OIDC
// verifier; the saml-sp ADR owns SAML/XML-DSIG; and the import-paths ADR owns
// SOPS. Exceptions are exact package paths: oidcfed verifies workload OIDC
// tokens directly, while samltest is the signed IdP fixture harness. Generated
// files receive no exception; go list includes their production imports, and
// allImports adds both internal and external test imports to the same check.
var protocolImportConfinements = []ImportConfinement{
	{
		Name:               "OIDC",
		DependencyPrefixes: []string{"github.com/coreos/go-oidc/v3"},
		AllowedImporters: []string{
			module + "/internal/oidcrp",
			module + "/internal/oidcfed", // workload-identity verifier (#45)
		},
	},
	{
		Name:               "OAuth2",
		DependencyPrefixes: []string{"golang.org/x/oauth2"},
		AllowedImporters:   []string{module + "/internal/oidcrp"},
	},
	{
		Name:               "WebAuthn",
		DependencyPrefixes: []string{"github.com/go-webauthn/webauthn"},
		AllowedImporters:   []string{module + "/internal/webauthnrp"},
	},
	{
		Name: "SAML/XML-DSIG",
		DependencyPrefixes: []string{
			"github.com/russellhaering/gosaml2",
			"github.com/russellhaering/goxmldsig",
			"github.com/mattermost/xml-roundtrip-validator",
		},
		AllowedImporters: []string{
			module + "/internal/samlsp",
			module + "/internal/samltest", // signed-IdP fixture harness (tests only)
		},
	},
	{
		Name:               "SOPS",
		DependencyPrefixes: []string{"github.com/getsops/sops/v3"},
		AllowedImporters:   []string{module + "/internal/importer"},
	},
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

// Crypto chokepoint (encryption-model ADR CI invariant 12, placed by the
// system-architecture ADR § Encryption boundary): no import of a
// cryptographic primitive package outside the envelope package, and age
// nowhere outside the backup package. crypto/sha256 and crypto/subtle stay
// unrestricted — hashing verifiers is not envelope encryption.
var cryptoPrimitiveImporters = map[string]bool{
	module + "/internal/crypto": true,
	// internal/crypto/backup imports no primitive of its own: the age
	// container is the whole of its cryptography (#76), so it stays off this
	// list and appears only on the age allowlist below.
}

var cryptoPrimitivePrefixes = []string{
	"golang.org/x/crypto/",
	"crypto/cipher",
	"crypto/aes",
	"crypto/hkdf",
	"crypto/hmac",
}

var ageImporters = map[string]bool{
	module + "/internal/crypto/backup": true, // sole age importer (#76)
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

type confinementViolation struct {
	Importer   string
	Dependency string
}

func matchesDependencyPrefix(importPath, dependencyPrefix string) bool {
	return importPath == dependencyPrefix || strings.HasPrefix(importPath, dependencyPrefix+"/")
}

func importerAllowed(importPath string, allowedImporters []string) bool {
	for _, allowedImporter := range allowedImporters {
		if importPath == allowedImporter {
			return true
		}
	}
	return false
}

func confinementViolations(confinement ImportConfinement, packages []pkg) []confinementViolation {
	var violations []confinementViolation
	for _, p := range packages {
		for _, imp := range allImports(p) {
			for _, dependencyPrefix := range confinement.DependencyPrefixes {
				if matchesDependencyPrefix(imp, dependencyPrefix) && !importerAllowed(p.ImportPath, confinement.AllowedImporters) {
					violations = append(violations, confinementViolation{Importer: p.ImportPath, Dependency: imp})
				}
			}
		}
	}
	return violations
}

func TestProtocolImportConfinementMatchers(t *testing.T) {
	const forbiddenImporter = module + "/internal/boundaryfixture"

	for _, confinement := range protocolImportConfinements {
		t.Run(confinement.Name, func(t *testing.T) {
			for _, dependencyPrefix := range confinement.DependencyPrefixes {
				t.Run(dependencyPrefix, func(t *testing.T) {
					allowedImporter := confinement.AllowedImporters[0]
					forbiddenSubpackageImporter := forbiddenImporter + "/subpackage"
					forbiddenSubpackage := dependencyPrefix + "/subpkg"
					packages := []pkg{
						{ImportPath: forbiddenImporter, Imports: []string{dependencyPrefix}},
						{ImportPath: forbiddenSubpackageImporter, TestImports: []string{forbiddenSubpackage}},
						{ImportPath: allowedImporter, XTestImports: []string{forbiddenSubpackage}},
						{ImportPath: forbiddenImporter, XTestImports: []string{dependencyPrefix + "-unrelated/subpkg"}},
					}

					violations := confinementViolations(confinement, packages)
					if len(violations) != 2 {
						t.Fatalf("got %d violations, want 2: %v", len(violations), violations)
					}
					if violations[0].Importer != forbiddenImporter || violations[0].Dependency != dependencyPrefix {
						t.Fatalf("got violation %+v, want importer %s and dependency %s", violations[0], forbiddenImporter, dependencyPrefix)
					}
					if violations[1].Importer != forbiddenSubpackageImporter || violations[1].Dependency != forbiddenSubpackage {
						t.Fatalf("got violation %+v, want importer %s and dependency %s", violations[1], forbiddenSubpackageImporter, forbiddenSubpackage)
					}
				})
			}
		})
	}
}

func TestStoreImportAllowlist(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, imp := range allImports(p) {
			if matchesDependencyPrefix(imp, module+"/internal/store") {
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
			if matchesDependencyPrefix(imp, "filippo.io/age") && !ageImporters[p.ImportPath] {
				t.Errorf("%s imports %s: age is confined to internal/crypto/backup", p.ImportPath, imp)
			}
		}
	}
}

// TestProtocolLibraryImportConfinement executes every declarative protocol
// dependency rule through the same go-list import graph walker.
func TestProtocolLibraryImportConfinement(t *testing.T) {
	packages := loadPackages(t)
	for _, confinement := range protocolImportConfinements {
		t.Run(confinement.Name, func(t *testing.T) {
			for _, violation := range confinementViolations(confinement, packages) {
				t.Errorf("%s imports %s: %s dependencies are confined to %s", violation.Importer, violation.Dependency, confinement.Name, strings.Join(confinement.AllowedImporters, ", "))
			}
		})
	}
}

// scanningHashPrimitivePrefixes are the hash/HMAC primitives the runtime
// secret-scanning code must never import (secret-scanning ADR §4, SS4): the
// value fingerprint is a keyed digest computed inside internal/crypto under the
// dedicated tier-3 scanning key, and the scanning package "never touches a hash
// or HMAC primitive itself". crypto/hmac and golang.org/x/crypto are already
// banned everywhere but internal/crypto by the crypto chokepoint above; what
// SS4 adds is the SHA family (crypto/sha256 is deliberately unrestricted
// globally — see the chokepoint comment), so this is a separate path-scoped ban.
var scanningHashPrimitivePrefixes = []string{
	"crypto/sha256",
	"crypto/sha512",
	"crypto/sha1",
	"crypto/hmac",
	"golang.org/x/crypto/",
}

// TestScanningNoHashPrimitives enforces SS4 on the RUNTIME scanning code. Two
// deliberate scopes:
//   - PRODUCTION imports only (p.Imports): a test that verifies a vendored-file
//     hash or independently recomputes crypto's fingerprint for a known-answer
//     assertion is not runtime scanning code computing its own digest, and the
//     global hmac/x-crypto ban already covers tests.
//   - the build-time rule generator (internal/scanning/gen) is excluded: the
//     seam computes the per-rule semantic digest with SHA-256 AT GENERATION TIME
//     and emits it as string constants precisely so the runtime package imports
//     no hash primitive. Banning the generator would forbid the very mechanism
//     that keeps the runtime clean.
//
// The check applies only when internal/scanning exists (a parallel stream
// authors it and it may be absent at first) and does not fail on its absence.
func TestScanningNoHashPrimitives(t *testing.T) {
	scanning := module + "/internal/scanning"
	generator := scanning + "/gen"
	saw := false
	for _, p := range loadPackages(t) {
		if p.ImportPath != scanning && !strings.HasPrefix(p.ImportPath, scanning+"/") {
			continue
		}
		if p.ImportPath == generator || strings.HasPrefix(p.ImportPath, generator+"/") {
			continue
		}
		saw = true
		for _, imp := range p.Imports {
			for _, prefix := range scanningHashPrimitivePrefixes {
				if imp == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(imp, prefix) {
					t.Errorf("%s imports %s: runtime scanning code must not touch a hash/HMAC primitive — the fingerprint is computed inside internal/crypto and rule digests are generation-time constants (SS4)", p.ImportPath, imp)
				}
			}
		}
	}
	if !saw {
		t.Log("internal/scanning not present yet; the hash-primitive ban applies once it exists")
	}
}

func TestForbiddenEdges(t *testing.T) {
	for _, p := range loadPackages(t) {
		for _, rule := range forbidden {
			if !strings.HasPrefix(p.ImportPath, rule.importer) {
				continue
			}
			for _, imp := range allImports(p) {
				// An external test package (`package foo_test`) importing the
				// package under test is not a dependency edge — it is the
				// same package seen from outside, and counting it would make
				// every leaf package unable to have a black-box test.
				if imp == p.ImportPath {
					continue
				}
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
		// The audit vocabulary (leaf) and the shared Row→params mapping, for
		// the denial writer — one of the surface's pinned write paths (audit-model
		// ADR amendment part 4).
		module + "/internal/audit":          true,
		module + "/internal/store/auditrow": true,
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
