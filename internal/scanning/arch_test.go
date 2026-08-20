package scanning

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoHashPrimitiveImport enforces SS4 locally: the runtime scanning package
// imports no hash/HMAC/sha primitive. Semantic digests and the snapshot version
// are computed at generation and embedded as constants; runtime never hashes.
// (Stream B's boundary test is the authoritative sweep; this is a fast local
// guard so a regression fails inside this package's own suite.)
func TestNoHashPrimitiveImport(t *testing.T) {
	banned := []string{"crypto/sha256", "crypto/sha1", "crypto/sha512", "crypto/md5", "crypto/hmac", "hash", "hash/crc32", "hash/fnv"}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, b := range banned {
				if path == b {
					t.Errorf("%s imports banned hash primitive %q (SS4: runtime must not hash)", name, path)
				}
			}
		}
	}
}
