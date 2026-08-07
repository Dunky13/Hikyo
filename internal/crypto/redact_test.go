package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// The A6 formatting-surface coverage test: each of String / GoString /
// LogValue / MarshalText / MarshalJSON is exercised against a PLANTED
// secret, and the output must carry the marker and never the material —
// in raw, hex or JSON-escaped form. fmt's reflective struct printing is
// exactly what these surfaces exist to intercept.
func TestRedactionSurfacesAgainstPlantedSecret(t *testing.T) {
	planted := []byte("PLANTED-SECRET-0123456789abcdef01")
	kr := &Keyring{
		master:   keyHandle{id: "master", version: 1, key: planted},
		instance: keyHandle{id: "dek-instance", version: 1, key: planted},
		token:    keyHandle{id: "token-root", version: 1, key: planted},
	}
	sealers := map[string]any{
		"keyring":         kr,
		"project sealer":  &ProjectSealer{kr: kr, orgID: "o", projectID: "p", dek: keyHandle{id: "dek", key: planted}},
		"instance sealer": &InstanceSealer{kr: kr},
		"key handle":      keyHandle{id: "h", key: planted},
		"dek entry":       dekEntry{scope: "s", handle: keyHandle{id: "h", key: planted}},
	}

	leaks := []string{
		string(planted),
		hex.EncodeToString(planted),
		fmt.Sprintf("%v", planted), // the byte-slice decimal dump reflection would print
	}
	assertClean := func(name, surface, out string) {
		t.Helper()
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s: %s output %q does not carry the redaction marker", name, surface, out)
		}
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Errorf("%s: %s leaks the planted secret: %q", name, surface, out)
			}
		}
	}

	for name, v := range sealers {
		assertClean(name, "%v", fmt.Sprintf("%v", v))
		assertClean(name, "%s", fmt.Sprintf("%s", v))
		assertClean(name, "%#v", fmt.Sprintf("%#v", v))
		assertClean(name, "%+v", fmt.Sprintf("%+v", v))

		lv, ok := v.(slog.LogValuer)
		if !ok {
			t.Fatalf("%s: not a slog.LogValuer", name)
		}
		assertClean(name, "LogValue", lv.LogValue().String())

		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", name, err)
		}
		assertClean(name, "MarshalJSON", string(b))

		tm, ok := v.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatalf("%s: no MarshalText", name)
		}
		tb, err := tm.MarshalText()
		if err != nil {
			t.Fatalf("%s: MarshalText: %v", name, err)
		}
		assertClean(name, "MarshalText", string(tb))
	}
}
