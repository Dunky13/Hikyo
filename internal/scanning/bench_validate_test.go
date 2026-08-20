package scanning

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/scanning/bench"
)

const piArtifactPath = "testdata/bench/pi-result.json"

// TestPiBenchArtifact is the executable form of the *(measured)* gate (ADR §7,
// SS1): the committed Pi-class bench-scan artifact must parse, match the pinned
// harness and ruleset snapshot versions, and report p99 ≤ 5 ms per item at the
// 64 KiB cap with boot compile ≤ 2 s.
//
// The artifact is produced on Pi-class hardware in a later phase and must NOT be
// fabricated. Until it exists this test FAILS by design with a clear message —
// a named blocking leftover, never a silent skip.
func TestPiBenchArtifact(t *testing.T) {
	data, err := os.ReadFile(piArtifactPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Pi artifact missing — produce with cmd/bench-scan on Pi-class hardware and commit it at %s", piArtifactPath)
	}
	if err != nil {
		t.Fatalf("read Pi artifact: %v", err)
	}

	var res bench.Result
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("parse Pi artifact %s: %v", piArtifactPath, err)
	}

	if res.HarnessVersion != bench.HarnessVersion {
		t.Errorf("harness version %q != current %q — regenerate the artifact", res.HarnessVersion, bench.HarnessVersion)
	}
	if want := mustLoad(t).SnapshotVersion(); res.SnapshotVersion != want {
		t.Errorf("artifact snapshot %q != current ruleset %q — regenerate the artifact", res.SnapshotVersion, want)
	}
	if res.ItemBytes != 64*1024 {
		t.Errorf("artifact item bytes %d; want the 64 KiB size cap", res.ItemBytes)
	}
	if res.P99Millis > 5 {
		t.Errorf("p99 %.3fms exceeds the 5 ms per-item budget", res.P99Millis)
	}
	if res.BootCompileMillis > 2000 {
		t.Errorf("boot compile %.1fms exceeds the 2 s budget", res.BootCompileMillis)
	}
	// ADR §7 boot bound: ≤ 32 MiB. Require a nonzero measurement — a silently
	// absent one passing the gate is the fail-open shape the ADR forbids (the
	// Pi is linux, where Getrusage populates ru_maxrss).
	const maxBootRSS = 32 * 1024 * 1024
	if res.BootPeakRSSBytes <= 0 {
		t.Errorf("boot peak RSS not measured (%d) — the artifact must carry it", res.BootPeakRSSBytes)
	} else if res.BootPeakRSSBytes > maxBootRSS {
		t.Errorf("boot peak RSS %d bytes exceeds the 32 MiB budget", res.BootPeakRSSBytes)
	}
}
