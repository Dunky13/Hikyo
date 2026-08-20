// Command bench-scan measures the secret scanner against the fixture corpus:
// per-item latency distribution (p50/p99) at the 64 KiB size cap, boot-compile
// (Load) duration, and peak RSS where cheaply obtainable. It emits a JSON
// artifact embedding the harness version and the ruleset snapshot version.
//
// The absolute-ms gate is a property of Pi-class hardware (ADR §7); this binary
// produces the artifact the scanning validation test checks. `-check` runs the
// same measurement and prints the result without any absolute-ms assertion, for
// CI use as a relative regression guard.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/scanning"
	"github.com/Hikyo-Org/hikyo/internal/scanning/bench"
	"github.com/Hikyo-Org/hikyo/internal/scanning/corpus"
)

// itemBytes is the per-item scanned bytes cap (ADR §7): the 64 KiB value /
// declaration size cap. Each corpus item is padded to this size so the latency
// distribution is measured at the cap, where the p99 gate is defined.
const itemBytes = 64 * 1024

func main() {
	out := flag.String("o", "", "write the JSON result artifact to this path (default stdout)")
	check := flag.Bool("check", false, "run as a relative regression guard: measure and print, no absolute-ms assertion")
	host := flag.String("host", "", "host label recorded in the artifact (e.g. pi4-4gb)")
	flag.Parse()

	res, err := measure(*host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench-scan:", err)
		os.Exit(1)
	}

	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench-scan:", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if *check {
		fmt.Printf("bench-scan: %d items @ %d bytes, boot %.2fms, p50 %.3fms, p99 %.3fms\n",
			res.Items, res.ItemBytes, res.BootCompileMillis, res.P50Millis, res.P99Millis)
		return
	}
	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "bench-scan:", err)
		os.Exit(1)
	}
	fmt.Printf("bench-scan: wrote %s\n", *out)
}

func measure(host string) (bench.Result, error) {
	bootStart := time.Now()
	rs, err := scanning.Load()
	bootMillis := float64(time.Since(bootStart).Microseconds()) / 1000
	bootRSS := peakRSSBytes() // startup + compile, before any scan
	if err != nil {
		return bench.Result{}, fmt.Errorf("load ruleset: %w", err)
	}

	items, err := corpusItems()
	if err != nil {
		return bench.Result{}, err
	}

	ctx := context.Background()
	latencies := make([]float64, 0, len(items))
	for _, item := range items {
		start := time.Now()
		if _, err := rs.Scan(ctx, item); err != nil {
			return bench.Result{}, fmt.Errorf("scan: %w", err)
		}
		latencies = append(latencies, float64(time.Since(start).Microseconds())/1000)
	}

	if host == "" {
		host = runtime.GOOS + "/" + runtime.GOARCH
	}
	return bench.Result{
		HarnessVersion:    bench.HarnessVersion,
		SnapshotVersion:   rs.SnapshotVersion(),
		Host:              host,
		Items:             len(items),
		ItemBytes:         itemBytes,
		BootCompileMillis: bootMillis,
		BootPeakRSSBytes:  bootRSS,
		P50Millis:         bench.Percentile(latencies, 50),
		P99Millis:         bench.Percentile(latencies, 99),
		PeakRSSBytes:      peakRSSBytes(),
	}, nil
}

// corpusItems pads every corpus TP and FP to the size cap, planting the
// credential near the end so the scan traverses the full buffer.
func corpusItems() ([][]byte, error) {
	fixtures, err := corpus.All()
	if err != nil {
		return nil, err
	}
	// Benign filler that contains no rule keyword, sized to exceed the cap.
	const phrase = "the quick brown fox jumps over the lazy dog. "
	filler := strings.Repeat(phrase, itemBytes/len(phrase)+1)
	var items [][]byte
	for _, f := range fixtures {
		for _, s := range append(append([]string{}, f.TP...), f.FP...) {
			items = append(items, pad(filler, s))
		}
	}
	return items, nil
}

func pad(filler, credential string) []byte {
	if len(credential) >= itemBytes {
		return []byte(credential[:itemBytes])
	}
	head := itemBytes - len(credential)
	return []byte(filler[:head] + credential)
}

// peakRSSBytes returns the process peak resident set size in bytes, or 0 if not
// available. ru_maxrss is bytes on darwin and KiB on linux.
func peakRSSBytes() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	max := int64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		return max * 1024
	}
	return max
}
