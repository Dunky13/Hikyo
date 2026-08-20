// Package bench is the schema shared by cmd/bench-scan (which writes the result
// artifact) and the scanning validation test (which parses it). One struct, no
// drift between producer and consumer.
package bench

import "sort"

// HarnessVersion is bumped when the measurement method or the artifact schema
// changes, so a stale artifact fails the version match in the validation test.
const HarnessVersion = "1"

// Result is the JSON artifact emitted by cmd/bench-scan. Durations are in
// milliseconds. PeakRSSBytes is 0 when not cheaply obtainable; PeakRSSUnit
// records the platform meaning of the raw ru_maxrss value the run observed.
type Result struct {
	HarnessVersion    string  `json:"harness_version"`
	SnapshotVersion   string  `json:"snapshot_version"`
	Host              string  `json:"host"`
	Items             int     `json:"items"`
	ItemBytes         int     `json:"item_bytes"`
	BootCompileMillis float64 `json:"boot_compile_millis"`
	// BootPeakRSSBytes is peak RSS captured immediately after Load, i.e.
	// startup + ruleset compile, the ADR §7 ≤ 32 MiB boot bound.
	BootPeakRSSBytes int64   `json:"boot_peak_rss_bytes"`
	P50Millis        float64 `json:"p50_millis"`
	P99Millis        float64 `json:"p99_millis"`
	// PeakRSSBytes is peak RSS at the end of the run (informational — it
	// conflates compile and scan memory).
	PeakRSSBytes int64 `json:"peak_rss_bytes"`
}

// Percentile returns the p-th percentile (0..100) of durations in
// milliseconds, using nearest-rank on a copy. Returns 0 for an empty input.
func Percentile(millis []float64, p float64) float64 {
	if len(millis) == 0 {
		return 0
	}
	sorted := append([]float64(nil), millis...)
	sort.Float64s(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	rank := int((p/100)*float64(len(sorted)-1) + 0.5)
	return sorted[rank]
}
