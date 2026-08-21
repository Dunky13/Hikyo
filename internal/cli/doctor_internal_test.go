package cli

import (
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func TestDoctorResultsUseServerWarningsWithoutRecalculation(t *testing.T) {
	effectiveAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	lastPrune := effectiveAt.Add(-time.Hour)
	result, rows := doctorResults(apigen.SamlProviderList{Providers: []apigen.SamlProvider{{
		Slug: "corp",
		Warnings: []apigen.SamlProviderWarning{{
			Code: apigen.MetadataExpired, Severity: apigen.SamlProviderWarningSeverityError,
			Message: "server message", EffectiveAt: effectiveAt,
		}},
	}}}, apigen.RetentionHealth{LastPruneSuccess: &lastPrune, Stale: false, StaleAfterSeconds: 86400}, effectiveAt)
	// Findings: [0] retention-prune, [1] project-storage, [2] the provider error.
	if result.Status != "error" || len(result.Findings) != 3 {
		t.Fatalf("doctor result = %#v", result)
	}
	if got := result.Findings[2]; got.Provider != "corp" || got.Code != "metadata_expired" || got.Message != "server message" {
		t.Fatalf("doctor finding = %#v", got)
	}
	if len(rows) != 3 || rows[2][4] != "server message" {
		t.Fatalf("doctor rows = %#v", rows)
	}
}

func TestDoctorStorageFinding(t *testing.T) {
	const gib = 1 << 30
	tests := []struct {
		name     string
		health   apigen.RetentionHealth
		severity string
		message  string
	}{
		{"empty", apigen.RetentionHealth{PeakProjectBytes: 0, StorageWarn: false}, "ok", "peak project holds 0.0 MiB"},
		{"under", apigen.RetentionHealth{PeakProjectBytes: 512 << 20, StorageWarn: false}, "ok", "peak project holds 512.0 MiB"},
		{"warn", apigen.RetentionHealth{PeakProjectBytes: 3 * gib / 2, StorageWarn: true}, "warn",
			"peak project holds 1.50 GiB, at or over the 1 GiB warn (4 GiB refuses new publishes)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := doctorStorageFinding(tc.health)
			if got.Severity != tc.severity || got.Message != tc.message {
				t.Fatalf("finding = %#v", got)
			}
		})
	}
}

func TestDoctorPruneHealthRows(t *testing.T) {
	now := time.Date(2026, 9, 2, 0, 0, 1, 0, time.UTC)
	old := now.Add(-24*time.Hour - time.Second)
	tests := []struct {
		name    string
		health  apigen.RetentionHealth
		status  string
		message string
	}{
		{"never", apigen.RetentionHealth{Stale: true, StaleAfterSeconds: 86400}, "warn", "never recorded"},
		{"stale", apigen.RetentionHealth{LastPruneSuccess: &old, Stale: true, StaleAfterSeconds: 86400}, "warn", "last_prune_success is 24h0m1s old (> 24h)"},
		{"fresh", apigen.RetentionHealth{LastPruneSuccess: &now, Stale: false, StaleAfterSeconds: 86400}, "ok", "last_prune_success is 0s old"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := doctorPruneFinding(tc.health, now)
			if got.Severity != tc.status || got.Message != tc.message {
				t.Fatalf("finding = %#v", got)
			}
		})
	}
}
