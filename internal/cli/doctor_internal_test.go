package cli

import (
	"testing"
	"time"

	"github.com/Dunky13/wenv/api/apigen"
)

func TestDoctorResultsUseServerWarningsWithoutRecalculation(t *testing.T) {
	effectiveAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	result, rows := doctorResults(apigen.SamlProviderList{Providers: []apigen.SamlProvider{{
		Slug: "corp",
		Warnings: []apigen.SamlProviderWarning{{
			Code: apigen.MetadataExpired, Severity: apigen.SamlProviderWarningSeverityError,
			Message: "server message", EffectiveAt: effectiveAt,
		}},
	}}})
	if result.Status != "error" || len(result.Findings) != 1 {
		t.Fatalf("doctor result = %#v", result)
	}
	if got := result.Findings[0]; got.Provider != "corp" || got.Code != "metadata_expired" || got.Message != "server message" {
		t.Fatalf("doctor finding = %#v", got)
	}
	if len(rows) != 1 || rows[0][4] != "server message" {
		t.Fatalf("doctor rows = %#v", rows)
	}
}
