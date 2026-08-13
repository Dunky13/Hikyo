package server

import (
	"errors"
	"testing"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
)

func TestWorkspaceAdmissionChargesTheSharedPreAuthBudget(t *testing.T) {
	limiter, err := admission.New(admission.Config{
		BudgetMiB:      admission.DefaultBudgetMiB,
		ArgonMemoryKiB: 64 * 1024,
		PerIPPerMinute: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := API{Admission: limiter}
	ctx := audit.WithContext(t.Context(), audit.Context{SourceIP: "192.0.2.1"})
	release, err := api.enterWorkspaceAdmission(ctx)
	if err != nil {
		t.Fatalf("first handoff admission: %v", err)
	}
	release()
	if _, err := api.enterWorkspaceAdmission(ctx); !errors.Is(err, admission.ErrOverloaded) {
		t.Fatalf("second handoff admission = %v, want ErrOverloaded", err)
	}
}
