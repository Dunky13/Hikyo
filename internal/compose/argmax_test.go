package compose

import "testing"

func TestExecSizeOK(t *testing.T) {
	env := []string{"A=1", "BB=22"}   // (3+1)+(5+1) = 10
	argv := []string{"echo", "hello"} // (4+1)+(5+1) = 11
	total, ok := ExecSizeOK(env, argv, 1<<20)
	if total != 21 {
		t.Errorf("total = %d, want 21", total)
	}
	if !ok {
		t.Error("should fit under a 1 MiB limit")
	}
}

func TestExecSizeOKRespectsSafetyMargin(t *testing.T) {
	// A single arg just over (limit - 64 KiB) must be refused.
	limit := 128 * 1024
	big := make([]byte, limit-argMaxSafetyMargin) // exactly the budget, before the +1 NUL
	_, ok := ExecSizeOK(nil, []string{string(big)}, limit)
	if ok {
		t.Error("arg of exactly budget+1 (with NUL) should be refused")
	}
	// One byte smaller fits.
	small := make([]byte, limit-argMaxSafetyMargin-1)
	if _, ok := ExecSizeOK(nil, []string{string(small)}, limit); !ok {
		t.Error("arg one byte under budget should fit")
	}
}

func TestDefaultArgMaxPositive(t *testing.T) {
	if DefaultArgMax() <= 0 {
		t.Fatal("DefaultArgMax must be positive")
	}
}
