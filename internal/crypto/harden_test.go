package crypto

import (
	"syscall"
	"testing"
)

func TestHardenProcess(t *testing.T) {
	if err := HardenProcess(); err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Errorf("RLIMIT_CORE = %d/%d, want 0/0", lim.Cur, lim.Max)
	}
}
