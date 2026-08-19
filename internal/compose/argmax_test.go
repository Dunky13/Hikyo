package compose

import "testing"

func TestExecSizePOSIX(t *testing.T) {
	env := []string{"A=1", "BB=22"}   // (3+1)+(5+1) = 10
	argv := []string{"echo", "hello"} // (4+1)+(5+1) = 11
	total, ok := ExecSizePOSIX(env, argv, 1<<20)
	if total != 21 {
		t.Errorf("total = %d, want 21", total)
	}
	if !ok {
		t.Error("should fit under a 1 MiB limit")
	}
}

func TestExecSizePOSIXRespectsSafetyMargin(t *testing.T) {
	limit := 128 * 1024
	big := make([]byte, limit-argMaxSafetyMargin) // exactly the budget, before the +1 NUL
	if _, ok := ExecSizePOSIX(nil, []string{string(big)}, limit); ok {
		t.Error("arg of exactly budget+1 (with NUL) should be refused")
	}
	small := make([]byte, limit-argMaxSafetyMargin-1)
	if _, ok := ExecSizePOSIX(nil, []string{string(small)}, limit); !ok {
		t.Error("arg one byte under budget should fit")
	}
}

func TestExecSizeWindowsSeparateBudgets(t *testing.T) {
	// A small command line with a huge environment: the command line fits but
	// the environment block does not — the two must be judged separately.
	argv := []string{"app"}
	bigVal := make([]byte, windowsMaxUTF16) // "K=" + this > 32767 units
	env := []string{"K=" + string(bigVal)}
	cmd, envUnits, ok := ExecSizeWindows(env, argv)
	if ok {
		t.Errorf("oversized environment block must be refused (cmd=%d env=%d)", cmd, envUnits)
	}
	if cmd > windowsMaxUTF16 {
		t.Errorf("command line %d should be well under the cap", cmd)
	}
	// A modest pair fits.
	if _, _, ok := ExecSizeWindows([]string{"PATH=/bin"}, []string{"app", "arg"}); !ok {
		t.Error("a modest command should fit both budgets")
	}
}

func TestExecSizeWindowsUTF16SurrogatePairs(t *testing.T) {
	// A non-BMP rune is two UTF-16 units, not one — the count must reflect that.
	argv := []string{"\U0001F600"} // one rune, two UTF-16 units
	cmd, _, _ := ExecSizeWindows(nil, argv)
	// 2 units for the rune + 1 terminating NUL = 3.
	if cmd != 3 {
		t.Errorf("command line units = %d, want 3 (surrogate pair counts as 2 + NUL)", cmd)
	}
}

func TestEscapeArg(t *testing.T) {
	// Vectors matching syscall.EscapeArg: empty→"", spaces force quotes, a bare
	// quote is backslash-escaped, backslashes are only doubled when they precede a
	// quote or the closing quote of a quoted (space-bearing) argument.
	for _, tc := range []struct{ in, want string }{
		{"", `""`},
		{"plain", "plain"},
		{"a b", `"a b"`},
		{`a"b`, `a\"b`},
		{`a\`, `a\`},        // no space, trailing slash NOT doubled
		{`a b\`, `"a b\\"`}, // space → quoted, trailing slash doubled before closing quote
		{`\"`, `\\\"`},      // slash then quote: slash doubled, quote escaped
		{"tab\there", "\"tab\there\""},
	} {
		if got := escapeArg(tc.in); got != tc.want {
			t.Errorf("escapeArg(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestExecSizeWindowsCountsQuoting: an argument with a space gains surrounding
// quotes on the real command line, so counting the RAW argv would undercount.
func TestExecSizeWindowsCountsQuoting(t *testing.T) {
	argv := []string{"a b"} // command line becomes `"a b"` = 5 units + NUL = 6
	cmd, _, _ := ExecSizeWindows(nil, argv)
	if cmd != 6 {
		t.Errorf("command line units = %d, want 6 (quoted `\"a b\"` + NUL)", cmd)
	}
}

func TestExecPreflight(t *testing.T) {
	if ok, detail := ExecPreflight([]string{"A=1"}, []string{"echo"}, DefaultArgMax()); !ok {
		t.Errorf("small command refused: %s", detail)
	}
}

func TestDefaultArgMaxPositive(t *testing.T) {
	if DefaultArgMax() <= 0 {
		t.Fatal("DefaultArgMax must be positive")
	}
}
