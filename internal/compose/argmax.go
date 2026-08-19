package compose

import "unicode/utf16"

// ARG_MAX preflight for `hikyo run --` (compose-integration ADR /
// ops-spec § 6: "the client sums the rendered environment, the inherited
// environment, and argv against the runtime limit … minus a 64 KiB safety
// margin and refuses loud pre-exec"). E2BIG at exec time is the wrong layer to
// discover this — the per-value cap bounds one string, not the composite.
//
// The two platforms count DIFFERENT things and must not share one formula:
//   - POSIX: the kernel counts the combined argv+envp region as bytes
//     (name=value plus a NUL per string), against _SC_ARG_MAX minus a 64 KiB
//     margin (the kernel also spends space on pointer arrays and alignment).
//   - Windows: CreateProcess caps the command line and the environment block
//     SEPARATELY, each at 32767 UTF-16 code units, and there is no equivalent
//     margin. Counting UTF-8 bytes against one combined limit — the previous
//     shared code — refused every Windows invocation.
//
// Both size functions are PURE and exported so the Windows logic is testable on
// any OS; ExecPreflight is the build-tagged entry the CLI calls.

// argMaxSafetyMargin is subtracted from the POSIX limit: the kernel also counts
// pointer arrays and alignment, so the usable budget is smaller than
// _SC_ARG_MAX (ops-spec § 6: "minus a 64 KiB safety margin").
const argMaxSafetyMargin = 64 * 1024

// conservativeArgMax is the POSIX fallback when the platform limit cannot be read.
const conservativeArgMax = 128 * 1024

// windowsMaxUTF16 is the CreateProcess cap on BOTH the command line and the
// environment block, in UTF-16 code units.
const windowsMaxUTF16 = 32767

// ExecSizePOSIX sums len(entry)+1 over env and len(arg)+1 over argv — the
// per-string NUL the kernel counts — and reports whether the total fits within
// argMax - 64 KiB. It returns the computed total so the caller can name the
// overage.
func ExecSizePOSIX(env, argv []string, argMax int) (total int, ok bool) {
	for _, e := range env {
		total += len(e) + 1
	}
	for _, a := range argv {
		total += len(a) + 1
	}
	return total, total <= argMax-argMaxSafetyMargin
}

// ExecSizeWindows counts the command line and the environment block in UTF-16
// code units the way CreateProcess does, and reports whether EACH fits under
// 32767 (no margin). The command line is argv joined by single spaces plus a
// terminating NUL; the environment block is each "name=value\0" plus a final
// terminating NUL.
func ExecSizeWindows(env, argv []string) (cmdlineUnits, envUnits int, ok bool) {
	for i, a := range argv {
		if i > 0 {
			cmdlineUnits++ // separating space
		}
		cmdlineUnits += utf16Len(a)
	}
	cmdlineUnits++ // terminating NUL
	for _, e := range env {
		envUnits += utf16Len(e) + 1 // "name=value" + NUL
	}
	envUnits++ // block terminator
	ok = cmdlineUnits <= windowsMaxUTF16 && envUnits <= windowsMaxUTF16
	return cmdlineUnits, envUnits, ok
}

// utf16Len returns the number of UTF-16 code units s encodes to (a code point
// above the BMP counts as two, matching how CreateProcess measures).
func utf16Len(s string) int {
	return len(utf16.Encode([]rune(s)))
}
