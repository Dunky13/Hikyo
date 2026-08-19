package compose

// ARG_MAX preflight for `hikyo run --` (compose-integration ADR /
// ops-spec § 6: "the client sums the rendered environment, the inherited
// environment, and argv against the runtime limit … minus a 64 KiB safety
// margin and refuses loud pre-exec"). E2BIG at exec time is the wrong layer to
// discover this — the per-value cap bounds one string, not the composite.

// argMaxSafetyMargin is subtracted from the raw limit: the kernel also counts
// pointer arrays and alignment, so the usable budget is smaller than
// _SC_ARG_MAX (ops-spec § 6: "minus a 64 KiB safety margin").
const argMaxSafetyMargin = 64 * 1024

// conservativeArgMax is the fallback when the platform limit cannot be read.
const conservativeArgMax = 128 * 1024

// ExecSizeOK sums len(entry)+1 over env and len(arg)+1 over argv — the
// per-string NUL the kernel counts — and reports whether the total fits within
// limit - 64 KiB. It returns the computed total so the caller can name the
// overage.
func ExecSizeOK(env []string, argv []string, limit int) (total int, ok bool) {
	for _, e := range env {
		total += len(e) + 1
	}
	for _, a := range argv {
		total += len(a) + 1
	}
	budget := limit - argMaxSafetyMargin
	return total, total <= budget
}
