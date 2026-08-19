//go:build unix

package compose

import "fmt"

// ExecPreflight is the POSIX leg: it checks the combined argv+environment byte
// size against argMax minus the 64 KiB margin and returns a refusal reason
// naming the overage. Pass DefaultArgMax() when no explicit limit is known.
func ExecPreflight(env, argv []string, argMax int) (ok bool, detail string) {
	total, ok := ExecSizePOSIX(env, argv, argMax)
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("argv+environment is %d bytes, over the %d-byte budget (_SC_ARG_MAX %d minus a 64 KiB margin)",
		total, argMax-argMaxSafetyMargin, argMax)
}
