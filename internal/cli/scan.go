package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// ackFlag registers the shared --acknowledge flag for a Surface-2 declaration
// verb (#74): the override token(s) a resubmission presents, comma-separated.
func ackFlag(fs *flag.FlagSet, dst *string) {
	fs.StringVar(dst, "acknowledge", "",
		"secret-scanning override token(s) from a prior refusal, comma-separated")
}

// Secret-scanning finding presentation (#74). The CLI renders exactly what the
// redacted DTO carries — rule id, surface/ingress, locator, and (where present)
// the opaque acknowledgement token — and NEVER any matched text, offset, length,
// or excerpt (there is none on the type; SS4's canary sweep hunts for leaks in
// this output). The token is printed so an operator can resubmit with
// `--acknowledge`; it embeds no plaintext.

// findingLine renders one finding as a single indented line. The token, when
// present, is shown so it can be presented on the resubmission.
func findingLine(f apigen.ScanFinding) string {
	line := fmt.Sprintf("  - rule %s at %s", f.RuleId, f.Locator)
	if f.Acknowledgement != nil && *f.Acknowledgement != "" {
		line += " (acknowledge with: " + *f.Acknowledgement + ")"
	}
	return line
}

// formatFindings renders a findings block. Used for both the Surface-2 refusal
// message and the Surface-1 warn output.
func formatFindings(findings []apigen.ScanFinding) string {
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, findingLine(f))
	}
	return strings.Join(lines, "\n")
}

// acksPtr turns the comma-separated --acknowledge flag into the optional
// request member. Base64url tokens never contain a comma, so a comma split is
// unambiguous. Empty means no tokens presented.
func acksPtr(raw string) *apigen.Acknowledgements {
	tokens := splitList(raw)
	if len(tokens) == 0 {
		return nil
	}
	acks := apigen.Acknowledgements(tokens)
	return &acks
}

// warnFindings prints the Surface-1 warnings a successful write returned, to
// stderr so they never pollute the table/JSON on stdout. The save SUCCEEDED; the
// warnings are advisory. Empty findings print nothing.
func warnFindings(ios IO, findings *[]apigen.ScanFinding) {
	if findings == nil || len(*findings) == 0 {
		return
	}
	fmt.Fprintf(ios.Stderr,
		"secret-scanning warning: %d config value(s) look like credentials:\n%s\n"+
			"reclassify them as secret, or keep-as-config by re-saving with --acknowledge.\n",
		len(*findings), formatFindings(*findings))
}
