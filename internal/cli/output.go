package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// The output grammar (api-cli-surface ADR § Output grammar).
//
// `table` is the default and is deterministic REGARDLESS OF TTY — scripts opt
// into `json` explicitly rather than having a machine format appear because
// stdout happened to be a pipe. Human-oriented table output is explicitly not
// frozen; `-o json` shapes are, with the same unknown-field rule the API
// carries.

// Format is the envelope selector for browse verbs.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// ParseFormat validates `-o`.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatTable, FormatJSON:
		return Format(s), nil
	default:
		return "", failf(ExitUsage, "unknown output format %q: use table or json", s)
	}
}

// Table is a rendered result: a header plus rows, or a JSON document. Both
// come from the same value so the two formats cannot describe different
// things.
type Table struct {
	Columns []string
	Rows    [][]string
	// JSON is what `-o json` emits. It is the generated contract type, so the
	// machine shape is the API's shape rather than a hand-written echo of it.
	JSON any
}

// Render writes the table in the requested format to stdout.
func Render(w io.Writer, format Format, t Table) error {
	if format == FormatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(t.JSON)
	}
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	if len(t.Columns) > 0 {
		fmt.Fprintln(tw, strings.Join(t.Columns, "\t"))
	}
	for _, row := range t.Rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

// asCLIError unwraps a *Error from anywhere in the chain, so a code raised
// deep inside the HTTP stack survives the wrapping net/http applies.
func asCLIError(err error, out **Error) bool {
	var e *Error
	if errors.As(err, &e) {
		*out = e
		return true
	}
	return false
}
