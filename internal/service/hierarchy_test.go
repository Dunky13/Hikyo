package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/Dunky13/wenv/internal/domain"
)

// The grammar guards are the one piece of non-trivial branching this ticket adds
// below the transport, and nothing above them can be reached with a bad name —
// so they get the check.
func TestNameAndFolderPathGrammar(t *testing.T) {
	for _, bad := range []string{"", " leading", "trailing ", "with\ttab", strings.Repeat("x", maxNameBytes+1)} {
		if err := checkName("organisation name", bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("checkName(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	if err := checkName("organisation name", "Acme Platform"); err != nil {
		t.Errorf("a legitimate name was refused: %v", err)
	}

	for _, bad := range []string{
		"", "/leading", "trailing/", "double//segment", ".", "..", "a/../b",
		strings.Repeat("a/", maxFolderPathSegs) + "a",
		strings.Repeat("x", maxFolderPathLen+1),
	} {
		if err := checkFolderPath(bad); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("checkFolderPath(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	for _, ok := range []string{"shared", "services/api", "a/b/c"} {
		if err := checkFolderPath(ok); err != nil {
			t.Errorf("checkFolderPath(%q) refused a legitimate path: %v", ok, err)
		}
	}
	// The message reads as a sentence, which is the point of `what`.
	err := checkFolderPath("a//b")
	if got := err.Error(); !strings.Contains(got, "folder path segment must not be empty") {
		t.Errorf("message %q does not read naturally", got)
	}
}
