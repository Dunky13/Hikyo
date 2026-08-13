// Package pathutil centralizes filesystem containment checks.
package pathutil

import (
	"path/filepath"
	"strings"
)

// Within reports whether target is root itself or a lexical descendant of
// root. The separator boundary matters: a valid child named "..prod" is not
// the parent marker "..".
func Within(root, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ResolveWithin resolves symlinks and returns the resolved target only when it
// remains inside the resolved root. Both paths must exist; use Within for a
// destination that has not been created yet. Callers should read the returned
// path so the checked symlink is not followed again.
func ResolveWithin(root, target string) (string, bool) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", false
	}
	if !Within(resolvedRoot, resolvedTarget) {
		return "", false
	}
	return resolvedTarget, true
}
