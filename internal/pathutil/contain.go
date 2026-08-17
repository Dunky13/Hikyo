// Package pathutil centralizes filesystem containment checks.
package pathutil

import (
	"fmt"
	"os"
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

// ReadFileWithin reads target through an open handle to root. The rooted read
// follows symlinks only while they remain inside root, so validation and use
// cannot be separated by a pathname race.
func ReadFileWithin(root, target string) ([]byte, error) {
	rootClean := filepath.Clean(root)
	targetClean := filepath.Clean(target)
	rel, err := filepath.Rel(rootClean, targetClean)
	if err != nil {
		return nil, fmt.Errorf("make target %q relative to root %q: %w", targetClean, rootClean, err)
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("target %q escapes root %q: %w", targetClean, rootClean, os.ErrInvalid)
	}

	rootHandle, err := os.OpenRoot(rootClean)
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", rootClean, err)
	}
	defer rootHandle.Close()

	b, err := rootHandle.ReadFile(rel)
	if err != nil {
		return nil, fmt.Errorf("read target %q within root %q: %w", rel, rootClean, err)
	}
	return b, nil
}
