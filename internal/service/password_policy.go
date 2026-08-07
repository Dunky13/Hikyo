package service

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// Password policy (human-auth ADR § Credential storage): a length floor of
// 12, no composition rules, no forced rotation — the NIST SP 800-63B shape —
// with rejection against a bundled common-password list.
//
// Composition rules produce `Password1!` and a false sense of entropy;
// forced rotation produces `Password2!`. Neither exists here and neither
// should be added.
//
// The list is checked AT SET TIME ONLY, never at login. Checking at login
// would put a variable-cost lookup on the timing-sensitive path for no
// benefit: the password was already refused when it was set.

// commonPasswords is the bundled list.
//
// STATED GAP: the ops spec calls for the embedded top-100k (SecLists/HIBP-
// derived), pinned and hash-checked in CI. What ships here is a starter set,
// because sourcing the full list needs a network fetch and a licence review
// that this ticket did not do. The MECHANISM is complete and on the right
// path; the DATA is not, and TestCommonListIsAKnownPlaceholder fails the day
// someone mistakes one for the other.
//
//go:embed common-passwords.txt
var commonPasswords string

// PlaceholderListBound is the size below which the bundled list is understood
// to be the starter set rather than the specified one. Replacing the file
// with the real top-100k is what removes the placeholder status.
const PlaceholderListBound = 1000

var (
	commonOnce sync.Once
	commonSet  map[string]struct{}
)

func commonList() map[string]struct{} {
	commonOnce.Do(func() {
		commonSet = map[string]struct{}{}
		for line := range strings.SplitSeq(commonPasswords, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			commonSet[strings.ToLower(line)] = struct{}{}
		}
	})
	return commonSet
}

// ErrCommonPassword refuses a password from the bundled list. Like the length
// floor it is loud and specific: this is the caller's own input, evaluated
// before anything is looked up, so naming the rule helps the human and
// reveals nothing about what exists.
var ErrCommonPassword = errors.New("that password appears in a list of commonly used passwords; choose another")

// CheckPassword applies the whole policy.
func CheckPassword(password string) error {
	if len([]rune(password)) < PasswordMinLength {
		return ErrWeakPassword
	}
	// A password of one repeated character passes any length floor and is on
	// no list long enough to matter, so the floor alone would admit
	// "aaaaaaaaaaaa". This is not a composition rule — it adds no required
	// character class — it refuses a string with no variation at all.
	if uniqueRunes(password) < 2 {
		return fmt.Errorf("%w: it repeats a single character", ErrWeakPassword)
	}
	// Case-insensitively, because `Password123` and `password123` are the
	// same guess.
	if _, listed := commonList()[strings.ToLower(strings.TrimFunc(password, unicode.IsSpace))]; listed {
		return ErrCommonPassword
	}
	return nil
}

func uniqueRunes(s string) int {
	seen := map[rune]struct{}{}
	for _, r := range s {
		seen[r] = struct{}{}
	}
	return len(seen)
}
