package service

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordPolicy(t *testing.T) {
	cases := map[string]struct {
		password string
		want     error
	}{
		"below the floor":             {"short", ErrWeakPassword},
		"exactly at the floor":        {"twelvechars", ErrWeakPassword}, // 11
		"one character repeated":      {"aaaaaaaaaaaaaa", ErrWeakPassword},
		"on the list":                 {"correcthorsebatterystaple", ErrCommonPassword},
		"on the list, different case": {"CorrectHorseBatteryStaple", ErrCommonPassword},
		"fine":                        {"a perfectly ordinary passphrase", nil},
		// No composition rules: a long all-lowercase phrase with no digit,
		// symbol or capital is accepted, because demanding them produces
		// `Password1!` and a false sense of entropy.
		"no composition rules": {"whistling kettle on the hob", nil},
		// No forced rotation and no length ceiling that would push people
		// toward shorter secrets.
		"very long": {strings.Repeat("passphrase segment ", 20), nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := CheckPassword(tc.password)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// The bundled list is a starter set, not the specified top-100k. This test is
// what stops the two being confused: it fails when the file grows past the
// placeholder bound WITHOUT the bound moving, which is exactly the moment
// someone drops the real list in and should also update the claim in
// docs/handoff/47-first-slice.md.
func TestCommonListIsAKnownPlaceholder(t *testing.T) {
	n := len(commonList())
	if n == 0 {
		t.Fatal("the bundled list is empty — the check would be vacuous")
	}
	if n >= PlaceholderListBound {
		t.Fatalf("the bundled list has %d entries, past the placeholder bound of %d. "+
			"If the specified top-100k has landed: raise PlaceholderListBound, add the CI hash pin the "+
			"ops spec requires, and correct deviation 5 in docs/handoff/47-first-slice.md, which currently "+
			"records this as a known data gap.", n, PlaceholderListBound)
	}
	t.Logf("bundled list: %d entries (placeholder; the ops spec specifies the top-100k)", n)
}
