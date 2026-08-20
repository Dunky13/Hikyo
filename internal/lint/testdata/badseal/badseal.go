// Package badseal is a negative fixture for the fence-completeness analyzer:
// four functions that seal ciphertext, one of which omits the writer fence and
// must be flagged, three of which are correct (fenced, or explicitly marked).
package badseal

import "github.com/Hikyo-Org/hikyo/internal/crypto"

// fenceProject stands in for the service package's in-package fence helper; the
// analyzer name-matches it against the scanned package's own path.
func fenceProject() error { return nil }

func aad() crypto.ProjectFieldAAD { return crypto.ProjectFieldAAD{} }

// missingFence seals but never fences — the violation the analyzer must catch.
func missingFence(s *crypto.ProjectSealer) []byte {
	b, _ := s.SealField(aad(), nil)
	return b
}

// hasFence seals and fences — must NOT be flagged.
func hasFence(s *crypto.ProjectSealer) []byte {
	b, _ := s.SealField(aad(), nil)
	_ = fenceProject()
	return b
}

// delegatedSeal seals and returns the ciphertext to a caller that fences.
//
// fence:delegated — must NOT be flagged.
func delegatedSeal(s *crypto.ProjectSealer) []byte {
	b, _ := s.SealField(aad(), nil)
	return b
}

// exemptSeal seals bytes that are never written to any table.
//
// fence:exempt — must NOT be flagged.
func exemptSeal(s *crypto.ProjectSealer) []byte {
	b, _ := s.SealField(aad(), nil)
	return b
}
