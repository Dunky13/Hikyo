// Package badnil is a negative fixture for the proof-forgery guard: every
// construct below is a nil-in-Proof-position forgery the analyzer must flag.
package badnil

import (
	"reflect"

	"github.com/Dunky13/wenv/internal/authz"
)

func returnsNil() authz.Proof { return nil }

var globalNil authz.Proof = nil

func passesNil() {
	take(nil)
}

func take(p authz.Proof) { _ = p }

// A package handling Proof values while importing reflect is itself a
// finding, independent of the nil literals.
var _ = reflect.TypeOf(returnsNil())
