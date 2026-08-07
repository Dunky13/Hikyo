package crypto

import "log/slog"

// Log non-disclosure (audit-model ADR § Operational logs, CI invariant 8):
// the types holding unwrapped key material implement the FULL formatting
// surface as redaction. String and GoString are what fmt actually consults
// for %v/%s/%#v — without them fmt prints unexported fields by reflection,
// so an accidental `%v` on a Keyring would dump key bytes. LogValue covers
// slog (fmt never calls it), MarshalText/MarshalJSON cover encoders.
//
// The honest limits, stated: reflection-based access, deliberate field
// extraction inside this package, and third-party serializers that bypass
// the marshal interfaces can still leak — the lint rule banning
// formatting/marshaling expressions on these types outside this package is
// the guardrail for that, with its own evasion limits. No memory-secrecy
// claim exists anywhere.

// Redacted is the marker every formatting surface of a sensitive type
// returns.
const Redacted = "[REDACTED:wenv-key-material]"

// redactor is embedded in every sensitive type; method promotion gives the
// outer type the full surface. The methods take value receivers so both the
// value and the pointer form redact.
type redactor struct{}

func (redactor) String() string               { return Redacted }
func (redactor) GoString() string             { return Redacted }
func (redactor) LogValue() slog.Value         { return slog.StringValue(Redacted) }
func (redactor) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (redactor) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// redactionSurface is the full surface CI invariant 8 demands.
type redactionSurface interface {
	String() string
	GoString() string
	LogValue() slog.Value
	MarshalText() ([]byte, error)
	MarshalJSON() ([]byte, error)
}

// The compile-time pin of the sensitive set: each type must carry all five
// surfaces. The lint analyzer's list (lint.SensitiveTypes) names the same
// exported types; its test asserts the two stay in sync.
var (
	_ redactionSurface = (*Keyring)(nil)
	_ redactionSurface = (*ProjectSealer)(nil)
	_ redactionSurface = (*InstanceSealer)(nil)
	_ redactionSurface = keyHandle{}
	_ redactionSurface = dekEntry{}
)
