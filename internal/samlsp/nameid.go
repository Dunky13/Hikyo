// Package samlsp owns Hikyo's relying-party policy around SAML parsing and
// identity material. Cryptographic verification remains the responsibility of
// the pinned SAML/XML-DSIG libraries; this package makes their policy inputs
// unambiguous and fail-closed.
package samlsp

import (
	"encoding/binary"
	"errors"
	"math"
)

var ErrEmptyNameID = errors.New("samlsp: NameID value is empty")

// NameID is the byte-exact identity material extracted from a verified SAML
// Assertion. Pointers preserve the difference between an absent XML attribute
// and one explicitly present with an empty value.
type NameID struct {
	Value           []byte
	Format          *string
	NameQualifier   *string
	SPNameQualifier *string
}

// EncodeNameID returns the injective subject encoding fixed by the SAML ADR.
// Each field is presence-byte || uint32-big-endian-length || bytes. Value is
// mandatory and therefore always present; optional attributes retain presence.
func EncodeNameID(id NameID) ([]byte, error) {
	if len(id.Value) == 0 {
		return nil, ErrEmptyNameID
	}

	encoded := make([]byte, 0, len(id.Value)+20)
	encoded = appendPresentField(encoded, id.Value)
	encoded = appendOptionalField(encoded, id.Format)
	encoded = appendOptionalField(encoded, id.NameQualifier)
	encoded = appendOptionalField(encoded, id.SPNameQualifier)
	return encoded, nil
}

func appendOptionalField(dst []byte, value *string) []byte {
	if value == nil {
		return appendField(dst, false, nil)
	}
	return appendField(dst, true, []byte(*value))
}

func appendPresentField(dst, value []byte) []byte {
	return appendField(dst, true, value)
}

func appendField(dst []byte, present bool, value []byte) []byte {
	if uint64(len(value)) > math.MaxUint32 {
		panic("samlsp: NameID field exceeds uint32")
	}
	if present {
		dst = append(dst, 1)
	} else {
		dst = append(dst, 0)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	return append(dst, value...)
}
