package samlsp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestEncodeNameIDIsInjectiveAcrossFieldsAndPresence(t *testing.T) {
	t.Parallel()

	empty := ""
	format := "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	tests := []struct {
		name string
		id   NameID
	}{
		{name: "baseline", id: NameID{Value: []byte("alice")}},
		{name: "different bytes", id: NameID{Value: []byte("Alice")}},
		{name: "format", id: NameID{Value: []byte("alice"), Format: &format}},
		{name: "present empty format", id: NameID{Value: []byte("alice"), Format: &empty}},
		{name: "present empty name qualifier", id: NameID{Value: []byte("alice"), NameQualifier: &empty}},
		{name: "present empty sp name qualifier", id: NameID{Value: []byte("alice"), SPNameQualifier: &empty}},
	}

	encoded := make(map[string]string, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncodeNameID(tt.id)
			if err != nil {
				t.Fatalf("EncodeNameID() error = %v", err)
			}
			key := string(got)
			if previous, exists := encoded[key]; exists {
				t.Fatalf("encoding collides with %q: %x", previous, got)
			}
			encoded[key] = tt.name
		})
	}
}

func TestEncodeNameIDUsesSpecifiedWireEncoding(t *testing.T) {
	t.Parallel()

	empty := ""
	got, err := EncodeNameID(NameID{Value: []byte("A"), Format: &empty})
	if err != nil {
		t.Fatalf("EncodeNameID() error = %v", err)
	}
	want, err := hex.DecodeString("010000000141010000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeNameID() = %x, want %x", got, want)
	}
}

func TestEncodeNameIDRefusesEmptyValue(t *testing.T) {
	t.Parallel()

	_, err := EncodeNameID(NameID{})
	if !errors.Is(err, ErrEmptyNameID) {
		t.Fatalf("EncodeNameID() error = %v, want ErrEmptyNameID", err)
	}
}
