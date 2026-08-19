package delivery

import (
	"bytes"
	"testing"
)

func TestCursorEncodingBindsConfigOnlyMode(t *testing.T) {
	base := Cursor{
		ChangeToken: "v1:token", Projection: []string{"read"},
		AuthorizationRevision: 7, PinGeneration: 3,
	}
	full := EncodeCursor(base)
	base.ConfigOnly = true
	configOnly := EncodeCursor(base)
	if bytes.Equal(full, configOnly) {
		t.Fatal("full and config-only modes encoded to the same cursor tuple")
	}
	base.ConfigOnly = false
	if roundTrip := EncodeCursor(base); !bytes.Equal(full, roundTrip) {
		t.Fatal("returning to full mode did not reproduce its canonical encoding")
	}
}
