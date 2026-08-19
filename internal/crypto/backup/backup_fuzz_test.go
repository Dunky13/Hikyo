package backup

import (
	"bytes"
	"io"
	"testing"
)

// FuzzExtractTo checks the encryption-model backup reader returns normally on complete, truncated, and arbitrary containers.
func FuzzExtractTo(f *testing.F) {
	identity, recipient, err := GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	var container bytes.Buffer
	w, err := Encrypt(&container, Options{Recipients: []string{recipient}})
	if err != nil {
		f.Fatal(err)
	}
	if _, err := w.Write([]byte("backup payload")); err != nil {
		f.Fatal(err)
	}
	if err := w.Close(); err != nil {
		f.Fatal(err)
	}
	valid := container.Bytes()
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte("not an age container"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ExtractTo(io.Discard, bytes.NewReader(raw), Unlock{Identity: identity})
	})
}
