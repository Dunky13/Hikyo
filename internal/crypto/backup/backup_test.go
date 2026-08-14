package backup_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/crypto/backup"
)

func mustIdentity(t *testing.T) (identity, recipient string) {
	t.Helper()
	id, rcp, err := backup.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id, rcp
}

// seal is the whole write side in one call: it is what every case below
// needs and nothing else.
func seal(t *testing.T, o backup.Options, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := backup.Encrypt(&out, o)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close container: %v", err)
	}
	return out.Bytes()
}

func extract(u backup.Unlock, container []byte) ([]byte, error) {
	var out bytes.Buffer
	err := backup.ExtractTo(&out, bytes.NewReader(container), u)
	return out.Bytes(), err
}

// A payload comfortably larger than age's 64 KiB STREAM chunk, so the
// truncation cases below have a real chunk boundary to cut at.
func payload() []byte {
	b := make([]byte, 200*1024)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func TestZeroRecipientsRefused(t *testing.T) {
	if _, err := backup.Encrypt(io.Discard, backup.Options{}); !errors.Is(err, backup.ErrNoRecipients) {
		t.Fatalf("Encrypt with no recipients = %v, want ErrNoRecipients", err)
	}
}

// The scrypt stanza must be the only stanza in its container (encryption ADR
// § Backups), so export takes public recipients or a passphrase, never both.
func TestScryptExclusivityRefusedAtExport(t *testing.T) {
	_, recipient := mustIdentity(t)
	_, err := backup.Encrypt(io.Discard, backup.Options{Recipients: []string{recipient}, Passphrase: "correct horse battery staple"})
	if !errors.Is(err, backup.ErrRecipientExclusive) {
		t.Fatalf("Encrypt with recipients AND passphrase = %v, want ErrRecipientExclusive", err)
	}
}

func TestRoundTripX25519(t *testing.T) {
	identity, recipient := mustIdentity(t)
	want := payload()
	container := seal(t, backup.Options{Recipients: []string{recipient}}, want)
	got, err := extract(backup.Unlock{Identity: identity}, container)
	if err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("round-tripped payload differs")
	}
}

// Multi-recipient wrapping means any single recipient restores.
func TestRoundTripMultipleRecipients(t *testing.T) {
	idA, rcpA := mustIdentity(t)
	idB, rcpB := mustIdentity(t)
	want := []byte("two recipients, either one opens it")
	container := seal(t, backup.Options{Recipients: []string{rcpA, rcpB}}, want)
	for name, identity := range map[string]string{"first": idA, "second": idB} {
		got, err := extract(backup.Unlock{Identity: identity}, container)
		if err != nil {
			t.Fatalf("%s recipient: ExtractTo: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s recipient: payload differs", name)
		}
	}
}

func TestRoundTripPassphrase(t *testing.T) {
	const pass = "correct horse battery staple"
	want := payload()
	container := seal(t, backup.Options{Passphrase: pass}, want)
	got, err := extract(backup.Unlock{Passphrase: pass}, container)
	if err != nil {
		t.Fatalf("ExtractTo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("round-tripped payload differs")
	}
	if _, err := extract(backup.Unlock{Passphrase: "wrong"}, container); err == nil {
		t.Fatal("a wrong passphrase opened the container")
	}
}

func TestWrongIdentityRefused(t *testing.T) {
	_, recipient := mustIdentity(t)
	other, _ := mustIdentity(t)
	container := seal(t, backup.Options{Recipients: []string{recipient}}, []byte("secret"))
	if _, err := extract(backup.Unlock{Identity: other}, container); err == nil {
		t.Fatal("a foreign identity opened the container")
	}
}

func TestTamperedContainerRefused(t *testing.T) {
	identity, recipient := mustIdentity(t)
	container := seal(t, backup.Options{Recipients: []string{recipient}}, payload())
	// Flip a bit well inside the payload, past the header.
	container[len(container)-64] ^= 0x01
	if _, err := extract(backup.Unlock{Identity: identity}, container); err == nil {
		t.Fatal("a tampered container decrypted")
	}
}

// Truncation is detected before ExtractTo returns, which is what lets the
// restore path treat a successful extract as "the whole archive is here".
// Every cut point matters, and they fail for different reasons: mid-chunk
// fails the chunk's own authentication tag, while a cut exactly on a chunk
// boundary fails ONLY because the final chunk never arrived — the case a
// naive stream-and-apply restore would swallow silently, and the reason
// ErrTruncated is asserted by name there.
func TestTruncatedContainerRefused(t *testing.T) {
	identity, recipient := mustIdentity(t)
	container := seal(t, backup.Options{Recipients: []string{recipient}}, payload())

	headerLen := bytes.Index(container, []byte("---"))
	if headerLen < 0 {
		t.Fatal("no age header in the container")
	}
	// Past "--- <mac>\n" the payload begins with a 16-byte STREAM nonce,
	// then chunks of 64 KiB plaintext + a 16-byte tag each.
	streamStart := headerLen + bytes.IndexByte(container[headerLen:], '\n') + 1
	const nonce, chunk = 16, 64*1024 + 16

	cases := []struct {
		name         string
		cut          int
		wantSentinel error
	}{
		{"exact chunk boundary", streamStart + nonce + chunk, backup.ErrTruncated},
		{"no chunks at all", streamStart + nonce, backup.ErrTruncated},
		{"no payload at all", streamStart, backup.ErrTruncated},
		{"mid-chunk", len(container) - 1024, nil},
		{"mid-header", headerLen / 2, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cut <= 0 || tc.cut >= len(container) {
				t.Fatalf("cut point %d out of range for a %d-byte container", tc.cut, len(container))
			}
			_, err := extract(backup.Unlock{Identity: identity}, container[:tc.cut])
			if err == nil {
				t.Fatal("a truncated container extracted cleanly")
			}
			if tc.wantSentinel != nil && !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("truncation error = %v, want %v", err, tc.wantSentinel)
			}
		})
	}
}

// A container mixing an scrypt stanza with a public-recipient stanza is
// refused on open too, not only at export: age enforces the exclusivity rule
// only on the ScryptIdentity path, so an X25519 identity would otherwise open
// a container whose passphrase half is a second, weaker door.
func TestScryptExclusivityRefusedOnOpen(t *testing.T) {
	identity, recipient := mustIdentity(t)
	container := seal(t, backup.Options{Recipients: []string{recipient}}, []byte("payload"))
	passphrased := seal(t, backup.Options{Passphrase: "correct horse battery staple"}, []byte("payload"))

	// Splice the scrypt stanza (its "-> scrypt" line and body line) into the
	// X25519 container's header. The MAC will not verify, but the exclusivity
	// check must refuse before any of that is attempted.
	scryptStanza := stanzaLines(t, passphrased, "scrypt")
	mixed := spliceStanza(t, container, scryptStanza)

	_, err := extract(backup.Unlock{Identity: identity}, mixed)
	if !errors.Is(err, backup.ErrMixedStanzas) {
		t.Fatalf("open of a mixed container = %v, want ErrMixedStanzas", err)
	}
}

// stanzaLines returns the "-> type ..." line and its body lines from a
// container's header.
func stanzaLines(t *testing.T, container []byte, kind string) string {
	t.Helper()
	lines := strings.Split(string(container), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "-> "+kind+" ") {
			continue
		}
		out := []string{line}
		for _, body := range lines[i+1:] {
			if strings.HasPrefix(body, "-> ") || strings.HasPrefix(body, "---") {
				break
			}
			out = append(out, body)
		}
		return strings.Join(out, "\n")
	}
	t.Fatalf("no %s stanza in the container", kind)
	return ""
}

// spliceStanza inserts extra stanza lines directly before the header MAC.
func spliceStanza(t *testing.T, container []byte, stanza string) []byte {
	t.Helper()
	idx := bytes.Index(container, []byte("\n---"))
	if idx < 0 {
		t.Fatal("no header MAC line in the container")
	}
	out := make([]byte, 0, len(container)+len(stanza)+1)
	out = append(out, container[:idx+1]...)
	out = append(out, stanza...)
	out = append(out, '\n')
	return append(out, container[idx+1:]...)
}

func TestUnlockRequiresExactlyOneSecret(t *testing.T) {
	_, recipient := mustIdentity(t)
	container := seal(t, backup.Options{Recipients: []string{recipient}}, []byte("payload"))
	for name, u := range map[string]backup.Unlock{
		"neither": {},
		"both":    {Identity: "AGE-SECRET-KEY-1", Passphrase: "x"},
	} {
		if _, err := extract(u, container); !errors.Is(err, backup.ErrUnlock) {
			t.Fatalf("%s: ExtractTo = %v, want ErrUnlock", name, err)
		}
	}
}
