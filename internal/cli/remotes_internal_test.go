package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// `remote add`'s CEREMONY ORDER (#71, multi-instance ADR § The connection
// entry): TLS connect, fingerprint confirm, PRE-AUTH META READ, and only then
// the credential paste.
//
// The meta read is not decoration. It is what lets the command refuse a peer
// that does not speak this protocol at a usable revision BEFORE a human has
// pasted a directory credential into it — every step before the paste can
// refuse without a secret having been typed, which is the whole reason the
// paste is last.

// answeringTTY is a terminal that answers from a script and writes elsewhere,
// so the fingerprint confirmation can be driven without a real /dev/tty.
type answeringTTY struct {
	in  *strings.Reader
	out bytes.Buffer
}

func (a *answeringTTY) Read(p []byte) (int, error)  { return a.in.Read(p) }
func (a *answeringTTY) Write(p []byte) (int, error) { return a.out.Write(p) }
func (a *answeringTTY) Close() error                { return nil }

// fakePeer is a TLS server standing in for the instance being added. `meta` is
// nil to answer 404 there — a host that is up but is not a Hikyo instance. The
// counter is what proves the read happened at all rather than being skipped.
func fakePeer(t *testing.T, meta *apigen.Meta, hits *int) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/meta" && hits != nil {
			*hits++
		}
		if r.URL.Path != "/api/v1/meta" || meta == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
	t.Cleanup(s.Close)
	return s
}

// addRemoteIO confirms the fingerprint and FAILS THE TEST if the credential is
// asked for. Every case below must refuse before that point.
func addRemoteIO(t *testing.T) IO {
	t.Helper()
	return IO{
		Stdout:  io.Discard,
		Stderr:  io.Discard,
		Env:     Env{Getenv: func(string) string { return "" }},
		Workdir: t.TempDir(),
		OpenTerminal: func() (io.WriteCloser, error) {
			return &answeringTTY{in: strings.NewReader("y\n")}, nil
		},
		ReadPassword: func(string) (string, error) {
			t.Fatal("the credential was asked for before the peer had proven it speaks this protocol")
			return "", nil
		},
	}
}

func TestRemoteAddReadsMetaBeforeAskingForTheCredential(t *testing.T) {
	state, err := NewState(Env{Getenv: func(k string) string {
		if k == "HIKYO_STATE_DIR" {
			return t.TempDir()
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a host that does not answer the meta endpoint", func(t *testing.T) {
		hits := 0
		peer := fakePeer(t, nil, &hits)
		err := addRemote(t.Context(), addRemoteIO(t), state, commonFlags{}, FormatTable, "peer-b", peer.URL)
		assertRefused(t, err, "meta endpoint")
		if hits != 1 {
			t.Errorf("the meta endpoint was read %d times, want exactly 1", hits)
		}
	})

	t.Run("a peer too old to serve a directory", func(t *testing.T) {
		// serveDirectory's x-hikyo-min-revision is 1, so revision 0 is a peer
		// this client cannot use — and the refusal must land before the paste,
		// not after the server rejects the entry.
		hits := 0
		peer := fakePeer(t, &apigen.Meta{
			ServerVersion: "0.0.1-ancient", ApiRevision: 0,
			ProtocolCapabilities: []apigen.ProtocolCapability{},
		}, &hits)
		err := addRemote(t.Context(), addRemoteIO(t), state, commonFlags{}, FormatTable, "peer-b", peer.URL)
		assertRefused(t, err, "not a compatible peer")
		if hits != 1 {
			t.Errorf("the meta endpoint was read %d times, want exactly 1", hits)
		}
	})

	t.Run("a compatible peer passes the check", func(t *testing.T) {
		// The positive control: without it the two refusals above would pass
		// against a command that refuses every peer. A compatible peer's meta
		// read must be performed AND accepted, so the command carries on past
		// it — here into resolving this operator's own instance, which this
		// test deliberately has none of.
		hits := 0
		peer := fakePeer(t, &apigen.Meta{
			ServerVersion: "1.0.0", ApiRevision: 1,
			ProtocolCapabilities: []apigen.ProtocolCapability{},
		}, &hits)
		err := addRemote(t.Context(), addRemoteIO(t), state, commonFlags{}, FormatTable, "peer-b", peer.URL)
		if hits != 1 {
			t.Errorf("the meta endpoint was read %d times, want exactly 1", hits)
		}
		if err == nil {
			t.Fatal("the add somehow succeeded with no local instance established")
		}
		if strings.Contains(err.Error(), "no credential was asked for") {
			t.Fatalf("a revision-1 peer was refused by the compatibility check: %v", err)
		}
	})
}

func assertRefused(t *testing.T, err error, wants string) {
	t.Helper()
	var ce *Error
	if !asCLIError(err, &ce) {
		t.Fatalf("err = %v, want a CLI refusal", err)
	}
	if ce.Code != ExitRefused {
		t.Errorf("exit code %d, want %d (refused)", ce.Code, ExitRefused)
	}
	if !strings.Contains(err.Error(), wants) {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if !strings.Contains(err.Error(), "no credential was asked for") {
		t.Errorf("the refusal does not tell the operator their credential is untouched: %v", err)
	}
}

// PLAINTEXT IS REFUSED BEFORE ANY CEREMONY RUNS.
//
// The general CLI's origin grammar admits http on purpose — a loopback origin
// is a legitimate thing for other verbs to address, and the workspace allowlist
// stores origins that may be plaintext. A REMOTE URL is neither. Left to the
// general rule, `remote add peer http://127.0.0.1:8080` reached FetchIdentity,
// which returns an EMPTY pin for a non-https origin, and then asked a human to
// confirm a blank fingerprint, read meta in the clear, and paste a directory
// credential. The server's ValidateRemoteURL refused the result — one secret
// too late to matter.
func TestRemoteAddRefusesPlaintext(t *testing.T) {
	state, err := NewState(Env{Getenv: func(k string) string {
		if k == "HIKYO_STATE_DIR" {
			return t.TempDir()
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	// A terminal that fails the test if it is consulted at all: the refusal
	// must land before the fingerprint prompt, not at it.
	ios := IO{
		Stdout: io.Discard, Stderr: io.Discard,
		Env:     Env{Getenv: func(string) string { return "" }},
		Workdir: t.TempDir(),
		OpenTerminal: func() (io.WriteCloser, error) {
			t.Fatal("a fingerprint confirmation was offered for a plaintext origin — " +
				"there is no key to pin, so there is nothing to confirm")
			return nil, nil
		},
		ReadPassword: func(string) (string, error) {
			t.Fatal("a credential was asked for over a plaintext origin")
			return "", nil
		},
	}
	for _, raw := range []string{"http://127.0.0.1:8080", "http://peer.example", "http://localhost:9999/"} {
		err := addRemote(t.Context(), ios, state, commonFlags{}, FormatTable, "peer-b", raw)
		var ce *Error
		if !asCLIError(err, &ce) || ce.Code != ExitUsage {
			t.Errorf("%s: err = %v, want a usage refusal", raw, err)
			continue
		}
		if !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: the refusal does not say why: %v", raw, err)
		}
	}
}

// IO.ReadPassword documents "nil means the real terminal", and every other verb
// honours it through ios.readPassword. addRemote read the FIELD, so the only
// uninjected path — every real invocation — refused itself with "no terminal to
// read the credential from" after the human had already confirmed a
// fingerprint. This asserts the accessor is what it consults, without needing a
// terminal: the accessor's own no-terminal refusal is a DIFFERENT message from
// the one the field-reading version produced.
func TestRemoteAddUsesTheDefaultPasswordReader(t *testing.T) {
	state, err := NewState(Env{Getenv: func(k string) string {
		if k == "HIKYO_STATE_DIR" {
			return t.TempDir()
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	meta := &apigen.Meta{ServerVersion: "1.0.0", ApiRevision: 1}
	hits := 0
	peer := fakePeer(t, meta, &hits)
	ios := addRemoteIO(t)
	ios.ReadPassword = nil // the documented "use the real terminal" default

	err = addRemote(t.Context(), ios, state, commonFlags{}, FormatTable, "peer-b", peer.URL)
	if err == nil {
		t.Fatal("the ceremony completed with no terminal at all")
	}
	if strings.Contains(err.Error(), "no terminal to read the credential from") {
		t.Fatal("addRemote read the ReadPassword FIELD instead of going through " +
			"ios.readPassword, so the documented nil default refuses every real invocation")
	}
}
