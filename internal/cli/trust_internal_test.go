package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPinnedClientReplacesPKIVerificationWithExactLeafIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	pin, err := FetchIdentity(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if want := SPKIFingerprint(server.Certificate()); pin != want {
		t.Fatalf("fetched pin = %q, want %q", pin, want)
	}

	client, err := NewClient(TrustEntry{Name: "test", Origin: server.URL, SPKIPin: pin}, "")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.HTTP.Get(server.URL)
	if err != nil {
		t.Fatalf("exact pinned identity refused: %v", err)
	}
	response.Body.Close()

	client, err = NewClient(TrustEntry{Name: "test", Origin: server.URL, SPKIPin: "wrong-pin"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if response, err = client.HTTP.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("different leaf identity passed the recorded SPKI pin")
	}
}
