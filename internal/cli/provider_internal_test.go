package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/api/apigen"
)

func TestMetadataConfirmationRerunQuotesUntrustedValues(t *testing.T) {
	var stdout bytes.Buffer
	endpoint := "https://idp.example/sso?next=$(touch /tmp/hikyo-pwned)'suffix"
	err := finishSAMLMutation(IO{Stdout: &stdout}, FormatJSON, apigen.SamlProviderMutationResult{
		Applied: false,
		Diff: apigen.SamlMetadataDiff{
			EndpointsAdded: []string{endpoint}, EndpointsRemoved: []string{},
			CertsAddedFps: []string{"sha256:$unsafe"}, CertsRemovedFps: []string{},
		},
		RequiredEndpoints: []string{endpoint}, RequiredFingerprints: []string{"sha256:$unsafe"},
	})
	var cliErr *Error
	if !asCLIError(err, &cliErr) || cliErr.Code != ExitRefused {
		t.Fatalf("error = %v, want ExitRefused", err)
	}
	message := cliErr.Error()
	for _, want := range []string{
		"--confirm-fingerprint 'sha256:$unsafe'",
		"--confirm-endpoint 'https://idp.example/sso?next=$(touch /tmp/hikyo-pwned)'\"'\"'suffix'",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("rerun command does not safely quote %q:\n%s", want, message)
		}
	}
	if !strings.Contains(stdout.String(), `"applied": false`) {
		t.Errorf("structured diff was not printed:\n%s", stdout.String())
	}
}

func TestStringListRejectsDuplicates(t *testing.T) {
	var values stringList
	if err := values.Set("one"); err != nil {
		t.Fatal(err)
	}
	if err := values.Set("one"); err == nil {
		t.Fatal("duplicate confirmation accepted")
	}
}
