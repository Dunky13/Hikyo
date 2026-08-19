package operator

import (
	"context"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestClientsetMinterWiring proves the PRODUCTION federation minter (the one
// manager.go wires from a real clientset) issues a TokenRequest with the
// instance audience and the 600s API-server-minimum expiry — the path a stub
// minter in the reconciler tests cannot exercise (§ 0.5, decision 5).
func TestClientsetMinterWiring(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var gotAudiences []string
	var gotExpiry int64
	var gotSubresource string
	cs.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := action.(k8stesting.CreateAction)
		if !ok || ca.GetSubresource() != "token" {
			return false, nil, nil
		}
		gotSubresource = ca.GetSubresource()
		tr := ca.GetObject().(*authnv1.TokenRequest)
		gotAudiences = tr.Spec.Audiences
		if tr.Spec.ExpirationSeconds != nil {
			gotExpiry = *tr.Spec.ExpirationSeconds
		}
		tr.Status.Token = "minted-token"
		return true, tr, nil
	})

	m := clientsetMinter{cs: cs}
	tok, err := m.Mint(context.Background(), "team-a", "worker", "hikyo-audience")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok != "minted-token" {
		t.Fatalf("token = %q", tok)
	}
	if gotSubresource != "token" {
		t.Fatalf("did not hit the token subresource: %q", gotSubresource)
	}
	if len(gotAudiences) != 1 || gotAudiences[0] != "hikyo-audience" {
		t.Fatalf("audiences = %v, want [hikyo-audience]", gotAudiences)
	}
	if gotExpiry != tokenExpirationSeconds {
		t.Fatalf("expirationSeconds = %d, want %d", gotExpiry, tokenExpirationSeconds)
	}
}
