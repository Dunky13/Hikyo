package operator

import (
	"context"
	"fmt"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	hikyov1 "github.com/Hikyo-Org/hikyo/internal/operator/api/v1alpha1"
)

// tokenExpirationSeconds is the API-server minimum TokenRequest expiry (§ 0.5):
// the operator requests the shortest-lived token the API server grants, holds it
// in memory only, and re-mints per fetch — never cached to disk or status.
const tokenExpirationSeconds int64 = 600

// tokenMinter mints a short-lived audience-bound ServiceAccount token via the
// TokenRequest API. It is an interface so unit tests can inject a stub — the
// controller-runtime fake client does not serve the token subresource.
type tokenMinter interface {
	Mint(ctx context.Context, namespace, serviceAccount, audience string) (string, error)
}

// clientsetMinter is the production tokenMinter, backed by a real clientset.
type clientsetMinter struct {
	cs kubernetes.Interface
}

func (m clientsetMinter) Mint(ctx context.Context, namespace, serviceAccount, audience string) (string, error) {
	tr := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			// A per-instance, non-default audience — never the API-server default
			// (ADR § Identity). No boundObjectRef: the operator holds the token in
			// memory for one fetch, and the server-side caps on token age bound it.
			Audiences:         []string{audience},
			ExpirationSeconds: ptrInt64(tokenExpirationSeconds),
		},
	}
	out, err := m.cs.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("mint token for serviceaccount %s/%s: %w", namespace, serviceAccount, err)
	}
	return out.Status.Token, nil
}

func ptrInt64(v int64) *int64 { return &v }

// bootstrapToken extracts the bearer credential from a designated bootstrap
// Secret's data. A missing or empty hikyo-token key means the Secret is not a
// usable delivery credential — reported as SecretNotDesignated so the message
// names the missing token rather than surfacing as an opaque fetch failure.
func bootstrapToken(secret *corev1.Secret) (string, error) {
	raw, ok := secret.Data[hikyov1.BootstrapTokenKey]
	if !ok || len(raw) == 0 {
		return "", fmt.Errorf("bootstrap secret %s/%s has no %q data key", secret.Namespace, secret.Name, hikyov1.BootstrapTokenKey)
	}
	return string(raw), nil
}
