package operator

import (
	"context"

	opclient "github.com/Hikyo-Org/hikyo/internal/operator/client"
)

// deliveryClient is the fetch surface the reconciler depends on. The concrete
// *opclient.Client satisfies it; tests inject a stub against an httptest server
// so the reconciler is exercised without a real Hikyo server.
type deliveryClient interface {
	Fetch(ctx context.Context, r opclient.FetchRequest) (*opclient.DeliveryResponse, opclient.Outcome, error)
}

// clientFactory builds a deliveryClient for one instance's URL and CA bundle.
// The reconciler's NewClientForURL hook defaults to this.
func defaultClientFactory(rawURL string, caBundlePEM []byte) (deliveryClient, error) {
	return opclient.NewClient(rawURL, caBundlePEM, "hikyo-operator/"+Version)
}
