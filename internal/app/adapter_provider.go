package app

import (
	"errors"
	"net/netip"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/adapter/forgejo"
	"github.com/Hikyo-Org/hikyo/internal/adapter/githubactions"
)

func deploymentModule(provider, origin, credential string, allowed []netip.Prefix) (adapter.Module, func(), error) {
	switch provider {
	case "forgejo":
		client, err := forgejo.NewClient(forgejo.ClientConfig{Origin: origin, Credential: credential, AllowedCIDRs: append([]netip.Prefix(nil), allowed...), Deadline: 15 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		return &forgejo.Module{API: client}, client.Forget, nil
	case "github-actions":
		client, err := githubactions.NewClient(githubactions.ClientConfig{Origin: origin, Credential: credential, AllowedCIDRs: append([]netip.Prefix(nil), allowed...), Deadline: 15 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		return &githubactions.Module{API: client}, client.Forget, nil
	default:
		return nil, nil, errors.New("app: unsupported deployment adapter provider")
	}
}
