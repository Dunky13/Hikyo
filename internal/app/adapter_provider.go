package app

import (
	"errors"
	"net/netip"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/adapter/forgejo"
	"github.com/Hikyo-Org/hikyo/internal/adapter/githubactions"
)

type providerConstructor func(adapter.Config, string, []netip.Prefix) (adapter.Module, func(), error)

type adapterModuleFactory struct {
	egressPolicy map[string][]netip.Prefix
	providers    map[adapter.Provider]providerConstructor
}

type adapterModuleWiring struct {
	worker  adapter.ModuleFactory
	service adapter.ModuleFactory
}

func deploymentProviderRegistry() map[adapter.Provider]providerConstructor {
	return map[adapter.Provider]providerConstructor{
		adapter.ForgejoProvider: func(config adapter.Config, credential string, allowed []netip.Prefix) (adapter.Module, func(), error) {
			client, err := forgejo.NewClient(forgejo.ClientConfig{Origin: config.Origin, Credential: credential, AllowedCIDRs: allowed, Deadline: 15 * time.Second})
			if err != nil {
				return nil, nil, err
			}
			return &forgejo.Module{API: client}, client.Forget, nil
		},
		adapter.GitHubActionsProvider: func(config adapter.Config, credential string, allowed []netip.Prefix) (adapter.Module, func(), error) {
			client, err := githubactions.NewClient(githubactions.ClientConfig{Origin: config.Origin, Credential: credential, AllowedCIDRs: allowed, Deadline: 15 * time.Second})
			if err != nil {
				return nil, nil, err
			}
			return &githubactions.Module{API: client}, client.Forget, nil
		},
	}
}

func newAdapterModuleFactory(egressPolicy map[string][]netip.Prefix) *adapterModuleFactory {
	return &adapterModuleFactory{egressPolicy: egressPolicy, providers: deploymentProviderRegistry()}
}

func newAdapterModuleWiring(egressPolicy map[string][]netip.Prefix) adapterModuleWiring {
	factory := newAdapterModuleFactory(egressPolicy)
	return adapterModuleWiring{worker: factory.Build, service: factory.Build}
}

func (f *adapterModuleFactory) Build(provider adapter.Provider, config adapter.Config, credential string) (*adapter.ModuleLease, error) {
	if f == nil {
		return nil, errors.New("app: adapter module factory is not configured")
	}
	constructor := f.providers[provider]
	if constructor == nil {
		return nil, errors.New("app: unsupported deployment adapter provider")
	}
	allowed := append([]netip.Prefix(nil), f.egressPolicy[config.Origin]...)
	module, release, err := constructor(config, credential, allowed)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	lease, err := adapter.NewModuleLease(module, release)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	return lease, nil
}
