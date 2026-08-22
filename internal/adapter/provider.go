package adapter

import (
	"fmt"
	"sync"
)

// Provider is the closed set of compiled-in deployment providers.
type Provider string

const (
	ForgejoProvider       Provider = "forgejo"
	GitHubActionsProvider Provider = "github-actions"
)

var supportedProviders = [...]Provider{ForgejoProvider, GitHubActionsProvider}

// SupportedProviders returns the complete compiled-in provider set.
func SupportedProviders() []Provider {
	return append([]Provider(nil), supportedProviders[:]...)
}

// ParseProvider rejects missing and unknown persisted provider identities.
// API defaults must resolve to an explicit provider before this boundary.
func ParseProvider(raw string) (Provider, error) {
	provider := Provider(raw)
	for _, supported := range supportedProviders {
		if provider == supported {
			return provider, nil
		}
	}
	return "", fmt.Errorf("adapter: unknown provider %q", raw)
}

// ModuleLease binds one constructed module to its idempotent cleanup.
type ModuleLease struct {
	Module  Module
	release func()
}

// NewModuleLease transfers module cleanup ownership to one release-once value.
func NewModuleLease(module Module, release func()) (*ModuleLease, error) {
	if module == nil {
		return nil, fmt.Errorf("adapter: provider factory returned no module")
	}
	if release == nil {
		release = func() {}
	}
	return &ModuleLease{Module: module, release: sync.OnceFunc(release)}, nil
}

// Release drops provider resources exactly once.
func (l *ModuleLease) Release() {
	if l != nil && l.release != nil {
		l.release()
	}
}

// ModuleFactory is the shared worker/service construction seam.
type ModuleFactory func(Provider, Config, string) (*ModuleLease, error)
