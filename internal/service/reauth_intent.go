package service

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// ReauthIntent is the closed representation of one reauthentication decision.
// Its fields are private so purpose, operation, environment and key bindings
// cannot be assembled independently after the transport boundary has parsed
// them. Constructors below are the only way to create a value.
type ReauthIntent struct {
	variant        reauthIntentVariant
	environmentID  string
	environmentIDs []string
	keyIDs         []string
	keySet         string
	environmentSet string
}

type reauthIntentVariant uint8

const (
	intentUnbound reauthIntentVariant = iota + 1
	intentReveal
	intentCopy
	intentPublish
	intentMint
	intentAdapterConfigure
	intentAdapterCredentialSet
	intentAdapterAdopt
	intentAdapterSync
)

// reauthIntentBinding is the single derived spelling consumed by windows,
// signed WebAuthn ceremonies and handoffs.
type reauthIntentBinding struct {
	purpose          ReauthPurpose
	operation        authz.Operation
	environmentID    string
	keyIDs           []string
	keySet           string
	environmentIDs   []string
	environmentSet   string
	challengeBinding string
}

// reauthIntentDescriptor is the single closed relation between an intent's
// variant, public purpose and authorization operation. Every lookup below
// projects from this table so adding a variant cannot create competing maps.
type reauthIntentDescriptor struct {
	variant   reauthIntentVariant
	purpose   ReauthPurpose
	operation authz.Operation
	adapter   bool
}

var reauthIntentDescriptors = [...]reauthIntentDescriptor{
	{variant: intentUnbound},
	{variant: intentReveal, purpose: PurposeReveal, operation: authz.OpValueReveal},
	{variant: intentCopy, purpose: PurposeCopy, operation: authz.OpValueCopySource},
	{variant: intentPublish, purpose: PurposePublish, operation: authz.OpValueCopyDestination},
	{variant: intentMint, purpose: PurposeMint, operation: authz.OpCredentialMint},
	{variant: intentAdapterConfigure, purpose: PurposeAdapter, operation: authz.OpAdapterConfigure, adapter: true},
	{variant: intentAdapterCredentialSet, purpose: PurposeAdapter, operation: authz.OpAdapterCredentialSet, adapter: true},
	{variant: intentAdapterAdopt, purpose: PurposeAdapter, operation: authz.OpAdapterAdopt, adapter: true},
	{variant: intentAdapterSync, purpose: PurposeAdapter, operation: authz.OpAdapterSync, adapter: true},
}

func descriptorForVariant(variant reauthIntentVariant) (reauthIntentDescriptor, bool) {
	for _, descriptor := range reauthIntentDescriptors {
		if descriptor.variant == variant {
			return descriptor, true
		}
	}
	return reauthIntentDescriptor{}, false
}

func disclosureDescriptorForPurpose(purpose ReauthPurpose) (reauthIntentDescriptor, bool) {
	for _, descriptor := range reauthIntentDescriptors {
		if !descriptor.adapter && descriptor.variant != intentUnbound && descriptor.purpose == purpose {
			return descriptor, true
		}
	}
	return reauthIntentDescriptor{}, false
}

func descriptorForOperation(operation authz.Operation) (reauthIntentDescriptor, bool) {
	for _, descriptor := range reauthIntentDescriptors {
		if descriptor.variant != intentUnbound && descriptor.operation == operation {
			return descriptor, true
		}
	}
	return reauthIntentDescriptor{}, false
}

func NewUnboundReauthIntent(environmentID string) (ReauthIntent, error) {
	return newDisclosureReauthIntent(intentUnbound, []string{environmentID}, nil)
}

func NewRevealReauthIntent(environmentID string, keyIDs []string) (ReauthIntent, error) {
	return NewDisclosureReauthIntent(PurposeReveal, []string{environmentID}, keyIDs)
}

func NewCopyReauthIntent(environmentID string, keyIDs []string) (ReauthIntent, error) {
	return NewDisclosureReauthIntent(PurposeCopy, []string{environmentID}, keyIDs)
}

func NewPublishReauthIntent(environmentID string, keyIDs []string) (ReauthIntent, error) {
	return NewDisclosureReauthIntent(PurposePublish, []string{environmentID}, keyIDs)
}

func NewMintReauthIntent(environmentID string, keyIDs []string) (ReauthIntent, error) {
	return NewDisclosureReauthIntent(PurposeMint, []string{environmentID}, keyIDs)
}

// NewDisclosureReauthIntent parses the wire purpose at the transport boundary.
// Past this constructor purpose, operation, environment and keys travel as one
// value and cannot be recombined.
func NewDisclosureReauthIntent(purpose ReauthPurpose, environmentIDs, keyIDs []string) (ReauthIntent, error) {
	if purpose == PurposeAdapter {
		return ReauthIntent{}, fmt.Errorf("%w: adapter reauthentication requires an adapter intent", domain.ErrInvalid)
	}
	descriptor, ok := disclosureDescriptorForPurpose(purpose)
	if !ok {
		return ReauthIntent{}, fmt.Errorf("%w: unknown reauthentication purpose %q", domain.ErrInvalid, purpose)
	}
	return newDisclosureReauthIntent(descriptor.variant, environmentIDs, keyIDs)
}

func newReauthIntentForOperation(operation authz.Operation, environmentID string, keyIDs []string) (ReauthIntent, error) {
	descriptor, ok := descriptorForOperation(operation)
	if !ok || descriptor.adapter {
		return ReauthIntent{}, fmt.Errorf("%w: unknown reauthentication operation %q", domain.ErrInvalid, operation)
	}
	return newDisclosureReauthIntent(descriptor.variant, []string{environmentID}, keyIDs)
}

func newDisclosureReauthIntent(variant reauthIntentVariant, environmentIDs, keyIDs []string) (ReauthIntent, error) {
	canonicalEnvironments := append([]string(nil), environmentIDs...)
	sort.Strings(canonicalEnvironments)
	canonicalEnvironments = slices.Compact(canonicalEnvironments)
	if len(canonicalEnvironments) == 0 {
		return ReauthIntent{}, fmt.Errorf("%w: reauthentication intent requires an environment", domain.ErrInvalid)
	}
	for _, environmentID := range canonicalEnvironments {
		if environmentID == "" {
			return ReauthIntent{}, fmt.Errorf("%w: reauthentication intent contains an empty environment", domain.ErrInvalid)
		}
	}
	if len(canonicalEnvironments) != 1 {
		return ReauthIntent{}, fmt.Errorf("%w: disclosure reauthentication covers exactly one environment", domain.ErrInvalid)
	}
	canonicalKeys := append([]string(nil), keyIDs...)
	sort.Strings(canonicalKeys)
	return ReauthIntent{
		variant: variant, environmentID: canonicalEnvironments[0],
		environmentIDs: canonicalEnvironments, keyIDs: canonicalKeys,
		keySet: strings.Join(canonicalKeys, "\n"), environmentSet: strings.Join(canonicalEnvironments, "\n"),
	}, nil
}

func NewAdapterConfigureReauthIntent(environmentIDs []string) (ReauthIntent, error) {
	return NewAdapterReauthIntent(string(authz.OpAdapterConfigure), environmentIDs)
}

func NewAdapterCredentialSetReauthIntent(environmentIDs []string) (ReauthIntent, error) {
	return NewAdapterReauthIntent(string(authz.OpAdapterCredentialSet), environmentIDs)
}

func NewAdapterAdoptReauthIntent(environmentIDs []string) (ReauthIntent, error) {
	return NewAdapterReauthIntent(string(authz.OpAdapterAdopt), environmentIDs)
}

func NewAdapterSyncReauthIntent(environmentIDs []string) (ReauthIntent, error) {
	return NewAdapterReauthIntent(string(authz.OpAdapterSync), environmentIDs)
}

// NewAdapterReauthIntent parses the wire adapter operation into one of four
// closed variants. Other authz operations cannot inhabit an adapter intent.
func NewAdapterReauthIntent(operation string, environmentIDs []string) (ReauthIntent, error) {
	return newReauthIntentForAdapterOperation(authz.Operation(operation), environmentIDs)
}

func newReauthIntentForAdapterOperation(operation authz.Operation, environmentIDs []string) (ReauthIntent, error) {
	descriptor, ok := descriptorForOperation(operation)
	if !ok || !descriptor.adapter {
		return ReauthIntent{}, ErrReauthUnitMismatch
	}
	return newAdapterReauthIntent(descriptor.variant, environmentIDs)
}

func newReauthIntentFromBinding(purpose ReauthPurpose, operation authz.Operation, environmentIDs, keyIDs []string) (ReauthIntent, error) {
	var (
		intent ReauthIntent
		err    error
	)
	if purpose == PurposeAdapter {
		if len(keyIDs) != 0 {
			return ReauthIntent{}, ErrReauthUnitMismatch
		}
		intent, err = newReauthIntentForAdapterOperation(operation, environmentIDs)
	} else {
		intent, err = NewDisclosureReauthIntent(purpose, environmentIDs, keyIDs)
	}
	if err != nil {
		return ReauthIntent{}, err
	}
	binding, err := intent.bindingFor(environmentIDs[0])
	if err != nil || binding.purpose != purpose || binding.operation != operation {
		return ReauthIntent{}, ErrReauthUnitMismatch
	}
	return intent, nil
}

func newAdapterReauthIntent(variant reauthIntentVariant, environmentIDs []string) (ReauthIntent, error) {
	canonical := append([]string(nil), environmentIDs...)
	sort.Strings(canonical)
	canonical = slices.Compact(canonical)
	if len(canonical) == 0 {
		return ReauthIntent{}, fmt.Errorf("%w: adapter reauthentication intent requires environments", domain.ErrInvalid)
	}
	for _, environmentID := range canonical {
		if environmentID == "" {
			return ReauthIntent{}, fmt.Errorf("%w: adapter reauthentication intent contains an empty environment", domain.ErrInvalid)
		}
	}
	return ReauthIntent{
		variant: variant, environmentID: canonical[0], environmentIDs: canonical,
		environmentSet: strings.Join(canonical, "\n"),
	}, nil
}

// bindingFor derives every persisted and signed field from the closed variant.
// Adapter ceremonies additionally name the member of the canonical full set
// whose window is being opened or consumed.
func (i ReauthIntent) bindingFor(adapterEnvironmentID string) (reauthIntentBinding, error) {
	binding := reauthIntentBinding{
		environmentID: i.environmentID,
		keyIDs:        append([]string(nil), i.keyIDs...),
		keySet:        i.keySet,
	}
	descriptor, ok := descriptorForVariant(i.variant)
	if !ok {
		return reauthIntentBinding{}, fmt.Errorf("%w: unknown reauthentication intent variant", domain.ErrInvalid)
	}
	if descriptor.variant == intentUnbound {
		return binding, nil
	}
	binding.purpose, binding.operation = descriptor.purpose, descriptor.operation

	if descriptor.adapter {
		binding.environmentIDs = append([]string(nil), i.environmentIDs...)
		binding.environmentSet = i.environmentSet
		if adapterEnvironmentID == "" {
			adapterEnvironmentID = i.environmentID
		}
		if adapterEnvironmentID == "" || !slices.Contains(binding.environmentIDs, adapterEnvironmentID) {
			return reauthIntentBinding{}, ErrReauthUnitMismatch
		}
		binding.environmentID = adapterEnvironmentID
		challengeBinding, err := adapterOperationBinding(binding.operation, binding.environmentID, binding.environmentIDs)
		if err != nil {
			return reauthIntentBinding{}, err
		}
		binding.challengeBinding = challengeBinding
		return binding, nil
	}
	if adapterEnvironmentID != "" && adapterEnvironmentID != binding.environmentID {
		return reauthIntentBinding{}, ErrReauthUnitMismatch
	}
	challengeBinding, err := operationBinding(binding.purpose, binding.environmentID, binding.keyIDs)
	if err != nil {
		return reauthIntentBinding{}, err
	}
	binding.challengeBinding = challengeBinding
	return binding, nil
}

// ForEnvironment selects one environment from an already canonical intent.
// It is used where one member of an adapter or CLI environment set is about to
// be signed or consumed; a non-member cannot be represented by the result.
func (i ReauthIntent) ForEnvironment(environmentID string) (ReauthIntent, error) {
	if !slices.Contains(i.environmentIDs, environmentID) {
		return ReauthIntent{}, ErrReauthUnitMismatch
	}
	i.environmentID = environmentID
	return i, nil
}

func (i ReauthIntent) Purpose() (ReauthPurpose, error) {
	binding, err := i.bindingFor(i.environmentID)
	if err != nil {
		return "", err
	}
	return binding.purpose, nil
}

func (i ReauthIntent) Operation() (authz.Operation, error) {
	binding, err := i.bindingFor(i.environmentID)
	if err != nil {
		return "", err
	}
	return binding.operation, nil
}

func (i ReauthIntent) EnvironmentIDs() []string {
	return append([]string(nil), i.environmentIDs...)
}

func (i ReauthIntent) KeyIDs() []string {
	return append([]string(nil), i.keyIDs...)
}

func (i ReauthIntent) isUnbound() (bool, error) {
	descriptor, ok := descriptorForVariant(i.variant)
	if !ok {
		return false, fmt.Errorf("%w: unknown reauthentication intent variant", domain.ErrInvalid)
	}
	return descriptor.variant == intentUnbound, nil
}

func (i ReauthIntent) isAdapter() (bool, error) {
	descriptor, ok := descriptorForVariant(i.variant)
	if !ok {
		return false, fmt.Errorf("%w: unknown reauthentication intent variant", domain.ErrInvalid)
	}
	return descriptor.adapter, nil
}
