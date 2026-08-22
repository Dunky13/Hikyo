package crypto

import (
	"fmt"
	"strings"
	"time"
)

// SnapshotBindingScope is the locally known identity of one offline snapshot.
// It is validated and copied by NewSnapshotBinding before it can be used for a
// filesystem lookup or compared with an authenticated snapshot header.
type SnapshotBindingScope struct {
	StorageDir            string
	InstanceOrigin        string
	OrgID                 string
	ProjectID             string
	EnvironmentID         string
	CredentialFingerprint string
	ConfigOnly            bool
	TargetNames           []string
}

// SnapshotBindingDelivery is the server-asserted remainder of a snapshot
// binding. WithDelivery adds it atomically: callers cannot construct a binding
// containing only some revision, projection, or issuance fields.
type SnapshotBindingDelivery struct {
	CredentialID   string
	PinnedRevision int64
	ChangeToken    string
	Projection     []string
	IssuedAt       string
	ExpiresAt      string
}

// SnapshotBinding carries one validated snapshot identity through both live
// and offline paths. Its scope-only state is valid for locating and checking an
// offline snapshot. Its delivery-complete state additionally owns every field
// required to derive the serialized SnapshotAAD.
//
// Fields are private so list canonicalization and issuance-window validation
// cannot be bypassed by mutation after construction.
type SnapshotBinding struct {
	scope    SnapshotBindingScope
	delivery *SnapshotBindingDelivery
}

// NewSnapshotBinding validates and owns the locally derivable snapshot scope.
func NewSnapshotBinding(scope SnapshotBindingScope) (SnapshotBinding, error) {
	canonical, err := canonicalSnapshotScope(scope)
	if err != nil {
		return SnapshotBinding{}, err
	}
	return SnapshotBinding{scope: canonical}, nil
}

// WithDelivery returns a delivery-complete binding. A binding can be completed
// once only, preventing accidental reconstruction with a second response.
func (b SnapshotBinding) WithDelivery(delivery SnapshotBindingDelivery) (SnapshotBinding, error) {
	if err := b.validateScope(); err != nil {
		return SnapshotBinding{}, err
	}
	if b.delivery != nil {
		return SnapshotBinding{}, fmt.Errorf("crypto: snapshot binding already has delivery fields")
	}
	canonical, err := canonicalSnapshotDelivery(delivery)
	if err != nil {
		return SnapshotBinding{}, err
	}
	b.delivery = &canonical
	return b, nil
}

// CanonicalAAD derives the stable serialized AAD bytes from a complete binding.
func (b SnapshotBinding) CanonicalAAD() ([]byte, error) {
	aad, err := b.AAD()
	if err != nil {
		return nil, err
	}
	return aad.Canonical()
}

// AAD derives a detached serialization value from a complete binding. Slices
// are copied, so mutating the returned DTO cannot mutate the binding.
func (b SnapshotBinding) AAD() (SnapshotAAD, error) {
	if err := b.validateComplete(); err != nil {
		return SnapshotAAD{}, err
	}
	delivery := *b.delivery
	return SnapshotAAD{
		InstanceOrigin:        b.scope.InstanceOrigin,
		OrgID:                 b.scope.OrgID,
		ProjectID:             b.scope.ProjectID,
		EnvironmentID:         b.scope.EnvironmentID,
		CredentialID:          delivery.CredentialID,
		CredentialFingerprint: b.scope.CredentialFingerprint,
		ConfigOnly:            b.scope.ConfigOnly,
		TargetNames:           append([]string(nil), b.scope.TargetNames...),
		PinnedRevision:        delivery.PinnedRevision,
		ChangeToken:           delivery.ChangeToken,
		Projection:            append([]string(nil), delivery.Projection...),
		IssuedAt:              delivery.IssuedAt,
		ExpiresAt:             delivery.ExpiresAt,
	}, nil
}

// StorageDir returns the validated local storage locator owned by the binding.
// It is intentionally absent from SnapshotAAD: moving a state directory does
// not change cryptographic or serialized snapshot identity.
func (b SnapshotBinding) StorageDir() (string, error) {
	if err := b.validateScope(); err != nil {
		return "", err
	}
	return b.scope.StorageDir, nil
}

// ParseSnapshotBinding validates an existing serialized AAD header without
// changing its field names, ordering, or timestamp spellings.
func ParseSnapshotBinding(storageDir string, header []byte) (SnapshotBinding, error) {
	aad, err := ParseSnapshotHeader(header)
	if err != nil {
		return SnapshotBinding{}, err
	}
	binding, err := NewSnapshotBinding(SnapshotBindingScope{
		StorageDir:            storageDir,
		InstanceOrigin:        aad.InstanceOrigin,
		OrgID:                 aad.OrgID,
		ProjectID:             aad.ProjectID,
		EnvironmentID:         aad.EnvironmentID,
		CredentialFingerprint: aad.CredentialFingerprint,
		ConfigOnly:            aad.ConfigOnly,
		TargetNames:           aad.TargetNames,
	})
	if err != nil {
		return SnapshotBinding{}, err
	}
	return binding.WithDelivery(SnapshotBindingDelivery{
		CredentialID:   aad.CredentialID,
		PinnedRevision: aad.PinnedRevision,
		ChangeToken:    aad.ChangeToken,
		Projection:     aad.Projection,
		IssuedAt:       aad.IssuedAt,
		ExpiresAt:      aad.ExpiresAt,
	})
}

// ContextMatches compares the locally knowable scope of two validated
// bindings. Server-only delivery fields are intentionally not expectations on
// an offline box.
func (b SnapshotBinding) ContextMatches(expect SnapshotBinding) error {
	if err := b.validateComplete(); err != nil {
		return err
	}
	if err := expect.validateScope(); err != nil {
		return err
	}
	for _, field := range []struct {
		name     string
		got, exp string
	}{
		{"instance", b.scope.InstanceOrigin, expect.scope.InstanceOrigin},
		{"org", b.scope.OrgID, expect.scope.OrgID},
		{"project", b.scope.ProjectID, expect.scope.ProjectID},
		{"environment", b.scope.EnvironmentID, expect.scope.EnvironmentID},
		{"credential", b.scope.CredentialFingerprint, expect.scope.CredentialFingerprint},
	} {
		if field.got != field.exp {
			return fmt.Errorf("crypto: snapshot %s %q does not match local context %q", field.name, field.got, field.exp)
		}
	}
	if b.scope.ConfigOnly != expect.scope.ConfigOnly {
		return fmt.Errorf("crypto: snapshot config_only=%v does not match local context config_only=%v", b.scope.ConfigOnly, expect.scope.ConfigOnly)
	}
	if !equalStrings(b.scope.TargetNames, expect.scope.TargetNames) {
		return fmt.Errorf("crypto: snapshot target set %v does not match local context %v", b.scope.TargetNames, expect.scope.TargetNames)
	}
	return nil
}

// ValidateScope reports whether the binding can safely identify an offline
// snapshot. Both scope-only and delivery-complete bindings are valid locators.
func (b SnapshotBinding) ValidateScope() error {
	return b.validateScope()
}

func (b SnapshotBinding) validateScope() error {
	_, err := canonicalSnapshotScope(b.scope)
	return err
}

func (b SnapshotBinding) validateComplete() error {
	if err := b.validateScope(); err != nil {
		return err
	}
	if b.delivery == nil {
		return fmt.Errorf("crypto: snapshot binding has no delivery fields")
	}
	_, err := canonicalSnapshotDelivery(*b.delivery)
	return err
}

func canonicalSnapshotScope(scope SnapshotBindingScope) (SnapshotBindingScope, error) {
	for _, field := range []struct {
		name, value string
	}{
		{"storage dir", scope.StorageDir},
		{"instance origin", scope.InstanceOrigin},
		{"org id", scope.OrgID},
		{"project id", scope.ProjectID},
		{"environment id", scope.EnvironmentID},
		{"credential fingerprint", scope.CredentialFingerprint},
	} {
		if strings.TrimSpace(field.value) == "" {
			return SnapshotBindingScope{}, fmt.Errorf("crypto: snapshot binding %s is required", field.name)
		}
	}
	targets, err := canonicalRequiredSet("target", scope.TargetNames)
	if err != nil {
		return SnapshotBindingScope{}, err
	}
	scope.TargetNames = targets
	return scope, nil
}

func canonicalSnapshotDelivery(delivery SnapshotBindingDelivery) (SnapshotBindingDelivery, error) {
	for _, field := range []struct {
		name, value string
	}{
		{"credential id", delivery.CredentialID},
		{"change token", delivery.ChangeToken},
		{"issued at", delivery.IssuedAt},
		{"expires at", delivery.ExpiresAt},
	} {
		if strings.TrimSpace(field.value) == "" {
			return SnapshotBindingDelivery{}, fmt.Errorf("crypto: snapshot binding %s is required", field.name)
		}
	}
	if delivery.PinnedRevision < 0 {
		return SnapshotBindingDelivery{}, fmt.Errorf("crypto: snapshot binding pinned revision must not be negative")
	}
	projection, err := canonicalRequiredSet("projection", delivery.Projection)
	if err != nil {
		return SnapshotBindingDelivery{}, err
	}
	issued, err := time.Parse(time.RFC3339, delivery.IssuedAt)
	if err != nil {
		return SnapshotBindingDelivery{}, fmt.Errorf("crypto: snapshot binding issued_at %q is not RFC3339: %w", delivery.IssuedAt, err)
	}
	expires, err := time.Parse(time.RFC3339, delivery.ExpiresAt)
	if err != nil {
		return SnapshotBindingDelivery{}, fmt.Errorf("crypto: snapshot binding expires_at %q is not RFC3339: %w", delivery.ExpiresAt, err)
	}
	if !expires.After(issued) {
		return SnapshotBindingDelivery{}, fmt.Errorf("crypto: snapshot binding expires_at %q must be after issued_at %q", delivery.ExpiresAt, delivery.IssuedAt)
	}
	delivery.IssuedAt = issued.UTC().Format(time.RFC3339Nano)
	delivery.ExpiresAt = expires.UTC().Format(time.RFC3339Nano)
	delivery.Projection = projection
	return delivery, nil
}

func canonicalRequiredSet(name string, items []string) ([]string, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("crypto: snapshot binding %s set is required", name)
	}
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return nil, fmt.Errorf("crypto: snapshot binding %s set contains an empty value", name)
		}
	}
	return CanonicalStringSet(items), nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
