package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	wencrypto "github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/samlsp"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

var (
	ErrSAMLProviderRace               = errors.New("service: SAML provider row changed underneath this write")
	ErrSAMLEntityIDImmutable          = errors.New("service: a SAML provider entityID is immutable; delete and recreate")
	ErrSAMLMetadataSource             = errors.New("service: SAML metadata source must be exactly one file document or URL")
	ErrSAMLMetadataFetch              = errors.New("service: SAML metadata fetch failed")
	ErrSAMLMetadataInvalid            = errors.New("service: SAML metadata is invalid")
	ErrSAMLMetadataSignatureDowngrade = errors.New("service: unsigned SAML metadata cannot replace signed metadata")
)

// SAMLProviders is instance-scoped SAML provider administration.
type SAMLProviders struct {
	DB             *store.DB
	Keyring        *wencrypto.Keyring
	ExternalOrigin string
	HTTPClient     *http.Client
	Now            func() time.Time
}

func (s *SAMLProviders) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

type SAMLProviderInput struct {
	DisplayName           string
	EntityID              string
	MetadataSource        string
	MetadataDocument      []byte
	MetadataURL           *string
	AssurancePolicy       *[]string
	AllowEmailNameID      bool
	ForceSignRequests     bool
	Enabled               bool
	ConfirmedFingerprints []string
	ConfirmedEndpoints    []string
}

type SAMLProviderPatch struct {
	DisplayName       *string
	AssurancePolicy   *[]string
	AllowEmailNameID  *bool
	ForceSignRequests *bool
	Enabled           *bool
}

type SAMLMetadataRefreshInput struct {
	MetadataDocument      []byte
	ConfirmedFingerprints []string
	ConfirmedEndpoints    []string
}

type SAMLProviderView struct {
	id                             string
	Slug                           string
	DisplayName                    string
	EntityID                       string
	ACSURL                         string
	SSORedirectURL                 string
	SigningCertificateFingerprints []string
	AssurancePolicy                *[]string
	AllowEmailNameID               bool
	ForceSignRequests              bool
	MetadataSource                 string
	MetadataURL                    *string
	MetadataSigned                 bool
	MetadataSigningFingerprint     *string
	MetadataValidUntil             *time.Time
	Warnings                       []SAMLProviderWarning
	Enabled                        bool
	RowVersion                     int64
	CreatedAt                      time.Time
	UpdatedAt                      time.Time
}

// SAMLProviderWarning is the server-authoritative provider health result used
// by admin views and doctor. EffectiveAt is the metadata/certificate boundary
// that caused the warning; Fingerprint is present only for certificate rows.
type SAMLProviderWarning struct {
	Code        string
	Severity    string
	Message     string
	EffectiveAt time.Time
	Fingerprint *string
}

// SAMLMetadataDiff is the complete trust-material change shown before a
// provider mutation is applied. Empty collections are non-nil for stable JSON.
type SAMLMetadataDiff struct {
	EndpointsAdded   []string
	EndpointsRemoved []string
	CertsAddedFps    []string
	CertsRemovedFps  []string
	ValidUntil       *time.Time
}

// SAMLProviderMutationResult is both legs of the metadata ceremony. A false
// Applied value is a successful preview and guarantees that no state changed.
type SAMLProviderMutationResult struct {
	Applied              bool
	Provider             *SAMLProviderView
	Diff                 SAMLMetadataDiff
	RequiredFingerprints []string
	RequiredEndpoints    []string
}

func (s *SAMLProviders) acsURL(slug string) string {
	return strings.TrimRight(s.ExternalOrigin, "/") + "/api/v1/auth/saml/" + slug + "/acs"
}

func (s *SAMLProviders) Put(ctx context.Context, actor Actor, slug string, input SAMLProviderInput) (SAMLProviderMutationResult, error) {
	if err := s.authorize(ctx, actor, authz.OpSAMLProviderPut); err != nil {
		return SAMLProviderMutationResult{}, err
	}
	fail := func(cause string, original error) (SAMLProviderMutationResult, error) {
		return SAMLProviderMutationResult{}, s.recordProviderFailure(ctx, actor, authz.OpSAMLProviderPut,
			audit.EventSAMLProviderConfigure, slug, input.EntityID, input.MetadataSource,
			input.ConfirmedFingerprints, cause, original)
	}
	if input.EntityID == "" {
		return fail("metadata-source", ErrSAMLMetadataSource)
	}
	raw, err := s.metadataBytes(ctx, input.MetadataSource, input.MetadataDocument, input.MetadataURL)
	if err != nil {
		return fail("metadata-fetch", err)
	}
	metadata, err := samlsp.ParseMetadata(raw, input.EntityID)
	if err != nil {
		return fail("metadata-invalid", fmt.Errorf("%w: %v", ErrSAMLMetadataInvalid, err))
	}
	var previous *authz.SAMLProvider
	if err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		provider, readErr := az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(readErr, domain.ErrNotFound) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		previous = &provider
		return nil
	}); err != nil {
		return SAMLProviderMutationResult{}, err
	}
	if previous != nil && previous.EntityID != input.EntityID {
		return fail("entity-id-immutable", ErrSAMLEntityIDImmutable)
	}
	if previous != nil && previous.MetadataSigned && !metadata.Signed {
		return fail("signature-downgrade", ErrSAMLMetadataSignatureDowngrade)
	}
	assessment, err := assessSAMLMetadata(metadata, previous, input.ConfirmedFingerprints, input.ConfirmedEndpoints)
	if err != nil {
		return fail("trust-confirmation", err)
	}
	if len(assessment.RequiredFingerprints) != 0 || len(assessment.RequiredEndpoints) != 0 {
		return assessment.preview(), nil
	}
	policy, err := encodeSAMLPolicy(input.AssurancePolicy)
	if err != nil {
		return SAMLProviderMutationResult{}, err
	}
	var generatedKey generatedSAMLSPKey
	if previous == nil {
		generatedKey, err = s.generateSPKey()
		if err != nil {
			return fail("sp-key-generation", err)
		}
	}

	var output SAMLProviderView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderPut, domain.Scope{})
		if err != nil {
			return err
		}
		existing, err := az.SAMLProviderBySlug(ctx, slug)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			if previous != nil {
				return ErrSAMLProviderRace
			}
			providerID, idErr := newID("samlp")
			if idErr != nil {
				return idErr
			}
			now := s.now()
			provider := authz.NewSAMLProvider{
				ID: providerID, Slug: slug, DisplayName: input.DisplayName, EntityID: metadata.EntityID,
				ACSURL: s.acsURL(slug), SSORedirectURL: metadata.SSOURL,
				SigningCertificates: assessment.CertificatesJSON, AssurancePolicy: policy,
				AllowEmailNameID:                input.AllowEmailNameID,
				ForceSignRequests:               input.ForceSignRequests,
				MetadataWantAuthnRequestsSigned: metadata.WantAuthnRequestsSigned,
				MetadataSource:                  input.MetadataSource, MetadataURL: input.MetadataURL,
				MetadataSigned: metadata.Signed, MetadataSigningFingerprint: assessment.MetadataFingerprint,
				MetadataValidUntil: metadata.ValidUntil, Enabled: input.Enabled, CreatedAt: now, UpdatedAt: now,
			}
			if err := az.CreateSAMLProvider(ctx, provider); err != nil {
				return err
			}
			if err := s.ensureSPKey(ctx, az, caller.Principal, generatedKey); err != nil {
				return err
			}
			output, err = samlProviderView(authz.SAMLProvider{
				ID: provider.ID, Slug: provider.Slug, DisplayName: provider.DisplayName, Kind: SAMLKind,
				EntityID: provider.EntityID, ACSURL: provider.ACSURL, SSORedirectURL: provider.SSORedirectURL,
				SigningCertificates: provider.SigningCertificates, AssurancePolicy: provider.AssurancePolicy,
				AllowEmailNameID: provider.AllowEmailNameID, ForceSignRequests: provider.ForceSignRequests,
				MetadataWantAuthnRequestsSigned: provider.MetadataWantAuthnRequestsSigned,
				MetadataSource:                  provider.MetadataSource, MetadataURL: provider.MetadataURL,
				MetadataSigned: provider.MetadataSigned, MetadataSigningFingerprint: provider.MetadataSigningFingerprint,
				MetadataValidUntil: provider.MetadataValidUntil, Enabled: provider.Enabled, RowVersion: 1,
				CreatedAt: now, UpdatedAt: now,
			}, s.now())
			if err != nil {
				return err
			}
			emailState := ""
			if input.AllowEmailNameID {
				emailState = "set"
			}
			return s.recordProviderMutationEvents(ctx, repos, proof, caller.Principal,
				audit.EventSAMLProviderConfigure, output, assessment.Diff, input.ConfirmedFingerprints, emailState)
		case err != nil:
			return err
		}
		if previous == nil {
			return ErrSAMLProviderRace
		}
		if existing.EntityID != input.EntityID {
			return ErrSAMLEntityIDImmutable
		}
		if existing.RowVersion != previous.RowVersion {
			return ErrSAMLProviderRace
		}
		if existing.MetadataSigned && !metadata.Signed {
			return ErrSAMLMetadataSignatureDowngrade
		}
		swept, err := s.updateProvider(ctx, az, existing, input.DisplayName, assessment.CertificatesJSON, policy,
			input.AllowEmailNameID, input.ForceSignRequests, metadata.WantAuthnRequestsSigned,
			input.MetadataSource, input.MetadataURL, metadata, input.Enabled)
		if err != nil {
			return err
		}
		updated, err := az.SAMLProviderBySlug(ctx, slug)
		if err != nil {
			return err
		}
		output, err = samlProviderView(updated, s.now())
		if err != nil {
			return err
		}
		emailState := ""
		if existing.AllowEmailNameID != input.AllowEmailNameID {
			emailState = "unset"
			if input.AllowEmailNameID {
				emailState = "set"
			}
		}
		_ = swept
		return s.recordProviderMutationEvents(ctx, repos, proof, caller.Principal,
			audit.EventSAMLProviderConfigure, output, assessment.Diff, input.ConfirmedFingerprints, emailState)
	})
	if err != nil {
		return fail("mutation", err)
	}
	return assessment.applied(output), nil
}

func (s *SAMLProviders) authorize(ctx context.Context, actor Actor, operation authz.Operation) error {
	return tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		_, err = az.Authorize(ctx, caller, operation, domain.Scope{})
		return err
	})
}

func (s *SAMLProviders) Patch(ctx context.Context, actor Actor, slug string, patch SAMLProviderPatch) (SAMLProviderView, error) {
	var output SAMLProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderPatch, domain.Scope{})
		if err != nil {
			return err
		}
		provider, err := az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLProviderNotFound
		}
		if err != nil {
			return err
		}
		displayName := provider.DisplayName
		if patch.DisplayName != nil {
			displayName = *patch.DisplayName
		}
		policy := provider.AssurancePolicy
		if patch.AssurancePolicy != nil {
			policy, err = encodeSAMLPolicy(patch.AssurancePolicy)
			if err != nil {
				return err
			}
		}
		allowEmail := provider.AllowEmailNameID
		priorAllowEmail := allowEmail
		if patch.AllowEmailNameID != nil {
			allowEmail = *patch.AllowEmailNameID
		}
		forceSign := provider.ForceSignRequests
		if patch.ForceSignRequests != nil {
			forceSign = *patch.ForceSignRequests
		}
		enabled := provider.Enabled
		if patch.Enabled != nil {
			enabled = *patch.Enabled
		}
		updated, err := az.UpdateSAMLProvider(ctx, authz.SAMLProviderUpdate{
			ID: provider.ID, DisplayName: displayName, ACSURL: provider.ACSURL,
			SSORedirectURL: provider.SSORedirectURL, SigningCertificates: provider.SigningCertificates,
			AssurancePolicy: policy, AllowEmailNameID: allowEmail, ForceSignRequests: forceSign,
			MetadataWantAuthnRequestsSigned: provider.MetadataWantAuthnRequestsSigned,
			MetadataSource:                  provider.MetadataSource, MetadataURL: provider.MetadataURL,
			MetadataSigned: provider.MetadataSigned, MetadataSigningFingerprint: provider.MetadataSigningFingerprint,
			MetadataValidUntil: provider.MetadataValidUntil, Enabled: enabled,
			RowVersion: provider.RowVersion, UpdatedAt: s.now(),
		})
		if err != nil {
			return err
		}
		if !updated {
			return ErrSAMLProviderRace
		}
		swept := int64(0)
		if provider.Enabled && !enabled || !equalOptionalString(provider.AssurancePolicy, policy) || provider.AllowEmailNameID != allowEmail {
			swept, err = az.SweepSessionsForSAMLProvider(ctx, provider.ID)
			if err != nil {
				return err
			}
		}
		provider.DisplayName, provider.AssurancePolicy = displayName, policy
		provider.AllowEmailNameID, provider.ForceSignRequests, provider.Enabled = allowEmail, forceSign, enabled
		provider.RowVersion++
		provider.UpdatedAt = s.now()
		output, err = samlProviderView(provider, s.now())
		if err != nil {
			return err
		}
		if patch.AllowEmailNameID != nil && allowEmail != priorAllowEmail {
			state := "unset"
			if allowEmail {
				state = "set"
			}
			event, eventErr := newAuditEvent(ctx, audit.EventSAMLEmailNameIDOptIn, caller.Principal,
				audit.Object{Type: "saml_provider", ID: provider.ID}, audit.OutcomeSuccess, "",
				audit.Payload{"provider_id": provider.ID, "entity_id": provider.EntityID, "state": state})
			if eventErr != nil {
				return eventErr
			}
			if eventErr := az.RecordAuthEvent(ctx, event); eventErr != nil {
				return eventErr
			}
		}
		_ = swept
		return s.recordProviderEvent(ctx, repos, proof, caller.Principal, audit.EventSAMLProviderConfigure, output, nil, nil)
	})
	return output, err
}

func (s *SAMLProviders) Get(ctx context.Context, actor Actor, slug string) (SAMLProviderView, error) {
	var output SAMLProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderGet, domain.Scope{})
		if err != nil {
			return err
		}
		provider, err := az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLProviderNotFound
		}
		if err != nil {
			return err
		}
		output, err = samlProviderView(provider, s.now())
		if err != nil {
			return err
		}
		if err := s.recordProviderRead(ctx, repos, proof, caller.Principal, "get", 1); err != nil {
			return err
		}
		return s.recordMetadataExpiryWarnings(ctx, repos, proof, caller.Principal, []SAMLProviderView{output})
	})
	return output, err
}

func (s *SAMLProviders) List(ctx context.Context, actor Actor) ([]SAMLProviderView, error) {
	var output []SAMLProviderView
	err := tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderList, domain.Scope{})
		if err != nil {
			return err
		}
		providers, err := az.ListSAMLProviders(ctx)
		if err != nil {
			return err
		}
		output = make([]SAMLProviderView, 0, len(providers))
		for _, provider := range providers {
			view, viewErr := samlProviderView(provider, s.now())
			if viewErr != nil {
				return viewErr
			}
			output = append(output, view)
		}
		if err := s.recordProviderRead(ctx, repos, proof, caller.Principal, "list", len(output)); err != nil {
			return err
		}
		return s.recordMetadataExpiryWarnings(ctx, repos, proof, caller.Principal, output)
	})
	return output, err
}

func (s *SAMLProviders) Delete(ctx context.Context, actor Actor, slug string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderDelete, domain.Scope{})
		if err != nil {
			return err
		}
		provider, err := az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLProviderNotFound
		}
		if err != nil {
			return err
		}
		if err := az.LockSAMLProviderForDelete(ctx, provider.ID); err != nil {
			return err
		}
		swept, err := az.SweepSessionsForSAMLProvider(ctx, provider.ID)
		if err != nil {
			return err
		}
		if err := az.DeleteSAMLProvider(ctx, provider.ID); err != nil {
			return err
		}
		view, err := samlProviderView(provider, s.now())
		if err != nil {
			return err
		}
		_ = swept
		return s.recordProviderEvent(ctx, repos, proof, caller.Principal, audit.EventSAMLProviderRemove, view, nil, nil)
	})
}

func (s *SAMLProviders) RefreshMetadata(ctx context.Context, actor Actor, slug string, input SAMLMetadataRefreshInput) (SAMLProviderMutationResult, error) {
	var existing authz.SAMLProvider
	if err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		if _, err = az.Authorize(ctx, caller, authz.OpSAMLProviderRefreshMetadata, domain.Scope{}); err != nil {
			return err
		}
		existing, err = az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(err, domain.ErrNotFound) {
			return ErrSAMLProviderNotFound
		}
		return err
	}); err != nil {
		return SAMLProviderMutationResult{}, err
	}
	fail := func(cause string, original error) (SAMLProviderMutationResult, error) {
		return SAMLProviderMutationResult{}, s.recordProviderFailure(ctx, actor, authz.OpSAMLProviderRefreshMetadata,
			audit.EventSAMLProviderRefresh, slug, existing.EntityID, existing.MetadataSource,
			input.ConfirmedFingerprints, cause, original)
	}
	raw, err := s.metadataBytes(ctx, existing.MetadataSource, input.MetadataDocument, existing.MetadataURL)
	if err != nil {
		return fail("metadata-fetch", err)
	}
	metadata, err := samlsp.ParseMetadata(raw, existing.EntityID)
	if err != nil {
		return fail("metadata-invalid", fmt.Errorf("%w: %v", ErrSAMLMetadataInvalid, err))
	}
	if existing.MetadataSigned && !metadata.Signed {
		return fail("signature-downgrade", ErrSAMLMetadataSignatureDowngrade)
	}
	assessment, err := assessSAMLMetadata(metadata, &existing, input.ConfirmedFingerprints, input.ConfirmedEndpoints)
	if err != nil {
		return fail("trust-confirmation", err)
	}
	if len(assessment.RequiredFingerprints) != 0 || len(assessment.RequiredEndpoints) != 0 {
		return assessment.preview(), nil
	}
	var output SAMLProviderView
	err = tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, authz.OpSAMLProviderRefreshMetadata, domain.Scope{})
		if err != nil {
			return err
		}
		fresh, err := az.SAMLProviderBySlug(ctx, slug)
		if err != nil {
			return err
		}
		if fresh.RowVersion != existing.RowVersion || fresh.EntityID != existing.EntityID {
			return ErrSAMLProviderRace
		}
		if fresh.MetadataSigned && !metadata.Signed {
			return ErrSAMLMetadataSignatureDowngrade
		}
		swept, err := s.updateProvider(ctx, az, fresh, fresh.DisplayName, assessment.CertificatesJSON,
			fresh.AssurancePolicy, fresh.AllowEmailNameID,
			fresh.ForceSignRequests, metadata.WantAuthnRequestsSigned,
			fresh.MetadataSource, fresh.MetadataURL, metadata, fresh.Enabled)
		if err != nil {
			return err
		}
		fresh.SigningCertificates = assessment.CertificatesJSON
		fresh.SSORedirectURL = metadata.SSOURL
		fresh.MetadataWantAuthnRequestsSigned = metadata.WantAuthnRequestsSigned
		fresh.MetadataSigned = metadata.Signed
		fresh.MetadataSigningFingerprint = assessment.MetadataFingerprint
		fresh.MetadataValidUntil = metadata.ValidUntil
		fresh.RowVersion++
		fresh.UpdatedAt = s.now()
		output, err = samlProviderView(fresh, s.now())
		if err != nil {
			return err
		}
		_ = swept
		return s.recordProviderMutationEvents(ctx, repos, proof, caller.Principal,
			audit.EventSAMLProviderRefresh, output, assessment.Diff, input.ConfirmedFingerprints, "")
	})
	if err != nil {
		return fail("mutation", err)
	}
	return assessment.applied(output), nil
}

type samlMetadataAssessment struct {
	CertificatesJSON     []byte
	MetadataFingerprint  *string
	Diff                 SAMLMetadataDiff
	RequiredFingerprints []string
	RequiredEndpoints    []string
}

func (a samlMetadataAssessment) preview() SAMLProviderMutationResult {
	return SAMLProviderMutationResult{
		Applied: false, Diff: a.Diff,
		RequiredFingerprints: slices.Clone(a.RequiredFingerprints),
		RequiredEndpoints:    slices.Clone(a.RequiredEndpoints),
	}
}

func (a samlMetadataAssessment) applied(provider SAMLProviderView) SAMLProviderMutationResult {
	return SAMLProviderMutationResult{
		Applied: true, Provider: &provider, Diff: a.Diff,
		RequiredFingerprints: []string{}, RequiredEndpoints: []string{},
	}
}

func assessSAMLMetadata(metadata samlsp.Metadata, previous *authz.SAMLProvider, confirmed, confirmedEndpoints []string) (samlMetadataAssessment, error) {
	confirmedSet := make(map[string]bool, len(confirmed))
	for _, fingerprint := range confirmed {
		confirmedSet[fingerprint] = true
	}
	oldFingerprints := map[string]bool{}
	oldEndpoint := ""
	if previous != nil {
		oldEndpoint = previous.SSORedirectURL
		oldCertificates, err := parseSAMLCertificates(previous.SigningCertificates)
		if err != nil {
			return samlMetadataAssessment{}, err
		}
		for _, certificate := range oldCertificates {
			fingerprint, err := certificateFingerprint(certificate)
			if err != nil {
				return samlMetadataAssessment{}, err
			}
			oldFingerprints[fingerprint] = true
		}
	}
	assessment := samlMetadataAssessment{
		Diff: SAMLMetadataDiff{
			EndpointsAdded: []string{}, EndpointsRemoved: []string{},
			CertsAddedFps: []string{}, CertsRemovedFps: []string{}, ValidUntil: metadata.ValidUntil,
		},
		RequiredFingerprints: []string{}, RequiredEndpoints: []string{},
	}
	if oldEndpoint != metadata.SSOURL {
		if metadata.SSOURL != "" {
			assessment.Diff.EndpointsAdded = append(assessment.Diff.EndpointsAdded, metadata.SSOURL)
			if !slices.Contains(confirmedEndpoints, metadata.SSOURL) {
				assessment.RequiredEndpoints = append(assessment.RequiredEndpoints, metadata.SSOURL)
			}
		}
		if oldEndpoint != "" {
			assessment.Diff.EndpointsRemoved = append(assessment.Diff.EndpointsRemoved, oldEndpoint)
		}
	}
	ders := make([][]byte, 0, len(metadata.SigningCertificates))
	newFingerprints := make(map[string]bool, len(metadata.SigningCertificates))
	for _, certificate := range metadata.SigningCertificates {
		fingerprint, err := certificateFingerprint(certificate)
		if err != nil {
			return samlMetadataAssessment{}, err
		}
		newFingerprints[fingerprint] = true
		if !oldFingerprints[fingerprint] {
			assessment.Diff.CertsAddedFps = append(assessment.Diff.CertsAddedFps, fingerprint)
			if !confirmedSet[fingerprint] {
				assessment.RequiredFingerprints = append(assessment.RequiredFingerprints, fingerprint)
			}
		}
		ders = append(ders, certificate.Raw)
	}
	for fingerprint := range oldFingerprints {
		if !newFingerprints[fingerprint] {
			assessment.Diff.CertsRemovedFps = append(assessment.Diff.CertsRemovedFps, fingerprint)
		}
	}
	if metadata.Signed {
		fingerprint, err := certificateFingerprint(metadata.SignatureCertificate)
		if err != nil {
			return samlMetadataAssessment{}, err
		}
		oldMetadataFingerprint := previous != nil && previous.MetadataSigningFingerprint != nil && *previous.MetadataSigningFingerprint == fingerprint
		if !oldMetadataFingerprint && !confirmedSet[fingerprint] {
			assessment.RequiredFingerprints = append(assessment.RequiredFingerprints, fingerprint)
		}
		assessment.MetadataFingerprint = &fingerprint
	}
	encoded, err := json.Marshal(ders)
	if err != nil {
		return samlMetadataAssessment{}, err
	}
	assessment.CertificatesJSON = encoded
	slices.Sort(assessment.Diff.EndpointsAdded)
	slices.Sort(assessment.Diff.EndpointsRemoved)
	slices.Sort(assessment.Diff.CertsAddedFps)
	slices.Sort(assessment.Diff.CertsRemovedFps)
	slices.Sort(assessment.RequiredFingerprints)
	assessment.RequiredFingerprints = slices.Compact(assessment.RequiredFingerprints)
	slices.Sort(assessment.RequiredEndpoints)
	assessment.RequiredEndpoints = slices.Compact(assessment.RequiredEndpoints)
	return assessment, nil
}

func certificateFingerprint(certificate *x509.Certificate) (string, error) {
	if certificate == nil {
		return "", errors.New("service: nil SAML certificate")
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spki)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func encodeSAMLPolicy(policy *[]string) (*string, error) {
	if policy == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(*policy)
	if err != nil {
		return nil, err
	}
	value := string(encoded)
	return &value, nil
}

func decodeSAMLPolicy(policy *string) (*[]string, error) {
	if policy == nil {
		return nil, nil
	}
	var refs []string
	if err := json.Unmarshal([]byte(*policy), &refs); err != nil {
		return nil, fmt.Errorf("service: parsing stored SAML assurance policy: %w", err)
	}
	return &refs, nil
}

func samlProviderView(provider authz.SAMLProvider, now time.Time) (SAMLProviderView, error) {
	fingerprints := make([]string, 0)
	certificates, err := parseSAMLCertificates(provider.SigningCertificates)
	if err != nil {
		return SAMLProviderView{}, err
	}
	for _, certificate := range certificates {
		fingerprint, err := certificateFingerprint(certificate)
		if err != nil {
			return SAMLProviderView{}, err
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	warnings, err := samlProviderWarnings(provider, now)
	if err != nil {
		return SAMLProviderView{}, err
	}
	policy, err := decodeSAMLPolicy(provider.AssurancePolicy)
	if err != nil {
		return SAMLProviderView{}, err
	}
	return SAMLProviderView{
		id:   provider.ID,
		Slug: provider.Slug, DisplayName: provider.DisplayName, EntityID: provider.EntityID,
		ACSURL: provider.ACSURL, SSORedirectURL: provider.SSORedirectURL,
		SigningCertificateFingerprints: fingerprints, AssurancePolicy: policy,
		AllowEmailNameID: provider.AllowEmailNameID, ForceSignRequests: provider.ForceSignRequests,
		MetadataSource: provider.MetadataSource, MetadataURL: provider.MetadataURL,
		MetadataSigned: provider.MetadataSigned, MetadataSigningFingerprint: provider.MetadataSigningFingerprint,
		MetadataValidUntil: provider.MetadataValidUntil, Warnings: warnings, Enabled: provider.Enabled,
		RowVersion: provider.RowVersion, CreatedAt: provider.CreatedAt, UpdatedAt: provider.UpdatedAt,
	}, nil
}

func samlProviderWarnings(provider authz.SAMLProvider, now time.Time) ([]SAMLProviderWarning, error) {
	warnings := make([]SAMLProviderWarning, 0)
	if provider.MetadataValidUntil != nil {
		switch {
		case !provider.MetadataValidUntil.After(now):
			warnings = append(warnings, SAMLProviderWarning{
				Code: "metadata_expired", Severity: "error",
				Message:     "SAML metadata has expired; logins through this provider are refused",
				EffectiveAt: *provider.MetadataValidUntil,
			})
		case !provider.MetadataValidUntil.After(now.Add(30 * 24 * time.Hour)):
			warnings = append(warnings, SAMLProviderWarning{
				Code: "metadata_expires_soon", Severity: "warning",
				Message:     "SAML metadata expires within 30 days",
				EffectiveAt: *provider.MetadataValidUntil,
			})
		}
	}
	certificates, err := parseSAMLCertificates(provider.SigningCertificates)
	if err != nil {
		return nil, err
	}
	for _, certificate := range certificates {
		fingerprint, err := certificateFingerprint(certificate)
		if err != nil {
			return nil, err
		}
		switch {
		case now.Before(certificate.NotBefore):
			warnings = append(warnings, SAMLProviderWarning{
				Code: "signing_certificate_not_yet_valid", Severity: "warning",
				Message:     "Pinned IdP signing certificate is not yet valid; pinned-key validation remains enabled",
				EffectiveAt: certificate.NotBefore, Fingerprint: &fingerprint,
			})
		case !now.Before(certificate.NotAfter):
			warnings = append(warnings, SAMLProviderWarning{
				Code: "signing_certificate_expired", Severity: "warning",
				Message:     "Pinned IdP signing certificate has expired; pinned-key validation remains enabled",
				EffectiveAt: certificate.NotAfter, Fingerprint: &fingerprint,
			})
		}
	}
	slices.SortFunc(warnings, func(a, b SAMLProviderWarning) int {
		if byCode := strings.Compare(a.Code, b.Code); byCode != 0 {
			return byCode
		}
		if byTime := a.EffectiveAt.Compare(b.EffectiveAt); byTime != 0 {
			return byTime
		}
		left, right := "", ""
		if a.Fingerprint != nil {
			left = *a.Fingerprint
		}
		if b.Fingerprint != nil {
			right = *b.Fingerprint
		}
		return strings.Compare(left, right)
	})
	return warnings, nil
}

func (s *SAMLProviders) updateProvider(ctx context.Context, az *authz.TxAuthorizer, provider authz.SAMLProvider,
	displayName string, certificates []byte, policy *string, allowEmail, forceSign, metadataWantSign bool,
	metadataSource string, metadataURL *string, metadata samlsp.Metadata, enabled bool,
) (int64, error) {
	updated, err := az.UpdateSAMLProvider(ctx, authz.SAMLProviderUpdate{
		ID: provider.ID, DisplayName: displayName, ACSURL: provider.ACSURL,
		SSORedirectURL: metadata.SSOURL, SigningCertificates: certificates,
		AssurancePolicy: policy, AllowEmailNameID: allowEmail, ForceSignRequests: forceSign,
		MetadataWantAuthnRequestsSigned: metadataWantSign,
		MetadataSource:                  metadataSource, MetadataURL: metadataURL,
		MetadataSigned: metadata.Signed, MetadataValidUntil: metadata.ValidUntil,
		MetadataSigningFingerprint: metadataFingerprint(metadata), Enabled: enabled,
		RowVersion: provider.RowVersion, UpdatedAt: s.now(),
	})
	if err != nil {
		return 0, err
	}
	if !updated {
		return 0, ErrSAMLProviderRace
	}
	if provider.Enabled && !enabled || !equalOptionalString(provider.AssurancePolicy, policy) ||
		!bytes.Equal(provider.SigningCertificates, certificates) || provider.SSORedirectURL != metadata.SSOURL ||
		provider.AllowEmailNameID != allowEmail {
		return az.SweepSessionsForSAMLProvider(ctx, provider.ID)
	}
	return 0, nil
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func metadataFingerprint(metadata samlsp.Metadata) *string {
	if !metadata.Signed {
		return nil
	}
	fingerprint, err := certificateFingerprint(metadata.SignatureCertificate)
	if err != nil {
		return nil
	}
	return &fingerprint
}

func (s *SAMLProviders) metadataBytes(ctx context.Context, source string, document []byte, metadataURL *string) ([]byte, error) {
	switch source {
	case "file":
		if len(document) == 0 || metadataURL != nil {
			return nil, ErrSAMLMetadataSource
		}
		return document, nil
	case "url":
		if len(document) != 0 || metadataURL == nil || *metadataURL == "" {
			return nil, ErrSAMLMetadataSource
		}
		return s.fetchMetadata(ctx, *metadataURL)
	default:
		return nil, ErrSAMLMetadataSource
	}
}

func (s *SAMLProviders) fetchMetadata(ctx context.Context, rawURL string) ([]byte, error) {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil ||
		target.Fragment != "" || metadataHostIsNonPublic(target.Hostname()) {
		return nil, ErrSAMLMetadataFetch
	}
	client := s.HTTPClient
	if client == nil {
		client = publicMetadataHTTPClient()
	}
	copyClient := *client
	priorRedirect := copyClient.CheckRedirect
	copyClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if request.URL.Scheme != target.Scheme || request.URL.Host != target.Host {
			return errors.New("service: SAML metadata redirect changed origin")
		}
		if metadataHostIsNonPublic(request.URL.Hostname()) {
			return errors.New("service: SAML metadata redirect resolved to a non-public target")
		}
		if priorRedirect != nil {
			return priorRedirect(request, via)
		}
		if len(via) >= 5 {
			return errors.New("service: too many SAML metadata redirects")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, ErrSAMLMetadataFetch
	}
	// Production requests use publicMetadataHTTPClient, whose dialer resolves
	// and pins a public IP for every connection. The explicit suppression records
	// that CodeQL cannot model this transport-level SSRF boundary.
	// codeql[go/request-forgery]
	response, err := copyClient.Do(request)
	if err != nil {
		return nil, ErrSAMLMetadataFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrSAMLMetadataFetch
	}
	limited := io.LimitReader(response.Body, samlsp.MaxDocumentBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil || len(payload) > samlsp.MaxDocumentBytes {
		return nil, ErrSAMLMetadataFetch
	}
	return payload, nil
}

// These are the IANA IPv4 special-purpose ranges that are not globally
// reachable. Broad parent prefixes are deliberately conservative where IANA
// has carved out a globally reachable anycast address inside a special block:
// metadata retrieval needs ordinary public hosting, not protocol anycast.
var nonPublicMetadataIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var (
	publicMetadataIPv6Prefix      = netip.MustParsePrefix("2000::/3")
	nonPublicMetadataIPv6Prefixes = []netip.Prefix{
		// IANA special-purpose ranges inside 2000::/3 which are not ordinary
		// globally reachable addresses.
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
	}
)

func metadataHostIsNonPublic(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)
	return err == nil && metadataIPIsNonPublic(address)
}

func metadataIPIsNonPublic(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	prefixes := nonPublicMetadataIPv4Prefixes
	if address.Is6() {
		if !publicMetadataIPv6Prefix.Contains(address) {
			return true
		}
		prefixes = nonPublicMetadataIPv6Prefixes
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func publicMetadataHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 10 * time.Second
	return &http.Client{
		Transport: &publicMetadataRoundTripper{base: transport, resolver: net.DefaultResolver},
		Timeout:   15 * time.Second,
	}
}

type metadataResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// publicMetadataRoundTripper resolves and validates the destination before
// handing it to net/http. The request then names the approved IP, preventing a
// second DNS lookup from rebinding it. The original hostname remains in Host
// and TLS ServerName, preserving HTTP routing and certificate verification.
//
// Proxy selection deliberately happens before the URL is pinned. HTTP,
// HTTPS, and SOCKS proxies therefore keep working, but CONNECT receives the
// already-approved IP rather than a hostname the proxy could resolve privately.
type publicMetadataRoundTripper struct {
	base     *http.Transport
	resolver metadataResolver
}

func (t *publicMetadataRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	addresses, proxyURL, err := t.destinations(request)
	if err != nil {
		return nil, err
	}
	var attempts []error
	for _, address := range addresses {
		pinned, transport := t.prepareAddress(request, address, proxyURL)
		response, err := transport.RoundTrip(pinned)
		if err == nil {
			return response, nil
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		attempts = append(attempts, fmt.Errorf("%s: %w", address, err))
		if err := request.Context().Err(); err != nil {
			return nil, err
		}
	}
	return nil, errors.Join(attempts...)
}

func (t *publicMetadataRoundTripper) prepare(request *http.Request) (*http.Request, *http.Transport, error) {
	addresses, proxyURL, err := t.destinations(request)
	if err != nil {
		return nil, nil, err
	}
	pinned, transport := t.prepareAddress(request, addresses[0], proxyURL)
	return pinned, transport, nil
}

func (t *publicMetadataRoundTripper) destinations(request *http.Request) ([]netip.Addr, *url.URL, error) {
	host := request.URL.Hostname()
	addresses, err := t.resolver.LookupNetIP(request.Context(), "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, nil, errors.New("service: SAML metadata host did not resolve")
	}
	for _, resolved := range addresses {
		if metadataIPIsNonPublic(resolved) {
			return nil, nil, errors.New("service: SAML metadata host resolved to a non-public address")
		}
	}

	var proxyURL *url.URL
	if t.base.Proxy != nil {
		proxyURL, err = t.base.Proxy(request)
		if err != nil {
			return nil, nil, err
		}
	}
	return addresses, proxyURL, nil
}

func (t *publicMetadataRoundTripper) prepareAddress(
	request *http.Request,
	address netip.Addr,
	proxyURL *url.URL,
) (*http.Request, *http.Transport) {
	transport := t.base.Clone()
	host := request.URL.Hostname()
	transport.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	// One transport is built per request because its TLS identity and pinned IP
	// are request-specific. Prevent it from retaining an unusable idle pool.
	transport.DisableKeepAlives = true

	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	pinned := request.Clone(request.Context())
	pinnedURL := *request.URL
	pinnedURL.Host = net.JoinHostPort(address.Unmap().String(), port)
	pinned.URL = &pinnedURL
	pinned.Host = request.Host
	if pinned.Host == "" {
		pinned.Host = request.URL.Host
	}

	targetTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		targetTLS = transport.TLSClientConfig.Clone()
	}
	targetTLS.ServerName = host
	transport.TLSClientConfig = targetTLS

	// An HTTPS proxy needs a different TLS identity on the first hop. The
	// transport uses targetTLS again only after CONNECT, for the nested TLS
	// session whose ServerName must remain the original metadata hostname.
	if proxyURL != nil && proxyURL.Scheme == "https" {
		proxyHost := proxyURL.Hostname()
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			proxyTLS := targetTLS.Clone()
			proxyTLS.ServerName = proxyHost
			connection := tls.Client(raw, proxyTLS)
			if err := connection.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return connection, nil
		}
	}
	return pinned, transport
}

type generatedSAMLSPKey struct {
	ID                  string
	EncryptedPrivateKey []byte
	CertificateDER      []byte
	Fingerprint         string
	DEKVersion          int64
	CreatedAt           time.Time
}

func (s *SAMLProviders) generateSPKey() (generatedSAMLSPKey, error) {
	id, err := newID("samlkey")
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	now := s.now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: samlSPEntityID(s.ExternalOrigin)},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	fingerprint, err := certificateFingerprint(certificate)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	defer wencrypto.Zero(pkcs8)
	sealer := s.Keyring.ForInstance()
	sealed, err := sealer.SealField(samlSPKeyAAD(id), pkcs8)
	if err != nil {
		return generatedSAMLSPKey{}, err
	}
	return generatedSAMLSPKey{
		ID: id, EncryptedPrivateKey: sealed, CertificateDER: der, Fingerprint: fingerprint,
		DEKVersion: int64(sealer.Version()), CreatedAt: now,
	}, nil
}

func (s *SAMLProviders) ensureSPKey(ctx context.Context, az *authz.TxAuthorizer, principal domain.PrincipalID, generated generatedSAMLSPKey) error {
	if _, err := az.ActiveSAMLSPKey(ctx); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	if err := az.CreateSAMLSPKey(ctx, authz.NewSAMLSPKey{
		ID: generated.ID, State: "active", EncryptedPrivateKey: generated.EncryptedPrivateKey,
		CertificateDER: generated.CertificateDER, Fingerprint: generated.Fingerprint,
		DEKVersion: generated.DEKVersion, CreatedAt: generated.CreatedAt,
	}); err != nil {
		return err
	}
	event, err := newAuditEvent(ctx, audit.EventSAMLSPKey, principal,
		audit.Object{Type: "saml_sp_key", ID: generated.ID}, audit.OutcomeSuccess, "",
		audit.Payload{"action": "mint", "key_fingerprint": generated.Fingerprint})
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, event)
}

func (s *SAMLProviders) recordProviderEvent(ctx context.Context, repos store.Repos, proof authz.Proof, principal domain.PrincipalID, eventType audit.EventType, provider SAMLProviderView, confirmed []string, diff *SAMLMetadataDiff) error {
	confirmedCopy := slices.Clone(confirmed)
	slices.Sort(confirmedCopy)
	payload := audit.Payload{
		"provider_id": providerIDForView(provider), "entity_id": provider.EntityID,
		"source": provider.MetadataSource, "signed": provider.MetadataSigned,
		"confirmed_fps": confirmedCopy,
	}
	diffPayload := audit.Payload{
		"endpoints_added": []string{}, "endpoints_removed": []string{},
		"certs_added_fps": []string{}, "certs_removed_fps": []string{},
	}
	if diff != nil {
		diffPayload["endpoints_added"] = slices.Clone(diff.EndpointsAdded)
		diffPayload["endpoints_removed"] = slices.Clone(diff.EndpointsRemoved)
		diffPayload["certs_added_fps"] = slices.Clone(diff.CertsAddedFps)
		diffPayload["certs_removed_fps"] = slices.Clone(diff.CertsRemovedFps)
	}
	if provider.MetadataValidUntil != nil {
		diffPayload["valid_until"] = provider.MetadataValidUntil.UTC().Format(time.RFC3339Nano)
	}
	payload["diff"] = diffPayload
	event, err := newAuditEvent(ctx, eventType, principal,
		audit.Object{Type: "saml_provider", ID: providerIDForView(provider)}, audit.OutcomeSuccess, "", payload)
	if err != nil {
		return err
	}
	return repos.Audit().InsertInstance(ctx, proof, event)
}

func (s *SAMLProviders) recordProviderFailure(ctx context.Context, actor Actor, operation authz.Operation,
	eventType audit.EventType, slug, entityID, source string, confirmed []string, cause string, original error,
) error {
	confirmedCopy := slices.Clone(confirmed)
	slices.Sort(confirmedCopy)
	auditErr := tx.Write(ctx, s.DB, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		proof, err := az.Authorize(ctx, caller, operation, domain.Scope{})
		if err != nil {
			return err
		}
		payload := audit.Payload{
			"provider_id": slug, "entity_id": entityID, "source": source, "signed": false,
			"diff": audit.Payload{
				"endpoints_added": []string{}, "endpoints_removed": []string{},
				"certs_added_fps": []string{}, "certs_removed_fps": []string{},
			},
			"confirmed_fps": confirmedCopy, "cause": cause,
		}
		event, err := newAuditEvent(ctx, eventType, caller.Principal,
			audit.Object{Type: "saml_provider", ID: slug}, audit.OutcomeFailure, "", payload)
		if err != nil {
			return err
		}
		return repos.Audit().InsertInstance(ctx, proof, event)
	})
	if auditErr != nil {
		return errors.Join(original, auditErr)
	}
	return original
}

func (s *SAMLProviders) recordProviderMutationEvents(ctx context.Context, repos store.Repos, proof authz.Proof,
	principal domain.PrincipalID, eventType audit.EventType, provider SAMLProviderView, diff SAMLMetadataDiff,
	confirmed []string, emailState string,
) error {
	if err := s.recordProviderEvent(ctx, repos, proof, principal, eventType, provider, confirmed, &diff); err != nil {
		return err
	}
	for _, change := range []struct {
		kind         string
		fingerprints []string
	}{{"added", diff.CertsAddedFps}, {"removed", diff.CertsRemovedFps}} {
		for _, fingerprint := range change.fingerprints {
			event, err := newAuditEvent(ctx, audit.EventSAMLCertChange, principal,
				audit.Object{Type: "saml_provider", ID: providerIDForView(provider)}, audit.OutcomeSuccess, "",
				audit.Payload{"provider_id": providerIDForView(provider), "entity_id": provider.EntityID,
					"change": change.kind, "fingerprint": fingerprint})
			if err != nil {
				return err
			}
			if err := repos.Audit().InsertInstance(ctx, proof, event); err != nil {
				return err
			}
		}
	}
	if emailState != "" {
		event, err := newAuditEvent(ctx, audit.EventSAMLEmailNameIDOptIn, principal,
			audit.Object{Type: "saml_provider", ID: providerIDForView(provider)}, audit.OutcomeSuccess, "",
			audit.Payload{"provider_id": providerIDForView(provider), "entity_id": provider.EntityID, "state": emailState})
		if err != nil {
			return err
		}
		if err := repos.Audit().InsertInstance(ctx, proof, event); err != nil {
			return err
		}
	}
	if provider.MetadataValidUntil != nil && !provider.MetadataValidUntil.After(s.now().Add(30*24*time.Hour)) {
		event, err := newAuditEvent(ctx, audit.EventSAMLMetadataExpiryWarning, principal,
			audit.Object{Type: "saml_provider", ID: providerIDForView(provider)}, audit.OutcomeSuccess, "",
			audit.Payload{"provider_id": providerIDForView(provider), "entity_id": provider.EntityID,
				"valid_until": provider.MetadataValidUntil.UTC().Format(time.RFC3339Nano), "threshold": "30d"})
		if err != nil {
			return err
		}
		return repos.Audit().InsertInstance(ctx, proof, event)
	}
	return nil
}

// Provider ids are deliberately not exposed in the public view. The slug is a
// stable non-secret audit object id at this transport boundary.
func providerIDForView(provider SAMLProviderView) string { return provider.id }

func (s *SAMLProviders) recordMetadataExpiryWarnings(ctx context.Context, repos store.Repos, proof authz.Proof,
	principal domain.PrincipalID, providers []SAMLProviderView,
) error {
	threshold := s.now().Add(30 * 24 * time.Hour)
	for _, provider := range providers {
		if provider.MetadataValidUntil == nil || provider.MetadataValidUntil.After(threshold) {
			continue
		}
		event, err := newAuditEvent(ctx, audit.EventSAMLMetadataExpiryWarning, principal,
			audit.Object{Type: "saml_provider", ID: providerIDForView(provider)}, audit.OutcomeSuccess, "",
			audit.Payload{"provider_id": providerIDForView(provider), "entity_id": provider.EntityID,
				"valid_until": provider.MetadataValidUntil.UTC().Format(time.RFC3339Nano), "threshold": "30d"})
		if err != nil {
			return err
		}
		if err := repos.Audit().InsertInstance(ctx, proof, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *SAMLProviders) recordProviderRead(ctx context.Context, repos store.Repos, proof authz.Proof, principal domain.PrincipalID, query string, count int) error {
	event, err := newAuditEvent(ctx, audit.EventOIDCProviderRead, principal,
		audit.Object{Type: "saml_provider"}, audit.OutcomeSuccess, "",
		audit.Payload{"query": query, "row_count": count})
	if err != nil {
		return err
	}
	return repos.Audit().InsertInstance(ctx, proof, event)
}

type spEntityDescriptor struct {
	XMLName  xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string          `xml:"entityID,attr"`
	SP       spSSODescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

type spSSODescriptor struct {
	ProtocolSupportEnumeration string              `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        bool                `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                `xml:"WantAssertionsSigned,attr"`
	Keys                       []spKeyDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	ACS                        spAssertionConsumer `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
}

type spKeyDescriptor struct {
	Use     string    `xml:"use,attr"`
	KeyInfo spKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type spKeyInfo struct {
	Data spX509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type spX509Data struct {
	Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type spAssertionConsumer struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
	Default  bool   `xml:"isDefault,attr"`
}

// SAMLMetadata publishes documentation-class SP material for one provider.
func (s *Auth) SAMLMetadata(ctx context.Context, slug string) ([]byte, error) {
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return nil, err
	}
	defer release()
	var (
		provider authz.SAMLProvider
		keys     []authz.SAMLSPKey
	)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var readErr error
		provider, readErr = az.SAMLProviderBySlug(ctx, slug)
		if errors.Is(readErr, domain.ErrNotFound) {
			return ErrSAMLProviderNotFound
		}
		if readErr != nil {
			return readErr
		}
		keys, readErr = az.SAMLSPKeys(ctx)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	keyDescriptors := make([]spKeyDescriptor, 0, len(keys))
	for _, key := range keys {
		keyDescriptors = append(keyDescriptors, spKeyDescriptor{
			Use: "signing", KeyInfo: spKeyInfo{Data: spX509Data{Certificate: base64.StdEncoding.EncodeToString(key.CertificateDER)}},
		})
	}
	descriptor := spEntityDescriptor{
		EntityID: samlSPEntityID(s.ExternalOrigin),
		SP: spSSODescriptor{
			ProtocolSupportEnumeration: samlsp.SAMLProtocolNamespace,
			AuthnRequestsSigned:        provider.ForceSignRequests || provider.MetadataWantAuthnRequestsSigned, WantAssertionsSigned: true,
			Keys: keyDescriptors,
			ACS: spAssertionConsumer{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: provider.ACSURL, Index: 0, Default: true,
			},
		},
	}
	encoded, err := xml.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), encoded...), nil
}
