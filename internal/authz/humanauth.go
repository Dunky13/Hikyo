package authz

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/authn"
)

// The in-transaction human-authentication surface.
//
// It hangs off TxAuthorizer rather than off a package the service layer could
// import directly, and that is the whole point: the resolution surface stays
// importable by exactly {authz, tx}, the service layer reaches it only inside
// a transaction it already holds, and authentication therefore cannot happen
// anywhere the authorization chokepoint is not already standing.
//
// These methods are deliberately thin. Policy — liveness, epoch, generation,
// uniform refusal — lives in session.go and in the service; storage lives in
// internal/store/authn. This file is the seam, and a seam that starts making
// decisions is how two places end up disagreeing about who is logged in.

// Account is a resolved human account.
type Account = authn.Account

// PasswordCredential is a resolved verifier row with its CAS version.
type PasswordCredential = authn.PasswordCredential

// KDFParams are the Argon2id parameters recorded with a verifier.
type KDFParams = authn.KDFParams

// CredentialAuthority is a resolved credential-establishment authority.
type CredentialAuthority = authn.CredentialAuthority

// NewCredentialAuthority is the mint carrier.
type NewCredentialAuthority = authn.NewCredentialAuthority

// NewSession is the session-mint carrier.
type NewSession = authn.NewSession

// AccountByUsername resolves a login handle inside this transaction.
func (a *TxAuthorizer) AccountByUsername(ctx context.Context, username string) (Account, error) {
	return a.r.AccountByUsername(ctx, username)
}

// AccountByID resolves an account by id.
func (a *TxAuthorizer) AccountByID(ctx context.Context, id string) (Account, error) {
	return a.r.AccountByID(ctx, id)
}

// AccountByPrincipal resolves the account a session's principal owns — the
// bridge the factor paths need to reach an account's password/TOTP/recovery
// rows from the principal a session carries.
func (a *TxAuthorizer) AccountByPrincipal(ctx context.Context, p domain.PrincipalID) (Account, error) {
	return a.r.AccountByPrincipal(ctx, p)
}

// AccountCount answers the bootstrap path's one question. It has no network
// route: `hikyo admin create` runs on the server's own host.
func (a *TxAuthorizer) AccountCount(ctx context.Context) (int64, error) {
	return a.r.AccountCount(ctx)
}

// PasswordCredentialFor reads an account's verifier row.
func (a *TxAuthorizer) PasswordCredentialFor(ctx context.Context, accountID string) (PasswordCredential, error) {
	return a.r.PasswordCredential(ctx, accountID)
}

// PrincipalGeneration reads the principal's current session generation, so a
// freshly minted session records the generation it was born under.
func (a *TxAuthorizer) PrincipalGeneration(ctx context.Context, p domain.PrincipalID) (int64, error) {
	return a.r.PrincipalGeneration(ctx, p)
}

// CredentialEpoch reads the instance epoch.
func (a *TxAuthorizer) CredentialEpoch(ctx context.Context) (int64, error) {
	return a.r.CredentialEpoch(ctx)
}

// AuthorityByValue resolves a presented credential-establishment authority.
func (a *TxAuthorizer) AuthorityByValue(ctx context.Context, verifier []byte) (CredentialAuthority, error) {
	return a.r.CredentialAuthorityByVerifier(ctx, verifier)
}

// ConsumeAuthority claims an authority atomically; false means it was already
// consumed and the caller must fail closed.
func (a *TxAuthorizer) ConsumeAuthority(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ConsumeCredentialAuthority(ctx, id, at)
}

// MintAuthority writes a new credential-establishment authority.
func (a *TxAuthorizer) MintAuthority(ctx context.Context, n NewCredentialAuthority) error {
	return a.r.CreateCredentialAuthority(ctx, n)
}

// WritePasswordCredential inserts the first verifier for an account.
func (a *TxAuthorizer) WritePasswordCredential(ctx context.Context, c PasswordCredential, at time.Time) error {
	return a.r.CreatePasswordCredential(ctx, c, at)
}

// ReplacePasswordCredential compare-and-swaps an existing verifier. False
// means the row moved underneath and the caller must not write a stale
// verifier back.
func (a *TxAuthorizer) ReplacePasswordCredential(ctx context.Context, c PasswordCredential, at time.Time) (bool, error) {
	return a.r.UpdatePasswordCredential(ctx, c, at)
}

// MintSession writes a session row.
func (a *TxAuthorizer) MintSession(ctx context.Context, s NewSession) error {
	return a.r.CreateSession(ctx, s)
}

// SlideSession advances the idle clock only. The absolute lifetime is never
// extended by activity — two independent clocks is the design.
func (a *TxAuthorizer) SlideSession(ctx context.Context, id string, seen, idleExpires time.Time) error {
	return a.r.TouchSession(ctx, id, seen, idleExpires)
}

// RevokeSession deletes one session in this transaction.
func (a *TxAuthorizer) RevokeSession(ctx context.Context, id string) error {
	return a.r.DeleteSession(ctx, id)
}

// RevokeAllSessionsFor deletes every session of a principal.
func (a *TxAuthorizer) RevokeAllSessionsFor(ctx context.Context, p domain.PrincipalID) error {
	return a.r.DeleteSessionsForPrincipal(ctx, p)
}

// AdvanceGeneration invalidates every session of a principal at once. It runs
// in the same transaction as the change that triggered it.
func (a *TxAuthorizer) AdvanceGeneration(ctx context.Context, p domain.PrincipalID) error {
	return a.r.AdvanceGeneration(ctx, p)
}

// CreateHumanPrincipal and CreateAccount are the bootstrap path's writes,
// reachable only from `hikyo admin create` on the server's own host — the
// closed local-authority exception set's boot/bootstrap member. There is no
// HTTP route to either, and the classification-totality invariant is what
// keeps that true.
func (a *TxAuthorizer) CreateHumanPrincipal(ctx context.Context, id domain.PrincipalID, at time.Time) error {
	return a.r.CreatePrincipal(ctx, id, "human", at)
}

func (a *TxAuthorizer) CreateAccount(ctx context.Context, acc Account) error {
	return a.r.CreateAccount(ctx, acc)
}

// CreateGrant writes one grant row. The bootstrap path uses it to expand the
// `admin` template into separate, visible, individually revocable rows rather
// than an implicit bundle. The general grant surface is #55's.
func (a *TxAuthorizer) CreateGrant(ctx context.Context, id string, p domain.PrincipalID, g domain.Grant, at time.Time) error {
	return a.r.CreateGrant(ctx, id, p, g, at)
}

// Factor seam (#54). TOTP, recovery codes and step-up rotation reach the
// resolution surface through the same in-transaction authorizer, for the same
// reason the login writers do: they mutate the artifacts that decide how a
// caller authenticated, which is resolution rather than authorization.

// TOTPCredential is a resolved TOTP factor.
type TOTPCredential = authn.TOTPCredential

// NewTOTPCredential is the TOTP insert carrier.
type NewTOTPCredential = authn.NewTOTPCredential

// RecoveryBatch is a resolved recovery-code batch.
type RecoveryBatch = authn.RecoveryBatch

// ConfirmedTOTP resolves an account's confirmed TOTP factor.
func (a *TxAuthorizer) ConfirmedTOTP(ctx context.Context, accountID string) (TOTPCredential, error) {
	return a.r.ConfirmedTOTP(ctx, accountID)
}

// PendingTOTP resolves an account's in-progress enrolment.
func (a *TxAuthorizer) PendingTOTP(ctx context.Context, accountID string) (TOTPCredential, error) {
	return a.r.PendingTOTP(ctx, accountID)
}

// CreateTOTP inserts a pending TOTP enrolment.
func (a *TxAuthorizer) CreateTOTP(ctx context.Context, c NewTOTPCredential) error {
	return a.r.CreateTOTP(ctx, c)
}

// ConfirmTOTP promotes and consumes a step in one CAS; false means the row
// moved or the step was not beyond the last.
func (a *TxAuthorizer) ConfirmTOTP(ctx context.Context, id string, rowVersion, step int64, at time.Time) (bool, error) {
	return a.r.ConfirmTOTP(ctx, id, rowVersion, step, at)
}

// AdvanceTOTPStep consumes a code's step; false means it was not beyond the last.
func (a *TxAuthorizer) AdvanceTOTPStep(ctx context.Context, id string, rowVersion, step int64) (bool, error) {
	return a.r.AdvanceTOTPStep(ctx, id, rowVersion, step)
}

// RemoveTOTPForAccount deletes every TOTP row of an account.
func (a *TxAuthorizer) RemoveTOTPForAccount(ctx context.Context, accountID string) error {
	return a.r.DeleteTOTPForAccount(ctx, accountID)
}

// ClearPendingTOTP removes only in-progress enrolments.
func (a *TxAuthorizer) ClearPendingTOTP(ctx context.Context, accountID string) error {
	return a.r.DeletePendingTOTPForAccount(ctx, accountID)
}

// RecoveryCodesFor resolves an account's batch.
func (a *TxAuthorizer) RecoveryCodesFor(ctx context.Context, accountID string) (RecoveryBatch, error) {
	return a.r.RecoveryCodes(ctx, accountID)
}

// WriteRecoveryCodes writes the first batch for an account.
func (a *TxAuthorizer) WriteRecoveryCodes(ctx context.Context, b RecoveryBatch, at time.Time) error {
	return a.r.CreateRecoveryCodes(ctx, b, at)
}

// ReplaceRecoveryCodes compare-and-swaps the batch; false means it moved.
func (a *TxAuthorizer) ReplaceRecoveryCodes(ctx context.Context, b RecoveryBatch, at time.Time) (bool, error) {
	return a.r.UpdateRecoveryCodes(ctx, b, at)
}

// RotateSessionFactors rotates the acting session token and rewrites its
// factor set on step-up, preserving the original authentication attribution.
func (a *TxAuthorizer) RotateSessionFactors(ctx context.Context, id string, verifier []byte, factors string) error {
	return a.r.RotateSessionFactors(ctx, id, verifier, factors)
}

// ConsumeOutstandingAuthorities marks every unconsumed authority of an account
// consumed, in the same transaction as a fresh mint or consumption.
func (a *TxAuthorizer) ConsumeOutstandingAuthorities(ctx context.Context, accountID string, at time.Time) error {
	return a.r.ConsumeOutstandingAuthorities(ctx, accountID, at)
}

// OIDC seam (#54). Login, callback, link and reauth reach the resolution
// surface through the same in-transaction authorizer as the login writers: they
// mutate the artifacts that decide who a caller is, which is resolution rather
// than authorization. Provider administration is proof-bound and does NOT come
// through here.

// OIDCProvider is a resolved provider row.
type OIDCProvider = authn.OIDCProvider

// OIDCTransaction is a resolved transaction row.
type OIDCTransaction = authn.OIDCTransaction

// NewOIDCTransaction is the transaction insert carrier.
type NewOIDCTransaction = authn.NewOIDCTransaction

// ExternalIdentity is a resolved linked identity.
type ExternalIdentity = authn.ExternalIdentity

// NewExternalIdentity is the link insert carrier.
type NewExternalIdentity = authn.NewExternalIdentity

// NewReauthWindow is the reauth-window insert carrier.
type NewReauthWindow = authn.NewReauthWindow
type CLIReauthHandoff = authn.CLIReauthHandoff
type NewCLIReauthHandoff = authn.NewCLIReauthHandoff

// EnabledProviderByIssuer resolves the currently enabled provider for an issuer.
func (a *TxAuthorizer) EnabledProviderByIssuer(ctx context.Context, kind, issuer string) (OIDCProvider, error) {
	return a.r.EnabledProviderByIssuer(ctx, kind, issuer)
}

// NewProvider is the provider create carrier.
type NewProvider = authn.NewProvider

// ProviderUpdate is the provider reconfigure carrier.
type ProviderUpdate = authn.ProviderUpdate

// EnabledProviderBySlug resolves an enabled provider by slug, for start.
func (a *TxAuthorizer) EnabledProviderBySlug(ctx context.Context, slug string) (OIDCProvider, error) {
	return a.r.EnabledProviderBySlug(ctx, slug)
}

// ProviderBySlug resolves a provider by slug for administration (any state).
// The mutation that follows is authorized at the chokepoint first.
func (a *TxAuthorizer) ProviderBySlug(ctx context.Context, slug string) (OIDCProvider, error) {
	return a.r.ProviderBySlug(ctx, slug)
}

// ListProviders lists every configured provider.
func (a *TxAuthorizer) ListProviders(ctx context.Context) ([]OIDCProvider, error) {
	return a.r.ListProviders(ctx)
}

// CreateProvider inserts a provider row (authorized at the chokepoint first).
func (a *TxAuthorizer) CreateProvider(ctx context.Context, n NewProvider) error {
	return a.r.CreateProvider(ctx, n)
}

// UpdateProvider compare-and-swaps a provider; false means the row moved.
func (a *TxAuthorizer) UpdateProvider(ctx context.Context, u ProviderUpdate) (bool, error) {
	return a.r.UpdateProvider(ctx, u)
}

// LockProviderForDelete locks the provider row inside the delete tx so the
// session sweep runs with the row held and a concurrent mint guard serializes
// behind it (A14). ErrNotFound means a concurrent delete already removed it.
func (a *TxAuthorizer) LockProviderForDelete(ctx context.Context, id string) error {
	return a.r.LockProviderForDelete(ctx, id)
}

// DeleteProvider removes a provider.
func (a *TxAuthorizer) DeleteProvider(ctx context.Context, id string) error {
	return a.r.DeleteProvider(ctx, id)
}

// ProviderForCallback resolves the provider a transaction pinned, by id.
func (a *TxAuthorizer) ProviderForCallback(ctx context.Context, id string) (OIDCProvider, error) {
	return a.r.ProviderForCallback(ctx, id)
}

// GuardProviderForMint locks the pinned provider row inside a Phase-C mint tx
// and reports whether it still matches the Phase-A snapshot; false means the
// provider moved and the mint must refuse (A4 TOCTOU, sweep wins).
func (a *TxAuthorizer) GuardProviderForMint(ctx context.Context, id string, rowVersion int64, issuer string) (bool, error) {
	return a.r.GuardProviderForMint(ctx, id, rowVersion, issuer)
}

// CreateOIDCTransaction writes a single-use transaction row.
func (a *TxAuthorizer) CreateOIDCTransaction(ctx context.Context, t NewOIDCTransaction) error {
	return a.r.CreateOIDCTransaction(ctx, t)
}

// OIDCTransactionByState resolves a transaction by its state verifier.
func (a *TxAuthorizer) OIDCTransactionByState(ctx context.Context, stateVerifier []byte) (OIDCTransaction, error) {
	return a.r.OIDCTransactionByState(ctx, stateVerifier)
}

// ConsumeOIDCTransaction claims a transaction atomically; false means it moved.
func (a *TxAuthorizer) ConsumeOIDCTransaction(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ConsumeOIDCTransaction(ctx, id, at)
}

// ExternalIdentityByKey resolves a byte-exact (kind, issuer, subject).
func (a *TxAuthorizer) ExternalIdentityByKey(ctx context.Context, kind, issuer, subject string) (ExternalIdentity, error) {
	return a.r.ExternalIdentityByKey(ctx, kind, issuer, subject)
}

// ExternalIdentityByID resolves a link by id.
func (a *TxAuthorizer) ExternalIdentityByID(ctx context.Context, id string) (ExternalIdentity, error) {
	return a.r.ExternalIdentityByID(ctx, id)
}

// ExternalIdentitiesForAccount lists an account's linked identities.
func (a *TxAuthorizer) ExternalIdentitiesForAccount(ctx context.Context, accountID string) ([]ExternalIdentity, error) {
	return a.r.ExternalIdentitiesForAccount(ctx, accountID)
}

// CreateExternalIdentity writes a link.
func (a *TxAuthorizer) CreateExternalIdentity(ctx context.Context, n NewExternalIdentity) error {
	return a.r.CreateExternalIdentity(ctx, n)
}

// RebindSAMLExternalIdentityProvider compare-and-swaps provider provenance
// after the same byte-exact entity has been removed and configured again.
func (a *TxAuthorizer) RebindSAMLExternalIdentityProvider(ctx context.Context, id, expectedProviderID, newProviderID string) (bool, error) {
	return a.r.RebindSAMLExternalIdentityProvider(ctx, id, expectedProviderID, newProviderID)
}

// RemoveExternalIdentity removes a link (unlink).
func (a *TxAuthorizer) RemoveExternalIdentity(ctx context.Context, id string) error {
	return a.r.DeleteExternalIdentity(ctx, id)
}

// SweepSessionsForProvider deletes every session minted through a provider and
// returns the count for audit (A4).
func (a *TxAuthorizer) SweepSessionsForProvider(ctx context.Context, providerID string) (int64, error) {
	return a.r.DeleteSessionsForProvider(ctx, providerID)
}

// OpenReauthWindow opens a reauthentication window over one environment.
func (a *TxAuthorizer) OpenReauthWindow(ctx context.Context, w NewReauthWindow) error {
	return a.r.CreateReauthWindow(ctx, w)
}

func (a *TxAuthorizer) CreateCLIReauthHandoff(ctx context.Context, h NewCLIReauthHandoff) error {
	return a.r.CreateCLIReauthHandoff(ctx, h)
}
func (a *TxAuthorizer) CLIReauthHandoffByState(ctx context.Context, verifier []byte) (CLIReauthHandoff, error) {
	return a.r.CLIReauthHandoffByState(ctx, verifier)
}
func (a *TxAuthorizer) CLIReauthHandoffByCode(ctx context.Context, verifier []byte) (CLIReauthHandoff, error) {
	return a.r.CLIReauthHandoffByCode(ctx, verifier)
}
func (a *TxAuthorizer) ApproveCLIReauthHandoff(ctx context.Context, id string, codeVerifier, windows []byte) (bool, error) {
	return a.r.ApproveCLIReauthHandoff(ctx, id, codeVerifier, windows)
}
func (a *TxAuthorizer) ConsumeCLIReauthHandoff(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ConsumeCLIReauthHandoff(ctx, id, at)
}

// ReauthWindow is a resolved reauthentication-window row.
type ReauthWindow = authn.ReauthWindow

// ReauthWindowFor resolves the window over one environment for one session.
func (a *TxAuthorizer) ReauthWindowFor(ctx context.Context, sessionID, environmentID string) (ReauthWindow, error) {
	return a.r.ReauthWindowFor(ctx, sessionID, environmentID)
}

// SlideReauthWindow advances a sliding window's idle clock; false means the row
// moved and the caller must not extend it.
func (a *TxAuthorizer) SlideReauthWindow(ctx context.Context, id string, windowExpires time.Time) (bool, error) {
	return a.r.SlideReauthWindow(ctx, id, windowExpires)
}

// ConsumeSingleDecisionWindow claims a single-decision window exactly once;
// false means it was already spent (B11 double-spend).
func (a *TxAuthorizer) ConsumeSingleDecisionWindow(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ConsumeSingleDecisionWindow(ctx, id, at)
}

// SAML seam (#72). The strict XML/signature policy lives in internal/samlsp;
// this surface only keeps its durable resolution and write phase inside the
// transaction that will mint or rotate a session.

// SAMLProvider is a resolved SAML identity-provider row.
type SAMLProvider = authn.SAMLProvider

// NewSAMLProvider is the provider insert carrier.
type NewSAMLProvider = authn.NewSAMLProvider

// SAMLProviderUpdate is the provider compare-and-swap carrier.
type SAMLProviderUpdate = authn.SAMLProviderUpdate

// SAMLTransaction is a server-side AuthnRequest transaction.
type SAMLTransaction = authn.SAMLTransaction

// NewSAMLTransaction is the transaction insert carrier.
type NewSAMLTransaction = authn.NewSAMLTransaction

// NewSAMLReplay is the durable assertion replay insert carrier.
type NewSAMLReplay = authn.NewSAMLReplay

// SAMLSPKey is stored SP signing material.
type SAMLSPKey = authn.SAMLSPKey

// NewSAMLSPKey is the SP signing-key insert carrier.
type NewSAMLSPKey = authn.NewSAMLSPKey

// SAMLProviderBySlug resolves a provider in any state for administration.
func (a *TxAuthorizer) SAMLProviderBySlug(ctx context.Context, slug string) (SAMLProvider, error) {
	return a.r.SAMLProviderBySlug(ctx, slug)
}

// SAMLProviderForCallback resolves the provider pinned by a transaction.
func (a *TxAuthorizer) SAMLProviderForCallback(ctx context.Context, id string) (SAMLProvider, error) {
	return a.r.SAMLProviderForCallback(ctx, id)
}

// ListSAMLProviders lists all configured SAML providers.
func (a *TxAuthorizer) ListSAMLProviders(ctx context.Context) ([]SAMLProvider, error) {
	return a.r.ListSAMLProviders(ctx)
}

// CreateSAMLProvider inserts a provider after instance-config authorization.
func (a *TxAuthorizer) CreateSAMLProvider(ctx context.Context, provider NewSAMLProvider) error {
	return a.r.CreateSAMLProvider(ctx, provider)
}

// UpdateSAMLProvider compare-and-swaps a provider configuration.
func (a *TxAuthorizer) UpdateSAMLProvider(ctx context.Context, provider SAMLProviderUpdate) (bool, error) {
	return a.r.UpdateSAMLProvider(ctx, provider)
}

// LockSAMLProviderForDelete serializes provider deletion against Phase-C mints.
func (a *TxAuthorizer) LockSAMLProviderForDelete(ctx context.Context, id string) error {
	return a.r.LockSAMLProviderForDelete(ctx, id)
}

// DeleteSAMLProvider removes a locked provider row.
func (a *TxAuthorizer) DeleteSAMLProvider(ctx context.Context, id string) error {
	return a.r.DeleteSAMLProvider(ctx, id)
}

// GuardSAMLProviderForMint proves the provider still matches the Phase-A
// snapshot immediately before a session or reauth window is written.
func (a *TxAuthorizer) GuardSAMLProviderForMint(ctx context.Context, id string, rowVersion int64, entityID string) (bool, error) {
	return a.r.GuardSAMLProviderForMint(ctx, id, rowVersion, entityID)
}

// CreateSAMLTransaction writes a single-use AuthnRequest transaction.
func (a *TxAuthorizer) CreateSAMLTransaction(ctx context.Context, transaction NewSAMLTransaction) error {
	return a.r.CreateSAMLTransaction(ctx, transaction)
}

// SAMLTransactionByRelayState resolves the opaque front-channel handle before
// the strict wrapper's single response-validation pass.
func (a *TxAuthorizer) SAMLTransactionByRelayState(ctx context.Context, verifier []byte) (SAMLTransaction, error) {
	return a.r.SAMLTransactionByRelayState(ctx, verifier)
}

// ConsumeSAMLTransaction spends a transaction on first presentation, success
// or failure.
func (a *TxAuthorizer) ConsumeSAMLTransaction(ctx context.Context, id string, at time.Time) (bool, error) {
	return a.r.ConsumeSAMLTransaction(ctx, id, at)
}

// ClaimSAMLReplay atomically records an assertion ID. False means replay.
func (a *TxAuthorizer) ClaimSAMLReplay(ctx context.Context, replay NewSAMLReplay) (bool, error) {
	return a.r.ClaimSAMLReplay(ctx, replay)
}

// DeleteExpiredSAMLReplay removes replay rows after their signed validity plus
// skew has elapsed.
func (a *TxAuthorizer) DeleteExpiredSAMLReplay(ctx context.Context, at time.Time) (int64, error) {
	return a.r.DeleteExpiredSAMLReplay(ctx, at)
}

// ActiveSAMLSPKey resolves the signing key used for AuthnRequests.
func (a *TxAuthorizer) ActiveSAMLSPKey(ctx context.Context) (SAMLSPKey, error) {
	return a.r.ActiveSAMLSPKey(ctx)
}

// SAMLSPKeys lists active and overlap-retiring public material.
func (a *TxAuthorizer) SAMLSPKeys(ctx context.Context) ([]SAMLSPKey, error) {
	return a.r.SAMLSPKeys(ctx)
}

// CreateSAMLSPKey stores a freshly minted encrypted private key.
func (a *TxAuthorizer) CreateSAMLSPKey(ctx context.Context, key NewSAMLSPKey) error {
	return a.r.CreateSAMLSPKey(ctx, key)
}

// MarkSAMLSPKeyRetiring compare-and-swaps an active key into overlap state.
func (a *TxAuthorizer) MarkSAMLSPKeyRetiring(ctx context.Context, id string, rowVersion int64) (bool, error) {
	return a.r.MarkSAMLSPKeyRetiring(ctx, id, rowVersion)
}

// DeleteRetiringSAMLSPKey erases a retiring key.
func (a *TxAuthorizer) DeleteRetiringSAMLSPKey(ctx context.Context, id string) (bool, error) {
	return a.r.DeleteRetiringSAMLSPKey(ctx, id)
}

// BindSessionToSAMLProvider records SAML provider provenance in the same
// transaction that mints the session.
func (a *TxAuthorizer) BindSessionToSAMLProvider(ctx context.Context, sessionID, providerID string) (bool, error) {
	return a.r.BindSessionToSAMLProvider(ctx, sessionID, providerID)
}

// SweepSessionsForSAMLProvider deletes all sessions minted through a SAML IdP.
func (a *TxAuthorizer) SweepSessionsForSAMLProvider(ctx context.Context, providerID string) (int64, error) {
	return a.r.DeleteSessionsForSAMLProvider(ctx, providerID)
}

// InvalidateReauthWindowsForEnvironment deletes every open window on one
// environment (the effective-window transition, B6) and returns the count.
func (a *TxAuthorizer) InvalidateReauthWindowsForEnvironment(ctx context.Context, environmentID string) (int64, error) {
	return a.r.DeleteReauthWindowsForEnvironment(ctx, environmentID)
}

// StrandedRevealPrincipals enumerates the reveal-holding principals a 0
// effective window would strand on the given environment chain (B6).
func (a *TxAuthorizer) StrandedRevealPrincipals(ctx context.Context, org, project, env string) ([]domain.PrincipalID, error) {
	return a.r.StrandedRevealPrincipals(ctx, org, project, env)
}

// OrgIdentity re-exports the resolution surface's navigation record so
// internal/service can name it without importing internal/store/authn, which
// the boundary test forbids.
type OrgIdentity = authn.OrgIdentity

// OrgsForPrincipal projects the caller's OWN grants onto the organisations
// they name. It authorizes nothing and needs no proof: the result set is
// defined by the caller's own grant rows, so it can disclose nothing they do
// not already hold. See the resolver for why an instance-scoped principal
// correctly gets an empty set.
func (a *TxAuthorizer) OrgsForPrincipal(ctx context.Context, p domain.PrincipalID) ([]OrgIdentity, error) {
	return a.r.OrgsForPrincipal(ctx, p)
}

// GrantsForResetTarget reads the credential-reset target's full grant set for
// the org-bounded test, under the row lock the reset holds.
func (a *TxAuthorizer) GrantsForResetTarget(ctx context.Context, p domain.PrincipalID) ([]domain.Grant, error) {
	return a.r.GrantsForResetTarget(ctx, p)
}

// LockTargetPrincipal takes the target principal's row lock so the org-bounded
// test and every grant mutation serialize on the same row (B14).
func (a *TxAuthorizer) LockTargetPrincipal(ctx context.Context, p domain.PrincipalID) error {
	return a.r.LockPrincipalRow(ctx, p)
}

// WebAuthnCeremonyByID resolves a ceremony by id, for single-decision window
// unit matching at disclosure.
func (a *TxAuthorizer) WebAuthnCeremonyByID(ctx context.Context, id string) (WebAuthnCeremony, error) {
	return a.r.WebAuthnCeremonyByID(ctx, id)
}

// EnvironmentChain is a resolved (org, project, env) chain.
type EnvironmentChain = authn.EnvironmentChain

// EnvironmentChainByID resolves an environment's chain from its id, so
// LowerEffectiveWindow can build the grant-coverage predicate from an env id.
func (a *TxAuthorizer) EnvironmentChainByID(ctx context.Context, envID string) (EnvironmentChain, error) {
	return a.r.EnvironmentChainByID(ctx, envID)
}

// WebAuthn seam (#54). Passkey enrolment, discoverable login, step-up, reauth
// and removal reach the resolution surface through the same in-transaction
// authorizer as the OIDC and factor writers: they mutate the artifacts that
// decide who a caller is and how strongly they authenticated.

// WebAuthnCredential is a resolved registered passkey.
type WebAuthnCredential = authn.WebAuthnCredential

// NewWebAuthnCredential is the passkey insert carrier.
type NewWebAuthnCredential = authn.NewWebAuthnCredential

// WebAuthnCeremony is a resolved ceremony row.
type WebAuthnCeremony = authn.WebAuthnCeremony

// NewWebAuthnCeremony is the ceremony insert carrier.
type NewWebAuthnCeremony = authn.NewWebAuthnCeremony

// WebAuthnCredentialByID resolves a credential by its surrogate id.
func (a *TxAuthorizer) WebAuthnCredentialByID(ctx context.Context, id string) (WebAuthnCredential, error) {
	return a.r.WebAuthnCredentialByID(ctx, id)
}

// WebAuthnCredentialByCredentialID resolves the row a passkey assertion names.
func (a *TxAuthorizer) WebAuthnCredentialByCredentialID(ctx context.Context, credentialID []byte) (WebAuthnCredential, error) {
	return a.r.WebAuthnCredentialByCredentialID(ctx, credentialID)
}

// WebAuthnCredentialsForAccount lists an account's passkeys.
func (a *TxAuthorizer) WebAuthnCredentialsForAccount(ctx context.Context, accountID string) ([]WebAuthnCredential, error) {
	return a.r.WebAuthnCredentialsForAccount(ctx, accountID)
}

// CreateWebAuthnCredential inserts a freshly enrolled passkey.
func (a *TxAuthorizer) CreateWebAuthnCredential(ctx context.Context, c NewWebAuthnCredential) error {
	return a.r.CreateWebAuthnCredential(ctx, c)
}

// AdvanceWebAuthnSignCount writes the presented counter under a row_version CAS;
// false means the row moved or was disabled.
func (a *TxAuthorizer) AdvanceWebAuthnSignCount(ctx context.Context, id string, rowVersion, count int64, at time.Time) (bool, error) {
	return a.r.AdvanceWebAuthnSignCount(ctx, id, rowVersion, count, at)
}

// DisableWebAuthnCredential sets disabled_at under a CAS (the clone response);
// false means the row moved or was already disabled.
func (a *TxAuthorizer) DisableWebAuthnCredential(ctx context.Context, id string, rowVersion int64, at time.Time) (bool, error) {
	return a.r.DisableWebAuthnCredential(ctx, id, rowVersion, at)
}

// DeleteWebAuthnCredential removes a credential (de-enrolment) under an
// account_id predicate. False means zero rows matched — refused fail-closed.
func (a *TxAuthorizer) DeleteWebAuthnCredential(ctx context.Context, id, accountID string) (bool, error) {
	return a.r.DeleteWebAuthnCredential(ctx, id, accountID)
}

// SweepSessionsForWebAuthnCredential deletes every session a passkey login
// minted through a credential and returns the count for audit (B9 clone sweep).
func (a *TxAuthorizer) SweepSessionsForWebAuthnCredential(ctx context.Context, credentialID string) (int64, error) {
	return a.r.DeleteSessionsForWebAuthnCredential(ctx, credentialID)
}

// CreateWebAuthnCeremony writes a single-use, expiring challenge row.
func (a *TxAuthorizer) CreateWebAuthnCeremony(ctx context.Context, c NewWebAuthnCeremony) error {
	return a.r.CreateWebAuthnCeremony(ctx, c)
}

// WebAuthnCeremonyByChallenge resolves a ceremony by its challenge verifier.
func (a *TxAuthorizer) WebAuthnCeremonyByChallenge(ctx context.Context, challengeVerifier []byte) (WebAuthnCeremony, error) {
	return a.r.WebAuthnCeremonyByChallenge(ctx, challengeVerifier)
}

// ConsumeWebAuthnCeremony claims a ceremony atomically and stamps the credential
// that answered it; false means it was already consumed.
func (a *TxAuthorizer) ConsumeWebAuthnCeremony(ctx context.Context, id, credentialID string, at time.Time) (bool, error) {
	return a.r.ConsumeWebAuthnCeremony(ctx, id, credentialID, at)
}

// WebAuthnUserHandle reads an account's opaque handle, or nil when unset.
func (a *TxAuthorizer) WebAuthnUserHandle(ctx context.Context, accountID string) ([]byte, error) {
	return a.r.WebAuthnUserHandle(ctx, accountID)
}

// SetWebAuthnUserHandle sets the opaque handle once; false means one already
// exists (the caller reads it back rather than rotating).
func (a *TxAuthorizer) SetWebAuthnUserHandle(ctx context.Context, accountID string, handle []byte) (bool, error) {
	return a.r.SetWebAuthnUserHandle(ctx, accountID, handle)
}

// AccountByWebAuthnUserHandle resolves the account a discoverable assertion names.
func (a *TxAuthorizer) AccountByWebAuthnUserHandle(ctx context.Context, handle []byte) (Account, error) {
	return a.r.AccountByWebAuthnUserHandle(ctx, handle)
}

// RecordAuthEvent writes an authentication audit event through the resolution
// surface's proof-free path. Authentication events cannot carry a proof: they
// are what produces the principal a proof would be minted for, and credential
// establishment deliberately produces no session at all.
//
// The event commits with the transaction that caused it, so a login without
// its durable record does not complete — the same durability discipline
// domain writes follow.
func (a *TxAuthorizer) RecordAuthEvent(ctx context.Context, e audit.Event) error {
	return a.r.WriteAuthEvent(ctx, e, audit.TrailInstance)
}
