package authz

import (
	"context"
	"time"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store/authn"
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
// route: `wenv admin create` runs on the server's own host.
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
// reachable only from `wenv admin create` on the server's own host — the
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
