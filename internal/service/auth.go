package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Dunky13/hikyo/internal/admission"
	"github.com/Dunky13/hikyo/internal/audit"
	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/crypto"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/oidcrp"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
	"github.com/Dunky13/hikyo/internal/webauthnrp"
)

// Human authentication: the local floor and credential establishment (#47,
// human-auth ADR). OIDC, WebAuthn, TOTP, recovery codes, the loopback and
// device-code transports and the full assurance check are #54, which this
// slice is explicitly the foundation for.

// Ops-spec session lifetimes (§ 3). CLI sessions may run longer than browser
// sessions because a session lifetime is not a plaintext-exposure window —
// disclosure is independently gated by the reveal ceremony and assurance.
const (
	CLISessionIdle     = 30 * 24 * time.Hour
	CLISessionAbsolute = 90 * 24 * time.Hour
	// BrowserSessionIdle/Absolute are the browser artifact's clocks. Recorded
	// here beside their sibling so the two are read together; the browser
	// artifact itself is minted by #54's login page.
	BrowserSessionIdle     = 7 * 24 * time.Hour
	BrowserSessionAbsolute = 30 * 24 * time.Hour
	// SlideGranularity bounds how often a read request rewrites the idle
	// clock. Without it every authenticated GET would issue a write; with it
	// the clock is accurate to the minute, which is four orders of magnitude
	// finer than the 30-day window it governs.
	SlideGranularity = time.Minute
	// PasswordMinLength is the ADR's length floor: no composition rules, no
	// forced rotation. Composition rules produce `Password1!`.
	PasswordMinLength = 12
	// AuthorityLifetime is the credential-establishment window — the
	// no-session, no-assurance enrolment authority, and the tightest of the
	// one-shot token expiries.
	AuthorityLifetime = 15 * time.Minute
	// BootstrapLifetime is the first-administrator token's expiry. If it
	// lapses a new one is minted from the CLI on the host; it is never
	// re-displayed.
	BootstrapLifetime = 24 * time.Hour
)

// Artifact is a session artifact kind: the closed set of client classes this
// instance mints sessions for. It is a type rather than a bare string because
// it threads through login, minting and the audit trail, and each of those is
// a place a typo would otherwise become a silently different session class —
// a browser session with the CLI's lifetime, say, or a cookie leg with no CSRF
// contract.
type Artifact string

const (
	// ArtifactCLI is a terminal session: a replayable bearer token, no cookie
	// channel, and therefore no CSRF contract.
	ArtifactCLI Artifact = "cli"
	// ArtifactBrowser is a cookie session: HttpOnly token, shorter clocks, and
	// a synchronizer token the client must echo.
	ArtifactBrowser Artifact = "browser"
)

// Valid reports whether a names a kind this instance mints. The wire enum is
// closed, so anything else is a caller error rather than a future value.
func (a Artifact) Valid() bool { return a == ArtifactCLI || a == ArtifactBrowser }

func (a Artifact) String() string { return string(a) }

// idle is the clock this artifact slides on. Sliding a browser session by the
// CLI window would silently hand a cookie session the CLI's far longer life,
// which is the opposite of what two artifact kinds are for.
func (a Artifact) idle() time.Duration {
	if a == ArtifactBrowser {
		return BrowserSessionIdle
	}
	return CLISessionIdle
}

// absolute is the lifetime activity never extends.
func (a Artifact) absolute() time.Duration {
	if a == ArtifactBrowser {
		return BrowserSessionAbsolute
	}
	return CLISessionAbsolute
}

// bearerKind is the token grammar this artifact's value carries.
func (a Artifact) bearerKind() crypto.ArtifactType {
	if a == ArtifactBrowser {
		return crypto.ArtifactBrowserSession
	}
	return crypto.ArtifactCLISession
}

// Authentication methods, matching the wire enum.
const (
	MethodLocalPassword = "local-password"
	// MethodLocalPasskey is a discoverable WebAuthn login: user-verifying and
	// inherently multi-factor.
	MethodLocalPasskey = "local-passkey"
)

// ErrWeakPassword is a loud, specific refusal — password policy is evaluated
// at set time, where naming the rule helps the human and reveals nothing.
var ErrWeakPassword = fmt.Errorf("password must be at least %d characters", PasswordMinLength)

// ErrCredentialRace reports a verifier row that moved underneath a
// compare-and-swap. It is loud rather than retried-into-silence: the caller
// decides, and a pass that cannot converge fails rather than skipping.
var ErrCredentialRace = errors.New("service: credential row changed underneath this write")

// Auth is the human-authentication service.
type Auth struct {
	DB      *store.DB
	Keyring *crypto.Keyring
	// KDF is the instance's configured Argon2id cost. Boot has already
	// verified it against the floor; this is the value new verifiers use.
	KDF crypto.PasswordParams
	// Admission is the instance-wide pre-authentication budget. Every path
	// that can run Argon2id — including the dummy-verifier path — passes
	// through it, or the budget is decorative.
	Admission *admission.Limiter
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time
	// ExternalOrigin is the instance's public origin; the OIDC callback validates
	// the redirect it replays against the per-provider registered URI (A1).
	ExternalOrigin string
	// OIDCDiscover replaces go-oidc discovery in tests, so a fixture can point an
	// httptest IdP's discovery at a byte-variant issuer. Nil means oidcrp.Discover.
	OIDCDiscover func(ctx context.Context, issuer string) (*oidcrp.Provider, error)
	// WebAuthn is the relying party: RP ID + expected origins are immutable
	// instance config derived from ExternalOrigin, never a request header (§5).
	// Nil means WebAuthn routes refuse (the RP could not be configured at boot).
	WebAuthn *webauthnrp.RP
	// ReauthWindow is the effective reauthentication window (default 0). OIDC
	// reauth opens a window only where it is > 0; a 0-window gate needs WebAuthn
	// (finding B18). #55's project-settings knob sets it per environment.
	ReauthWindow time.Duration
	// ReauthHardCap bounds the absolute age of a reauth window, never extended by
	// activity. Zero means the idle window value.
	ReauthHardCap time.Duration
	// Log records server-side faults that must not reach the caller — an
	// unreadable verifier answers the uniform refusal, and the reason it was
	// unreadable belongs in the process log and nowhere else.
	Log *slog.Logger

	// dummyRecoverySealed is a batch sealed once and opened on every
	// non-matching recovery path, so a miss costs the same envelope decrypt +
	// JSON decode + set scan as a hit — the recovery analogue of the login
	// dummy verifier, closing the account/batch existence timing oracle.
	dummyRecoveryOnce   sync.Once
	dummyRecoverySealed []byte
}

func (s *Auth) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// verifierAAD binds a sealed verifier to the row that owns it, so a verifier
// lifted from one account's row cannot be replayed into another's.
func verifierAAD(accountID string) crypto.InstanceFieldAAD {
	return crypto.InstanceFieldAAD{
		OwnerTable: "password_credentials", OwnerRowID: accountID, FieldTag: "verifier",
	}
}

// Assurance and Identity are the service layer's own shapes for what the
// chokepoint resolved. They are restated here rather than re-exported from
// internal/authz because the transport must not import the authorization
// package at all - the boundary test enforces that edge, and it is what keeps
// "handlers extract artifacts, they never evaluate policy" structural.
type Assurance struct {
	Method          string
	Factors         []string
	AuthenticatedAt time.Time
	CeremonyID      string
}

// Identity is a live, resolved caller.
type Identity struct {
	Principal         domain.PrincipalID
	SessionID         string
	Artifact          Artifact
	Assurance         Assurance
	CreatedAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

func identityOf(i authz.Identity) Identity {
	return Identity{
		Principal: i.Principal, SessionID: i.SessionID, Artifact: Artifact(i.Artifact),
		Assurance: Assurance{
			Method: i.Assurance.Method, Factors: i.Assurance.Factors,
			AuthenticatedAt: i.Assurance.AuthenticatedAt, CeremonyID: i.Assurance.CeremonyID,
		},
		CreatedAt: i.CreatedAt, IdleExpiresAt: i.IdleExpiresAt, AbsoluteExpiresAt: i.AbsoluteExpiresAt,
	}
}

// LoginResult is a freshly minted session. SessionToken is returned exactly
// once, to exactly one caller.
type LoginResult struct {
	SessionToken string
	SessionID    string
	Artifact     Artifact
	CreatedAt    time.Time
	IdleExpires  time.Time
	AbsExpires   time.Time
	Principal    domain.PrincipalID
	AccountID    string
	DisplayName  string
	Assurance    Assurance
	// CSRFToken is the synchronizer token for a browser session, returned once
	// at mint (A9). Empty for CLI sessions.
	CSRFToken string
}

// LocalLogin is the local floor: password verification against an
// envelope-encrypted Argon2id verifier, minting the session artifact the
// caller asked for — a CLI session, or the browser session #56's login page
// establishes.
//
// The shape is dictated by the enumeration rule. An unknown account traverses
// the same admission budget, the same per-account backoff bucket and a
// bounded dummy-verifier derivation, so neither the response nor the timing
// distinguishes it from a wrong password on a real account. Every refusal
// answers domain.ErrUnauthenticated.
func (s *Auth) LocalLogin(ctx context.Context, username, password string, artifact Artifact) (LoginResult, error) {
	// The caller states which artifact it wants; the server never infers it
	// from a header. An unrecognised value is a caller error, refused before
	// any credential work happens rather than silently downgraded to CLI — a
	// browser that got a CLI session would receive its token in the body,
	// which is exactly the disclosure the browser artifact exists to prevent.
	if artifact == "" {
		artifact = ArtifactCLI
	}
	if !artifact.Valid() {
		return LoginResult{}, fmt.Errorf("%w: unknown session artifact %q", domain.ErrInvalid, artifact)
	}

	// The per-account delay is evaluated BEFORE the semaphore, not after.
	// Sleeping while holding an expensive-work slot would let an attacker put
	// a handful of identifiers into backoff and then occupy every slot doing
	// no work at all, denying logins to everyone else — the throttle becoming
	// the outage. An account in backoff is refused outright with the same
	// uniform overload answer every other pre-auth path gives.
	if delay := s.Admission.AccountDelay(username); delay > 0 {
		return LoginResult{}, admission.ErrOverloaded
	}

	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return LoginResult{}, err // admission.ErrOverloaded — uniform on every pre-auth path
	}
	defer release()

	out, err := s.attemptLogin(ctx, username, password, artifact)
	switch {
	case err == nil:
		s.Admission.RecordSuccess(username)
		return out, nil
	case errors.Is(err, domain.ErrUnauthenticated):
		if crossed := s.Admission.RecordFailure(username); crossed {
			// Threshold crossing is its own audit event: a distributed
			// attempt should be visible, not merely slowed.
			s.recordThrottleCrossing(ctx, username)
		}
		return LoginResult{}, err
	default:
		return LoginResult{}, err
	}
}

// attemptLogin runs the three phases in the order their costs demand: read,
// verify, write.
//
// The Argon2id derivation deliberately happens BETWEEN two transactions
// rather than inside one. At the locked floor it costs 64 MiB and hundreds of
// milliseconds, and sqlite has a single write connection — so verifying
// inside a write transaction would hold a global write lock for the whole
// derivation, letting a handful of concurrent logins (the admission budget
// allows four) stall every other write on the instance. That is a denial of
// service reachable by anyone who can reach the login endpoint, which is
// everyone.
//
// Splitting it introduces one thing to be careful about: the credential can
// change between the read and the write. The write phase therefore re-reads
// the row and refuses if its version counter or the instance epoch moved,
// so a password changed mid-login cannot be used to mint a session.
func (s *Auth) attemptLogin(ctx context.Context, username, password string, artifact Artifact) (LoginResult, error) {
	// Phase 1 — read. A read transaction, so it does not queue behind the
	// single writer.
	var (
		account   authz.Account
		cred      authz.PasswordCredential
		epoch     int64
		resolved  bool
		haveCred  bool
		epochGood bool
	)
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var err error
		if epoch, err = az.CredentialEpoch(ctx); err != nil {
			return err
		}
		account, err = az.AccountByUsername(ctx, username)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		resolved = true
		cred, err = az.PasswordCredentialFor(ctx, account.ID)
		switch {
		case errors.Is(err, domain.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		haveCred = true
		epochGood = cred.CredentialEpoch == epoch
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}

	// Phase 2 — verify, outside any transaction. Every non-verifying path
	// burns an equivalent derivation: returning early on an unknown account,
	// a missing credential, a superseded epoch or an unreadable verifier
	// would make each of them observably faster than a wrong password, which
	// is exactly the oracle this path exists to close.
	cause := ""
	var (
		upgrade       bool
		upgradeSealed []byte
		upgradeParams authz.KDFParams
		upgradeDEK    int64
	)
	switch {
	case !resolved:
		crypto.BurnDummyVerification([]byte(password), s.KDF)
		cause = "unknown-subject"
	case !haveCred:
		crypto.BurnDummyVerification([]byte(password), s.KDF)
		cause = "no-credential"
	case !epochGood:
		// A restored verifier is inert until the operator re-establishes it.
		crypto.BurnDummyVerification([]byte(password), s.KDF)
		cause = "epoch-superseded"
	default:
		plain, err := s.Keyring.ForInstance().OpenField(verifierAAD(account.ID), cred.Verifier)
		if err != nil {
			// A verifier we cannot open is not a verifier we may accept. It is
			// a real fault — wrong key, tampered row — and it is logged as
			// one, but it must NOT reach the caller as a 500 while a missing
			// account answers 401: that difference is an account-existence
			// oracle for anyone who can provoke it. Burn the work and refuse
			// uniformly.
			s.logFault(ctx, "opening a password verifier failed", err, account.ID)
			crypto.BurnDummyVerification([]byte(password), s.KDF)
			cause = "verifier-unreadable"
			break
		}
		ok := crypto.VerifyPassword([]byte(password), plain, crypto.PasswordParams(cred.KDF))
		crypto.Zero(plain)
		if !ok {
			cause = "bad-password"
		} else if cred.KDF != (authz.KDFParams{MemoryKiB: s.KDF.MemoryKiB, Time: s.KDF.Time, Parallelism: s.KDF.Parallelism}) {
			// Derive the replacement HERE, outside any transaction, beside
			// the verification that just succeeded.
			// The verifier was written under different parameters. Re-derive
			// under the configured ones so stored costs converge on the
			// instance's — this is the "re-derivation on next successful
			// login" the ADR specifies, and it is also what keeps the
			// unknown-account burn (which uses the configured parameters)
			// comparable to a real verification over time.
			upgraded, upParams, upDEK, uerr := s.sealVerifier(account.ID, password)
			if uerr != nil {
				// An upgrade that cannot be prepared must not fail the login:
				// the credential that just verified is still valid.
				s.logFault(ctx, "preparing a KDF upgrade failed", uerr, account.ID)
			} else {
				upgrade, upgradeSealed, upgradeParams, upgradeDEK = true, upgraded, upParams, upDEK
			}
		}
	}

	// Phase 3 — write. The refusal travels out of the closure beside the
	// return value, because returning it would roll the transaction back —
	// and the transaction is what makes the failure event durable.
	var (
		result  LoginResult
		refused error
	)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		if cause != "" {
			if ferr := s.failLogin(ctx, az, now, accountIDOf(resolved, account), resolved, artifact, cause); ferr != nil {
				return ferr // audit not durable: roll back and fail loud
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		// Re-read under the write transaction: the credential must not have
		// moved while we were deriving.
		current, err := az.PasswordCredentialFor(ctx, account.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if ferr := s.failLogin(ctx, az, now, account.ID, true, artifact, "credential-removed"); ferr != nil {
					return ferr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if current.RowVersion != cred.RowVersion || current.CredentialEpoch != liveEpoch {
			if ferr := s.failLogin(ctx, az, now, account.ID, true, artifact, "credential-changed"); ferr != nil {
				return ferr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}
		if upgrade {
			if err := s.rehash(ctx, az, account.ID, upgradeSealed, upgradeParams, upgradeDEK, current, now); err != nil {
				return err
			}
		}
		result, err = s.mintSession(ctx, az, account, artifact, now)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if refused != nil {
		return LoginResult{}, refused
	}
	return result, nil
}

// rehash re-derives a verifier under the instance's configured parameters
// after a successful login, so a raised floor propagates without locking
// anyone out.
//
// The derivation happens BEFORE the write transaction for the same reason
// everything else here does, and the swap is conditional on the version the
// caller read: a password reset that landed while we were deriving must win,
// and a KDF upgrade must never write a verifier derived from the OLD password
// back over it. A losing swap is not an error — the credential is current
// either way, and the session being minted is still legitimate.
func (s *Auth) rehash(ctx context.Context, az *authz.TxAuthorizer, accountID string, sealed []byte, params authz.KDFParams, dekVersion int64, current authz.PasswordCredential, now time.Time) error {
	_, err := az.ReplacePasswordCredential(ctx, authz.PasswordCredential{
		AccountID: accountID, Verifier: sealed, KDF: params,
		DEKVersion:      dekVersion,
		CredentialEpoch: current.CredentialEpoch,
		RowVersion:      current.RowVersion,
	}, now)
	return err
}

// logFault records a server-side fault. Nothing about it reaches the caller.
func (s *Auth) logFault(ctx context.Context, what string, err error, accountID string) {
	if s.Log == nil {
		return
	}
	s.Log.ErrorContext(ctx, what, "err", err, "account_id", accountID)
}

func accountIDOf(resolved bool, a authz.Account) string {
	if resolved {
		return a.ID
	}
	return ""
}

// mintSession creates the artifact and its two audit events. The assurance
// record says single-factor password, truthfully: no factor exists in this
// slice, and recording something stronger would be a lie the chokepoint later
// acts on.
func (s *Auth) mintSession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, artifact Artifact, now time.Time) (LoginResult, error) {
	value, verifier, err := crypto.NewArtifact(artifact.bearerKind())
	if err != nil {
		return LoginResult{}, err
	}
	// A browser session authenticates on a cookie the browser attaches by
	// itself, so it needs a second value the browser will NOT attach by
	// itself. A CLI session has no cookie channel and therefore no CSRF
	// contract; minting a token it can never be asked for would be noise.
	var csrfValue string
	var csrfVerifier []byte
	if artifact == ArtifactBrowser {
		csrfValue, csrfVerifier, err = crypto.NewArtifact(crypto.ArtifactCSRF)
		if err != nil {
			return LoginResult{}, err
		}
	}
	id, err := newID("ses")
	if err != nil {
		return LoginResult{}, err
	}
	generation, err := az.PrincipalGeneration(ctx, account.PrincipalID)
	if err != nil {
		return LoginResult{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	factors, err := json.Marshal([]string{"password"})
	if err != nil {
		return LoginResult{}, err
	}
	wire := audit.FromContext(ctx)
	sess := authz.NewSession{
		ID: id, PrincipalID: account.PrincipalID, Verifier: verifier,
		Artifact: artifact.String(), SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: MethodLocalPassword, Factors: string(factors),
		AuthenticatedAt: now, CreatedAt: now,
		IdleExpiresAt: now.Add(artifact.idle()), AbsoluteExpiresAt: now.Add(artifact.absolute()),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent,
		CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}

	for _, ev := range []struct {
		typ     audit.EventType
		payload audit.Payload
	}{
		{audit.EventAuthLogin, audit.Payload{
			"method": MethodLocalPassword, "artifact": artifact.String(),
			"subject_resolved": true, "account_id": account.ID, "assurance": "single-factor",
		}},
		{audit.EventAuthSessionCreated, audit.Payload{
			"session_id": id, "artifact": artifact.String(),
			"method": MethodLocalPassword, "assurance": "single-factor",
		}},
	} {
		e, err := newAuditEvent(ctx, ev.typ, account.PrincipalID,
			audit.Object{Type: "session", ID: id}, audit.OutcomeSuccess, "", ev.payload)
		if err != nil {
			return LoginResult{}, err
		}
		if err := az.RecordAuthEvent(ctx, e); err != nil {
			return LoginResult{}, err
		}
	}

	return LoginResult{
		SessionToken: value, SessionID: id, Artifact: artifact, CSRFToken: csrfValue,
		CreatedAt: now, IdleExpires: sess.IdleExpiresAt, AbsExpires: sess.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{
			Method: MethodLocalPassword, Factors: []string{"password"}, AuthenticatedAt: now,
		},
	}, nil
}

// failLogin stages the failure event in the caller's transaction. It returns
// ONLY the audit-write error: nil means the event is staged and the caller
// may commit it and then refuse; a non-nil return means the record could not
// be written, and the caller MUST propagate it loudly rather than commit an
// eventless refusal. A denial without its durable record is exactly what
// fail-closed forbids. The cause is recorded by CLASS, never returned to the
// caller — the trail is audit-read gated and may hold the truth, the response
// may not.
func (s *Auth) failLogin(ctx context.Context, az *authz.TxAuthorizer, now time.Time, accountID string, resolved bool, artifact Artifact, cause string) error {
	payload := audit.Payload{
		"method": MethodLocalPassword, "artifact": artifact.String(),
		"subject_resolved": resolved, "cause": cause,
	}
	if accountID != "" {
		payload["account_id"] = accountID
	}
	e, err := newAuditEvent(ctx, audit.EventAuthLogin, "",
		audit.Object{Type: "account", ID: accountID}, audit.OutcomeFailure, "", payload)
	if err != nil {
		return err
	}
	e.OccurredAt = now
	return az.RecordAuthEvent(ctx, e)
}

func (s *Auth) recordThrottleCrossing(ctx context.Context, username string) {
	// Best-effort for the CALLER — the login is already refused, and failing
	// their request because a secondary observability event could not be
	// written would turn a throttle into an outage — but never silent. A
	// swallowed error here means a threshold crossing nobody sees, which is
	// the opposite of what the event is for.
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		accountID := ""
		resolved := false
		if acc, err := az.AccountByUsername(ctx, username); err == nil {
			accountID, resolved = acc.ID, true
		}
		payload := audit.Payload{"scope": "account", "subject_resolved": resolved}
		if accountID != "" {
			payload["account_id"] = accountID
		}
		e, err := newAuditEvent(ctx, audit.EventAuthThrottleCrossed, "",
			audit.Object{Type: "account", ID: accountID}, audit.OutcomeFailure, "", payload)
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		s.logFault(ctx, "recording a throttle threshold crossing failed", err, "")
	}
}

// EstablishCredential consumes a credential-establishment authority and sets
// exactly one initial credential, atomically, and nothing more: no session is
// created, no assurance is carried, no reauthentication window opens. The
// holder authenticates afterwards with the credential they just set.
//
// Every refusal — unknown, expired, consumed, wrong epoch — answers
// domain.ErrUnauthenticated, so presentation reveals nothing about which
// authorities exist. A weak password is the one loud refusal: it is the
// caller's own input, evaluated before anything is looked up.
func (s *Auth) EstablishCredential(ctx context.Context, authority, password string) error {
	// Policy first: it is the caller's own input, costs nothing, and refusing
	// here keeps a hopeless password from consuming an admission slot.
	if err := CheckPassword(password); err != nil {
		return err
	}
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return err
	}
	defer release()

	if err := crypto.ParseArtifact(authority, crypto.ArtifactBootstrap); err != nil {
		// Refused locally, before any database work — but still recorded,
		// because a stream of malformed presentations is a signal.
		return s.refuseAuthority(ctx, "malformed")
	}

	// Phase 1 — resolve and snapshot, in a READ transaction. Deriving inside
	// a write transaction would hold sqlite's single writer for the length of
	// an Argon2id derivation, which is the same denial of service the login
	// path was carrying until a reviewer found it.
	var (
		auth     authz.CredentialAuthority
		existing authz.PasswordCredential
		haveCred bool
		epoch    int64
		cause    string
	)
	verifier := crypto.ArtifactVerifier(authority)
	err = tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		var rerr error
		if epoch, rerr = az.CredentialEpoch(ctx); rerr != nil {
			return rerr
		}
		auth, rerr = az.AuthorityByValue(ctx, verifier)
		switch {
		case errors.Is(rerr, domain.ErrNotFound):
			cause = "unknown"
			return nil
		case rerr != nil:
			return rerr
		}
		now := s.now()
		switch {
		case auth.Consumed:
			cause = "consumed"
		case !now.Before(auth.ExpiresAt):
			cause = "expired"
		case auth.CredentialEpoch != epoch:
			cause = "epoch-superseded"
		}
		if cause != "" {
			return nil
		}
		existing, rerr = az.PasswordCredentialFor(ctx, auth.AccountID)
		switch {
		case errors.Is(rerr, domain.ErrNotFound):
			return nil
		case rerr != nil:
			return rerr
		}
		haveCred = true
		return nil
	})
	if err != nil {
		return err
	}
	if cause != "" {
		return s.refuseAuthority(ctx, cause)
	}

	// Phase 2 — derive, outside any transaction. The version counter was
	// snapshotted BEFORE this, so the compare-and-swap below covers the whole
	// derivation window rather than just the instant after it.
	sealed, params, dekVersion, err := s.sealVerifier(auth.AccountID, password)
	if err != nil {
		return err
	}

	// Phase 3 — claim and write, in a short write transaction.
	var refused error
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		// Re-validate everything the read phase decided on: it may have
		// changed while we derived, and the atomic claim below is the only
		// thing that makes single-use true under concurrency.
		live, err := az.AuthorityByValue(ctx, verifier)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				if aerr := s.refuseAuthorityIn(ctx, az, "unknown"); aerr != nil {
					return aerr
				}
				refused = domain.ErrUnauthenticated
				return nil
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		switch {
		case live.Consumed:
			if aerr := s.refuseAuthorityIn(ctx, az, "consumed"); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		case !now.Before(live.ExpiresAt):
			if aerr := s.refuseAuthorityIn(ctx, az, "expired"); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		case live.CredentialEpoch != liveEpoch || liveEpoch != epoch:
			if aerr := s.refuseAuthorityIn(ctx, az, "epoch-superseded"); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}

		// The NULL guard is the atomic claim: two concurrent presentations
		// cannot both establish a credential, and the loser fails closed.
		claimed, err := az.ConsumeAuthority(ctx, live.ID, now)
		if err != nil {
			return err
		}
		if !claimed {
			if aerr := s.refuseAuthorityIn(ctx, az, "consumed"); aerr != nil {
				return aerr
			}
			refused = domain.ErrUnauthenticated
			return nil
		}

		cred := authz.PasswordCredential{
			AccountID: live.AccountID, Verifier: sealed, KDF: params,
			DEKVersion: dekVersion, CredentialEpoch: liveEpoch,
			RowVersion: existing.RowVersion,
		}
		if !haveCred {
			if err := az.WritePasswordCredential(ctx, cred, now); err != nil {
				return err
			}
		} else {
			swapped, err := az.ReplacePasswordCredential(ctx, cred, now)
			if err != nil {
				return err
			}
			if !swapped {
				// The row moved while we derived. Loud rather than
				// retried-into-silence: writing anyway would clobber whatever
				// won, and the authority is already consumed, so the caller
				// needs to know this attempt did not establish anything.
				return ErrCredentialRace
			}
		}

		account, err := az.AccountByID(ctx, live.AccountID)
		if err != nil {
			return err
		}
		// Establishing a credential invalidates every session of the
		// principal: an account-security mutation deletes sessions in the
		// same transaction as the credential change.
		if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
			return err
		}
		if err := az.RevokeAllSessionsFor(ctx, account.PrincipalID); err != nil {
			return err
		}

		e, err := newAuditEvent(ctx, audit.EventAuthCredentialEstablished, account.PrincipalID,
			audit.Object{Type: "account", ID: live.AccountID}, audit.OutcomeSuccess, "",
			audit.Payload{
				"authority_id": live.ID, "account_id": live.AccountID,
				"credential": MethodLocalPassword,
			})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
	if err != nil {
		return err
	}
	return refused
}

// sealVerifier derives and envelope-encrypts a verifier. It touches no
// transaction, which is the point: it is the expensive half.
func (s *Auth) sealVerifier(accountID, password string) ([]byte, authz.KDFParams, int64, error) {
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, authz.KDFParams{}, 0, err
	}
	plain, err := crypto.DeriveVerifier([]byte(password), salt, s.KDF)
	if err != nil {
		return nil, authz.KDFParams{}, 0, err
	}
	defer crypto.Zero(plain)
	sealer := s.Keyring.ForInstance()
	sealed, err := sealer.SealField(verifierAAD(accountID), plain)
	if err != nil {
		return nil, authz.KDFParams{}, 0, err
	}
	return sealed,
		authz.KDFParams{MemoryKiB: s.KDF.MemoryKiB, Time: s.KDF.Time, Parallelism: s.KDF.Parallelism},
		int64(sealer.Version()), nil
}

func (s *Auth) refuseAuthority(ctx context.Context, cause string) error {
	// The event is staged inside the transaction and its write error is the
	// closure's return value: a failed insert rolls back and surfaces loudly
	// rather than committing an eventless 401. Only once the write succeeded
	// do we answer the uniform refusal.
	if err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return s.refuseAuthorityIn(ctx, az, cause)
	}); err != nil {
		return err
	}
	return domain.ErrUnauthenticated
}

// refuseAuthorityIn stages the refusal event in the caller's transaction and
// returns ONLY the audit-write error, on the same fail-closed contract as
// failLogin: nil means the event is staged and the caller may refuse, a
// non-nil return means the record could not be written and must be
// propagated loudly rather than committed as an eventless 401.
func (s *Auth) refuseAuthorityIn(ctx context.Context, az *authz.TxAuthorizer, cause string) error {
	e, err := newAuditEvent(ctx, audit.EventAuthAuthorityRefused, "",
		audit.Object{Type: "credential_authority"}, audit.OutcomeFailure, "",
		audit.Payload{"cause": cause})
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, e)
}

// Identity resolves a presented session artifact. It is the read half of
// every authenticated request, and it runs in the request's own transaction
// at the chokepoint — never in a middleware, never cached.
func (s *Auth) Identity(ctx context.Context, presented string) (Identity, error) {
	var out Identity
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		out = identityOf(id)
		return nil
	})
	return out, err
}

// ErrCSRFMismatch is a LIVE browser session that did not present its own
// synchronizer token. It is deliberately distinct from
// domain.ErrUnauthenticated: the transport treats a session that resolves to
// nothing as "no cookie leg" and lets the request through to be judged on its
// own merits, and treats this as the refusal the CSRF gate exists for. On the
// wire both are the same uniform 401.
var ErrCSRFMismatch = errors.New("service: the presented synchronizer token is not this session's")

// VerifyBrowserCSRF checks a presented synchronizer token against the session
// row's verifier.
//
// It is a transport duty, not an authorization one — #54 A10 fixes the CSRF
// REQUIREMENT in transport, and the check belongs with it — but the verifier
// lives on the session row, so the read happens here.
//
// Two outcomes, and the difference is load-bearing:
//
//   - domain.ErrUnauthenticated — the presented cookie resolves to no live
//     session. There is nothing to protect: a dead artifact authorizes
//     nothing, and refusing here would make a browser holding an expired
//     cookie unable to log in again, since a login POST carries that cookie.
//   - ErrCSRFMismatch — the session is live and the token is not its own.
//     This is the refusal the gate exists for.
//
// A CLI session reaching here is a mismatch, not a pass: it can only happen if
// a `cli` token was planted in the browser cookie, and a session with no CSRF
// verifier can satisfy no CSRF contract.
func (s *Auth) VerifyBrowserCSRF(ctx context.Context, presented, csrfToken string) error {
	return tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		if csrfToken == "" || len(id.CSRFVerifier) == 0 ||
			subtle.ConstantTimeCompare(id.CSRFVerifier, crypto.ArtifactVerifier(csrfToken)) != 1 {
			return ErrCSRFMismatch
		}
		return nil
	})
}

// Logout revokes the presented session. A session that no longer resolves
// answers the uniform unauthenticated refusal: there is nothing to revoke and
// nothing to report.
func (s *Auth) Logout(ctx context.Context, presented string) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, s.now())
		if err != nil {
			return err
		}
		if err := az.RevokeSession(ctx, id.SessionID); err != nil {
			return err
		}
		e, err := newAuditEvent(ctx, audit.EventAuthLogout, id.Principal,
			audit.Object{Type: "session", ID: id.SessionID}, audit.OutcomeSuccess, "",
			audit.Payload{"session_id": id.SessionID, "artifact": id.Artifact})
		if err != nil {
			return err
		}
		return az.RecordAuthEvent(ctx, e)
	})
}

// SlideIdleClock advances a live session's idle expiry, at most once per
// SlideGranularity. The transport calls it after a successful response, so
// the write never sits between authorization and the answer.
//
// The decision is made in a READ transaction and a write is opened only when
// one is actually needed. That ordering matters more than it looks: the
// transport calls this for every request carrying any bearer at all,
// including a fabricated one, so opening a write transaction first would let
// anyone contend for sqlite's single write connection just by sending an
// Authorization header full of noise.
//
// It is a no-op — not an error — when the session has since died: the request
// it belonged to already succeeded, and failing here would report a problem
// that no longer has a subject.
func (s *Auth) SlideIdleClock(ctx context.Context, presented string) error {
	now := s.now()
	var sessionID string
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		id, err := az.Authenticate(ctx, presented, now)
		if errors.Is(err, domain.ErrUnauthenticated) {
			return nil
		}
		if err != nil {
			return err
		}
		if now.Sub(id.LastSeenAt) < SlideGranularity {
			return nil
		}
		sessionID = id.SessionID
		return nil
	})
	if err != nil || sessionID == "" {
		return err
	}
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		// Re-authenticate inside the write transaction: the session may have
		// been revoked between the two, and sliding a dead session's clock
		// would resurrect nothing but would write to a row logout deleted.
		id, err := az.Authenticate(ctx, presented, now)
		if errors.Is(err, domain.ErrUnauthenticated) {
			return nil
		}
		if err != nil {
			return err
		}
		return az.SlideSession(ctx, id.SessionID, now, now.Add(Artifact(id.Artifact).idle()))
	})
}
