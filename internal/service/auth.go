package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Dunky13/wenv/internal/admission"
	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/authz"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/tx"
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

// Session artifact kinds, matching the wire enum.
const (
	ArtifactCLI     = "cli"
	ArtifactBrowser = "browser"
)

// Authentication methods, matching the wire enum.
const MethodLocalPassword = "local-password"

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
	Artifact          string
	Assurance         Assurance
	CreatedAt         time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

func identityOf(i authz.Identity) Identity {
	return Identity{
		Principal: i.Principal, SessionID: i.SessionID, Artifact: i.Artifact,
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
	Artifact     string
	CreatedAt    time.Time
	IdleExpires  time.Time
	AbsExpires   time.Time
	Principal    domain.PrincipalID
	AccountID    string
	DisplayName  string
	Assurance    Assurance
}

// LocalLogin is the local floor: password verification against an
// envelope-encrypted Argon2id verifier, minting a CLI session artifact.
//
// The shape is dictated by the enumeration rule. An unknown account traverses
// the same admission budget, the same per-account backoff bucket and a
// bounded dummy-verifier derivation, so neither the response nor the timing
// distinguishes it from a wrong password on a real account. Every refusal
// answers domain.ErrUnauthenticated.
func (s *Auth) LocalLogin(ctx context.Context, username, password string) (LoginResult, error) {
	release, err := s.Admission.Enter(ctx, audit.FromContext(ctx).SourceIP)
	if err != nil {
		return LoginResult{}, err // admission.ErrOverloaded — uniform on every pre-auth path
	}
	defer release()

	// The per-account delay is applied BEFORE verification begins and is
	// shared across concurrent attempts on the account, because it is stored
	// as an absolute instant rather than a per-call sleep.
	if delay := s.Admission.AccountDelay(username); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return LoginResult{}, admission.ErrOverloaded
		}
	}

	out, err := s.attemptLogin(ctx, username, password)
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
func (s *Auth) attemptLogin(ctx context.Context, username, password string) (LoginResult, error) {
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
	// a missing credential or a superseded epoch would make each of them
	// observably faster than a wrong password, which is exactly the oracle
	// this path exists to close.
	cause := ""
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
			// A verifier we cannot open is not a verifier we may accept. This
			// is a real fault (wrong key, tampered row), so it is loud — but
			// the caller still renders the uniform refusal.
			return LoginResult{}, fmt.Errorf("service: opening the verifier for %s failed: %w", account.ID, err)
		}
		ok := crypto.VerifyPassword([]byte(password), plain, crypto.PasswordParams(cred.KDF))
		crypto.Zero(plain)
		if !ok {
			cause = "bad-password"
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
			refused = s.failLogin(ctx, az, now, accountIDOf(resolved, account), resolved, cause)
			return nil
		}
		// Re-read under the write transaction: the credential must not have
		// moved while we were deriving.
		current, err := az.PasswordCredentialFor(ctx, account.ID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				refused = s.failLogin(ctx, az, now, account.ID, true, "credential-removed")
				return nil
			}
			return err
		}
		liveEpoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		if current.RowVersion != cred.RowVersion || current.CredentialEpoch != liveEpoch {
			refused = s.failLogin(ctx, az, now, account.ID, true, "credential-changed")
			return nil
		}
		result, err = s.mintSession(ctx, az, account, now)
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
func (s *Auth) mintSession(ctx context.Context, az *authz.TxAuthorizer, account authz.Account, now time.Time) (LoginResult, error) {
	value, verifier, err := crypto.NewArtifact(crypto.ArtifactCLISession)
	if err != nil {
		return LoginResult{}, err
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
		Artifact: ArtifactCLI, SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: MethodLocalPassword, Factors: string(factors),
		AuthenticatedAt: now, CreatedAt: now,
		IdleExpiresAt: now.Add(CLISessionIdle), AbsoluteExpiresAt: now.Add(CLISessionAbsolute),
		SourceIP: wire.SourceIP, UserAgent: wire.UserAgent,
	}
	if err := az.MintSession(ctx, sess); err != nil {
		return LoginResult{}, err
	}

	for _, ev := range []struct {
		typ     audit.EventType
		payload audit.Payload
	}{
		{audit.EventAuthLogin, audit.Payload{
			"method": MethodLocalPassword, "artifact": ArtifactCLI,
			"subject_resolved": true, "account_id": account.ID, "assurance": "single-factor",
		}},
		{audit.EventAuthSessionCreated, audit.Payload{
			"session_id": id, "artifact": ArtifactCLI,
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
		SessionToken: value, SessionID: id, Artifact: ArtifactCLI,
		CreatedAt: now, IdleExpires: sess.IdleExpiresAt, AbsExpires: sess.AbsoluteExpiresAt,
		Principal: account.PrincipalID, AccountID: account.ID, DisplayName: account.DisplayName,
		Assurance: Assurance{
			Method: MethodLocalPassword, Factors: []string{"password"}, AuthenticatedAt: now,
		},
	}, nil
}

// failLogin records the failure and returns the uniform refusal. The cause is
// recorded by CLASS in the trail, never returned to the caller: the trail is
// audit-read gated and may hold the truth, the response may not.
func (s *Auth) failLogin(ctx context.Context, az *authz.TxAuthorizer, now time.Time, accountID string, resolved bool, cause string) error {
	payload := audit.Payload{
		"method": MethodLocalPassword, "artifact": ArtifactCLI,
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
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return err
	}
	return domain.ErrUnauthenticated
}

func (s *Auth) recordThrottleCrossing(ctx context.Context, username string) {
	// Best-effort by design: the login has already been refused, and failing
	// the caller's request because a secondary observability event could not
	// be written would convert a throttle into an outage. The failure is
	// still loud in the process log via the transaction's own error.
	_ = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
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
	if len([]rune(password)) < PasswordMinLength {
		return ErrWeakPassword
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

	// Same discipline as the login path: a refusal leaves the closure through
	// `refused`, never through the return value, so the transaction commits
	// the record of it instead of rolling that record back.
	var refused error
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		refused = nil
		now := s.now()
		auth, err := az.AuthorityByValue(ctx, crypto.ArtifactVerifier(authority))
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				refused = s.refuseAuthorityIn(ctx, az, "unknown")
				return nil
			}
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		var cause string
		switch {
		case auth.Consumed:
			cause = "consumed"
		case !now.Before(auth.ExpiresAt):
			cause = "expired"
		case auth.CredentialEpoch != epoch:
			cause = "epoch-superseded"
		}
		if cause != "" {
			refused = s.refuseAuthorityIn(ctx, az, cause)
			return nil
		}

		// Claim it first. The NULL guard is the atomic claim, so two
		// concurrent presentations cannot both establish a credential and the
		// loser fails closed.
		claimed, err := az.ConsumeAuthority(ctx, auth.ID, now)
		if err != nil {
			return err
		}
		if !claimed {
			refused = s.refuseAuthorityIn(ctx, az, "consumed")
			return nil
		}

		if err := s.writeCredential(ctx, az, auth.AccountID, password, epoch, now); err != nil {
			return err
		}

		// Establishing a credential invalidates every session of the
		// principal: an account-security mutation deletes sessions in the
		// same transaction as the credential change.
		account, err := az.AccountByID(ctx, auth.AccountID)
		if err != nil {
			return err
		}
		if err := az.AdvanceGeneration(ctx, account.PrincipalID); err != nil {
			return err
		}
		if err := az.RevokeAllSessionsFor(ctx, account.PrincipalID); err != nil {
			return err
		}

		e, err := newAuditEvent(ctx, audit.EventAuthCredentialEstablished, account.PrincipalID,
			audit.Object{Type: "account", ID: auth.AccountID}, audit.OutcomeSuccess, "",
			audit.Payload{
				"authority_id": auth.ID, "account_id": auth.AccountID,
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

// writeCredential seals a fresh verifier and writes it, inserting or
// compare-and-swapping depending on whether one already exists.
func (s *Auth) writeCredential(ctx context.Context, az *authz.TxAuthorizer, accountID, password string, epoch int64, now time.Time) error {
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	plain, err := crypto.DeriveVerifier([]byte(password), salt, s.KDF)
	if err != nil {
		return err
	}
	defer crypto.Zero(plain)

	sealer := s.Keyring.ForInstance()
	sealed, err := sealer.SealField(verifierAAD(accountID), plain)
	if err != nil {
		return err
	}
	cred := authz.PasswordCredential{
		AccountID: accountID, Verifier: sealed,
		KDF:             authz.KDFParams{MemoryKiB: s.KDF.MemoryKiB, Time: s.KDF.Time, Parallelism: s.KDF.Parallelism},
		DEKVersion:      int64(sealer.Version()),
		CredentialEpoch: epoch,
	}

	existing, err := az.PasswordCredentialFor(ctx, accountID)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return az.WritePasswordCredential(ctx, cred, now)
	case err != nil:
		return err
	}
	cred.RowVersion = existing.RowVersion
	swapped, err := az.ReplacePasswordCredential(ctx, cred, now)
	if err != nil {
		return err
	}
	if !swapped {
		return ErrCredentialRace
	}
	return nil
}

func (s *Auth) refuseAuthority(ctx context.Context, cause string) error {
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return s.refuseAuthorityIn(ctx, az, cause)
	})
	if errors.Is(err, domain.ErrUnauthenticated) {
		return err
	}
	if err != nil {
		return err
	}
	return domain.ErrUnauthenticated
}

// refuseAuthorityIn records the refusal and returns the uniform outcome. The
// caller commits the transaction and then returns what this produced: the
// event has to survive the refusal it describes.
func (s *Auth) refuseAuthorityIn(ctx context.Context, az *authz.TxAuthorizer, cause string) error {
	e, err := newAuditEvent(ctx, audit.EventAuthAuthorityRefused, "",
		audit.Object{Type: "credential_authority"}, audit.OutcomeFailure, "",
		audit.Payload{"cause": cause})
	if err != nil {
		return err
	}
	if err := az.RecordAuthEvent(ctx, e); err != nil {
		return err
	}
	return domain.ErrUnauthenticated
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
// It is a no-op — not an error — when the session has since died: the request
// it belonged to already succeeded, and failing here would report a problem
// that no longer has a subject.
func (s *Auth) SlideIdleClock(ctx context.Context, presented string) error {
	now := s.now()
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
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
		return az.SlideSession(ctx, id.SessionID, now, now.Add(CLISessionIdle))
	})
}
