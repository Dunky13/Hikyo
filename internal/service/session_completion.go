package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// SessionCompletion is the closed input to the transaction-local session
// completion module. Creation and rotation are separate variants: creation
// owns a new row and clocks, while rotation preserves the live row's identity
// and clocks. A caller cannot select one behaviour with a Boolean flag.
type SessionCompletion interface {
	sessionCompletion()
}

// sessionCompletionAttempt carries refusal beside a display-once result so
// callers can commit required refusal audits without publishing values from a
// rolled-back transaction attempt.
type sessionCompletionAttempt struct {
	result  LoginResult
	refused sessionRefusal
}

type sessionRefusal uint8

const (
	sessionNotRefused sessionRefusal = iota
	sessionRefusedUnauthenticated
	sessionRefusedWindowClosed
	sessionRefusedAlreadyLinked
)

func (r sessionRefusal) err() error {
	switch r {
	case sessionNotRefused:
		return nil
	case sessionRefusedUnauthenticated:
		return domain.ErrUnauthenticated
	case sessionRefusedWindowClosed:
		return ErrReauthWindowClosed
	case sessionRefusedAlreadyLinked:
		return ErrAlreadyLinked
	default:
		return fmt.Errorf("%w: unknown committed session refusal", domain.ErrInvalid)
	}
}

func writeCommittedLoginResult(ctx context.Context, db *store.DB, fn func(context.Context, store.Repos, *authz.TxAuthorizer, *LoginResult) error) (LoginResult, error) {
	return tx.WriteResult(ctx, db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) (LoginResult, error) {
		var result LoginResult
		err := fn(ctx, repos, az, &result)
		return result, err
	})
}

func writeCommittedSessionAttempt(ctx context.Context, db *store.DB, fn func(context.Context, store.Repos, *authz.TxAuthorizer, *sessionCompletionAttempt) error) (sessionCompletionAttempt, error) {
	return tx.WriteResult(ctx, db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) (sessionCompletionAttempt, error) {
		var attempt sessionCompletionAttempt
		err := fn(ctx, repos, az, &attempt)
		return attempt, err
	})
}

func writeCommittedReauthResults(ctx context.Context, db *store.DB, fn func(context.Context, store.Repos, *authz.TxAuthorizer, *[]ReauthResult) error) ([]ReauthResult, error) {
	return tx.WriteResult(ctx, db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) ([]ReauthResult, error) {
		var results []ReauthResult
		err := fn(ctx, repos, az, &results)
		return results, err
	})
}

func writeCommittedCLIReauth(ctx context.Context, db *store.DB, fn func(context.Context, store.Repos, *authz.TxAuthorizer, *CLIReauthRedeemed) error) (CLIReauthRedeemed, error) {
	return tx.WriteResult(ctx, db, func(ctx context.Context, repos store.Repos, az *authz.TxAuthorizer) (CLIReauthRedeemed, error) {
		var result CLIReauthRedeemed
		err := fn(ctx, repos, az, &result)
		return result, err
	})
}

// CreateSession describes a newly authenticated session. Factor verification,
// audit events and any provider-specific binding stay with the caller.
type CreateSession struct {
	account    authz.Account
	artifact   Artifact
	assurance  Assurance
	csrf       sessionCSRF
	providerID string
}

func (CreateSession) sessionCompletion() {}

// RotateSession describes a live session whose bearer and factor projection
// are replaced in place. The caller must authenticate session inside the same
// transaction immediately before completion.
type RotateSession struct {
	session authz.Identity
	account authz.Account
	factors []string
}

func (RotateSession) sessionCompletion() {}

// sessionCSRF keeps browser-only CSRF creation caller-explicit without a
// Boolean option on the completion module.
type sessionCSRF uint8

const (
	sessionWithoutCSRF sessionCSRF = iota + 1
	sessionWithCSRF
)

// completeSession owns display-once artifact creation, verifier persistence,
// factor serialization and LoginResult projection. It must run inside the
// caller's write transaction, whose tx.WriteResult return publishes only the
// attempt that committed.
func (s *Auth) completeSession(ctx context.Context, az *authz.TxAuthorizer, completion SessionCompletion, now time.Time) (LoginResult, error) {
	switch value := completion.(type) {
	case CreateSession:
		return s.createCompletedSession(ctx, az, value, now)
	case RotateSession:
		return s.rotateCompletedSession(ctx, az, value)
	default:
		return LoginResult{}, fmt.Errorf("%w: unknown session completion variant", domain.ErrInvalid)
	}
}

func (s *Auth) createCompletedSession(ctx context.Context, az *authz.TxAuthorizer, completion CreateSession, now time.Time) (LoginResult, error) {
	if !completion.artifact.Valid() {
		return LoginResult{}, fmt.Errorf("%w: unknown session artifact %q", domain.ErrInvalid, completion.artifact)
	}
	if completion.account.ID == "" || completion.account.PrincipalID == "" {
		return LoginResult{}, fmt.Errorf("%w: session creation requires an account", domain.ErrInvalid)
	}
	switch {
	case completion.artifact == ArtifactBrowser && completion.csrf != sessionWithCSRF:
		return LoginResult{}, fmt.Errorf("%w: browser session requires CSRF creation", domain.ErrInvalid)
	case completion.artifact == ArtifactCLI && completion.csrf != sessionWithoutCSRF:
		return LoginResult{}, fmt.Errorf("%w: CLI session cannot create a CSRF token", domain.ErrInvalid)
	}

	value, verifier, err := crypto.NewArtifact(completion.artifact.bearerKind())
	if err != nil {
		return LoginResult{}, err
	}
	var csrfValue string
	var csrfVerifier []byte
	if completion.csrf == sessionWithCSRF {
		csrfValue, csrfVerifier, err = crypto.NewArtifact(crypto.ArtifactCSRF)
		if err != nil {
			return LoginResult{}, err
		}
	}
	sessionID, err := newID("ses")
	if err != nil {
		return LoginResult{}, err
	}
	generation, err := az.PrincipalGeneration(ctx, completion.account.PrincipalID)
	if err != nil {
		return LoginResult{}, err
	}
	epoch, err := az.CredentialEpoch(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	factors := append([]string(nil), completion.assurance.Factors...)
	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return LoginResult{}, err
	}
	wire := audit.FromContext(ctx)
	session := authz.NewSession{
		ID: sessionID, PrincipalID: completion.account.PrincipalID, Verifier: verifier,
		Artifact: completion.artifact.String(), SessionGeneration: generation, CredentialEpoch: epoch,
		AuthMethod: completion.assurance.Method, Factors: string(factorsJSON),
		AuthenticatedAt: completion.assurance.AuthenticatedAt, CeremonyID: completion.assurance.CeremonyID,
		CreatedAt: now, IdleExpiresAt: now.Add(completion.artifact.idle()),
		AbsoluteExpiresAt: now.Add(completion.artifact.absolute()),
		SourceIP:          wire.SourceIP, UserAgent: wire.UserAgent,
		ProviderID: completion.providerID, CSRFVerifier: csrfVerifier,
	}
	if err := az.MintSession(ctx, session); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: sessionID, Artifact: completion.artifact,
		CreatedAt: now, IdleExpires: session.IdleExpiresAt, AbsExpires: session.AbsoluteExpiresAt,
		Principal: completion.account.PrincipalID, AccountID: completion.account.ID,
		DisplayName: completion.account.DisplayName,
		Assurance: Assurance{
			Method: completion.assurance.Method, Factors: factors,
			AuthenticatedAt: completion.assurance.AuthenticatedAt, CeremonyID: completion.assurance.CeremonyID,
		},
		CSRFToken: csrfValue,
	}, nil
}

func (s *Auth) rotateCompletedSession(ctx context.Context, az *authz.TxAuthorizer, completion RotateSession) (LoginResult, error) {
	artifact := Artifact(completion.session.Artifact)
	if !artifact.Valid() || completion.session.SessionID == "" {
		return LoginResult{}, fmt.Errorf("%w: rotation requires a live browser or CLI session", domain.ErrInvalid)
	}
	if completion.account.ID == "" || completion.account.PrincipalID == "" {
		return LoginResult{}, fmt.Errorf("%w: session rotation requires an account", domain.ErrInvalid)
	}
	if completion.account.PrincipalID != completion.session.Principal {
		return LoginResult{}, fmt.Errorf("%w: rotation account does not own session", domain.ErrInvalid)
	}
	value, verifier, err := crypto.NewArtifact(artifact.bearerKind())
	if err != nil {
		return LoginResult{}, err
	}
	factors := append([]string(nil), completion.factors...)
	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return LoginResult{}, err
	}
	if err := az.RotateSessionFactors(ctx, completion.session.SessionID, verifier, string(factorsJSON)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		SessionToken: value, SessionID: completion.session.SessionID, Artifact: artifact,
		CreatedAt: completion.session.CreatedAt, IdleExpires: completion.session.IdleExpiresAt,
		AbsExpires: completion.session.AbsoluteExpiresAt, Principal: completion.session.Principal,
		AccountID: completion.account.ID, DisplayName: completion.account.DisplayName,
		Assurance: Assurance{
			Method: completion.session.Assurance.Method, Factors: factors,
			AuthenticatedAt: completion.session.Assurance.AuthenticatedAt,
			CeremonyID:      completion.session.Assurance.CeremonyID,
		},
	}, nil
}
