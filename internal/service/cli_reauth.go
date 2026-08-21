package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

const CLIReauthLifetime = 5 * time.Minute

var ErrCLIReauthInvalid = errors.New("service: invalid or spent CLI reauthentication handoff")

type CLIReauthStart struct {
	State     string
	ExpiresAt time.Time
}

type CLIReauthEnvironmentPolicy struct {
	EnvironmentID          string
	EffectiveWindowSeconds int
	RequiresWebAuthn       bool
}

type CLIReauthTransaction struct {
	State, Purpose, Operation, RedirectURI string
	Environments                           []CLIReauthEnvironmentPolicy
	// KeyIDs is the enumerated unit of a disclosure purpose (reveal, copy):
	// exactly the keys the one browser decision will cover. Empty for adapter.
	KeyIDs    []string
	ExpiresAt time.Time
}

type CLIReauthApproval struct {
	Code, State, RedirectURI string
}

type cliApprovedWindow struct {
	EnvironmentID   string    `json:"environment_id"`
	CeremonyID      string    `json:"ceremony_id"`
	FactorClass     string    `json:"factor_class"`
	SingleDecision  bool      `json:"single_decision"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
	WindowExpiresAt time.Time `json:"window_expires_at"`
	HardExpiresAt   time.Time `json:"hard_expires_at"`
	// The binding the browser's window carried, reproduced verbatim on the
	// CLI's window at redemption: an adapter window is bound to (purpose,
	// operation, environment set); a disclosure window opened by a sliding
	// TOTP ceremony is unbound, and a single-decision passkey window is bound
	// through its ceremony's pinned (purpose, environment, key set) binding,
	// which the ceremony id carries.
	BoundPurpose        string `json:"bound_purpose,omitempty"`
	BoundOperation      string `json:"bound_operation,omitempty"`
	BoundEnvironmentSet string `json:"bound_environment_set,omitempty"`
}

// cliReauthPurposeOperation is the closed (purpose, operation) table the
// handoff admits. A disclosure purpose maps to the one operation its
// ceremony binds (ceremony.go operationForReauthPurpose); the adapter purpose
// admits the four adapter operations.
func cliReauthPurposeOperation(purpose ReauthPurpose, operation authz.Operation) bool {
	switch purpose {
	case PurposeAdapter:
		return adapterReauthOperation(operation)
	case PurposeReveal:
		return operation == authz.OpValueReveal
	case PurposeCopy:
		return operation == authz.OpValueCopySource
	}
	return false
}

// cliReauthDisclosure reports whether the handoff carries a disclosure
// purpose: one the browser satisfies with the enumerated-key-set ceremony.
func cliReauthDisclosure(purpose string) bool {
	return purpose == string(PurposeReveal) || purpose == string(PurposeCopy)
}

type CLIReauthRedeemed struct {
	SessionToken string
	SessionID    string
	Windows      []ReauthResult
}

type cliReauthAuditContext struct {
	HandoffID, Operation, EnvironmentSet string
	Principal                            domain.PrincipalID
}

func cliReauthAuditFromHandoff(h authz.CLIReauthHandoff) cliReauthAuditContext {
	return cliReauthAuditContext{HandoffID: h.ID, Operation: h.Operation, EnvironmentSet: h.EnvironmentSet, Principal: h.PrincipalID}
}

func cliReauthAuditEvent(ctx context.Context, phase string, outcome audit.Outcome, detail cliReauthAuditContext, cause string) (audit.Event, error) {
	payload := audit.Payload{"phase": phase}
	if detail.HandoffID != "" {
		payload["handoff_id"] = detail.HandoffID
	}
	if detail.Operation != "" {
		payload["operation"] = detail.Operation
	}
	if detail.EnvironmentSet != "" {
		payload["environment_ids"] = strings.Split(detail.EnvironmentSet, "\n")
	}
	if cause != "" {
		payload["cause"] = cause
	}
	return newAuditEvent(ctx, audit.EventAuthCLIReauthHandoff, detail.Principal,
		audit.Object{Type: "cli-reauth-handoff", ID: detail.HandoffID}, outcome, "", payload)
}

func captureCLIReauthFailure(ctx context.Context, az *authz.TxAuthorizer, phase string, detail cliReauthAuditContext, cause string, failure error) error {
	event, err := cliReauthAuditEvent(ctx, phase, audit.OutcomeFailure, detail, cause)
	if err != nil {
		return err
	}
	az.CaptureAudit(audit.TrailInstance, domain.Scope{}, event)
	return failure
}

func recordCLIReauthSuccess(ctx context.Context, az *authz.TxAuthorizer, phase string, detail cliReauthAuditContext) error {
	event, err := cliReauthAuditEvent(ctx, phase, audit.OutcomeSuccess, detail, "")
	if err != nil {
		return err
	}
	return az.RecordAuthEvent(ctx, event)
}

func (s *Auth) rejectCLIReauthRequest(ctx context.Context, phase string, failure error) error {
	return tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		return captureCLIReauthFailure(ctx, az, phase, cliReauthAuditContext{}, "invalid_request", failure)
	})
}

func (s *Auth) StartCLIReauth(ctx context.Context, presented, purpose, operation string, environmentIDs, keyIDs []string, pkceChallenge, redirectURI string) (CLIReauthStart, error) {
	if !cliReauthPurposeOperation(ReauthPurpose(purpose), authz.Operation(operation)) || !validPKCEChallenge(pkceChallenge) || !validCLILoopbackRedirect(redirectURI) {
		failure := fmt.Errorf("%w: a known purpose with its operation, environments and PKCE S256 are required", domain.ErrInvalid)
		return CLIReauthStart{}, s.rejectCLIReauthRequest(ctx, "start", failure)
	}
	environmentIDs = adapterEnvironmentSet(environmentIDs)
	if len(environmentIDs) == 0 {
		return CLIReauthStart{}, s.rejectCLIReauthRequest(ctx, "start", ErrReauthUnitMismatch)
	}
	// A disclosure handoff carries its enumerated unit; an adapter handoff
	// carries none. The ceremony the browser runs binds exactly this set, and
	// the CLI's disclosure consumes exactly this set, so a handoff without one
	// would be a window any later disclosure could spend.
	keySet := CanonicalKeySet(keyIDs)
	if cliReauthDisclosure(purpose) == (keySet == "") {
		return CLIReauthStart{}, s.rejectCLIReauthRequest(ctx, "start", ErrReauthUnitMismatch)
	}
	for _, keyID := range keyIDs {
		if keyID == "" || strings.ContainsAny(keyID, "\n") {
			return CLIReauthStart{}, s.rejectCLIReauthRequest(ctx, "start", ErrReauthUnitMismatch)
		}
	}
	id, err := newID("crh")
	if err != nil {
		return CLIReauthStart{}, err
	}
	state, verifier, err := crypto.NewArtifact(crypto.ArtifactHandoffState)
	if err != nil {
		return CLIReauthStart{}, err
	}
	now := s.now()
	expires := now.Add(CLIReauthLifetime)
	err = tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		caller, err := az.Authenticate(ctx, presented, now)
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "start", cliReauthAuditContext{HandoffID: id, Operation: operation, EnvironmentSet: CanonicalEnvironmentSet(environmentIDs)}, "unauthenticated", fmt.Errorf("authenticate initiating CLI: %w", err))
		}
		detail := cliReauthAuditContext{HandoffID: id, Operation: operation, EnvironmentSet: CanonicalEnvironmentSet(environmentIDs), Principal: caller.Principal}
		if caller.Artifact != ArtifactCLI.String() {
			return captureCLIReauthFailure(ctx, az, "start", detail, "unauthenticated", fmt.Errorf("initiating artifact %q is not CLI: %w", caller.Artifact, domain.ErrUnauthenticated))
		}
		for _, environmentID := range environmentIDs {
			chain, err := az.EnvironmentChainByID(ctx, environmentID)
			if err != nil {
				return captureCLIReauthFailure(ctx, az, "start", detail, "unauthorized", err)
			}
			if err := cliReauthAuthorizeStart(ctx, az, caller, purpose, operation, chain, environmentID); err != nil {
				return captureCLIReauthFailure(ctx, az, "start", detail, "unauthorized", err)
			}
			// The reveal conjunct is re-evaluated by the real operation after
			// redemption. Authorizing it here would apply its MFA floor before
			// this very ceremony has had a chance to elevate the CLI session.
		}
		if err := az.CreateCLIReauthHandoff(ctx, authz.NewCLIReauthHandoff{ID: id, StateVerifier: verifier, SessionID: caller.SessionID, PrincipalID: caller.Principal, Purpose: purpose, Operation: operation, EnvironmentSet: CanonicalEnvironmentSet(environmentIDs), KeySet: keySet, PKCEChallenge: pkceChallenge, RedirectURI: redirectURI, CreatedAt: now, ExpiresAt: expires}); err != nil {
			return err
		}
		return recordCLIReauthSuccess(ctx, az, "start", detail)
	})
	if err != nil {
		return CLIReauthStart{}, err
	}
	return CLIReauthStart{State: state, ExpiresAt: expires}, nil
}

// cliReauthAuthorizeStart is the pre-ceremony authorization of a handoff:
// what the initiating CLI session must already hold BEFORE the browser
// elevates it. An adapter handoff authorizes the adapter operation at project
// depth (its reveal conjunct is dynamic and re-evaluated after redemption). A
// disclosure handoff authorizes `read` over the environment it will disclose
// in: a principal who cannot read the environment is not offered a ceremony,
// while the MFA-mandatory `reveal` conjunct is judged by the disclosure itself
// once the session carries the factor the ceremony adds.
func cliReauthAuthorizeStart(ctx context.Context, az *authz.TxAuthorizer, caller authz.Identity, purpose, operation string, chain authz.EnvironmentChain, environmentID string) error {
	if cliReauthDisclosure(purpose) {
		env := domain.Scope{Org: domain.OrgID(chain.Org), Project: domain.ProjectID(chain.Project), Env: domain.EnvID(environmentID)}
		if _, err := az.Authorize(ctx, caller, authz.OpValueList, env); err != nil {
			return fmt.Errorf("authorize read for %s: %w", environmentID, err)
		}
		return nil
	}
	project := domain.Scope{Org: domain.OrgID(chain.Org), Project: domain.ProjectID(chain.Project)}
	if _, err := az.Authorize(ctx, caller, authz.Operation(operation), project); err != nil {
		return fmt.Errorf("authorize %s for %s: %w", operation, environmentID, err)
	}
	return nil
}

func validCLILoopbackRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "/callback" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return false
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort <= 0 || parsedPort > 65535 {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && (host == "127.0.0.1" || host == "::1")
}

func (s *Auth) CLIReauthTransaction(ctx context.Context, actor Actor, state string) (CLIReauthTransaction, error) {
	if err := crypto.ParseArtifact(state, crypto.ArtifactHandoffState); err != nil {
		return CLIReauthTransaction{}, s.rejectCLIReauthRequest(ctx, "inspect", ErrCLIReauthInvalid)
	}
	now := s.now()
	var out CLIReauthTransaction
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "inspect", cliReauthAuditContext{}, "unauthenticated", err)
		}
		h, err := az.CLIReauthHandoffByState(ctx, crypto.ArtifactVerifier(state))
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "inspect", cliReauthAuditContext{Principal: caller.Principal}, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		detail := cliReauthAuditFromHandoff(h)
		if !h.Live(now) || len(h.CodeVerifier) != 0 || !validCLILoopbackRedirect(h.RedirectURI) {
			return captureCLIReauthFailure(ctx, az, "inspect", detail, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		if h.PrincipalID != caller.Principal {
			return captureCLIReauthFailure(ctx, az, "inspect", detail, "unauthorized", ErrCLIReauthInvalid)
		}
		out = CLIReauthTransaction{State: state, Purpose: h.Purpose, Operation: h.Operation, RedirectURI: h.RedirectURI, ExpiresAt: h.ExpiresAt, Environments: []CLIReauthEnvironmentPolicy{}, KeyIDs: []string{}}
		if h.KeySet != "" {
			out.KeyIDs = strings.Split(h.KeySet, "\n")
		}
		for _, environmentID := range strings.Split(h.EnvironmentSet, "\n") {
			chain, err := az.EnvironmentChainByID(ctx, environmentID)
			if err != nil {
				return captureCLIReauthFailure(ctx, az, "inspect", detail, "unauthorized", err)
			}
			if err := cliReauthAuthorizeStart(ctx, az, caller, h.Purpose, h.Operation, chain, environmentID); err != nil {
				return captureCLIReauthFailure(ctx, az, "inspect", detail, "unauthorized", err)
			}
			effective, err := s.effectiveReauthWindow(ctx, az, environmentID)
			if err != nil {
				return err
			}
			out.Environments = append(out.Environments, CLIReauthEnvironmentPolicy{EnvironmentID: environmentID, EffectiveWindowSeconds: int(effective / time.Second), RequiresWebAuthn: effective <= 0})
		}
		return recordCLIReauthSuccess(ctx, az, "inspect", detail)
	})
	return out, err
}

func (s *Auth) ApproveCLIReauth(ctx context.Context, actor Actor, state string) (CLIReauthApproval, error) {
	if err := crypto.ParseArtifact(state, crypto.ArtifactHandoffState); err != nil {
		return CLIReauthApproval{}, s.rejectCLIReauthRequest(ctx, "approve", ErrCLIReauthInvalid)
	}
	now := s.now()
	var out CLIReauthApproval
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		caller, err := az.Authenticate(ctx, actor.bearer, now)
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "approve", cliReauthAuditContext{}, "unauthenticated", err)
		}
		h, err := az.CLIReauthHandoffByState(ctx, crypto.ArtifactVerifier(state))
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "approve", cliReauthAuditContext{Principal: caller.Principal}, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		detail := cliReauthAuditFromHandoff(h)
		if !h.Live(now) || len(h.CodeVerifier) != 0 || !validCLILoopbackRedirect(h.RedirectURI) {
			return captureCLIReauthFailure(ctx, az, "approve", detail, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		if h.PrincipalID != caller.Principal {
			return captureCLIReauthFailure(ctx, az, "approve", detail, "unauthorized", ErrCLIReauthInvalid)
		}
		environments := strings.Split(h.EnvironmentSet, "\n")
		windows := make([]cliApprovedWindow, 0, len(environments))
		for _, environmentID := range environments {
			w, err := az.ReauthWindowFor(ctx, caller.SessionID, environmentID)
			if err != nil {
				return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthRequired)
			}
			if !now.Before(w.WindowExpiresAt) || !now.Before(w.HardExpiresAt) {
				return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthRequired)
			}
			effective, err := s.effectiveReauthWindow(ctx, az, environmentID)
			if err != nil {
				return err
			}
			if effective <= 0 && (w.FactorClass != "webauthn" || !w.SingleDecision) {
				return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthRequired)
			}
			if cliReauthDisclosure(h.Purpose) {
				// The browser ran the disclosure ceremony: a single-decision
				// passkey window carries its ceremony's pinned (purpose,
				// environment, key set) binding, which must equal the handoff's
				// unit byte-exact; a sliding window is unbound by construction and
				// is accepted as the environment-wide consent it is.
				if w.BoundPurpose != "" || w.BoundEnvironmentSet != "" {
					return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthUnitMismatch)
				}
				if w.SingleDecision {
					ceremony, err := az.WebAuthnCeremonyByID(ctx, w.CeremonyID)
					if err != nil {
						return err
					}
					want, err := operationBinding(ReauthPurpose(h.Purpose), environmentID, strings.Split(h.KeySet, "\n"))
					if err != nil {
						return err
					}
					if ceremony.OperationBinding != want {
						return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthUnitMismatch)
					}
				}
			} else if w.BoundPurpose != string(PurposeAdapter) || w.BoundOperation != h.Operation || w.BoundEnvironmentSet != h.EnvironmentSet {
				return captureCLIReauthFailure(ctx, az, "approve", detail, "reauth_required", ErrReauthRequired)
			}
			if w.SingleDecision {
				claimed, err := az.ConsumeSingleDecisionWindow(ctx, w.ID, now)
				if err != nil {
					return err
				}
				if !claimed {
					return captureCLIReauthFailure(ctx, az, "approve", detail, "already_consumed", ErrReauthWindowSpent)
				}
			}
			windows = append(windows, cliApprovedWindow{EnvironmentID: environmentID, CeremonyID: w.CeremonyID, FactorClass: w.FactorClass, SingleDecision: w.SingleDecision, AuthenticatedAt: w.AuthenticatedAt, WindowExpiresAt: w.WindowExpiresAt, HardExpiresAt: w.HardExpiresAt,
				BoundPurpose: w.BoundPurpose, BoundOperation: w.BoundOperation, BoundEnvironmentSet: w.BoundEnvironmentSet})
		}
		windowJSON, err := json.Marshal(windows)
		if err != nil {
			return err
		}
		value, verifier, err := crypto.NewArtifact(crypto.ArtifactHandoffCode)
		if err != nil {
			return err
		}
		claimed, err := az.ApproveCLIReauthHandoff(ctx, h.ID, verifier, windowJSON)
		if err != nil {
			return err
		}
		if !claimed {
			return captureCLIReauthFailure(ctx, az, "approve", detail, "already_consumed", ErrCLIReauthInvalid)
		}
		out = CLIReauthApproval{Code: value, State: state, RedirectURI: h.RedirectURI}
		return recordCLIReauthSuccess(ctx, az, "approve", detail)
	})
	return out, err
}

func (s *Auth) RedeemCLIReauth(ctx context.Context, code, pkceVerifier string) (CLIReauthRedeemed, error) {
	if err := crypto.ParseArtifact(code, crypto.ArtifactHandoffCode); err != nil || !validPKCEVerifier(pkceVerifier) {
		return CLIReauthRedeemed{}, s.rejectCLIReauthRequest(ctx, "redeem", ErrCLIReauthInvalid)
	}
	now := s.now()
	var out CLIReauthRedeemed
	err := tx.Write(ctx, s.DB, func(ctx context.Context, _ store.Repos, az *authz.TxAuthorizer) error {
		h, err := az.CLIReauthHandoffByCode(ctx, crypto.ArtifactVerifier(code))
		if err != nil {
			return captureCLIReauthFailure(ctx, az, "redeem", cliReauthAuditContext{}, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		detail := cliReauthAuditFromHandoff(h)
		if !h.ConsumedAt.IsZero() {
			return captureCLIReauthFailure(ctx, az, "redeem", detail, "already_consumed", ErrCLIReauthInvalid)
		}
		if !h.Live(now) || len(h.ApprovedWindows) == 0 {
			return captureCLIReauthFailure(ctx, az, "redeem", detail, "invalid_or_expired", ErrCLIReauthInvalid)
		}
		if pkceS256(pkceVerifier) != h.PKCEChallenge {
			return captureCLIReauthFailure(ctx, az, "redeem", detail, "pkce_mismatch", ErrCLIReauthInvalid)
		}
		caller, err := az.AuthenticateSessionByID(ctx, h.SessionID, now)
		if err != nil || caller.Principal != h.PrincipalID || caller.Artifact != ArtifactCLI.String() {
			return captureCLIReauthFailure(ctx, az, "redeem", detail, "unauthenticated", domain.ErrUnauthenticated)
		}
		claimed, err := az.ConsumeCLIReauthHandoff(ctx, h.ID, now)
		if err != nil {
			return err
		}
		if !claimed {
			return captureCLIReauthFailure(ctx, az, "redeem", detail, "already_consumed", ErrCLIReauthInvalid)
		}
		value, verifier, err := s.newSessionArtifact(ArtifactCLI)
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		var windows []cliApprovedWindow
		if err := json.Unmarshal(h.ApprovedWindows, &windows); err != nil {
			return err
		}
		factorsList := append([]string(nil), caller.Assurance.Factors...)
		for _, approved := range windows {
			factorsList = withFactor(factorsList, approved.FactorClass)
		}
		factors, err := json.Marshal(factorsList)
		if err != nil {
			return err
		}
		if err := az.RotateSessionFactors(ctx, caller.SessionID, verifier, string(factors)); err != nil {
			return err
		}
		for _, approved := range windows {
			if !now.Before(approved.WindowExpiresAt) || !now.Before(approved.HardExpiresAt) {
				return captureCLIReauthFailure(ctx, az, "redeem", detail, "reauth_required", ErrCLIReauthInvalid)
			}
			id, err := newID("raw")
			if err != nil {
				return err
			}
			// The CLI's window reproduces the browser window's binding exactly:
			// an adapter share stays bound to its (purpose, operation, set); a
			// disclosure window stays bound through its ceremony id alone, so
			// the CLI's disclosure is matched against the same pinned unit.
			if err := az.OpenReauthWindow(ctx, authz.NewReauthWindow{ID: id, SessionID: caller.SessionID, EnvironmentID: approved.EnvironmentID, CeremonyID: approved.CeremonyID, FactorClass: approved.FactorClass, SingleDecision: approved.SingleDecision, AuthenticatedAt: approved.AuthenticatedAt, WindowExpiresAt: approved.WindowExpiresAt, HardExpiresAt: approved.HardExpiresAt, CredentialEpoch: epoch, CreatedAt: now, BoundPurpose: approved.BoundPurpose, BoundOperation: approved.BoundOperation, BoundEnvironmentSet: approved.BoundEnvironmentSet}); err != nil {
				return err
			}
			out.Windows = append(out.Windows, ReauthResult{SessionID: caller.SessionID, EnvironmentID: approved.EnvironmentID, SingleDecision: approved.SingleDecision, WindowExpires: approved.WindowExpiresAt})
		}
		out.SessionToken, out.SessionID = value, caller.SessionID
		return recordCLIReauthSuccess(ctx, az, "redeem", detail)
	})
	if err != nil {
		return CLIReauthRedeemed{}, err
	}
	return out, nil
}
