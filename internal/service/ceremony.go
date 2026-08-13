package service

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Dunky13/hikyo/internal/authz"
	"github.com/Dunky13/hikyo/internal/domain"
	"github.com/Dunky13/hikyo/internal/store"
	"github.com/Dunky13/hikyo/internal/store/tx"
)

// The disclosure ceremony (#58, permission-model ADR § The reveal guard,
// locked prototype #21 `prototype/reveal-edit/`, approach a).
//
// #50 gave the value surface its CAPABILITY half: `read(E)` ∧ `reveal(E)` and
// one audit event per disclosed key. This file adds the second half the ADR
// puts in front of it — "a sliding reauthentication window, configured per
// environment under `project-settings`, where `0` means every disclosure" —
// and it is deliberately a THIN adapter over machinery that already exists:
// `Auth.ConsumeReauthWindow` (#54) is the window's consumption rule, this is
// only the seam that calls it at the value surface.
//
// Three ADR invariants are load-bearing here and are stated so a later edit
// cannot lose them by accident:
//
//  1. **The window gates the reauthentication PROMPT, never the authorization
//     check.** Every gate call below runs AFTER `authorize()` has already
//     produced a proof, inside the disclosure's own transaction. A revoked
//     `reveal` therefore stops revealing on the next cell even inside an open
//     window, because the capability check ran first and failed first.
//  2. **The gate covers every route in the formula table**, not only the
//     matrix cell: cell reveal, bulk reveal, diff reveal, and both ends of a
//     copy. The two ends are gated differently, and the difference is the ADR's
//     not this file's: the SOURCE is a disclosure and always takes the ceremony;
//     the DESTINATION takes it when it is PROTECTED, which is where the ADR puts
//     protected-environment confirmation and where the locked prototype puts the
//     publish-into-protected ceremony. A non-protected destination stays
//     capability-only — its `reveal` conjunct is checked at the chokepoint like
//     any other, and inventing a prompt there would train people to click through
//     the one that matters.
//  3. **Reauthentication does not apply to machine identities** — "the token
//     IS the credential and there is no second factor to re-present". A
//     machine identity carries no session id, which is what `skipsCeremony`
//     reads. It is a structural fact, not a policy flag someone can flip.
//
// The enumerated unit is `(environment, sorted key ids)`, matched byte-exact
// against the ceremony's pinned binding for a single-decision (0-window,
// protected) ceremony. That is the prototype's "one decision over exactly the
// keys below" made checkable: a passkey assertion authorizes those keys in
// that environment and nothing else, and it is spent by exactly one decision.

// ErrNoCeremonySeam is a wiring fault, never a caller's problem: a value
// surface built without an Auth cannot run the reveal guard, and a disclosure
// surface with a missing guard must refuse loudly rather than disclose.
var ErrNoCeremonySeam = errors.New("service: the value surface has no reauthentication seam wired")

// skipsCeremony answers the ADR's machine exemption structurally.
//
// A machine identity has no session row (`authz.Identity.SessionID` is empty
// for one, by that type's own documented contract), so it has nothing a window
// could hang off. Local host authority — break-glass — is in the same position
// and is likewise the one path the ADR says is not evaluated against a grant.
func skipsCeremony(caller authz.Identity) bool {
	return caller.SessionID == ""
}

// requireCeremony consumes the acting session's reauthentication window over
// one environment for exactly the enumerated keys.
//
// keyIDs is the disclosure's unit. Callers pass the keys whose plaintext this
// act will open — which is also exactly the set the ceremony modal enumerates
// and the set that will emit disclosure events, so the three cannot drift.
//
// An empty key set is NOT a free pass: it is a disclosure of nothing, and a
// disclosure of nothing needs no ceremony. Callers reach here only when there
// is `secret` material in play, so this is a guard against a caller that asked
// for a gate it does not need rather than a hole.
func requireCeremony(ctx context.Context, auth *Auth, az *authz.TxAuthorizer, caller authz.Identity,
	purpose ReauthPurpose, envID string, keyIDs []string) error {
	if skipsCeremony(caller) {
		return nil
	}
	if len(keyIDs) == 0 {
		return nil
	}
	if auth == nil {
		return ErrNoCeremonySeam
	}
	unit := append([]string(nil), keyIDs...)
	sort.Strings(unit)
	// The clock is read HERE, at consumption, never captured earlier by the
	// caller. A copy resolves its keys, takes the destination project lock and
	// runs a preflight before anything is opened; an instant captured before
	// that lock is an instant that can be arbitrarily old by the time it is
	// used, and a window that expired while the transaction waited would still
	// be spent against it.
	// #58's closed purpose set maps to the authz operation the shell names in
	// the matching workspace step-up consent. A bound window can therefore be
	// spent by this real disclosure seam, while ConsumeReauthWindow still
	// accepts every #54 UNBOUND window because it checks the name only when the
	// stored window itself carries a binding.
	return auth.ConsumeReauthWindow(ctx, az, caller.SessionID, purpose, envID,
		string(operationForReauthPurpose(purpose)), unit, auth.now())
}

// ceremonyGate is the callback the value paths hand to readCells and
// openSourceMaterial: the enumerated unit arrives, the window is consumed, and
// a refusal lands before any ciphertext is opened.
func ceremonyGate(ctx context.Context, auth *Auth, az *authz.TxAuthorizer, caller authz.Identity,
	purpose ReauthPurpose, envID string) discloseGate {
	return func(unit []string) error {
		return requireCeremony(ctx, auth, az, caller, purpose, envID, unit)
	}
}

// RevealWindow reports the reveal guard's state for one environment, for the
// acting session.
//
// It exists because the window gates the PROMPT: the browser has to decide
// whether to run a ceremony before a disclosure, and which factors that
// ceremony may offer, and it must not recompute that policy itself. The server
// owns "is this environment capped at 0", "is a window live right now", and
// "may TOTP open one here" — the client renders the answer.
//
// Nothing here is a disclosure. The effective window and the protected flag
// are project settings, and the live window is the caller's own session state;
// a caller who cannot `read` the environment never gets this far, because the
// formula is `read(E)` and the chokepoint answers the uniform nonexistent.
type RevealWindow struct {
	// EffectiveWindowSeconds is the environment's resolved window: its own
	// override, the protected cap, or the instance default. `0` means every
	// disclosure takes its own ceremony.
	EffectiveWindowSeconds int
	// Protected is the environment's protected flag. It is reported alongside
	// the window rather than folded into it because the UI states WHY the
	// window is 0, and "this environment is protected" is a different sentence
	// from "the window is set to 0".
	Protected bool
	// TOTPOffered is false exactly where the effective window is 0: TOTP
	// cannot bind a challenge to the enumerated unit, so it cannot honour a
	// per-disclosure gate, and the ceremony modal must not offer it there.
	// This is the [E2E] half of mvp-boundary A5 made a server fact rather than
	// a client convention.
	TOTPOffered bool
	// Live says a window is open for this session and environment right now.
	// When it is false the next disclosure prompts; when it is true the
	// disclosure proceeds and slides the window.
	Live bool
	// ExpiresAt is when the live window lapses — the countdown chip's input.
	// Zero when no window is live.
	ExpiresAt time.Time
	// SingleDecision marks a 0-window WebAuthn window: it authorizes exactly
	// the keys its ceremony enumerated and is spent by one decision, so the UI
	// must not present it as a standing window with a countdown.
	SingleDecision bool
	// CanReveal is whether this principal satisfies `read ∧ reveal` here.
	//
	// It is an AFFORDANCE, never a decision — the chokepoint still judges every
	// disclosure — and it is what makes write-only editing a first-class path
	// rather than a guess. `edit` without `reveal` is a supported state the
	// permission model refuses to reject ("write-only replacement (blind
	// rotation)… the UI MUST support the write-only editing path"), so the
	// editor has to offer a replacement field with honest microcopy to someone
	// who cannot read what is there. Deriving that from whether a cell happens
	// to be revealed on screen would make it a function of what the human last
	// clicked.
	CanReveal bool
}

// Reveal is the reveal guard's read surface. It is its own service rather than
// a method on Values because its formula is `read(E)` — a principal who may
// see an environment may see whether disclosing there will prompt them, which
// is not itself a disclosure — and because the browser calls it on paths where
// no value is being read at all (opening the ceremony modal, rendering the
// countdown chip after a remask).
type Reveal struct {
	DB   *store.DB
	Auth *Auth
}

// Window resolves the guard's state for one environment.
func (s *Reveal) Window(ctx context.Context, actor Actor, scope domain.Scope) (RevealWindow, error) {
	if s.Auth == nil {
		return RevealWindow{}, ErrNoCeremonySeam
	}
	if scope.Env == "" {
		return RevealWindow{}, errors.New("service: the reveal window is an environment's")
	}
	now := s.Auth.now()
	var out RevealWindow
	err := tx.Read(ctx, s.DB, func(ctx context.Context, _ store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, now)
		if err != nil {
			return err
		}
		// Authorize FIRST. Everything below is read only after the chokepoint
		// has said this caller may see this environment at all; an environment
		// they may not `read` answers the uniform nonexistent here exactly as
		// it does on the value routes.
		if _, err := az.Authorize(ctx, caller, authz.OpRevealWindowRead, scope); err != nil {
			return err
		}
		effective, err := s.Auth.effectiveReauthWindow(ctx, az, string(scope.Env))
		if err != nil {
			return err
		}
		settings, err := az.EnvironmentReauthSettings(ctx, string(scope.Env))
		if err != nil {
			return err
		}
		canReveal, err := az.CallerHolds(ctx, caller, authz.OpValueReveal, scope)
		if err != nil {
			return err
		}
		out = RevealWindow{
			EffectiveWindowSeconds: int(effective / time.Second),
			Protected:              settings.Protected,
			TOTPOffered:            effective > 0,
			CanReveal:              canReveal,
		}
		if skipsCeremony(caller) {
			// A machine never reauthenticates, so it never has a window and
			// never prompts. Reporting "no window, no TOTP" would read as "you
			// will be prompted", which is the opposite of the truth.
			return nil
		}
		w, err := az.ReauthWindowFor(ctx, caller.SessionID, string(scope.Env))
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		epoch, err := az.CredentialEpoch(ctx)
		if err != nil {
			return err
		}
		// The same three liveness conditions ConsumeReauthWindow enforces, read
		// rather than consumed. A window this reports as live is one that
		// consumption would accept; reporting a lapsed one live would put a
		// countdown on a chip that cannot disclose.
		if w.CredentialEpoch != epoch || !now.Before(w.HardExpiresAt) || !now.Before(w.WindowExpiresAt) {
			return nil
		}
		out.Live = true
		out.SingleDecision = w.SingleDecision
		out.ExpiresAt = w.WindowExpiresAt
		if w.HardExpiresAt.Before(out.ExpiresAt) {
			out.ExpiresAt = w.HardExpiresAt
		}
		return nil
	})
	if err != nil {
		return RevealWindow{}, err
	}
	return out, nil
}

// ReauthPurpose is the closed set of decisions a disclosure ceremony can
// authorize (#58, review R1 finding 3).
//
// It is part of the SIGNED binding, not decoration on a modal. A ceremony is
// "purpose-bound" only if the purpose is inside the thing the authenticator
// signed and the thing consumption matches: otherwise an assertion the human
// gave to "reveal · production" is spendable on "publish into · production"
// over the same keys, which is a different decision they were never shown.
//
// Four members: reading plaintext, taking it out of an environment, putting it
// into one, and minting or widening a machine path to it.
type ReauthPurpose string

const (
	// PurposeReveal renders plaintext to the principal — cell, bulk or diff.
	PurposeReveal ReauthPurpose = "reveal"
	// PurposeCopy takes stored material OUT of an environment: the source half
	// of a copy or clone, including copy-without-display.
	PurposeCopy ReauthPurpose = "copy"
	// PurposePublish delivers material INTO a protected environment.
	PurposePublish ReauthPurpose = "publish"
	// PurposeMint is the credential mint/widen conjunct (#61): disclosure by
	// proxy toward a credential the actor controls. It is its own member for
	// the same reason the others are — a ceremony given to "mint a token for
	// production" must not be spendable on reading production.
	PurposeMint ReauthPurpose = "mint"
)

// Valid reports membership of the closed set. An unknown purpose is refused
// rather than defaulted: a binding nobody can name is a binding nobody checks.
func (p ReauthPurpose) Valid() bool {
	switch p {
	case PurposeReveal, PurposeCopy, PurposePublish, PurposeMint:
		return true
	}
	return false
}

// operationForReauthPurpose is the workspace consent vocabulary for #58's
// closed purpose set. Keep one explicit switch arm per member: there is no
// unnamed fallback that could make a new purpose silently unspendable.
func operationForReauthPurpose(p ReauthPurpose) authz.Operation {
	switch p {
	case PurposeReveal:
		return authz.OpValueReveal
	case PurposeCopy:
		return authz.OpValueCopySource
	case PurposePublish:
		return authz.OpValueCopyDestination
	case PurposeMint:
		return authz.OpCredentialMint
	}
	panic("service: unhandled reauthentication purpose")
}
