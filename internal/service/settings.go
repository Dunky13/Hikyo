package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/audit"
	"github.com/Hikyo-Org/hikyo/internal/authz"
	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
	"github.com/Hikyo-Org/hikyo/internal/store/tx"
)

// `project-settings`: the protected-environment flag and the per-environment
// reauthentication window (#55, permission-model ADR - The reveal guard).
//
// Protected environments are NOT a different mechanism — they are the same
// sliding-window knob, and marking an environment protected CAPS its window at
// the protected default rather than merely suggesting it. Raising a protected
// environment's window above the cap is refused; every window change is
// audited.
//
// The capability is `project-settings`, deliberately split out of
// `definitions-edit`: these exist to restrain the definitions editor, and a
// guard whose off-switch sits in the hand it restrains is not a guard.

// ProtectedWindowCap is the protected-environment window cap: 0, meaning
// every disclosure reauthenticates. The permission-model ADR recommends it and the
// operations spec may narrow it, never widen it.
const ProtectedWindowCap = 0 * time.Second

// DefaultReauthHardCap bounds the absolute age of a reauthentication window.
//
// It exists because of #54's disposition item 1: with both the idle window and
// the hard cap at 0, a single-decision (0-window) WebAuthn reauth is minted
// with hard_expires_at == authenticated_at and is dead the instant it is
// created — so a protected environment, whose whole point is the 0 window,
// would be unusable. A hard cap is an absolute bound, never extended by
// activity, so a non-zero default is the honest value; zero was never a
// meaningful configuration, it was an unset field.
const DefaultReauthHardCap = 15 * time.Minute

var (
	// ErrProtectedWindowCap refuses raising a protected environment's
	// reauthentication window above the protected cap.
	ErrProtectedWindowCap = fmt.Errorf("%w: service: a protected environment's reauthentication window may not exceed the protected cap", domain.ErrInvalid)
	// ErrNegativeWindow refuses a negative window: 0 already means "every
	// disclosure", and there is nothing below it.
	ErrNegativeWindow = fmt.Errorf("%w: service: a reauthentication window cannot be negative", domain.ErrInvalid)
	// ErrNoReauthHardCap refuses leaving an environment at an effective
	// window of 0 while no hard cap is configured — the resulting window
	// would be born expired, and a disclosure gate that silently cannot be
	// satisfied is worse than one that refuses loudly.
	ErrNoReauthHardCap = fmt.Errorf("%w: service: an effective reauthentication window of 0 requires a non-zero reauthentication hard cap", domain.ErrConflict)
)

// EnvironmentSettings is the caller-facing shape of the two knobs.
type EnvironmentSettings struct {
	Protected bool
	// HasWindow false means the environment inherits the instance default.
	HasWindow bool
	Window    time.Duration
}

// ProjectSettings owns the `project-settings` surface. It holds the Auth
// service because lowering an environment's effective window is not a column
// write: it invalidates the open windows, enumerates the principals the
// transition strands and audits the transition — the library #54 shipped for
// exactly this caller.
type ProjectSettings struct {
	DB   *store.DB
	Auth *Auth
	Now  func() time.Time
}

func (s *ProjectSettings) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

// GetEnvironment reads one environment's protection state and window. It is
// bare `read(E)`: an environment's protection state is part of its public
// shape, and hiding it from a reader would make the reveal ceremony
// inexplicable to the person subject to it.
func (s *ProjectSettings) GetEnvironment(ctx context.Context, actor Actor, scope domain.Scope) (EnvironmentSettings, error) {
	var out EnvironmentSettings
	err := tx.Read(ctx, s.DB, func(ctx context.Context, r store.ReadRepos, az *authz.TxAuthorizer) error {
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvSettingsRead, scope)
		if err != nil {
			return err
		}
		st, err := r.Environments().Settings(ctx, p)
		if err != nil {
			return err
		}
		out = EnvironmentSettings{Protected: st.Protected, HasWindow: st.HasWindow, Window: st.Window}
		return nil
	})
	return out, err
}

// SetEnvironment writes both knobs as one fact, because they are one:
// marking an environment protected caps its window, so a surface that could
// write them apart would have an observable state where the flag is set and
// the window is not yet capped.
func (s *ProjectSettings) SetEnvironment(ctx context.Context, actor Actor, scope domain.Scope, want EnvironmentSettings) (EnvironmentSettings, error) {
	var out EnvironmentSettings
	err := tx.Write(ctx, s.DB, func(ctx context.Context, r store.Repos, az *authz.TxAuthorizer) error {
		if want.HasWindow && want.Window < 0 {
			return ErrNegativeWindow
		}
		caller, err := actor.resolve(ctx, az, s.now())
		if err != nil {
			return err
		}
		p, err := az.Authorize(ctx, caller, authz.OpEnvSettingsUpdate, scope)
		if err != nil {
			return err
		}
		before, err := r.Environments().Settings(ctx, p)
		if err != nil {
			return err
		}

		// Marking protected CAPS the window at the protected default. An
		// explicit request above the cap is refused rather than silently
		// clamped — the caller asked for a weaker gate on the environment
		// that exists to have the strongest one, and must learn that it did
		// not happen. With no explicit window, the cap is written rather than
		// left to inherit: an inherited instance default would silently
		// re-widen the environment the flag was set to protect.
		if want.Protected {
			if want.HasWindow && want.Window > ProtectedWindowCap {
				return fmt.Errorf("%w: %s exceeds the protected cap of %s",
					ErrProtectedWindowCap, want.Window, ProtectedWindowCap)
			}
			want.HasWindow = true
			if want.Window > ProtectedWindowCap {
				want.Window = ProtectedWindowCap
			}
		}

		beforeEff := effectiveWindow(before.Protected, before.HasWindow, before.Window, s.Auth.ReauthWindow)
		afterEff := effectiveWindow(want.Protected, want.HasWindow, want.Window, s.Auth.ReauthWindow)
		if afterEff <= 0 && s.Auth.hardCap() <= 0 {
			return ErrNoReauthHardCap
		}

		if err := r.Environments().SetSettings(ctx, p, store.EnvironmentSettings{
			Protected: want.Protected, HasWindow: want.HasWindow, Window: want.Window,
		}); err != nil {
			return err
		}

		// Lowering the effective window is the #54 library's job: it
		// invalidates the environment's open windows, RETAINS grants, and
		// enumerates and audits the principals the transition strands.
		if afterEff < beforeEff {
			if _, _, err := s.Auth.LowerEffectiveWindow(ctx, az, string(scope.Env), afterEff, s.now()); err != nil {
				return err
			}
		}

		var events []grantEventInput
		if want.Protected != before.Protected {
			events = append(events, grantEventInput{
				typ:    audit.EventProtectedFlagChange,
				object: audit.Object{Type: "environment", ID: string(scope.Env)},
				payload: audit.Payload{
					"protected":      want.Protected,
					"window_seconds": int(afterEff / time.Second),
				},
			})
		}
		// The STORED configuration, not only the effective duration. Moving an
		// environment from "inherits 5m" to "explicitly 5m" (or back) changes
		// no effective value today and every effective value the moment the
		// instance default moves — a policy change that would have left no
		// trace at all if the comparison stopped at the durations.
		configChanged := before.HasWindow != want.HasWindow ||
			(want.HasWindow && before.Window != want.Window)
		if beforeEff != afterEff || configChanged {
			events = append(events, grantEventInput{
				typ:    audit.EventReauthWindowChanged,
				object: audit.Object{Type: "environment", ID: string(scope.Env)},
				payload: audit.Payload{
					"previous_window_seconds": int(beforeEff / time.Second),
					"window_seconds":          int(afterEff / time.Second),
					// Widening stays its own field and stays about the
					// EFFECTIVE value: that is the direction that weakens the
					// gate, and an inheritance flip that changes nothing today
					// must not be filed as a widening.
					"widened":            afterEff > beforeEff,
					"protected":          want.Protected,
					"previous_inherited": !before.HasWindow,
					"inherited":          !want.HasWindow,
					// The stored configuration either side, with -1 standing
					// for "no stored value, inherits the instance default" —
					// distinct from 0, which is a real window meaning every
					// disclosure reauthenticates.
					"previous_configured_seconds": storedSeconds(before.HasWindow, before.Window),
					"configured_seconds":          storedSeconds(want.HasWindow, want.Window),
				},
			})
		}
		out = EnvironmentSettings{Protected: want.Protected, HasWindow: want.HasWindow, Window: want.Window}
		if len(events) == 0 {
			return nil
		}
		return insertGrantEvent(ctx, r, p, caller.Principal, domain.LevelEnv, events...)
	})
	return out, err
}

// effectiveWindow is the ONE rule turning stored settings into the window the
// reveal guard enforces. The reader (effectiveReauthWindow, inside the window
// openers' transactions) and this writer both call it, so a protected
// environment cannot end up with one answer here and another there.
func effectiveWindow(protected, hasWindow bool, window, instanceDefault time.Duration) time.Duration {
	// The base window first — explicit if the environment has one, the
	// instance default if it inherits — then the protected cap applied to
	// THAT. Returning the cap flat for the inherited case was not a clamp: if
	// the operations-owned cap ever becomes positive while the instance
	// default is smaller, protecting an environment would WIDEN its window,
	// which is the exact opposite of what the flag means.
	base := instanceDefault
	if hasWindow {
		base = window
	}
	if protected {
		return min(base, ProtectedWindowCap)
	}
	return base
}

// storedSeconds renders the STORED window for the trail: the configured value,
// or -1 for "no stored value, inherits the instance default". -1 rather than an
// absent member because 0 is a legal stored window (every disclosure
// reauthenticates) and an absent member would read as that.
func storedSeconds(hasWindow bool, window time.Duration) int {
	if !hasWindow {
		return -1
	}
	return int(window / time.Second)
}
