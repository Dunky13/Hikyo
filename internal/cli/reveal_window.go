package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// The CLI half of the disclosure reauthentication ceremony (api-cli-surface
// ADR § Login and reauth transports: "local-account sessions may satisfy a
// window > 0 with inline terminal TOTP where #16 permits TOTP"; human-auth ADR
// § Assurance).
//
// A disclosure - `values get/list/diff/export --reveal`, a copy that opens
// secret material, `run --use-human-session` - is refused by the server until
// the acting session holds a live reauthentication window over the
// environment it discloses in. The window's policy is the server's: whether
// one is live, how long the environment's effective window is, and whether
// TOTP may open it (it cannot where the effective window is 0 - a protected
// environment, or the instance default - because TOTP cannot bind a challenge
// to an enumerated key set). The CLI reads that answer and performs the one
// transport it owns: an authenticator code typed at the controlling terminal,
// presented to `/auth/reauth/totp`, which rotates the session token. The
// rotated token MUST replace the stored one, or every later verb in the same
// shell answers "authentication required" - the failure the readiness audit
// reproduced.
//
// A 0-window environment has no terminal path by design: the ceremony there is
// the browser's purpose-bound passkey ceremony. The refusal names both ways
// out rather than pretending a code would do.

// revealWindowPath is the reveal guard's read surface for one environment.
func revealWindowPath(projectBase, env string) string {
	return projectBase + "/environments/" + url.PathEscape(env) + "/reveal-window"
}

// forbidden reports whether err is a refusal the reauthentication ceremony can
// cure: the server's uniform 403 (the shape every disclosure without a live
// window answers with), or the widening conjunct's 409 naming reauthentication
// (a grant that makes machine plaintext reachable consumes the grantor's window
// over the environments it reaches - machine-identities ADR). Other refusals
// (a missing grant answers 403 too, but `ensureRevealWindow` then finds
// `can_reveal` false and hands the original error back) are not retried.
func forbidden(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Code != ExitRefused {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not permitted") || strings.Contains(msg, "reauthenticate over the environments")
}

// disclosure names what a CLI disclosure is about to do, for the ceremony
// that may have to precede it: the purpose and the keys per environment.
type disclosure struct {
	// purpose is "reveal" or "copy" (service.ReauthPurpose on the wire).
	purpose string
	// keys resolves the enumerated unit for one environment: the ids of the
	// secret keys the act will open there. It is consulted only when a
	// browser handoff is needed, so the common case costs no extra request.
	keys func(ctx context.Context, env string) ([]string, error)
}

// withRevealCeremony runs a disclosure, and on the server's refusal opens the
// reauthentication window over each named environment and runs it exactly
// once more: inline TOTP where the environment's window allows it, the
// browser's purpose-bound passkey ceremony (handoff) where it does not. The
// attempt comes first so a live window costs no extra round trip and a
// config-only copy never prompts.
func withRevealCeremony(ctx context.Context, client *Client, st *State, ios IO, artifact SessionArtifact,
	projectBase string, envs []string, d disclosure, attempt func() error) error {
	err := attempt()
	if err == nil || !forbidden(err) {
		return err
	}
	for _, env := range envs {
		if cerr := ensureRevealWindow(ctx, client, st, ios, &artifact, projectBase, env, d, err); cerr != nil {
			return cerr
		}
	}
	return attempt()
}

// ensureRevealWindow opens a live reauthentication window over env for the
// acting session, or returns an error naming why it cannot. `refusal` is the
// disclosure's own error, returned unchanged when the principal does not hold
// `read ∧ reveal` here - the chokepoint's answer is not second-guessed, and a
// ceremony is never offered to someone the server would refuse anyway.
func ensureRevealWindow(ctx context.Context, client *Client, st *State, ios IO, artifact *SessionArtifact,
	projectBase, env string, d disclosure, refusal error) error {
	var window apigen.RevealWindow
	if err := client.Do(ctx, http.MethodGet, revealWindowPath(projectBase, env), nil, &window); err != nil {
		return err
	}
	if window.Live {
		return nil
	}
	if !window.CanReveal {
		return refusal
	}
	if window.EffectiveWindowSeconds == 0 || !window.TotpOffered {
		// The 0-window case: only the browser's purpose-bound, enumerated-key-set
		// passkey ceremony may open it. Hand off, naming the reason first.
		why := "its reveal window is 0"
		if window.Protected {
			why = "it is a protected environment"
		}
		if d.keys == nil || d.purpose == "" || ios.OpenURL == nil {
			return failf(ExitAuth, "a disclosure in %s needs a reauthentication window and %s: every disclosure there takes its own passkey ceremony in the browser, "+
				"which this invocation cannot open; reveal it in the browser, or raise the window with `hikyo project-settings set --env %s --reauth-window-seconds 300`", env, why, env)
		}
		keyIDs, err := d.keys(ctx, env)
		if err != nil {
			return err
		}
		operation := "value.reveal"
		if d.purpose == "copy" {
			operation = "value.copy-source"
		}
		fmt.Fprintf(ios.Stderr, "disclosure in %s: %s, so every disclosure takes its own passkey ceremony. Opening the browser to authorize %d key(s)...\n", env, why, len(keyIDs))
		return runCLIDisclosureReauth(ctx, client, st, *artifact, d.purpose, operation, env, keyIDs, ios.OpenURL)
	}
	code, err := ios.readPassword(fmt.Sprintf(
		"Disclosure in %s needs a reauthentication window (%ds). Enter the code from your authenticator: ",
		env, window.EffectiveWindowSeconds))
	if err != nil {
		return err
	}
	envID := apigen.ID(env)
	var opened apigen.ReauthResult
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/reauth/totp",
		apigen.TotpReauthRequest{Code: code, EnvironmentId: &envID}, &opened); err != nil {
		return err
	}
	// The window opener rotates the session token. Persist it AND present it on
	// this client from here on; the old bearer is dead the moment the server
	// answered.
	if opened.SessionToken == nil || *opened.SessionToken == "" {
		return failf(ExitInternal, "the server opened a window but returned no rotated session token to a CLI caller")
	}
	artifact.Token = *opened.SessionToken
	artifact.SessionID = string(opened.SessionId)
	if err := st.PutSession(*artifact); err != nil {
		return err
	}
	client.Bearer = *opened.SessionToken
	fmt.Fprintf(ios.Stderr, "reauthentication window open over %s until %s\n", env, opened.WindowExpires.Format("15:04:05 MST"))
	return nil
}
