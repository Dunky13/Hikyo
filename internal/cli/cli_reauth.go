package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

const cliReauthCallbackPath = "/callback"

// runCLIAdapterReauth binds the callback before opening the browser, then
// silently rotates the local bearer after an exact state + PKCE exchange.
func runCLIAdapterReauth(ctx context.Context, client *Client, state *State, artifact SessionArtifact, operation string, environmentIDs []string, openURL func(string) error) error {
	return runCLIReauthHandoff(ctx, client, state, artifact, "adapter", operation, environmentIDs, nil, openURL)
}

// runCLIDisclosureReauth is the browser handoff for a disclosure the terminal
// cannot satisfy itself: a 0-window or protected environment, where only the
// purpose-bound, enumerated-key-set passkey ceremony the UI runs may open a
// window (api-cli-surface ADR § Login and reauth transports). The key set is
// the unit the browser decision covers and the unit the disclosure consumes.
func runCLIDisclosureReauth(ctx context.Context, client *Client, state *State, artifact SessionArtifact, purpose, operation, environmentID string, keyIDs []string, openURL func(string) error) error {
	if len(keyIDs) == 0 {
		return failf(ExitRefused, "a disclosure ceremony needs the keys it covers, and none resolved")
	}
	return runCLIReauthHandoff(ctx, client, state, artifact, purpose, operation, []string{environmentID}, keyIDs, openURL)
}

func runCLIReauthHandoff(ctx context.Context, client *Client, state *State, artifact SessionArtifact, purpose, operation string, environmentIDs, keyIDs []string, openURL func(string) error) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return failf(ExitUnavailable, "binding the CLI reauthentication callback: %v", err)
	}
	defer listener.Close()

	rawVerifier := make([]byte, 32)
	if _, err := rand.Read(rawVerifier); err != nil {
		return failf(ExitInternal, "generating the CLI reauthentication proof: %v", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(rawVerifier)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	redirectURI := "http://" + listener.Addr().String() + cliReauthCallbackPath
	environments := make([]apigen.ID, len(environmentIDs))
	for i, environmentID := range environmentIDs {
		environments[i] = apigen.ID(environmentID)
	}
	request := apigen.CLIReauthStartRequest{
		Purpose:        apigen.CLIReauthStartRequestPurpose(purpose),
		Operation:      apigen.CLIReauthStartRequestOperation(operation),
		EnvironmentIds: environments,
		PkceChallenge:  challenge,
		RedirectUri:    redirectURI,
	}
	if len(keyIDs) > 0 {
		keys := make([]apigen.ID, len(keyIDs))
		for i, keyID := range keyIDs {
			keys[i] = apigen.ID(keyID)
		}
		request.KeyIds = &keys
	}
	var started apigen.CLIReauthStart
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/cli-reauth/start", request, &started); err != nil {
		return err
	}

	target, err := url.Parse(client.Entry.Origin)
	if err != nil {
		return failf(ExitInternal, "the trusted instance origin is invalid: %v", err)
	}
	target.Path = "/reauth/cli"
	target.RawPath = ""
	target.RawQuery = url.Values{"transaction": []string{started.State}}.Encode()
	target.Fragment = ""

	code := make(chan string, 1)
	var callbackOnce sync.Once
	callback := http.NewServeMux()
	callback.HandleFunc(cliReauthCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !exactCallbackQuery(r.URL.Query(), started.State) {
			http.Error(w, "This CLI authorization callback did not match the request.", http.StatusBadRequest)
			return
		}
		accepted := false
		callbackOnce.Do(func() {
			accepted = true
			code <- r.URL.Query().Get("code")
		})
		if accepted {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("CLI authorization received. Return to the terminal.\n"))
			return
		}
		http.Error(w, "This CLI authorization callback was already used.", http.StatusConflict)
	})
	server := &http.Server{Handler: callback, ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	if openURL == nil {
		openURL = OpenBrowser
	}
	if err := openURL(target.String()); err != nil {
		return failf(ExitUnavailable, "opening the browser for CLI authorization: %v", err)
	}

	wait := time.Until(started.ExpiresAt)
	if wait <= 0 || wait > 5*time.Minute {
		wait = 5 * time.Minute
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	select {
	case value := <-code:
		return redeemCLIReauth(ctx, client, state, artifact, value, []byte(verifier))
	case <-ctx.Done():
		return ctx.Err()
	case <-deadline.C:
		return failf(ExitAuth, "CLI authorization expired; start the command again")
	}
}

func exactCallbackQuery(values url.Values, state string) bool {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return slices.Equal(keys, []string{"code", "state"}) && len(values["code"]) == 1 && values.Get("code") != "" && len(values["state"]) == 1 && values.Get("state") == state
}

// OpenBrowser launches the platform browser for the CLI front channel.
func OpenBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("starting the browser: %w", err)
	}
	_ = command.Process.Release()
	return nil
}

// redeemCLIReauth completes a browser-approved handoff and replaces the local
// bearer without returning it to any rendering or logging path.
func redeemCLIReauth(ctx context.Context, client *Client, state *State, artifact SessionArtifact, code string, verifier []byte) error {
	var result apigen.CLIReauthRedeemed
	request := apigen.CLIReauthRedeemRequest{Code: code, PkceVerifier: string(verifier)}
	if err := client.Do(ctx, http.MethodPost, api.PathPrefix+"/auth/cli-reauth/redeem", request, &result); err != nil {
		return err
	}
	if result.SessionToken == "" {
		return failf(ExitInternal, "server returned no rotated CLI session token")
	}
	artifact.Token = result.SessionToken
	artifact.SessionID = string(result.SessionId)
	if err := state.PutSession(artifact); err != nil {
		return err
	}
	client.Bearer = result.SessionToken
	return nil
}
