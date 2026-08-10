package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Client-side state under the XDG state directory: the trust store, named
// contexts, and per-instance session artifacts. Everything here is 0700/0600
// and `doctor`-verified; the CLI holds credentials as CUSTODY, never as
// authority — no policy is evaluated from any of it.

// Env is the process environment a run sees. Injecting it (rather than
// reading os.Getenv inline) is what makes the resolution chain testable
// without mutating the test process.
type Env struct {
	Getenv func(string) string
	Home   string
	StateD string
}

// State locates the client state directory.
type State struct {
	dir string
}

// NewState resolves the state directory: $HIKYO_STATE_DIR, else
// $XDG_STATE_HOME/hikyo, else ~/.local/state/hikyo (%LocalAppData%\hikyo on
// Windows).
func NewState(env Env) (*State, error) {
	if d := env.Getenv("HIKYO_STATE_DIR"); d != "" {
		return &State{dir: d}, nil
	}
	if d := env.Getenv("XDG_STATE_HOME"); d != "" {
		return &State{dir: filepath.Join(d, "hikyo")}, nil
	}
	if runtime.GOOS == "windows" {
		if d := env.Getenv("LocalAppData"); d != "" {
			return &State{dir: filepath.Join(d, "hikyo")}, nil
		}
	}
	home := env.Getenv("HOME")
	if home == "" {
		return nil, failf(ExitUsage,
			"cannot locate a state directory: neither HIKYO_STATE_DIR, XDG_STATE_HOME nor HOME is set")
	}
	return &State{dir: filepath.Join(home, ".local", "state", "hikyo")}, nil
}

// Dir is the resolved state directory.
func (s *State) Dir() string { return s.dir }

// Trust returns the trust store.
func (s *State) Trust() *TrustStore { return &TrustStore{dir: s.dir} }

// Context is a stored target tuple. It names an instance by REFERENCE, never
// by origin: a context, like a pin file, directs but never introduces trust.
type Context struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
	Org      string `json:"org,omitempty"`
	Project  string `json:"project,omitempty"`
	Env      string `json:"env,omitempty"`
}

func (s *State) contextsPath() string { return filepath.Join(s.dir, "contexts.json") }

// Contexts reads the stored contexts.
func (s *State) Contexts() (map[string]Context, error) {
	raw, err := os.ReadFile(s.contextsPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Context{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]Context
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("contexts file at %s is unreadable: %w", s.contextsPath(), err)
	}
	if out == nil {
		out = map[string]Context{}
	}
	return out, nil
}

// PutContext stores a context.
func (s *State) PutContext(c Context) error {
	all, err := s.Contexts()
	if err != nil {
		return err
	}
	all[c.Name] = c
	return s.writeJSON(s.contextsPath(), all)
}

// DeleteContext removes a context.
func (s *State) DeleteContext(name string) error {
	all, err := s.Contexts()
	if err != nil {
		return err
	}
	if _, ok := all[name]; !ok {
		return failf(ExitNotFound, "no context named %q", name)
	}
	delete(all, name)
	return s.writeJSON(s.contextsPath(), all)
}

// sessionsPath holds per-instance session artifacts. Multiple instances
// coexist; a context names which one it binds.
func (s *State) sessionsPath() string { return filepath.Join(s.dir, "sessions.json") }

// SessionArtifact is a stored CLI session. The value is a replayable bearer
// credential, which is why the file is 0600 in a 0700 directory and why the
// stored record carries the origin it was established against: the CLI
// presents it only to that origin.
type SessionArtifact struct {
	Instance  string `json:"instance"`
	Origin    string `json:"origin"`
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	Principal string `json:"principal"`
	ExpiresAt string `json:"expires_at"`
}

// Sessions reads the stored artifacts.
func (s *State) Sessions() (map[string]SessionArtifact, error) {
	raw, err := os.ReadFile(s.sessionsPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]SessionArtifact{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]SessionArtifact
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("session file at %s is unreadable: %w", s.sessionsPath(), err)
	}
	if out == nil {
		out = map[string]SessionArtifact{}
	}
	return out, nil
}

// PutSession stores an artifact for an instance.
func (s *State) PutSession(a SessionArtifact) error {
	all, err := s.Sessions()
	if err != nil {
		return err
	}
	all[a.Instance] = a
	return s.writeJSON(s.sessionsPath(), all)
}

// DeleteSession forgets an artifact.
func (s *State) DeleteSession(instance string) error {
	all, err := s.Sessions()
	if err != nil {
		return err
	}
	delete(all, instance)
	return s.writeJSON(s.sessionsPath(), all)
}

func (s *State) writeJSON(path string, v any) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// PinFile is the committable, non-secret project-dir file: the `.nvmrc` of
// Hikyo. It names an instance REFERENCE plus org/project/env — never
// credentials, never an origin. A hostile edit is bounded to retargeting
// within origins this box already trusts and grants the caller already holds;
// the credential-exfiltration variant is closed by construction, because a
// reference that is not in the trust store is a hard refusal.
type PinFile struct {
	Instance string `json:"instance,omitempty"`
	Org      string `json:"org,omitempty"`
	Project  string `json:"project,omitempty"`
	Env      string `json:"env,omitempty"`
}

// PinFileName is the file the CLI looks for, walking up from the working
// directory.
const PinFileName = ".hikyo.json"

// FindPinFile walks up from dir looking for a pin file, stopping at the
// filesystem root.
func FindPinFile(dir string) (PinFile, string, error) {
	for {
		candidate := filepath.Join(dir, PinFileName)
		raw, err := os.ReadFile(candidate)
		switch {
		case err == nil:
			var pin PinFile
			if err := json.Unmarshal(raw, &pin); err != nil {
				return PinFile{}, "", failf(ExitRefused, "%s is not valid JSON: %v", candidate, err)
			}
			return pin, candidate, nil
		case !errors.Is(err, os.ErrNotExist):
			return PinFile{}, "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir || strings.TrimSpace(parent) == "" {
			return PinFile{}, "", nil
		}
		dir = parent
	}
}
