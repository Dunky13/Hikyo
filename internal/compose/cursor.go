package compose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// Conditional-fetch cursor state (compose-integration ADR § "Cursor rules").
//
// The stored cursor is local state that can desynchronize from local delivery
// state, which the server cannot see. It is presented ONLY when EVERY binding
// field matches, the exact render-target set matches, and each target's
// generation named in the cursor equals the managed-block stamp AND is present,
// complete, and has its <target>.env file on disk. On any failure the client
// performs a full authorized fetch.
//
// The binding is one typed struct — credential, environment, config-only mode,
// pinned revision, authorized projection, and the canonical target→key-id
// membership map (compose ADR § Cursor rules: "credential identity,
// environment, pin generation, authorized delivery projection, delivery mode,
// and the render-target id set"). Binding to the target→key-id MAP, not a flat
// id list, is deliberate: the ADR fixes that membership is by immutable key id,
// so a cursor must invalidate when a key moves into or out of a target, not
// only when the flat union of ids changes.

const cursorFile = "cursor.json"

// CursorBinding is the full set of authorization-bound coordinates a cursor is
// tied to. Any change to any field invalidates the cursor.
type CursorBinding struct {
	CredentialID   string `json:"credential_id"`
	Environment    string `json:"environment"`
	ConfigOnly     bool   `json:"config_only"`
	PinnedRevision int64  `json:"pinned_revision"` // 0 = unpinned (current)
	// Projection is the authorized delivery capability list, canonicalized.
	Projection []string `json:"projection"`
	// TargetKeyIDs is the render-target membership: target name → its immutable
	// key ids. Both the key set and the target set are compared exactly.
	TargetKeyIDs map[string][]string `json:"target_key_ids"`
}

// canonical returns a copy with the projection and every key-id list sorted and
// deduplicated, so equality is order- and duplicate-invariant.
func (b CursorBinding) canonical() CursorBinding {
	out := CursorBinding{
		CredentialID:   b.CredentialID,
		Environment:    b.Environment,
		ConfigOnly:     b.ConfigOnly,
		PinnedRevision: b.PinnedRevision,
		Projection:     crypto.CanonicalStringSet(b.Projection),
	}
	if b.TargetKeyIDs != nil {
		out.TargetKeyIDs = make(map[string][]string, len(b.TargetKeyIDs))
		for t, ids := range b.TargetKeyIDs {
			out.TargetKeyIDs[t] = crypto.CanonicalStringSet(ids)
		}
	}
	return out
}

// Equal reports whether two bindings are identical after canonicalization,
// including the EXACT target set (an extra or missing target → not equal).
func (b CursorBinding) Equal(other CursorBinding) bool {
	return reflect.DeepEqual(b.canonical(), other.canonical())
}

// CursorState is the persisted cursor plus the binding that makes it eligible
// and the per-target generation stamps the cursor was issued against.
type CursorState struct {
	Cursor           string            `json:"cursor"`
	Binding          CursorBinding     `json:"binding"`
	GenerationStamps map[string]string `json:"generation_stamps"`
}

// LoadCursor strictly parses cursor.json. A missing file returns (nil, nil):
// no cursor is a legitimate state (a full fetch follows).
func LoadCursor(stateDir string) (*CursorState, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, cursorFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("compose: read cursor: %w", err)
	}
	var c CursorState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("compose: parse cursor: %w", err)
	}
	return &c, nil
}

// SaveCursor writes cursor.json atomically (0600). The CLI calls it ONLY after
// a successful, committed render — NEVER after a refused or failed one.
func SaveCursor(stateDir string, c CursorState) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("compose: marshal cursor: %w", err)
	}
	if err := atomicWrite(filepath.Join(stateDir, cursorFile), data, 0o600); err != nil {
		return fmt.Errorf("compose: write cursor: %w", err)
	}
	return nil
}

// EligibleCursor returns the stored cursor and true only when the full
// eligibility test holds against the current local delivery state: the binding
// matches `want` (every field and the exact target set), and for EVERY target
// the cursor's generation equals the managed-block stamp, is present and
// complete, and its <target>.env file exists in the generation directory.
func EligibleCursor(state *CursorState, want CursorBinding, currentStamps map[string]string, runtimeDir string) (string, bool) {
	if state == nil {
		return "", false
	}
	if !state.Binding.Equal(want) {
		return "", false
	}
	// The target set is authoritative from the binding; the cursor must carry a
	// generation for exactly those targets.
	if len(state.GenerationStamps) != len(want.TargetKeyIDs) {
		return "", false
	}
	for target := range want.TargetKeyIDs {
		stamp, ok := state.GenerationStamps[target]
		if !ok {
			return "", false
		}
		if err := crypto.ParseStamp(stamp); err != nil {
			return "", false
		}
		if currentStamps[target] != stamp {
			return "", false
		}
		if _, complete := GenerationState(runtimeDir, stamp); !complete {
			return "", false
		}
		if _, err := os.Stat(filepath.Join(runtimeDir, stamp, target+".env")); err != nil {
			return "", false
		}
	}
	return state.Cursor, true
}
