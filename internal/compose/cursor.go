package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/crypto"
)

// Conditional-fetch cursor state (compose-integration ADR § "Cursor rules").
//
// The stored cursor is local state that can desynchronize from local delivery
// state, which the server cannot see. It is presented ONLY when the three-part
// test holds: every binding matches, every target's generation named in the
// cursor equals the one in the managed block, and that generation is present
// AND complete. On any failure the client performs a full authorized fetch.
// After a reboot the tmpfs render is gone while a persistent cursor would still
// read "current" — the three-part test is what stops the server answering
// "current" and leaving rendering impossible.

const cursorFile = "cursor.json"

// CursorState is the persisted cursor plus the bindings that make it eligible.
type CursorState struct {
	Cursor           string            `json:"cursor"`
	CredentialID     string            `json:"credential_id"`
	Environment      string            `json:"environment"`
	ConfigOnly       bool              `json:"config_only"`
	TargetIDsHash    string            `json:"target_ids_hash"`
	PinGeneration    string            `json:"pin_generation,omitempty"`
	GenerationStamps map[string]string `json:"generation_stamps"`
}

// HashTargetIDs is a canonical, order-independent hash of the render-target id
// set, so a cursor is invalidated when the target composition changes.
func HashTargetIDs(ids []string) string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, id := range sorted {
		// length-prefixed so ("a","bc") and ("ab","c") differ.
		var n [8]byte
		l := len(id)
		for i := 0; i < 8; i++ {
			n[i] = byte(l >> (8 * (7 - i)))
		}
		h.Write(n[:])
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))
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
// a successful, committed render — NEVER after a refused or failed one (the
// cursor is never advanced past a render that did not happen).
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

// EligibleCursor returns the stored cursor and true only when it passes the
// full three-part eligibility test against the current local delivery state.
func EligibleCursor(state *CursorState, currentStamps map[string]string, runtimeDir, credentialID, env string, configOnly bool, targetIDs []string) (string, bool) {
	if state == nil {
		return "", false
	}
	// Binding checks.
	if state.CredentialID != credentialID ||
		state.Environment != env ||
		state.ConfigOnly != configOnly ||
		state.TargetIDsHash != HashTargetIDs(targetIDs) {
		return "", false
	}
	if len(state.GenerationStamps) == 0 {
		return "", false
	}
	// Every target's cursor generation must equal the managed-block stamp AND
	// that generation must be present and complete on disk.
	for target, stamp := range state.GenerationStamps {
		if err := crypto.ParseStamp(stamp); err != nil {
			return "", false
		}
		if currentStamps[target] != stamp {
			return "", false
		}
		if _, complete := GenerationState(runtimeDir, stamp); !complete {
			return "", false
		}
	}
	return state.Cursor, true
}
