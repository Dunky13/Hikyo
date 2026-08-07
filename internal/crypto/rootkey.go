package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Root-key bootstrap, per the encryption ADR: the operator-held 256-bit root
// key arrives as a file (`--root-key-file`, which also covers systemd
// LoadCredential delivery) or the WENV_ROOT_KEY environment variable —
// documented as the weakest tier, since an env value sits in process memory
// for the whole lifetime and defeats the post-boot wipe.
//
// Encoding is fixed: 64 hex characters (surrounding whitespace ignored).
// No padding, no stretching, no derivation from a short string.

// Startup refusals — each is its own distinct error (CI invariant 6), all
// hard failures with no override flag.
var (
	ErrNoRootKey = errors.New("crypto: no root key configured: set --root-key-file or WENV_ROOT_KEY")
	// ErrRootKeyPerms: a key file readable by group or other is refused.
	ErrRootKeyPerms = errors.New("crypto: root key file is readable by group or other (chmod 600 it)")
	// ErrRootKeyFormat: anything but 256 bits after hex decoding is refused.
	ErrRootKeyFormat = errors.New("crypto: root key must decode to exactly 256 bits (64 hex characters)")
	// ErrRootKeyMismatch: the master key's Poly1305 tag failed to verify.
	ErrRootKeyMismatch = errors.New("crypto: root key does not match this datastore")
)

// ReadRootKey loads and validates the root key from a file path or an
// env-delivered value; exactly one source must be present (the config layer
// refuses ambiguity before this runs). The caller owns the returned bytes
// and must Zero them when done.
func ReadRootKey(file, envValue string) ([]byte, error) {
	switch {
	case file != "":
		info, err := os.Stat(file)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%w (file %s does not exist)", ErrNoRootKey, file)
			}
			return nil, fmt.Errorf("crypto: root key file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s is mode %04o", ErrRootKeyPerms, file, info.Mode().Perm())
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("crypto: root key file: %w", err)
		}
		return decodeRootKey(string(raw))
	case envValue != "":
		return decodeRootKey(envValue)
	default:
		return nil, ErrNoRootKey
	}
}

func decodeRootKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(key) != KeySize {
		// Never echo the value or the hex error (which embeds input bytes).
		return nil, ErrRootKeyFormat
	}
	return key, nil
}

// EncodeRootKey renders a root key in the fixed on-disk encoding. It exists
// for key generation (`wenv init`, dev bootstrap) so the format lives in one
// place.
func EncodeRootKey(key []byte) string { return hex.EncodeToString(key) }

// GenerateRootKey mints a fresh 256-bit root key. Randomness failure aborts,
// as at every other key generation.
func GenerateRootKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("crypto: randomness unavailable, refusing to generate root key: %w", err)
	}
	return key, nil
}
