// Package backup owns the age container around an instance export (#76,
// encryption ADR § Backups and exports). It is the SOLE importer of
// filippo.io/age in the module, enforced by internal/boundary.
//
// Hikyo specifies no container format of its own: age supplies the recipient
// stanzas, the scrypt passphrase recipient, and the STREAM chunked payload
// with its chunk ordering and truncation detection. What this package owns is
// the contract AROUND the container, which delegation does not supply:
//
//   - a zero-recipient export is refused, loudly, never written in the clear;
//   - an scrypt (passphrase) stanza must be the ONLY stanza in its container,
//     so export takes public recipients or a passphrase and never both — and
//     a container that mixes them is refused on OPEN too, because age enforces
//     that rule only on its own ScryptIdentity path (an X25519 identity would
//     otherwise happily open a container whose passphrase half is a second,
//     weaker door);
//   - the whole archive authenticates through to its final chunk BEFORE any
//     caller applies a byte of it.
//
// The package is a leaf, like the rest of internal/crypto: it imports nothing
// under internal/.
package backup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// Export and open refusals. Each is its own sentinel because the operator
// error behind each is different, and a restore runbook that cannot tell
// "you handed me the wrong key" from "this file is a prefix" is useless.
var (
	// ErrNoRecipients is encryption-ADR startup refusal 6: an export with
	// zero configured recipients is refused rather than silently written
	// without encryption.
	ErrNoRecipients = errors.New("backup: export needs at least one age recipient — refusing to write an unencrypted export")

	// ErrRecipientExclusive is the scrypt-stanza exclusivity rule at export.
	ErrRecipientExclusive = errors.New("backup: a passphrase (scrypt) recipient must be the only recipient in its container — export takes public recipients or a passphrase, never both")

	// ErrMixedStanzas is the same rule at open: a container carrying an
	// scrypt stanza alongside any other recipient stanza is refused before
	// any key is tried.
	ErrMixedStanzas = errors.New("backup: container mixes an scrypt stanza with other recipient stanzas — refused per the age specification")

	// ErrTruncated reports a container whose payload ended before a verified
	// final chunk. This is the failure a stream-and-apply restore would
	// commit a prefix of.
	ErrTruncated = errors.New("backup: container ends before its final chunk — truncated or incomplete")

	// ErrUnlock reports an unusable unlock: neither an identity nor a
	// passphrase, or both at once.
	ErrUnlock = errors.New("backup: restore needs exactly one of the backup identity or the container passphrase")
)

// Options is the export recipient policy. Recipients are age public
// recipients (`age1…`); Passphrase selects age's scrypt recipient. The two
// are mutually exclusive and at least one is required.
type Options struct {
	Recipients []string
	Passphrase string
}

// Unlock is the restore-side secret: exactly one of the two. The instance
// stores neither — the backup identity never touches the datastore, and it is
// deliberately a different failure domain from the root key.
type Unlock struct {
	Identity   string
	Passphrase string
}

// Configured reports whether an export could run — the pre-migration export's
// with-recipients / loud-skip-without decision (ops spec § 11).
func (o Options) Configured() bool { return len(o.Recipients) > 0 || o.Passphrase != "" }

// Validate resolves the recipient policy without producing a container, so a
// caller can refuse a bad policy before it creates the file the refusal would
// then have to delete.
func (o Options) Validate() error {
	_, err := o.recipients()
	return err
}

func (o Options) recipients() ([]age.Recipient, error) {
	if len(o.Recipients) > 0 && o.Passphrase != "" {
		return nil, ErrRecipientExclusive
	}
	if o.Passphrase != "" {
		r, err := age.NewScryptRecipient(o.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("backup: passphrase recipient: %w", err)
		}
		return []age.Recipient{r}, nil
	}
	if len(o.Recipients) == 0 {
		return nil, ErrNoRecipients
	}
	out := make([]age.Recipient, 0, len(o.Recipients))
	for _, s := range o.Recipients {
		r, err := age.ParseX25519Recipient(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("backup: recipient %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (u Unlock) identity() (age.Identity, error) {
	switch {
	case (u.Identity == "") == (u.Passphrase == ""):
		return nil, ErrUnlock
	case u.Passphrase != "":
		i, err := age.NewScryptIdentity(u.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("backup: passphrase identity: %w", err)
		}
		return i, nil
	default:
		i, err := age.ParseX25519Identity(strings.TrimSpace(u.Identity))
		if err != nil {
			// The identity itself never reaches an error string.
			return nil, errors.New("backup: backup identity is not a valid age X25519 identity")
		}
		return i, nil
	}
}

// GenerateIdentity mints a fresh age identity, returning the private identity
// and its public recipient in that order. The private half is the operator's
// to escrow in a custody store SEPARATE from the root key's — two keys in one
// password manager is one failure domain wearing two names.
func GenerateIdentity() (identity, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", fmt.Errorf("backup: generate identity: %w", err)
	}
	return id.String(), id.Recipient().String(), nil
}

// Encrypt opens the container. The caller writes the archive and MUST Close
// the returned writer: age's final chunk — the thing that distinguishes a
// complete archive from a prefix — is written by Close and by nothing else.
func Encrypt(dst io.Writer, o Options) (io.WriteCloser, error) {
	recipients, err := o.recipients()
	if err != nil {
		return nil, err
	}
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return nil, fmt.Errorf("backup: open container: %w", err)
	}
	return w, nil
}

// ExtractTo decrypts src into dst, verifying the container through to its
// final chunk. It returns only after the WHOLE archive has authenticated, so
// a caller that applies dst's contents only on a nil error cannot commit a
// prefix of a truncated backup.
//
// On error the contents of dst are undefined and must not be applied — that
// is the entire reason dst is a rewindable sink (a temp file) at every call
// site and never the restore applier itself.
func ExtractTo(dst io.Writer, src io.Reader, u Unlock) error {
	identity, err := u.identity()
	if err != nil {
		return err
	}

	// The stanza scan runs before any key is tried, so a mixed container is
	// refused on its shape rather than on whether this caller happens to hold
	// the stronger of its two doors.
	var consumed bytes.Buffer
	header, err := age.ExtractHeader(io.TeeReader(src, &consumed))
	if err != nil {
		return fmt.Errorf("backup: read container header: %w", err)
	}
	if err := checkStanzaExclusivity(header); err != nil {
		return err
	}

	r, err := age.Decrypt(io.MultiReader(&consumed, src), identity)
	if err != nil {
		// A container that ends inside the payload's STREAM nonce never
		// reaches a chunk: age fails here, and it is the same truncation.
		return truncationOr("backup: open container", err)
	}
	if _, err := io.Copy(dst, r); err != nil {
		return truncationOr("backup: container failed to authenticate", err)
	}
	return nil
}

// truncationOr names the EOF-shaped failures as truncation and leaves every
// other failure — a wrong key, a flipped bit — reading as what it is.
func truncationOr(context string, err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %v", ErrTruncated, err)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// checkStanzaExclusivity counts the recipient stanzas in an age header and
// refuses a container mixing scrypt with anything else. The header is plain
// ASCII up to its MAC line: a stanza opens with "-> <type>" and its body
// lines follow, so counting the "-> " lines counts the recipients.
func checkStanzaExclusivity(header []byte) error {
	var stanzas, scrypt int
	s := bufio.NewScanner(bytes.NewReader(header))
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "---") {
			break
		}
		if !strings.HasPrefix(line, "-> ") {
			continue
		}
		stanzas++
		if fields := strings.Fields(line); len(fields) >= 2 && fields[1] == "scrypt" {
			scrypt++
		}
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("backup: scan container header: %w", err)
	}
	if stanzas == 0 {
		return errors.New("backup: container has no recipient stanzas")
	}
	if scrypt > 0 && stanzas > 1 {
		return ErrMixedStanzas
	}
	return nil
}
