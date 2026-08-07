package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Versioned ciphertext envelope, per the encryption ADR § Envelope format:
//
//	header = format_version ‖ envelope_kind ‖ algorithm_id ‖
//	         LP(wrapping_key_id) ‖ wrapping_key_version(uint32 BE) ‖ LP(nonce)
//	record = header ‖ ciphertext‖tag
//
// The header is authenticated as part of the AAD, so no header field can be
// edited independently of the payload.

type header struct {
	format     byte
	kind       Kind
	alg        byte
	keyID      []byte
	keyVersion uint32
	nonce      []byte
}

func appendHeader(dst []byte, h header) []byte {
	dst = append(dst, h.format, byte(h.kind), h.alg)
	dst = appendLP(dst, h.keyID)
	dst = append(dst, be32(h.keyVersion)...)
	return appendLP(dst, h.nonce)
}

// parseHeader decodes a record's header with strict bounds: a header whose
// declared lengths do not fit the buffer is rejected. It returns the header
// and the number of bytes it consumed.
func parseHeader(record []byte) (header, int, error) {
	var h header
	if len(record) < 3 {
		return h, 0, ErrDecrypt
	}
	h.format, h.kind, h.alg = record[0], Kind(record[1]), record[2]
	if h.format != formatV1 {
		return h, 0, fmt.Errorf("%w: %d", ErrUnknownFormat, h.format)
	}
	pos := 3
	var err error
	if h.keyID, pos, err = readLP(record, pos); err != nil {
		return h, 0, err
	}
	if pos+4 > len(record) {
		return h, 0, ErrDecrypt
	}
	h.keyVersion = binary.BigEndian.Uint32(record[pos:])
	pos += 4
	if h.nonce, pos, err = readLP(record, pos); err != nil {
		return h, 0, err
	}
	return h, pos, nil
}

func readLP(buf []byte, pos int) ([]byte, int, error) {
	if pos+4 > len(buf) {
		return nil, 0, ErrDecrypt
	}
	n := int(binary.BigEndian.Uint32(buf[pos:]))
	pos += 4
	if n < 0 || pos+n > len(buf) {
		return nil, 0, ErrDecrypt
	}
	return buf[pos : pos+n], pos + n, nil
}

// seal encrypts plaintext under key with a fresh random 192-bit nonce.
// keyID/keyVersion name the wrapping key in the authenticated header. A
// failed or short randomness read aborts — never a seal with weak randomness.
func seal(rnd io.Reader, key, keyID []byte, keyVersion uint32, a AAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, fmt.Errorf("crypto: randomness unavailable, refusing to seal: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	record := appendHeader(nil, header{
		format: formatV1, kind: a.kind(), alg: algXChaCha20Poly1305,
		keyID: keyID, keyVersion: keyVersion, nonce: nonce,
	})
	aad := appendAAD(record, a)
	return aead.Seal(record, nonce, plaintext, aad), nil
}

// open decrypts a record, requiring the header to name exactly the expected
// kind, wrapping key, and version, and the AAD to match the caller's row
// context. Any mismatch is a decrypt failure.
func open(key, keyID []byte, keyVersion uint32, a AAD, record []byte) ([]byte, error) {
	h, n, err := parseHeader(record)
	if err != nil {
		return nil, err
	}
	if h.kind != a.kind() || h.alg != algXChaCha20Poly1305 ||
		!bytes.Equal(h.keyID, keyID) || h.keyVersion != keyVersion ||
		len(h.nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aad := appendAAD(record[:n], a)
	pt, err := aead.Open(nil, h.nonce, record[n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
