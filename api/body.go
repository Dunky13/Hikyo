package api

import (
	"bytes"
	"io"
)

// readCloser wraps a recorded response body for the validator, which wants a
// stream it may consume.
func readCloser(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}
