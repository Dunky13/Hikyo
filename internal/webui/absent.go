//go:build !ui

package webui

import "io/fs"

// assets reports no application. The binary is an API server; the serving
// rules in internal/server answer every document request with the contract's
// own 404 rather than pretending a build happened.
func assets() fs.FS { return nil }
