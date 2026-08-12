// Package webui carries the built single-page application, or nothing.
//
// The embed sits behind the `ui` build tag on purpose. `//go:embed dist` is a
// COMPILE-TIME dependency on a directory the Go toolchain cannot produce: a
// contributor who has never run pnpm, and every `go build ./...` / `go test
// ./...` in this repo, would fail on a missing directory rather than on
// anything to do with their change. Committing a placeholder `dist` was the
// alternative and is worse — a checked-in minified bundle is unreviewable, and
// a stale one ships silently.
//
// So: default builds get an empty asset tree and serve the API alone (the
// serving rules answer 404 for the document, loudly). `go build -tags ui`
// embeds the real `dist`, which CI produces with `pnpm --dir web build`
// before it builds the binary.
package webui

import "io/fs"

// Assets is the built application, or nil when this binary was compiled
// without the `ui` tag. `internal/server` treats nil as "API only".
func Assets() fs.FS { return assets() }
