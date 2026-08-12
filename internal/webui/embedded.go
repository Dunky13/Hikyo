//go:build ui

package webui

import (
	"embed"
	"io/fs"
)

// dist is the Vite build output. `web/vite.config.ts` writes here rather than
// into `web/`, so the embed directive names a path inside this package (Go
// forbids `..`) and the pnpm workspace keeps its node_modules out of the Go
// tree.
//
// `all:` is required: without it `embed` skips names beginning with `_` or
// `.`, and a bundler is free to emit either.
//
//go:embed all:dist
var dist embed.FS

// assets strips the `dist/` prefix so a URL path maps directly onto a name.
func assets() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// Unreachable: the directory is embedded at compile time, so a failure
		// here would mean the embed itself is malformed.
		panic("webui: embedded dist is unreadable: " + err.Error())
	}
	return sub
}
