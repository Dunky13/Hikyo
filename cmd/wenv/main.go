// wenv is the multicall binary: `wenv server` and `wenv migrate` are real;
// client verbs are stubs until their tickets land.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/Dunky13/wenv/internal/app"
	"github.com/Dunky13/wenv/internal/config"
)

// Set by GoReleaser. Development builds deliberately identify themselves as
// unversioned instead of guessing from the local checkout.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	cmd, args := os.Args[1], os.Args[2:]

	app.Version = version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case cmd == "version" || cmd == "--version":
		fmt.Fprintln(os.Stdout, versionString())
		return 0
	case cmd == "server":
		return runServer(ctx, args)
	case cmd == "migrate":
		return runMigrate(ctx, args)
	case slices.Contains(app.ClientVerbs, cmd):
		fmt.Fprintf(os.Stderr, "wenv %s: not implemented yet\n", cmd)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "wenv: unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

func versionString() string {
	if version == "dev" {
		return "wenv dev"
	}
	return fmt.Sprintf("wenv %s (%s, %s)", version, commit, buildDate)
}

func runServer(ctx context.Context, args []string) int {
	cfg, warnings, err := config.Load("server", args, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "wenv server:", err)
		return 1
	}
	log := app.Logger(cfg.Dev)
	for _, w := range warnings {
		log.Warn(w)
	}
	srv, err := app.Boot(ctx, cfg, log)
	if err != nil {
		log.Error("startup failed", "err", err)
		return 1
	}
	if err := srv.Serve(ctx); err != nil {
		log.Error("server failed", "err", err)
		return 1
	}
	return 0
}

func runMigrate(ctx context.Context, args []string) int {
	cfg, warnings, err := config.Load("migrate", args, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "wenv migrate:", err)
		return 1
	}
	log := app.Logger(cfg.Dev)
	for _, w := range warnings {
		log.Warn(w)
	}
	if err := app.RunMigrate(ctx, cfg, log); err != nil {
		log.Error("migration failed", "err", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprintf(os.Stderr, `wenv — one binary, several roles

server commands:
  wenv server [--dev] [--listen ADDR] [--auto-migrate=BOOL]
  wenv migrate

version:
  wenv version

client verbs (not implemented yet):
  %v
`, app.ClientVerbs)
}
