// hikyo is the multicall binary: `hikyo server` and `hikyo migrate` are real;
// client verbs are stubs until their tickets land.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/Hikyo-Org/hikyo/internal/app"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/config"
	"github.com/Hikyo-Org/hikyo/internal/importer"
	"github.com/Hikyo-Org/hikyo/internal/operator"
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
	if handled, code := importer.RunInternalSubprocess(os.Args[1:], os.Stdout); handled {
		return code
	}
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
	case cmd == "operator":
		return runOperatorMode(ctx)
	case cmd == "migrate":
		return runMigrate(ctx, args)
	case cmd == "admin":
		return runAdmin(ctx, args)
	case cmd == "backup":
		return runOperator(ctx, "backup", args, app.RunBackup)
	case cmd == "restore":
		return runOperator(ctx, "restore", args, app.RunRestore)
	case slices.Contains(cli.Verbs, cmd):
		return cli.Run(ctx, cli.IO{
			Stdin:   os.Stdin,
			Stdout:  os.Stdout,
			Stderr:  os.Stderr,
			Env:     cli.Env{Getenv: os.Getenv},
			Workdir: workdir(),
			OpenURL: cli.OpenBrowser,
		}, os.Args[1:])
	case slices.Contains(app.ClientVerbs, cmd):
		fmt.Fprintf(os.Stderr, "hikyo %s: not implemented yet\n", cmd)
		return 2
	default:
		fmt.Fprintf(os.Stderr, "hikyo: unknown command %q\n\n", cmd)
		usage()
		return 2
	}
}

func versionString() string {
	if version == "dev" {
		return "hikyo dev"
	}
	return fmt.Sprintf("hikyo %s (%s, %s)", version, commit, buildDate)
}

func runServer(ctx context.Context, args []string) int {
	cfg, warnings, err := config.Load("server", args, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "hikyo server:", err)
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

// runOperatorMode is the `hikyo operator` deployable (k8s-integration ADR): a
// separate process, not a mode of the running server. It loads no keyring and no
// root key — configuration is HIKYO_OPERATOR_* env only, read inside
// internal/operator. It is a real multicall MODE, never a client verb, so it is
// absent from app.ClientVerbs.
func runOperatorMode(ctx context.Context) int {
	operator.Version = version
	log := app.Logger(false)
	if err := operator.Run(ctx, log); err != nil {
		log.Error("operator failed", "err", err)
		return 1
	}
	return 0
}

// runAdmin is the local-admin group: `hikyo admin create` on the server's own
// host. It is a client verb of the same binary, not a new multicall mode -
// the mode set (server/operator/migrate/client) is unchanged. It shares
// runOperator's shape: own flags, environment-only configuration.
func runAdmin(ctx context.Context, args []string) int {
	return runOperator(ctx, "admin", args, app.RunAdmin)
}

// runOperator is the shared shape of the host-only operator verb groups
// (`backup`, `restore`). Like `admin`, they take their own flags and read
// configuration from the environment only - the same environment the server
// beside them reads, so an operator cannot back up one datastore and restore
// another by passing a different flag.
func runOperator(ctx context.Context, name string, args []string,
	run func(context.Context, *config.Config, *slog.Logger, []string, io.Writer) error,
) int {
	cfg, warnings, err := config.Load(name, nil, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "hikyo %s: %v\n", name, err)
		return 2
	}
	log := app.Logger(cfg.Dev)
	for _, w := range warnings {
		log.Warn(w)
	}
	if err := run(ctx, cfg, log, args, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "hikyo %s: %v\n", name, err)
		return 1
	}
	return 0
}

func workdir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func runMigrate(ctx context.Context, args []string) int {
	cfg, warnings, err := config.Load("migrate", args, os.Getenv, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "hikyo migrate:", err)
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
	fmt.Fprintf(os.Stderr, `hikyo — one binary, several roles

server commands:
  hikyo server [--dev] [--listen ADDR] [--auto-migrate=BOOL]
  hikyo migrate

kubernetes operator (separate deployable; HIKYO_OPERATOR_* env only):
  hikyo operator

version:
  hikyo version

local host authority (server host only):
  hikyo admin create --username USER
  hikyo backup export [--out DIR]
  hikyo backup keygen
  hikyo restore run --from ARCHIVE --identity-file PATH
  hikyo restore status
  hikyo restore reconcile --principal ID

client verbs:
  %v

client verbs not implemented yet:
  %v
`, cli.Verbs, app.ClientVerbs)
}
