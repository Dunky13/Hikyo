package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/Dunky13/wenv/internal/config"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/disclose"
	"github.com/Dunky13/wenv/internal/service"
	"github.com/Dunky13/wenv/internal/store"
	"github.com/Dunky13/wenv/internal/store/keyring"
	"github.com/Dunky13/wenv/internal/store/migrate"
)

// `wenv admin create` — the first-administrator bootstrap.
//
// It is a CLIENT VERB OF THE SAME BINARY EXECUTED ON THE SERVER HOST, not a
// new mode and not a network endpoint. That siting is the decision: an open
// setup page until claimed was rejected outright, because whoever reaches the
// port first owns the instance, and on a LAN hosting a secrets manager that
// is a race with a catastrophic loser. Seeding administrator credentials from
// environment variables was rejected for the same family of reasons — a
// plaintext seed account by construction, landing in shell history, Compose
// files, `docker inspect` output and process listings.
//
// Ordering is fixed by the encryption ADR: the root key must be present and
// the instance initialized before any principal exists. This command
// therefore performs the same fail-closed boot sequence the server does,
// minus the listener.

// AdminUsage is the frozen help text for the local-admin group.
func AdminUsage(w io.Writer) {
	fmt.Fprint(w, `wenv admin - local host authority (server host only, never over the network)

  wenv admin create --username USER [--display-name NAME]
                    [--output-file PATH | --dangerously-print]

Mints the first administrator and a single-use credential-establishment
authority. The authority creates no session and carries no assurance: the
administrator sets their own credential with it, then logs in like anyone
else. It expires in 24h and is never re-displayed - if it lapses, mint a new
one here on the host.

Delivery follows the print triad. The value goes to the controlling terminal,
or to a file this command creates itself (0600, in a directory you own), or
to stdout only under --dangerously-print. Ordinary stdout is refused even
when stdout is a TTY: under Docker, Kubernetes, systemd or any log shipper
stdout is retained and readable by principals holding neither host access nor
the root key, so 'kubectl logs' would hand a remote reader the first
administrator account and its seeded reveal grants.
`)
}

// RunAdmin dispatches the local-admin verb group.
func RunAdmin(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		AdminUsage(stderr)
		return errors.New("usage: wenv admin create --username USER")
	}
	fs := flag.NewFlagSet("admin create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	username := fs.String("username", "", "the first administrator's login handle")
	displayName := fs.String("display-name", "", "display name (defaults to the username)")
	outputFile := fs.String("output-file", "", "write the authority to a file this command creates (0600)")
	dangerous := fs.Bool("dangerously-print", false, "write the authority to stdout, and to whatever collects it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *username == "" {
		return errors.New("--username is required")
	}

	// The delivery mode is decided BEFORE the authority exists, so it can be
	// recorded in the mint event. A token that reached a log shipper is a
	// different event from one written to a root-owned file, and the trail has
	// to be able to say which.
	delivery := string(disclose.DestTerminal)
	switch {
	case *outputFile != "" && *dangerous:
		return errors.New("--output-file and --dangerously-print name two destinations; choose one")
	case *outputFile != "":
		delivery = string(disclose.DestFile)
	case *dangerous:
		delivery = string(disclose.DestStdout)
	}

	sc := storeConfig(cfg)
	if cfg.AutoMigrate {
		if err := migrate.Run(ctx, sc); err != nil {
			return err
		}
	}
	if err := migrate.Check(ctx, sc); err != nil {
		return err
	}
	root, err := resolveRootKey(cfg, log)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, sc)
	if err != nil {
		crypto.Zero(root)
		return err
	}
	defer db.Close()
	kr, err := crypto.LoadKeyring(ctx, &keyring.Store{DB: db}, root)
	if err != nil {
		return err
	}
	kdf, limiter, err := AuthComponents(cfg)
	if err != nil {
		return err
	}
	auth := &service.Auth{DB: db, Keyring: kr, KDF: kdf, Admission: limiter}

	result, err := auth.BootstrapAdmin(ctx, *username, *displayName, delivery)
	if err != nil {
		return err
	}

	dest, err := disclose.Emit(
		fmt.Sprintf("Credential-establishment authority for %s (expires %s)",
			result.Username, result.ExpiresAt.Format("2006-01-02 15:04 MST")),
		result.Authority,
		disclose.Options{OutputFile: *outputFile, DangerouslyPrint: *dangerous})
	if err != nil {
		// The administrator exists and the authority is minted, but nobody
		// received it. Say so precisely rather than leaving the operator to
		// guess whether to run this again — running it again would refuse,
		// because the instance now has an account.
		return fmt.Errorf(
			"the administrator %q was created and its authority minted, but delivery failed and the value is now unrecoverable.\n"+
				"Mint a replacement with `wenv admin reset --username %s` once that verb lands, or restore and retry.\n%w",
			result.Username, result.Username, err)
	}

	fmt.Fprintf(stderr,
		"created administrator %q (principal %s); authority delivered to the %s and expires %s\n",
		result.Username, result.PrincipalID, dest, result.ExpiresAt.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(stderr,
		"next: on the administrator's own machine, run\n"+
			"    wenv login <instance-url> --local --as %s\n"+
			"after establishing the credential with the authority above.\n", result.Username)
	return nil
}
