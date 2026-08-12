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
	"github.com/Dunky13/wenv/internal/domain"
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
  wenv admin reset-credential --principal ID
                    [--output-file PATH | --dangerously-print]
  wenv admin grant --principal ID --capability CAP
                    [--org ID [--project ID [--env ID]]]

create mints the first administrator and a single-use credential-establishment
authority. reset-credential is the break-glass recovery path: it mints the same
authority for ANY existing principal, including an instance-capability holder no
network reset can reach, advances that principal's session generation and revokes
its sessions. Both create no session and carry no assurance: the holder sets a
password with the authority, then logs in like anyone else. The authority is
never re-displayed - if it lapses, mint a new one here on the host.

grant is the break-glass recovery grant: it creates one (principal, capability,
scope) grant under local host authority, naming its target and capability
explicitly, and writes a durable recovery audit record. It is the only
authorization path in the system not evaluated against a grant, and the way out
of the one state the lockout invariant cannot recover from - an instance with no
manage-members holder. It has no network route, and the origin it writes is
break-glass, not manual, so the row is distinguishable on the membership surface
from an ordinary grant.

Delivery follows the print triad. The value goes to the controlling terminal,
or to a file this command creates itself (0600, in a directory you own), or
to stdout only under --dangerously-print. Ordinary stdout is refused even
when stdout is a TTY: under Docker, Kubernetes, systemd or any log shipper
stdout is retained and readable by principals holding neither host access nor
the root key, so 'kubectl logs' would hand a remote reader the authority.
`)
}

// RunAdmin dispatches the local-admin verb group.
func RunAdmin(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, stderr io.Writer) error {
	if len(args) == 0 {
		AdminUsage(stderr)
		return errors.New("usage: wenv admin create --username USER | wenv admin reset-credential --principal ID | wenv admin grant --principal ID --capability CAP")
	}
	switch args[0] {
	case "create":
		return runAdminCreate(ctx, cfg, log, args, stderr)
	case "reset-credential":
		return runAdminReset(ctx, cfg, log, args, stderr)
	case "grant":
		return runAdminGrant(ctx, cfg, log, args, stderr)
	default:
		AdminUsage(stderr)
		return errors.New("usage: wenv admin create --username USER | wenv admin reset-credential --principal ID | wenv admin grant --principal ID --capability CAP")
	}
}

func runAdminCreate(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, stderr io.Writer) error {
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

	// Check the destination BEFORE anything is created. Minting first and
	// discovering afterwards that the value has nowhere to go would leave the
	// instance bootstrapped with an authority nobody ever saw — and running
	// this again refuses, because the instance now has an account.
	deliveryOpts := disclose.Options{OutputFile: *outputFile, DangerouslyPrint: *dangerous}
	if err := disclose.Preflight(deliveryOpts); err != nil {
		return err
	}

	auth, closeDB, err := adminAuth(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeDB()

	result, err := auth.BootstrapAdmin(ctx, *username, *displayName, delivery)
	if err != nil {
		return err
	}

	dest, err := disclose.Emit(
		fmt.Sprintf("Credential-establishment authority for %s (expires %s)",
			result.Username, result.ExpiresAt.Format("2006-01-02 15:04 MST")),
		result.Authority, deliveryOpts)
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

// adminAuth runs the same fail-closed boot sequence the server does, minus the
// listener, and returns a live Auth plus a cleanup that closes the store. The
// root key is read from the same sources the server uses; `admin` has no
// --root-key-file of its own.
func adminAuth(ctx context.Context, cfg *config.Config, log *slog.Logger) (*service.Auth, func(), error) {
	sc := storeConfig(cfg)
	if cfg.AutoMigrate {
		if err := migrate.Run(ctx, sc); err != nil {
			return nil, nil, err
		}
	}
	if err := migrate.Check(ctx, sc); err != nil {
		return nil, nil, err
	}
	root, err := resolveRootKey(cfg, log)
	if err != nil {
		return nil, nil, err
	}
	db, err := store.Open(ctx, sc)
	if err != nil {
		crypto.Zero(root)
		return nil, nil, err
	}
	kr, err := crypto.LoadKeyring(ctx, &keyring.Store{DB: db}, root)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	kdf, limiter, err := AuthComponents(cfg)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return &service.Auth{DB: db, Keyring: kr, KDF: kdf, Admission: limiter, Log: log}, func() { db.Close() }, nil
}

// runAdminReset is the break-glass recovery verb: `wenv admin reset-credential
// --principal ID`. It mints a credential-establishment authority for any existing
// principal — including an instance-capability holder no network reset can reach
// — on the server's own host under local authority, with no network route. The
// classification-totality invariant keeps that true: `cli:admin` is ClassSystem,
// whose probe contract is network unreachability.
func runAdminReset(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin reset-credential", flag.ContinueOnError)
	fs.SetOutput(stderr)
	principal := fs.String("principal", "", "the target principal id to reset")
	outputFile := fs.String("output-file", "", "write the authority to a file this command creates (0600)")
	dangerous := fs.Bool("dangerously-print", false, "write the authority to stdout, and to whatever collects it")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *principal == "" {
		return errors.New("--principal is required")
	}

	delivery := string(disclose.DestTerminal)
	switch {
	case *outputFile != "" && *dangerous:
		return errors.New("--output-file and --dangerously-print name two destinations; choose one")
	case *outputFile != "":
		delivery = string(disclose.DestFile)
	case *dangerous:
		delivery = string(disclose.DestStdout)
	}
	deliveryOpts := disclose.Options{OutputFile: *outputFile, DangerouslyPrint: *dangerous}
	if err := disclose.Preflight(deliveryOpts); err != nil {
		return err
	}

	auth, closeDB, err := adminAuth(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeDB()

	result, err := auth.BreakGlassResetCredential(ctx, *principal, delivery)
	if err != nil {
		return err
	}
	dest, err := disclose.Emit(
		fmt.Sprintf("Credential-establishment authority for %s (expires %s)",
			result.TargetUser, result.ExpiresAt.Format("2006-01-02 15:04 MST")),
		result.Authority, deliveryOpts)
	if err != nil {
		return fmt.Errorf(
			"the credential for principal %q was reset (its sessions revoked and generation advanced), "+
				"but delivery of the new authority failed and the value is now unrecoverable.\n"+
				"Run this again to mint a fresh authority.\n%w",
			*principal, err)
	}
	fmt.Fprintf(stderr,
		"reset credential for %q (account %s); authority delivered to the %s and expires %s\n",
		result.TargetUser, result.TargetAccount, dest, result.ExpiresAt.Format("2006-01-02 15:04 MST"))
	return nil
}

// runAdminGrant is the break-glass recovery grant: `wenv admin grant
// --principal ID --capability CAP [--org ... --project ... --env ...]`.
//
// It is the ONLY authorization path in the system not evaluated against a
// grant (permission ADR § Evaluation 6), and it exists for exactly one state
// the lockout invariant cannot recover from in-product: an instance, or an
// org, whose last `manage-members` holder is gone. Host access plus the root
// key already means full control-plane compromise per the threat model, so
// this adds no attacker capability — what it adds is a way back in that is
// structurally unreachable from the network.
func runAdminGrant(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("admin grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	principal := fs.String("principal", "", "the target principal id")
	capability := fs.String("capability", "", "the capability atom to grant")
	org := fs.String("org", "", "org id (omit for an instance-scope grant)")
	project := fs.String("project", "", "project id (requires --org)")
	env := fs.String("env", "", "environment id (requires --project)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	// Both are required and neither is inferable: the ADR requires this path
	// to name its target principal and capability EXPLICITLY, so there is no
	// default target and no default capability here by design.
	if *principal == "" || *capability == "" {
		return errors.New("--principal and --capability are both required: a break-glass grant names its target and capability explicitly")
	}
	scope := domain.Scope{
		Org:     domain.OrgID(*org),
		Project: domain.ProjectID(*project),
		Env:     domain.EnvID(*env),
	}
	if _, err := scope.Level(); err != nil {
		return errors.New("--org, --project and --env form a chain: name each level above the one you address")
	}

	auth, closeDB, err := adminAuth(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer closeDB()

	grants := &service.Grants{DB: auth.DB}
	res, err := grants.BreakGlassGrant(ctx, service.GrantSpec{
		Target:     domain.PrincipalID(*principal),
		Capability: domain.Capability(*capability),
		Scope:      scope,
	})
	if err != nil {
		return err
	}
	// The grant id, not the capability value: there is nothing secret here, and
	// the operator needs the id to revoke it again through the ordinary surface.
	verb := "joined"
	if res.Created {
		verb = "created"
	}
	fmt.Fprintf(stderr, "break-glass grant %s: %s (%s at %s) for %s\n",
		verb, res.GrantID, *capability, scopeLabel(scope), *principal)
	return nil
}

// scopeLabel renders a scope for the operator's confirmation line.
func scopeLabel(s domain.Scope) string {
	switch {
	case s.Env != "":
		return string(s.Org) + "/" + string(s.Project) + "/" + string(s.Env)
	case s.Project != "":
		return string(s.Org) + "/" + string(s.Project)
	case s.Org != "":
		return string(s.Org)
	default:
		return "instance"
	}
}
