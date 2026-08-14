package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// The hierarchy verbs (#48): `project`, `env` and `folder`, plus the `org`
// rename and delete that complete that family.
//
// Spelling note, for the record and for human disposition. The api-cli-surface
// ADR's closed v1 taxonomy fixes `org create|delete`, `project create|delete`,
// `env create|delete` and the browse verbs `org list`, `project list`,
// `env list`. It spells no `rename`, no `show`, no `reorder`, and no `folder`
// family at all. Each of those joins the EXISTING noun-verb families as a
// declared additive spelling under the ADR's own grammar, pre-freeze — the same
// move the flat-model ADR made for `values set --clear` and #47 made for
// `account establish-credential`. No new verb class, no new output class, no new
// grammar. The acceptance criteria for this ticket require create, list and
// rename at every level, which the closed set cannot express as written.
//
// Every verb here reaches only tenant-scoped routes, so a caller who may not
// reach an object gets exit 5 — indistinguishable from one that is not there.

// runProject is the project family.
func runProject(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("project", args, "list", "show", "create", "rename", "delete")
	if err != nil {
		return err
	}

	var format, name, confirm string
	st, flags, err := parseCommon("project "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
			fs.StringVar(&name, "name", "", "project name")
		}
		if sub == "delete" {
			fs.StringVar(&confirm, "confirm", "", "the project's current name, typed out, to confirm an irreversible delete")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax first, before any target resolution or session lookup, so an
	// invocation that is simply malformed answers the same exit code whether or
	// not the caller is logged in. The switch is exhaustive by construction —
	// subverb() admits nothing else — so every subverb is validated, including
	// the ones that take no object at all.
	switch sub {
	case "show", "rename", "delete":
		if err := flags.checkTarget("project "+sub, DimProject, flags.Project); err != nil {
			return err
		}
	default:
		if err := flags.checkNoPositionals("project " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "create" && name == "":
		return failf(ExitUsage, "usage: hikyo project create --name <name> [--org ORG]")
	case sub == "rename" && name == "":
		return failf(ExitUsage, "usage: hikyo project rename <project> --name <new-name>")
	case sub == "delete" && confirm == "":
		// Refused, not usage: this is a ceremony declined, which the exit-code
		// taxonomy spells 4. It is checked here so it refuses before any server
		// contact — including before the GET that reads the name to compare.
		return failf(ExitRefused,
			"deleting a project is irreversible: it crypto-shreds the project key. "+
				"Re-run with --confirm <project-name>, naming the project you mean")
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	base := api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects"

	switch sub {
	case "list":
		var list apigen.ProjectList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		rows := make([][]string, 0, len(list.Items))
		for _, p := range list.Items {
			rows = append(rows, projectRow(p))
		}
		return Render(ios.Stdout, f, Table{Columns: projectColumns, Rows: rows, JSON: list})

	case "show":
		id, err := addressed(resolved, DimProject, flags.positional(), "project show")
		if err != nil {
			return err
		}
		var project apigen.Project
		if err := client.Do(ctx, http.MethodGet, base+"/"+url.PathEscape(id), nil, &project); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: projectColumns, Rows: [][]string{projectRow(project)}, JSON: project})

	case "create":
		var project apigen.Project
		if err := client.Do(ctx, http.MethodPost, base, apigen.CreateProjectRequest{Name: name}, &project); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: projectColumns, Rows: [][]string{projectRow(project)}, JSON: project})

	case "rename":
		id, err := addressed(resolved, DimProject, flags.positional(), "project rename")
		if err != nil {
			return err
		}
		var project apigen.Project
		if err := client.Do(ctx, http.MethodPatch, base+"/"+url.PathEscape(id),
			apigen.RenameRequest{Name: name}, &project); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: projectColumns, Rows: [][]string{projectRow(project)}, JSON: project})

	case "delete":
		// The permission model's locked row for this operation is
		// `manage-projects(org)` ∧ EXPLICIT CONFIRMATION NAMING THE PROJECT (∧ no
		// protected environment in it, which needs the protected flag that does
		// not exist yet). Project deletion crypto-shreds the project DEK and is
		// irreversible, so the confirmation is not a nicety.
		//
		// It is a typed flag rather than an interactive prompt for two reasons:
		// the ADR's terminal-confirmation mechanism is reserved for plaintext
		// disclosure, and a prompt would make the verb unusable from the scripts
		// the CLI promises to serve. Typing the name is the confirmation — a
		// blind `--yes` would confirm nothing about WHICH project. Its ABSENCE is
		// refused above, before any request; the MATCH needs the server's copy of
		// the name, so it is checked here against a read.
		id, err := addressed(resolved, DimProject, flags.positional(), "project delete")
		if err != nil {
			return err
		}
		var project apigen.Project
		if err := client.Do(ctx, http.MethodGet, base+"/"+url.PathEscape(id), nil, &project); err != nil {
			return err
		}
		if confirm != project.Name {
			return failf(ExitRefused,
				"--confirm %q does not name project %s, which is called %q. Refusing rather than deleting something you did not name",
				confirm, id, project.Name)
		}
		if err := client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted project %s (%s)\n", id, project.Name)
		return nil

	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo project: unhandled subverb %q", sub)
}

// runEnv is the environment family. `reorder` takes the WHOLE ordered set for
// the same reason the endpoint does: a partial reorder is how two environments
// end up sharing a position.
func runEnv(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("env", args, "list", "show", "create", "rename", "reorder", "delete")
	if err != nil {
		return err
	}

	var format, name, cloneFrom string
	st, flags, err := parseCommon("env "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
			fs.StringVar(&name, "name", "", "environment name")
		}
		if sub == "create" {
			fs.StringVar(&cloneFrom, "clone-from", "",
				"create the environment holding a copy of this environment's values")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax before resolution — see runProject.
	switch sub {
	case "show", "rename", "delete":
		if err := flags.checkTarget("env "+sub, DimEnv, flags.Env); err != nil {
			return err
		}
	case "list", "create":
		if err := flags.checkNoPositionals("env " + sub); err != nil {
			return err
		}
	case "reorder":
		// The ordered list is ONE comma-joined argument, so a second positional
		// is a caller mistake (probably a space after a comma), not a second set.
		if err := flags.checkTarget("env reorder", DimEnv, ""); err != nil {
			return err
		}
		if flags.positional() == "" {
			return failf(ExitUsage,
				"usage: hikyo env reorder <env-id,env-id,...> — every environment in the project, once each, in display order")
		}
	}
	switch {
	case sub == "create" && name == "":
		return failf(ExitUsage, "usage: hikyo env create --name <name> [--org ORG --project PROJECT]")
	case sub == "rename" && name == "":
		return failf(ExitUsage, "usage: hikyo env rename <env> --name <new-name>")
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	base += "/environments"

	switch sub {
	case "list":
		var list apigen.EnvironmentList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, environmentTable(list))

	case "show":
		id, err := addressed(resolved, DimEnv, flags.positional(), "env show")
		if err != nil {
			return err
		}
		var env apigen.Environment
		if err := client.Do(ctx, http.MethodGet, base+"/"+url.PathEscape(id), nil, &env); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: envColumns, Rows: [][]string{envRow(env)}, JSON: env})

	case "create":
		// Clone-at-creation (#50) is its own route because its RESULT is
		// different: it reports what it could not take. What it could not take
		// is printed to stderr by name — the ADR's "never silent" — while
		// stdout keeps carrying exactly the environment row `create` always
		// carried, so a script parsing `-o json` is unaffected by the flag.
		if cloneFrom != "" {
			var cloned apigen.ClonedEnvironment
			if err := client.Do(ctx, http.MethodPost, base+"/clone",
				apigen.CloneEnvironmentRequest{Name: name, SourceEnvironmentId: cloneFrom}, &cloned); err != nil {
				return err
			}
			if len(cloned.UncopiedSecrets) > 0 {
				fmt.Fprintf(ios.Stderr, "secrets NOT copied (absent in %s): %s\n",
					cloned.Environment.Id, strings.Join(cloned.UncopiedSecrets, ", "))
			}
			return Render(ios.Stdout, f, Table{
				Columns: envColumns, Rows: [][]string{envRow(cloned.Environment)}, JSON: cloned,
			})
		}
		var env apigen.Environment
		if err := client.Do(ctx, http.MethodPost, base, apigen.CreateEnvironmentRequest{Name: name}, &env); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: envColumns, Rows: [][]string{envRow(env)}, JSON: env})

	case "rename":
		id, err := addressed(resolved, DimEnv, flags.positional(), "env rename")
		if err != nil {
			return err
		}
		var env apigen.Environment
		if err := client.Do(ctx, http.MethodPatch, base+"/"+url.PathEscape(id),
			apigen.RenameRequest{Name: name}, &env); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: envColumns, Rows: [][]string{envRow(env)}, JSON: env})

	case "reorder":
		ids := strings.Split(flags.positional(), ",")
		for i, id := range ids {
			ids[i] = strings.TrimSpace(id)
		}
		var list apigen.EnvironmentList
		if err := client.Do(ctx, http.MethodPut, base+"/order",
			apigen.EnvironmentOrderRequest{EnvironmentIds: ids}, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, environmentTable(list))

	case "delete":
		id, err := addressed(resolved, DimEnv, flags.positional(), "env delete")
		if err != nil {
			return err
		}
		if err := client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted environment %s\n", id)
		return nil

	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo env: unhandled subverb %q", sub)
}

// runFolder is the folder family: namespace and display grouping only.
func runFolder(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("folder", args, "list", "show", "create", "rename", "delete")
	if err != nil {
		return err
	}

	var format, path string
	st, flags, err := parseCommon("folder "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
			fs.StringVar(&path, "path", "", "folder path, slash-separated")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax before resolution — see runProject. There is no --folder selector
	// flag, so the folder id can only ever be positional; the check still
	// rejects a stray extra one.
	switch sub {
	case "show", "rename", "delete":
		if err := flags.checkTarget("folder "+sub, "folder", ""); err != nil {
			return err
		}
		if flags.positional() == "" {
			return failf(ExitUsage, "usage: hikyo folder %s <folder>", sub)
		}
	default:
		if err := flags.checkNoPositionals("folder " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "create" && path == "":
		return failf(ExitUsage, "usage: hikyo folder create --path <path>")
	case sub == "rename" && path == "":
		return failf(ExitUsage, "usage: hikyo folder rename <folder> --path <new-path>")
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	base += "/folders"

	switch sub {
	case "list":
		var list apigen.FolderList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		rows := make([][]string, 0, len(list.Items))
		for _, fl := range list.Items {
			rows = append(rows, folderRow(fl))
		}
		return Render(ios.Stdout, f, Table{Columns: folderColumns, Rows: rows, JSON: list})

	case "show":
		var folder apigen.Folder
		if err := client.Do(ctx, http.MethodGet, base+"/"+url.PathEscape(flags.positional()), nil, &folder); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: folderColumns, Rows: [][]string{folderRow(folder)}, JSON: folder})

	case "create":
		var folder apigen.Folder
		if err := client.Do(ctx, http.MethodPost, base, apigen.CreateFolderRequest{Path: path}, &folder); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: folderColumns, Rows: [][]string{folderRow(folder)}, JSON: folder})

	case "rename":
		var folder apigen.Folder
		if err := client.Do(ctx, http.MethodPatch, base+"/"+url.PathEscape(flags.positional()),
			apigen.RenameFolderRequest{Path: path}, &folder); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: folderColumns, Rows: [][]string{folderRow(folder)}, JSON: folder})

	case "delete":
		if err := client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(flags.positional()), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted folder %s\n", flags.positional())
		return nil

	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo folder: unhandled subverb %q", sub)
}

// subverb splits and VALIDATES the family's subverb before anything else runs.
// An unknown subverb is a usage error at the door, so `hikyo env warp` answers 2
// whether or not a session exists — previously it fell through to a default
// branch after target resolution and could answer 3 when logged out.
func subverb(family string, args []string, known ...string) (string, []string, error) {
	usage := family + " " + strings.Join(known, "|")
	if len(args) == 0 {
		return "", nil, failf(ExitUsage, "usage: hikyo %s", usage)
	}
	if !slices.Contains(known, args[0]) {
		return "", nil, failf(ExitUsage, "unknown %s verb %q: use %s", family, args[0], strings.Join(known, ", "))
	}
	return args[0], args[1:], nil
}

// addressed resolves which object a by-id verb targets: the positional argument
// if given, otherwise the resolved dimension. It never falls back to "the only
// one there is" — a delete aimed at a guess is the mistake the context model
// exists to prevent.
func addressed(resolved Resolved, dim Dimension, positional, verb string) (string, error) {
	if positional != "" {
		return positional, nil
	}
	id, err := resolved.Require(dim)
	if err != nil {
		return "", failf(ExitUsage, "usage: hikyo %s <%s> (or resolve --%s)", verb, dim, dim)
	}
	return id, nil
}

// projectBase is the URL prefix for everything inside a project. Both
// dimensions are required explicitly: guessing either is how a command lands in
// the wrong tenant.
func projectBase(resolved Resolved) (string, error) {
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return "", err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return "", err
	}
	return api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project), nil
}

var (
	projectColumns = []string{"ID", "NAME", "CREATED"}
	envColumns     = []string{"ID", "NAME", "ORDER", "CREATED"}
	folderColumns  = []string{"ID", "PATH", "CREATED"}
)

func projectRow(p apigen.Project) []string {
	return []string{p.Id, p.Name, p.CreatedAt.Format("2006-01-02")}
}

func envRow(e apigen.Environment) []string {
	return []string{e.Id, e.Name, strconv.Itoa(e.DisplayOrder), e.CreatedAt.Format("2006-01-02")}
}

func folderRow(f apigen.Folder) []string {
	return []string{f.Id, f.Path, f.CreatedAt.Format("2006-01-02")}
}

func environmentTable(list apigen.EnvironmentList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, e := range list.Items {
		rows = append(rows, envRow(e))
	}
	return Table{Columns: envColumns, Rows: rows, JSON: list}
}
