package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// The access verbs (#55): `hikyo access grant list|add|remove|template` and
// `hikyo access member list|remove`, plus `hikyo project-settings get|set`.
//
// Spelling note, same shape as #48's. The api-cli-surface ADR's access group
// is `grant list | add | remove`, `member list | invite | remove`,
// `credential-reset`, and puts "project-settings get/set" in the org/project
// lifecycle group. Two departures, both declared additive joins under the
// ADR's own grammar rather than new grammar:
//
//   - `grant template` — the ADR fixes no spelling for applying a role
//     template, and the acceptance criteria require one. It joins the grant
//     noun because a template IS grants: the expansion happens at grant time
//     and nothing stores the template name.
//   - `member invite` is NOT implemented. No spec fixes the claim flow,
//     the delivery channel or the expiry, and inventing them here would lock
//     three decisions nobody has made. The seam stays named
//     (service.ErrNoInvitationPath); the handoff carries it as an explicit
//     disposition item quoting the ADR line.
//
// Scope is addressed the ordinary way — `--org`/`--project`/`--env` through the
// same per-dimension precedence every other verb uses — and the DEEPEST
// dimension resolved decides the route, because the grant's scope is the route
// and the formula differs per depth. `--instance-scope` is the explicit opt-in
// for an instance-wide grant, since "no org resolved" must never silently mean
// "grant it to the whole instance".

func runAccess(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("access", args, "grant", "member")
	if err != nil {
		return err
	}
	switch sub {
	case "grant":
		return runAccessGrant(ctx, ios, rest)
	default:
		return runAccessMember(ctx, ios, rest)
	}
}

// accessScope is the resolved grant scope plus the route it addresses.
type accessScope struct {
	// path is the collection route: .../grants
	path string
	// label renders the scope for a human, matching the audit rendering.
	label string
}

// resolveAccessScope turns the resolved dimensions into the route the grant
// lives at. The DEEPEST dimension wins, because a grant addressed at project
// depth is a different authorization question from one at org depth, and
// silently widening it to the org would be the surface handing out more than
// the operator asked for.
func resolveAccessScope(resolved Resolved, flags commonFlags, instanceScope bool, verb string) (accessScope, error) {
	var tenant TenantScope
	var err error
	if instanceScope {
		if flags.Org != "" || flags.Project != "" || flags.Env != "" {
			return accessScope{}, failf(ExitUsage,
				"hikyo %s: --instance-scope and --org/--project/--env name two different scopes; choose one", verb)
		}
		// --instance-scope explicitly overrides lower-precedence tenant selections.
		// Still construct the Instance variant through the one scope validator.
		tenant, err = NewTenantScope(Resolved{})
	} else {
		tenant, err = NewTenantScope(resolved)
	}
	if err != nil {
		return accessScope{}, err
	}
	if tenant.Kind() == TenantScopeInstance {
		if instanceScope {
			return accessScope{path: api.PathPrefix + "/instance/grants", label: "instance"}, nil
		}
		_, err := resolved.Require(DimOrg)
		return accessScope{}, err
	}
	org := tenant.Get(DimOrg)
	path := api.PathPrefix + "/orgs/" + url.PathEscape(org)
	label := org
	if project := tenant.Get(DimProject); project != "" {
		path += "/projects/" + url.PathEscape(project)
		label += "/" + project
		if env := tenant.Get(DimEnv); env != "" {
			path += "/environments/" + url.PathEscape(env)
			label += "/" + env
		}
	}
	return accessScope{path: path + "/grants", label: label}, nil
}

func runAccessGrant(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("access grant", args, "list", "add", "remove", "template")
	if err != nil {
		return err
	}

	var format, principal, capability, template string
	var instanceScope bool
	st, flags, err := parseCommon("access grant "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&instanceScope, "instance-scope", false, "address instance scope rather than an org")
		if sub != "list" {
			fs.StringVar(&principal, "principal", "", "the principal receiving or losing the grant")
		}
		if sub == "add" || sub == "remove" {
			fs.StringVar(&capability, "capability", "", "the capability atom")
		}
		if sub == "template" {
			fs.StringVar(&template, "template", "", "the role template to expand")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax before resolution and before any session lookup, so an exit code
	// never depends on login state (#48's rule, unchanged).
	if err := flags.checkNoPositionals("access grant " + sub); err != nil {
		return err
	}
	switch {
	case sub != "list" && principal == "":
		return failf(ExitUsage, "usage: hikyo access grant %s --principal <id> ...", sub)
	case (sub == "add" || sub == "remove") && capability == "":
		return failf(ExitUsage, "usage: hikyo access grant %s --principal <id> --capability <atom>", sub)
	case sub == "template" && template == "":
		return failf(ExitUsage, "usage: hikyo access grant template --principal <id> --template <name>")
	}

	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return err
	}
	scope, err := resolveAccessScope(resolved, flags, instanceScope, "access grant "+sub)
	if err != nil {
		return err
	}
	client, artifact, _, err := authenticatedResolvedTarget(st, ios, flags, resolved)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		var list apigen.GrantList
		if err := client.Do(ctx, http.MethodGet, scope.path, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, grantTable(list))

	case "add":
		var res apigen.GrantResult
		body := apigen.CreateGrantRequest{Principal: principal, Capability: capability}
		// A grant that makes machine plaintext reachable (reveal on a machine
		// principal) consumes the grantor's reauthentication window over the
		// environments it reaches. For an environment-scoped grant that is
		// exactly the addressed environment, so the inline TOTP ceremony can
		// open it here; a wider scope is answered by the server's refusal,
		// which names the environments to reauthenticate over.
		attempt := func() error { return client.Do(ctx, http.MethodPost, scope.path, body, &res) }
		var err error
		if env := resolved.Get(DimEnv); env != "" && !instanceScope && capability == "reveal" {
			base, perr := projectBase(resolved)
			if perr != nil {
				return perr
			}
			// No browser handoff for a widening: a 0-window environment's grant
			// is made in the browser's Machine access page, which runs the
			// mint-purpose passkey ceremony itself.
			err = withRevealCeremony(ctx, client, st, ios, artifact, base, []string{env}, disclosure{}, attempt)
		} else {
			err = attempt()
		}
		if err != nil {
			return err
		}
		row, err := grantResultRow(res)
		if err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: grantResultColumns, Rows: [][]string{row}, JSON: res,
		})

	case "remove":
		q := url.Values{"principal": {principal}, "capability": {capability}}
		if err := client.Do(ctx, http.MethodDelete, scope.path+"?"+q.Encode(), nil, nil); err != nil {
			return err
		}
		return nil

	default: // template
		var res apigen.GrantResultList
		body := apigen.ApplyTemplateRequest{
			Principal: principal, Template: apigen.RoleTemplate(template),
		}
		if err := client.Do(ctx, http.MethodPost, scope.path+"/template", body, &res); err != nil {
			return err
		}
		rows := make([][]string, 0, len(res.Items))
		for _, r := range res.Items {
			row, err := grantResultRow(r)
			if err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return Render(ios.Stdout, f, Table{Columns: grantResultColumns, Rows: rows, JSON: res})
	}
}

// runAccessMember is the same grant data read and written by PRINCIPAL rather
// than by capability line: `member list` collapses the lines into one row per
// principal, `member remove` revokes every capability that principal holds at
// the scope.
//
// `member remove` is deliberately a client-side loop over the same
// per-capability revoke the ADR requires each capability to have, NOT a bulk
// server verb. Each revocation is its own audited event, which is what the
// audit-model ADR asks for; the honest cost is that it is not atomic, so a failure
// part-way leaves the earlier capabilities revoked. That is the safe direction
// to fail in — authority removed, not authority retained — and the command
// reports how far it got.
func runAccessMember(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("access member", args, "list", "remove")
	if err != nil {
		return err
	}
	var format, principal string
	var instanceScope bool
	st, flags, err := parseCommon("access member "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&instanceScope, "instance-scope", false, "address instance scope rather than an org")
		if sub == "remove" {
			fs.StringVar(&principal, "principal", "", "the principal to remove from this scope")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("access member " + sub); err != nil {
		return err
	}
	if sub == "remove" && principal == "" {
		return failf(ExitUsage, "usage: hikyo access member remove --principal <id>")
	}

	resolved, err := Resolve(st, ios.Env, flags.Flags, ios.Workdir)
	if err != nil {
		return err
	}
	scope, err := resolveAccessScope(resolved, flags, instanceScope, "access member "+sub)
	if err != nil {
		return err
	}
	client, _, _, err := authenticatedResolvedTarget(st, ios, flags, resolved)
	if err != nil {
		return err
	}
	// The membership listing is only served at org, project and instance
	// scope. "Who can reach this environment" must include the org- and
	// project-scoped grants that reach it, which an environment-only listing
	// would silently omit — so an env-addressed member verb is a usage error,
	// not a narrower answer.
	if strings.Contains(scope.path, "/environments/") {
		return failf(ExitUsage,
			"hikyo access member %s lists at org or project scope: an environment-only membership view would omit the org- and project-scoped grants that reach it", sub)
	}

	var list apigen.GrantList
	if err := client.Do(ctx, http.MethodGet, scope.path, nil, &list); err != nil {
		return err
	}
	if sub == "list" {
		return Render(ios.Stdout, f, memberTable(list))
	}

	revoked := 0
	for _, g := range list.Items {
		if g.PrincipalId != principal {
			continue
		}
		q := url.Values{"principal": {principal}, "capability": {g.Capability}}
		path := grantRouteFor(g, scope.path)
		if err := client.Do(ctx, http.MethodDelete, path+"?"+q.Encode(), nil, nil); err != nil {
			return failf(ExitRefused,
				"revoked %d capability line(s) before %q failed: %v — authority already removed stays removed",
				revoked, g.Capability, err)
		}
		revoked++
	}
	if revoked == 0 {
		return failf(ExitNotFound, "no grants for %s at %s", principal, scope.label)
	}
	return nil
}

// grantRouteFor is the revoke route for one listed grant line. A listing at
// org scope returns project- and environment-scoped lines too, and each must be
// revoked at ITS OWN depth — revoking an environment-scoped grant through the
// org route would address a triple that is not held.
func grantRouteFor(g apigen.Grant, listPath string) string {
	base := strings.TrimSuffix(listPath, "/grants")
	if g.Scope.OrgId == nil {
		return base + "/grants"
	}
	path := api.PathPrefix + "/orgs/" + url.PathEscape(*g.Scope.OrgId)
	if g.Scope.ProjectId != nil {
		path += "/projects/" + url.PathEscape(*g.Scope.ProjectId)
		if g.Scope.EnvironmentId != nil {
			path += "/environments/" + url.PathEscape(*g.Scope.EnvironmentId)
		}
	}
	return path + "/grants"
}

// runProjectSettings is the `project-settings get|set` pair. Both knobs are
// written together because they are one fact: marking an environment protected
// CAPS its window, so a surface that wrote them apart would have an observable
// state with the flag set and the window not yet capped.
func runProjectSettings(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("project-settings", args, "get", "set", "machine-reveal")
	if err != nil {
		return err
	}
	if sub == "machine-reveal" {
		return runMachineReveal(ctx, ios, rest)
	}
	var format, window, protected string
	st, flags, err := parseCommon("project-settings "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "set" {
			// TRI-STATE, not a bool. A bool flag defaults to false and is sent
			// on every `set`, so `--reauth-window-seconds 60` on a protected
			// environment silently unprotects it — a security control removed
			// by a command that never mentioned it. Unspecified means "leave
			// the stored value alone"; the PUT is a full replacement, so this
			// verb reads the current settings first and overlays what was
			// actually named.
			fs.StringVar(&protected, "protected", "",
				"true|false; omit to leave the environment's protection state unchanged")
			fs.StringVar(&window, "reauth-window-seconds", "",
				"the environment's own reauthentication window in seconds; omit to leave it unchanged, `inherit` to clear it")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("project-settings " + sub); err != nil {
		return err
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	env, err := resolved.Require(DimEnv)
	if err != nil {
		return err
	}
	path := base + "/environments/" + url.PathEscape(env) + "/settings"

	var out apigen.EnvironmentSettings
	if sub == "get" {
		if err := client.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, settingsTable(out))
	}

	if protected == "" && window == "" {
		return failf(ExitUsage,
			"usage: hikyo project-settings set --env E [--protected true|false] [--reauth-window-seconds N|inherit]")
	}
	// Read-then-overlay: the route is a full replacement, so an unnamed knob
	// has to be carried over rather than defaulted. The read runs under the
	// same session and the same authorization as the write.
	var current apigen.EnvironmentSettings
	if err := client.Do(ctx, http.MethodGet, path, nil, &current); err != nil {
		return err
	}
	body := current
	switch protected {
	case "":
		// unchanged
	case "true":
		body.Protected = true
	case "false":
		body.Protected = false
	default:
		return failf(ExitUsage, "--protected takes true or false, got %q", protected)
	}
	switch {
	case window == "":
		// unchanged
	case window == "inherit":
		body.ReauthWindowSeconds = nil
	default:
		seconds, err := strconv.Atoi(window)
		if err != nil || seconds < 0 {
			return failf(ExitUsage,
				"--reauth-window-seconds takes a non-negative whole number of seconds or `inherit`, got %q", window)
		}
		body.ReauthWindowSeconds = &seconds
	}
	if err := client.Do(ctx, http.MethodPut, path, body, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, settingsTable(out))
}

// runMachineReveal is the per-project machine-reveal opt-in (source-of-truth
// ADR: "an explicit, documented, per-project operator opt-in, never a
// default"). `get` reads it; `set --enabled true|false` flips it, which is a
// project-settings write carrying `reveal` at project depth and therefore
// MFA-mandatory: step up first. Enabling admits `reveal` grants onto workload
// and automation principals of the project - a standing decryption capability
// - and the verb says so before it writes. Withdrawing stops every machine
// secret delivery on the next fetch without touching any grant row.
func runMachineReveal(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("project-settings machine-reveal", args, "get", "set")
	if err != nil {
		return err
	}
	var format, enabled string
	st, flags, err := parseCommon("project-settings machine-reveal "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "set" {
			fs.StringVar(&enabled, "enabled", "", "true to admit reveal onto this project's machine principals, false to withdraw it")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("project-settings machine-reveal " + sub); err != nil {
		return err
	}
	var want bool
	if sub == "set" {
		switch enabled {
		case "true":
			want = true
		case "false":
			want = false
		default:
			return failf(ExitUsage, "usage: hikyo project-settings machine-reveal set --enabled true|false")
		}
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	path := base + "/machine-reveal"
	var out apigen.MachineRevealSettings
	if sub == "get" {
		if err := client.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, machineRevealTable(out))
	}
	if want {
		fmt.Fprintln(ios.Stderr, "enabling the machine-reveal opt-in: a machine principal holding reveal is a standing decryption capability, "+
			"and a CI runner holding it is that capability in the most-attacked box in the system. Each reveal grant still runs its own widening ceremony.")
	}
	if err := client.Do(ctx, http.MethodPut, path, apigen.MachineRevealSettings{Enabled: want}, &out); err != nil {
		return err
	}
	if !want {
		fmt.Fprintln(ios.Stderr, "machine-reveal opt-in withdrawn: every machine reveal grant in this project is inert from the next fetch; grant rows are untouched.")
	}
	return Render(ios.Stdout, f, machineRevealTable(out))
}

func machineRevealTable(s apigen.MachineRevealSettings) Table {
	return Table{Columns: []string{"MACHINE REVEAL"}, Rows: [][]string{{strconv.FormatBool(s.Enabled)}}, JSON: s}
}

var (
	grantColumns       = []string{"PRINCIPAL", "CAPABILITY", "SCOPE", "ORIGINS"}
	grantResultColumns = []string{"CAPABILITY", "GRANT", "OUTCOME"}
	memberColumns      = []string{"PRINCIPAL", "CAPABILITIES"}
	settingsColumns    = []string{"PROTECTED", "REAUTH WINDOW"}
)

// renderGrantScope matches the audit trail's rendering, so the same scope reads
// the same way in `access grant list` and in `audit query`.
func renderGrantScope(s apigen.GrantScope) string {
	parts := make([]string, 0, 3)
	for _, p := range []*string{s.OrgId, s.ProjectId, s.EnvironmentId} {
		if p == nil {
			break
		}
		parts = append(parts, *p)
	}
	if len(parts) == 0 {
		return "instance"
	}
	return strings.Join(parts, "/")
}

// renderOrigins is the origin chip row: the kind, with the subject for a
// manual grant so "who granted this" is answerable without a second lookup.
func renderOrigins(origins []apigen.GrantOrigin) string {
	chips := make([]string, 0, len(origins))
	for _, o := range origins {
		if o.Kind == apigen.GrantOriginKindManual {
			chips = append(chips, "manual("+o.Subject+")")
			continue
		}
		chips = append(chips, string(o.Kind))
	}
	return strings.Join(chips, ",")
}

func grantTable(list apigen.GrantList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, g := range list.Items {
		rows = append(rows, []string{
			g.PrincipalId, g.Capability, renderGrantScope(g.Scope), renderOrigins(g.Origins),
		})
	}
	return Table{Columns: grantColumns, Rows: rows, JSON: list}
}

func grantResultRow(r apigen.GrantResult) ([]string, error) {
	var outcome string
	switch r.Outcome {
	case api.GrantOutcomeCreated():
		outcome = "created"
	case api.GrantOutcomeOriginAdded():
		outcome = "origin added"
	case api.GrantOutcomeUnchanged():
		outcome = "unchanged"
	default:
		return nil, fmt.Errorf("server returned invalid grant outcome")
	}
	return []string{r.Capability, r.GrantId, outcome}, nil
}

// memberTable collapses the capability lines into one row per principal — the
// `member list` view. The per-capability lines are still the truth; this is a
// reading of them, which is why it never offers a revoke handle of its own.
func memberTable(list apigen.GrantList) Table {
	byPrincipal := map[string][]string{}
	for _, g := range list.Items {
		byPrincipal[g.PrincipalId] = append(byPrincipal[g.PrincipalId],
			g.Capability+"@"+renderGrantScope(g.Scope))
	}
	principals := make([]string, 0, len(byPrincipal))
	for p := range byPrincipal {
		principals = append(principals, p)
	}
	sort.Strings(principals)
	rows := make([][]string, 0, len(principals))
	for _, p := range principals {
		caps := byPrincipal[p]
		sort.Strings(caps)
		rows = append(rows, []string{p, strings.Join(caps, ",")})
	}
	return Table{Columns: memberColumns, Rows: rows, JSON: list}
}

func settingsTable(s apigen.EnvironmentSettings) Table {
	// "inherited" rather than an empty cell: 0 is a legal window meaning every
	// disclosure reauthenticates, and a blank would read as that.
	window := "inherited"
	if s.ReauthWindowSeconds != nil {
		window = strconv.Itoa(*s.ReauthWindowSeconds) + "s"
	}
	return Table{
		Columns: settingsColumns,
		Rows:    [][]string{{strconv.FormatBool(s.Protected), window}},
		JSON:    s,
	}
}
