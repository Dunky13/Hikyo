package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

// The SCIM administration verbs (#73), spelled by api-cli-spellings §1:
//
//	hikyo scim binding    create|list|show|delete
//	hikyo scim mapping    add|update|remove|list
//	hikyo scim credential mint|list|show|revoke
//	hikyo scim user  list <binding>
//	hikyo scim group list <binding>
//
// ONE departure from that document, declared rather than smuggled. §1 spells
// `mapping add|update|remove <binding> --group <g> --template <t>` with no
// scope, while the ADR §3 defines a mapping row as `(group -> template @
// scope)` and allows SEVERAL rows per group. As written the verbs cannot
// address one row among several, and `add` cannot express the scope the ADR
// requires. So a row is addressed by `(group, scope)` and the template is what
// an update CHANGES.
//
// The scope uses the ordinary per-dimension flags every other verb uses, with
// one difference from `access grant`: there is no default. `--org-scope` is an
// explicit opt-in exactly as `--instance-scope` is there, because an org-scoped
// mapping row is the WIDEST thing a binding can create — everyone in the group,
// on every project and environment, including ones created later — and a
// surface that defaults to it has preselected the blast radius for you.

func runSCIM(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("scim", args, "binding", "mapping", "credential", "user", "group")
	if err != nil {
		return err
	}
	switch sub {
	case "binding":
		return runSCIMBinding(ctx, ios, rest)
	case "mapping":
		return runSCIMMapping(ctx, ios, rest)
	case "credential":
		return runSCIMCredential(ctx, ios, rest)
	case "user":
		return runSCIMDirectory(ctx, ios, rest, "user")
	default:
		return runSCIMDirectory(ctx, ios, rest, "group")
	}
}

// scimBindingsPath is the org's binding collection. Every SCIM administration
// route hangs off it, and the org comes from the ordinary dimension
// precedence — a binding belongs to exactly one org and the route says which.
func scimBindingsPath(resolved Resolved) (string, error) {
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return "", err
	}
	return api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/scim-bindings", nil
}

// ---------------------------------------------------------------------------
// binding
// ---------------------------------------------------------------------------

func runSCIMBinding(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("scim binding", args, "create", "list", "show", "delete")
	if err != nil {
		return err
	}
	// `show` and `delete` take the binding id positionally, per the spellings.
	binding := ""
	if sub == "show" || sub == "delete" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return failf(ExitUsage, "usage: hikyo scim binding %s <binding>", sub)
		}
		binding, rest = rest[0], rest[1:]
	}

	var format, provider, kind, subjectSource string
	var nameIDFormat, nameIDQualifier, nameIDSPQualifier string
	var nameIDQualifierSet, nameIDSPQualifierSet bool
	st, flags, err := parseCommon("scim binding "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" {
			fs.StringVar(&provider, "provider", "", "the configured identity provider this binding references")
			// No DEFAULT. `oidc_providers.slug` and `saml_providers.slug` are
			// unique per TABLE, so one name can identify two different
			// providers; defaulting to oidc silently resolved the wrong one for
			// every documented SAML command. The locked spelling (§1) has no
			// such flag, which is a gap in the spelling rather than a licence
			// to guess — recorded as a #27 disposition in the handoff.
			fs.StringVar(&kind, "kind", "", "the provider family: oidc or saml (required)")
			fs.StringVar(&subjectSource, "subject-source", "externalId",
				"the SCIM attribute path carrying identity material; userName is refused by name")
			fs.StringVar(&nameIDFormat, "nameid-format", "", "SAML only: the NameID Format URI the login path sees")
			fs.StringVar(&nameIDQualifier, "nameid-qualifier", "", "SAML only: the fixed NameQualifier")
			fs.BoolVar(&nameIDQualifierSet, "nameid-qualifier-present", false,
				"SAML only: the assertion carries a NameQualifier at all (absent and empty are different subjects)")
			fs.StringVar(&nameIDSPQualifier, "nameid-sp-qualifier", "", "SAML only: the fixed SPNameQualifier")
			fs.BoolVar(&nameIDSPQualifierSet, "nameid-sp-qualifier-present", false,
				"SAML only: the assertion carries an SPNameQualifier at all")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("scim binding " + sub); err != nil {
		return err
	}
	if sub == "create" {
		if provider == "" {
			return failf(ExitUsage, "usage: hikyo scim binding create --org <org> --provider <provider> --kind oidc|saml")
		}
		if kind != "oidc" && kind != "saml" {
			return failf(ExitUsage,
				"hikyo scim binding create: --kind must be oidc or saml. A provider name is unique only within its family, so naming one without its kind cannot identify a provider")
		}
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := scimBindingsPath(resolved)
	if err != nil {
		return err
	}

	switch sub {
	case "create":
		body := apigen.CreateScimBindingRequest{
			ProviderKind:  apigen.CreateScimBindingRequestProviderKind(kind),
			ProviderSlug:  provider,
			SubjectSource: subjectSource,
		}
		if nameIDFormat != "" {
			body.NameidFormat = &nameIDFormat
		}
		if nameIDQualifier != "" {
			body.NameidQualifier = &nameIDQualifier
		}
		if nameIDQualifierSet {
			body.NameidQualifierPresent = &nameIDQualifierSet
		}
		if nameIDSPQualifier != "" {
			body.NameidSpQualifier = &nameIDSPQualifier
		}
		if nameIDSPQualifierSet {
			body.NameidSpQualifierPresent = &nameIDSPQualifierSet
		}
		var view apigen.ScimBinding
		if err := client.Do(ctx, http.MethodPost, base, body, &view); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr,
			"binding created. It has no credential yet: run `hikyo scim credential mint %s`, then point the identity provider at %s/orgs/%s/scim/v2/%s\n",
			view.Id, api.PathPrefix, resolved.Get(DimOrg), view.Id)
		return Render(ios.Stdout, f, scimOne(scimBindingTable([]apigen.ScimBinding{view}), view))

	case "list":
		var list apigen.ScimBindingList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimBindingTable(list.Items))

	case "show":
		var view apigen.ScimBinding
		if err := client.Do(ctx, http.MethodGet, base+"/"+url.PathEscape(binding), nil, &view); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimOne(scimBindingTable([]apigen.ScimBinding{view}), view))

	default: // delete
		if err := client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(binding), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr,
			"binding %s deleted: credentials revoked, provisioned grants released, the provisioning connection retired. Accounts and identity links survive.\n",
			binding)
		return nil
	}
}

// ---------------------------------------------------------------------------
// mapping
// ---------------------------------------------------------------------------

func runSCIMMapping(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("scim mapping", args, "add", "update", "remove", "list")
	if err != nil {
		return err
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return failf(ExitUsage, "usage: hikyo scim mapping %s <binding> ...", sub)
	}
	binding := rest[0]
	rest = rest[1:]

	var format, group, template string
	var orgScope bool
	st, flags, err := parseCommon("scim mapping "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub != "list" {
			fs.StringVar(&group, "group", "", "the server-minted SCIM group id this row maps")
			fs.BoolVar(&orgScope, "org-scope", false,
				"address the whole org rather than a project or environment (the widest a binding can reach)")
		}
		if sub == "add" || sub == "update" {
			fs.StringVar(&template, "template", "", "the role template this group expands into")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("scim mapping " + sub); err != nil {
		return err
	}
	switch {
	case sub != "list" && group == "":
		return failf(ExitUsage, "usage: hikyo scim mapping %s <binding> --group <idp-group-id> ...", sub)
	case (sub == "add" || sub == "update") && template == "":
		return failf(ExitUsage,
			"usage: hikyo scim mapping %s <binding> --group <idp-group-id> --template <template>", sub)
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := scimBindingsPath(resolved)
	if err != nil {
		return err
	}
	path := base + "/" + url.PathEscape(binding) + "/mappings"

	if sub == "list" {
		var list apigen.ScimMappingList
		if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimMappingTable(list.Items))
	}

	project, env := resolved.Get(DimProject), resolved.Get(DimEnv)
	// No default, on purpose. An org-scoped row is the widest thing a binding
	// can create, so it must be ASKED for; a picker that preselects it has
	// chosen the blast radius on the operator's behalf.
	switch {
	case orgScope && (project != "" || env != ""):
		return failf(ExitUsage,
			"hikyo scim mapping %s: --org-scope and --project/--env name two different scopes; choose one", sub)
	case !orgScope && project == "":
		return failf(ExitUsage,
			"hikyo scim mapping %s: name the scope this row grants at — --project (and optionally --env), or --org-scope for the whole organisation", sub)
	}

	if sub == "remove" {
		q := url.Values{"group": {group}}
		if project != "" {
			q.Set("project", project)
		}
		if env != "" {
			q.Set("environment", env)
		}
		var res apigen.ScimMappingResult
		if err := client.Do(ctx, http.MethodDelete, path+"?"+q.Encode(), nil, &res); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "mapping row removed; %d origin(s) released in the same transaction.\n",
			res.OriginsReleased)
		return Render(ios.Stdout, f, scimOne(scimMappingTable([]apigen.ScimMapping{res.Mapping}), res))
	}

	body := apigen.ScimMappingRequest{GroupId: apigen.ID(group), Template: template}
	if project != "" {
		body.ProjectId = &project
	}
	if env != "" {
		body.EnvironmentId = &env
	}
	method := http.MethodPost
	if sub == "update" {
		method = http.MethodPut
	}
	var res apigen.ScimMappingResult
	if err := client.Do(ctx, method, path, body, &res); err != nil {
		return err
	}
	// The consequence language is SERVER-AUTHORED and is printed before the
	// row, because it is about what just happened: the grants exist by the time
	// this returns. Rendering it in the client would be a second, unreviewed
	// policy about what the operator is told.
	for _, w := range res.Warnings {
		fmt.Fprintf(ios.Stderr, "%s: %s\n", strings.ToUpper(string(w.Severity)), w.Message)
	}
	fmt.Fprintf(ios.Stderr, "%d member(s) affected, %d grant(s) created, %d origin(s) released.\n",
		res.MembersAffected, res.GrantsCreated, res.OriginsReleased)
	return Render(ios.Stdout, f, scimOne(scimMappingTable([]apigen.ScimMapping{res.Mapping}), res))
}

// ---------------------------------------------------------------------------
// credential
// ---------------------------------------------------------------------------

func runSCIMCredential(ctx context.Context, ios IO, args []string) (returnErr error) {
	sub, rest, err := subverb("scim credential", args, "mint", "list", "show", "revoke")
	if err != nil {
		return err
	}
	if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
		return failf(ExitUsage, "usage: hikyo scim credential %s <binding> ...", sub)
	}
	binding := rest[0]
	rest = rest[1:]

	credential := ""
	if sub == "show" || sub == "revoke" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return failf(ExitUsage, "usage: hikyo scim credential %s <binding> <credential-id>", sub)
		}
		credential, rest = rest[0], rest[1:]
	}

	var format, outputFile string
	var dangerous, indefinite bool
	st, flags, err := parseCommon("scim credential "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "mint" {
			fs.StringVar(&outputFile, "output-file", "", "write the credential to a file this command creates (0600)")
			fs.BoolVar(&dangerous, "dangerously-print", false, "print the credential to stdout")
			fs.BoolVar(&indefinite, "indefinite", false,
				"mint without a lifetime ceiling; requires the instance opt-in and is refused without it")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("scim credential " + sub); err != nil {
		return err
	}

	// Reserve the print-triad destination BEFORE the mint, so a credential is
	// never created and then dropped on the floor.
	deliver := disclose.Options{
		OutputFile: outputFile, DangerouslyPrint: dangerous,
		Stdout: ios.Stdout,
	}
	var sink *disclose.PreparedSink
	if sub == "mint" {
		sink, err = ios.prepareDisclosure(deliver)
		if err != nil {
			return failf(ExitRefused, "the provisioning credential has nowhere to go: %v", err)
		}
		defer sink.AbortOnReturn(&returnErr)
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := scimBindingsPath(resolved)
	if err != nil {
		return err
	}
	path := base + "/" + url.PathEscape(binding) + "/credentials"

	switch sub {
	case "mint":
		// `∧ reauthentication` (§7): the proof is prompted for, never a flag —
		// a password or TOTP code on a command line lands in shell history.
		proof, err := ios.readPassword(
			"Account-security proof (your TOTP code, or password if no factor): ")
		if err != nil {
			return err
		}
		body := apigen.MintScimCredentialRequest{Proof: &proof}
		if indefinite {
			body.Indefinite = &indefinite
		}
		var res apigen.ScimMintResult
		if err := client.Do(ctx, http.MethodPost, path, body, &res); err != nil {
			return err
		}
		if _, err := sink.WriteOnce(
			fmt.Sprintf("SCIM provisioning credential %s (display-once)", res.Credential.Id),
			res.Token); err != nil {
			return failf(ExitRefused, "disclosing the provisioning credential: %v", err)
		}
		if res.Rotated {
			fmt.Fprintln(ios.Stderr,
				"a credential was already live: this is an overlap rotation. Update the identity provider, then revoke the old one — authority is identical throughout, so there is no offline window.")
		}
		// The metadata goes to STDERR when the token went to stdout. The
		// display-once stream has to stay token-only: appending a table (or a
		// second JSON document) to it makes `-o json` unparseable and makes a
		// pipe into a secret store capture the metadata too.
		if dangerous {
			return Render(ios.Stderr, f, scimOne(scimCredentialTable([]apigen.ScimCredential{res.Credential}), res.Credential))
		}
		return Render(ios.Stdout, f, scimOne(scimCredentialTable([]apigen.ScimCredential{res.Credential}), res.Credential))

	case "list":
		var list apigen.ScimCredentialList
		if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimCredentialTable(list.Items))

	case "show":
		var view apigen.ScimCredential
		if err := client.Do(ctx, http.MethodGet, path+"/"+url.PathEscape(credential), nil, &view); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimOne(scimCredentialTable([]apigen.ScimCredential{view}), view))

	default: // revoke
		if err := client.Do(ctx, http.MethodDelete, path+"/"+url.PathEscape(credential), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "credential %s revoked; it dies at the identity provider's next request.\n", credential)
		return nil
	}
}

// ---------------------------------------------------------------------------
// directory views
// ---------------------------------------------------------------------------

func runSCIMDirectory(ctx context.Context, ios IO, args []string, kind string) error {
	if _, rest, err := subverb("scim "+kind, args, "list"); err != nil {
		return err
	} else {
		args = rest
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return failf(ExitUsage, "usage: hikyo scim %s list <binding>", kind)
	}
	binding := args[0]

	var format string
	st, flags, err := parseCommon("scim "+kind+" list", ios, args[1:], func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("scim " + kind + " list"); err != nil {
		return err
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := scimBindingsPath(resolved)
	if err != nil {
		return err
	}
	path := base + "/" + url.PathEscape(binding) + "/directory/" + kind + "s"

	if kind == "user" {
		var list apigen.ScimDirectoryUserList
		if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
			return err
		}
		return Render(ios.Stdout, f, scimDirectoryUserTable(list.Items))
	}
	var list apigen.ScimDirectoryGroupList
	if err := client.Do(ctx, http.MethodGet, path, nil, &list); err != nil {
		return err
	}
	return Render(ios.Stdout, f, scimDirectoryGroupTable(list.Items))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// scimOne narrows a one-row table's JSON leg to the object itself. `create`
// and `show` address ONE thing, and wrapping it in a list would make every
// consumer index into a collection that can only ever have one member — the
// same shape `access grant add` already avoids.
func scimOne[T any](tbl Table, item T) Table {
	tbl.JSON = item
	return tbl
}

func scimBindingTable(items []apigen.ScimBinding) Table {
	rows := make([][]string, 0, len(items))
	for _, b := range items {
		rows = append(rows, []string{
			string(b.Id), string(b.ProviderKind), b.ProviderSlug, b.SubjectSource,
			timeOrDash(b.LastContactAt), attentionChips(b.Attention),
		})
	}
	return Table{
		Columns: []string{"ID", "KIND", "PROVIDER", "SUBJECT SOURCE", "LAST CONTACT", "ATTENTION"},
		Rows:    rows, JSON: apigen.ScimBindingList{Items: items, Count: len(items)},
	}
}

func scimMappingTable(items []apigen.ScimMapping) Table {
	rows := make([][]string, 0, len(items))
	for _, m := range items {
		state := "live"
		if m.Inert {
			state = "inert"
		}
		rows = append(rows, []string{
			string(m.Id), string(m.GroupId), m.Template,
			mappingScopeLabel(m), state, strings.Join(m.Capabilities, ","),
		})
	}
	return Table{
		Columns: []string{"ID", "GROUP", "TEMPLATE", "SCOPE", "STATE", "CAPABILITIES"},
		Rows:    rows, JSON: apigen.ScimMappingList{Items: items, Count: len(items)},
	}
}

func mappingScopeLabel(m apigen.ScimMapping) string {
	switch {
	case m.EnvironmentId != nil && *m.EnvironmentId != "":
		return derefStr(m.ProjectId) + "/" + *m.EnvironmentId
	case m.ProjectId != nil && *m.ProjectId != "":
		return *m.ProjectId
	default:
		return "org"
	}
}

func scimCredentialTable(items []apigen.ScimCredential) Table {
	rows := make([][]string, 0, len(items))
	for _, c := range items {
		state := "revoked"
		if c.Live {
			state = "live"
		} else if c.RevokedAt == nil {
			state = "expired"
		}
		rows = append(rows, []string{
			string(c.Id), state, c.CreatedAt.Format("2006-01-02T15:04:05Z"),
			timeOrDash(c.ExpiresAt), timeOrDash(c.LastUsedAt),
		})
	}
	return Table{
		Columns: []string{"ID", "STATE", "CREATED", "EXPIRES", "LAST USED"},
		Rows:    rows, JSON: apigen.ScimCredentialList{Items: items, Count: len(items)},
	}
}

func scimDirectoryUserTable(items []apigen.ScimDirectoryUser) Table {
	rows := make([][]string, 0, len(items))
	for _, u := range items {
		state := "inactive"
		if u.Active {
			state = "active"
		}
		rows = append(rows, []string{
			string(u.Id), u.UserName, state, strconv.Itoa(len(u.Groups)),
			attentionChips(u.Attention),
		})
	}
	return Table{
		Columns: []string{"ID", "USERNAME", "STATE", "GROUPS", "ATTENTION"},
		Rows:    rows, JSON: apigen.ScimDirectoryUserList{Items: items, Count: len(items)},
	}
}

func scimDirectoryGroupTable(items []apigen.ScimDirectoryGroup) Table {
	rows := make([][]string, 0, len(items))
	for _, g := range items {
		rows = append(rows, []string{
			string(g.Id), g.DisplayName, strconv.Itoa(g.MemberCount),
		})
	}
	return Table{
		Columns: []string{"ID", "DISPLAY NAME", "MEMBERS"},
		Rows:    rows, JSON: apigen.ScimDirectoryGroupList{Items: items, Count: len(items)},
	}
}

// attentionChips renders the raised states inline, in the same shape the
// origin chips take on the membership line: the table answers "what does SCIM
// think is wrong?" at a glance, and `-o json` carries the full remediation.
func attentionChips(in []apigen.ScimAttention) string {
	if len(in) == 0 {
		return "-"
	}
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, string(a.State))
	}
	return strings.Join(out, ",")
}

// timeOrDash renders an optional timestamp. A dash rather than an empty cell,
// because "no ceiling" and "a value the table failed to render" must not look
// the same in a column an operator scans for expiry.
func timeOrDash(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02T15:04:05Z")
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
