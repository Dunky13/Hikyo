package cli

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Dunky13/hikyo/api/apigen"
)

// The OIDC federation verbs (#62): instance-scoped issuer configuration and
// project-scoped `(issuer, subject)` bindings.
//
// TWO THINGS THIS FILE MUST NEVER GROW, both inherited from the reasons the
// binding rules exist.
//
// There is no verb that EDITS a binding. Bindings are immutable, so a change is
// `sa binding create --replaces <id>`: the predecessor is revoked and the
// successor inserted in one transaction. An `update` verb would be a request the
// server has no route for, and offering one would suggest an in-place re-point is
// a thing an operator can do.
//
// There is no `--any-subject`, `--subject-prefix` or `--namespace` flag, and no
// flag that could become one. A pattern rule such as "any ServiceAccount in
// namespace prod" hands a Hikyo principal to anyone holding `create
// serviceaccount` in that namespace, which is a far wider group than
// cluster-admin — so the grammar has no way to express it.

func runFederationIssuer(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("instance-config federation-issuer", args,
		"list", "add", "update", "remove")
	if err != nil {
		return err
	}

	var (
		format, id, issuer, issuerType, jwksMode, jwksFile string
		refused                                            stringList
	)
	st, flags, err := parseCommon("instance-config federation-issuer "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "add" {
			fs.StringVar(&issuer, "issuer", "", "the byte-exact `iss`, https only")
			fs.StringVar(&issuerType, "type", "", "kubernetes, forgejo or github-actions")
		}
		if sub == "add" {
			fs.StringVar(&jwksMode, "jwks", "discovery", "discovery or static")
		}
		if sub == "update" {
			// NO DEFAULT on update, deliberately. Defaulting to `discovery` made
			// `federation-issuer update --refuse-audience X` silently flip a
			// static issuer to discovery and drop its key document — a
			// configuration change nobody asked for, arriving through a flag they
			// did not type. The server's PATCH body requires the mode, so the
			// honest options were "require it here" or "make absent mean no
			// change" on the wire; requiring it is the one that cannot be
			// misread.
			fs.StringVar(&jwksMode, "jwks", "", "discovery or static; required on update")
		}
		if sub == "add" || sub == "update" {
			fs.StringVar(&jwksFile, "jwks-file", "", "the JWKS document, required under --jwks static")
			fs.Var(&refused, "refuse-audience",
				"an audience no binding may name and no token may carry; repeatable, at least one required")
		}
		if sub == "update" || sub == "remove" {
			fs.StringVar(&id, "id", "", "the issuer to change")
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
	// never depends on login state.
	if err := flags.checkNoPositionals("instance-config federation-issuer " + sub); err != nil {
		return err
	}
	switch {
	case sub == "add" && (issuer == "" || issuerType == "" || len(refused) == 0):
		return failf(ExitUsage, "usage: hikyo instance-config federation-issuer add --issuer <url> --type kubernetes|forgejo|github-actions --refuse-audience <aud> [--jwks discovery|static --jwks-file PATH]")
	case (sub == "update" || sub == "remove") && id == "":
		return failf(ExitUsage, "usage: hikyo instance-config federation-issuer %s --id <id>", sub)
	case sub == "update" && (len(refused) == 0 || jwksMode == ""):
		return failf(ExitUsage, "usage: hikyo instance-config federation-issuer update --id <id> --jwks discovery|static --refuse-audience <aud> [--jwks-file PATH]")
	}
	// The JWKS pairing is total, and it is checked here as well as at the server:
	// a document stored but unused is a key set nobody rotates, and a static mode
	// with no document is an issuer that authenticates nothing.
	var document string
	if sub == "add" || sub == "update" {
		document, err = readJWKSDocument(jwksMode, jwksFile)
		if err != nil {
			return err
		}
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	const base = "/api/v1/instance/federation-issuers"

	switch sub {
	case "list":
		var out apigen.FederationIssuerList
		if err := client.Do(ctx, http.MethodGet, base, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, issuerTable(out))
	case "add":
		body := apigen.CreateFederationIssuerRequest{
			Issuer:           issuer,
			IssuerType:       apigen.IssuerType(issuerType),
			JwksMode:         apigen.JWKSMode(jwksMode),
			RefusedAudiences: refused,
		}
		if document != "" {
			body.StaticJwks = &document
		}
		var out apigen.FederationIssuer
		if err := client.Do(ctx, http.MethodPost, base, body, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, issuerTable(apigen.FederationIssuerList{
			Items: []apigen.FederationIssuer{out}, Count: 1,
		}))
	case "update":
		body := apigen.UpdateFederationIssuerRequest{
			JwksMode:         apigen.JWKSMode(jwksMode),
			RefusedAudiences: refused,
		}
		if document != "" {
			body.StaticJwks = &document
		}
		var out apigen.FederationIssuer
		if err := client.Do(ctx, http.MethodPatch, base+"/"+url.PathEscape(id), body, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, issuerTable(apigen.FederationIssuerList{
			Items: []apigen.FederationIssuer{out}, Count: 1,
		}))
	default:
		// Refused while any binding still names it, live or historical: erasing
		// the issuer a past binding trusted erases what it trusted.
		return client.Do(ctx, http.MethodDelete, base+"/"+url.PathEscape(id), nil, nil)
	}
}

func runServiceAccountBinding(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("sa binding", args, "create")
	if err != nil {
		return err
	}
	_ = sub // `create` is the only verb: list and delete ride `sa credential`.

	var (
		format, saID, issuer, subject, audience, replaces, lifetime string
		claims                                                      stringList
		indefinite                                                  bool
	)
	st, flags, err := parseCommon("sa binding create", ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.StringVar(&saID, "sa", "", "the service account this identity may speak as")
		fs.StringVar(&issuer, "issuer", "", "the byte-exact `iss` of a configured issuer")
		fs.StringVar(&subject, "subject", "", "the byte-exact `sub`; no wildcards, prefixes or patterns")
		fs.StringVar(&audience, "audience", "",
			"the audience this binding accepts; may not be the issuer's default")
		fs.Var(&claims, "claim",
			"a pinned claim as name=value, name=#integer or name=?bool; repeatable, at least one required")
		fs.StringVar(&lifetime, "lifetime", "", "requested finite lifetime, e.g. 720h")
		fs.BoolVar(&indefinite, "indefinite", false,
			"the distinct typed lifetime; refused unless the instance permits it")
		fs.StringVar(&replaces, "replaces", "",
			"the binding this one supersedes; a change is a replacement, never an edit")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("sa binding create"); err != nil {
		return err
	}
	if saID == "" || issuer == "" || subject == "" || audience == "" || len(claims) == 0 {
		return failf(ExitUsage, "usage: hikyo sa binding create --sa <id> --issuer <url> --subject <sub> --audience <aud> --claim name=value [--claim ...] [--lifetime 720h | --indefinite] [--replaces <id>]")
	}
	if indefinite && lifetime != "" {
		// Two lifetimes named at once is a refusal, never a precedence rule: a
		// silent precedence on a credential is the quiet ambiguity fail-loud
		// exists to prevent.
		return failf(ExitUsage, "hikyo sa binding create: --indefinite and --lifetime name two different lifetimes")
	}
	pins, err := parseClaimPins(claims)
	if err != nil {
		return err
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := serviceAccountPath(resolved)
	if err != nil {
		return err
	}

	body := apigen.CreateBindingRequest{
		Issuer: issuer, Subject: subject, Audience: audience, RequiredClaims: pins,
	}
	if indefinite {
		body.Indefinite = &indefinite
	}
	if lifetime != "" {
		d, err := time.ParseDuration(lifetime)
		if err != nil || d <= 0 {
			return failf(ExitUsage, "hikyo sa binding create: --lifetime must be a positive duration, e.g. 720h")
		}
		seconds := int(d / time.Second)
		body.LifetimeSeconds = &seconds
	}
	if replaces != "" {
		body.Replaces = &replaces
	}

	var out apigen.FederatedBinding
	if err := client.Do(ctx, http.MethodPost,
		base+"/"+url.PathEscape(saID)+"/bindings", body, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, bindingTable(out))
}

// Both repeatable flags above reuse provider.go's stringList, which already
// refuses an empty value and a duplicate. That refusal matters here rather than
// merely being convenient: a refused-audience list with a duplicate says the
// same thing twice, and a claim pinned twice is two requirements for one value —
// a precedence rule on a security predicate, which is the quiet ambiguity
// fail-loud exists to prevent. The server refuses the duplicate pin too; this
// just says so before the round trip.

// parseClaimPins parses the `--claim` grammar into the discriminated wire pins.
//
// The type is EXPLICIT in the syntax rather than guessed from the text, and that
// is the whole point of the grammar:
//
//	name=value    a string
//	name=#4242    an integer
//	name=?true    a boolean
//
// Guessing would make `repository_id=4242` a number and `repository_id=04242` a
// string, so two operators writing the same intent would get different bindings —
// and the validator never folds a string onto a number, so one of them would
// silently never match. A sigil is uglier and cannot be wrong.
func parseClaimPins(claims []string) ([]apigen.FederatedClaimPin, error) {
	out := make([]apigen.FederatedClaimPin, 0, len(claims))
	for _, raw := range claims {
		name, value, ok := strings.Cut(raw, "=")
		if !ok || name == "" {
			return nil, failf(ExitUsage,
				"hikyo sa binding create: --claim %q is not name=value (use name=#42 for an integer, name=?true for a boolean)", raw)
		}
		pin := apigen.FederatedClaimPin{Claim: name}
		switch {
		case strings.HasPrefix(value, "#"):
			n, err := strconv.ParseInt(strings.TrimPrefix(value, "#"), 10, 64)
			if err != nil {
				return nil, failf(ExitUsage,
					"hikyo sa binding create: --claim %q names #<integer> but %q is not one", name, strings.TrimPrefix(value, "#"))
			}
			pin.NumberValue = &n
		case strings.HasPrefix(value, "?"):
			b, err := strconv.ParseBool(strings.TrimPrefix(value, "?"))
			if err != nil {
				return nil, failf(ExitUsage,
					"hikyo sa binding create: --claim %q names ?<bool> but %q is not one", name, strings.TrimPrefix(value, "?"))
			}
			pin.BoolValue = &b
		default:
			v := value
			pin.StringValue = &v
		}
		out = append(out, pin)
	}
	return out, nil
}

// readJWKSDocument enforces the total pairing between the mode and the document.
func readJWKSDocument(mode, path string) (string, error) {
	switch mode {
	case "discovery":
		if path != "" {
			return "", failf(ExitUsage,
				"hikyo instance-config federation-issuer: --jwks-file is only for --jwks static; under discovery the keys are fetched")
		}
		return "", nil
	case "static":
		if path == "" {
			return "", failf(ExitUsage,
				"hikyo instance-config federation-issuer: --jwks static needs --jwks-file PATH")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", failf(ExitUsage, "hikyo instance-config federation-issuer: --jwks-file %s: %v", path, err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			return "", failf(ExitUsage,
				"hikyo instance-config federation-issuer: --jwks-file %s is empty", path)
		}
		return string(raw), nil
	default:
		return "", failf(ExitUsage,
			"hikyo instance-config federation-issuer: --jwks must be discovery or static")
	}
}

func issuerTable(list apigen.FederationIssuerList) Table {
	rows := make([][]string, 0, len(list.Items))
	for _, iss := range list.Items {
		rows = append(rows, []string{
			iss.Id, iss.Issuer, string(iss.IssuerType), string(iss.JwksMode),
			strconv.Itoa(len(iss.RefusedAudiences)), strconv.Itoa(iss.LiveBindings),
		})
	}
	return Table{
		// REFUSED is a count rather than the list: the whole list is in the JSON
		// output, and a table column holding several audience URIs stops being a
		// table. The count is the fact an operator scans for — an issuer with zero
		// would be one whose default audience nothing refuses, which the server
		// makes unrepresentable.
		Columns: []string{"ID", "ISSUER", "TYPE", "JWKS", "REFUSED", "BINDINGS"},
		Rows:    rows,
		JSON:    list,
	}
}

func bindingTable(b apigen.FederatedBinding) Table {
	subject, audience := "-", "-"
	if b.Credential.Subject != nil {
		subject = *b.Credential.Subject
	}
	if b.Credential.Audience != nil {
		audience = *b.Credential.Audience
	}
	pins := 0
	if b.Credential.RequiredClaims != nil {
		pins = len(*b.Credential.RequiredClaims)
	}
	replaced := "-"
	if b.ReplacedId != nil {
		replaced = *b.ReplacedId
	}
	return Table{
		// No VALUE column, and unlike a bearer credential there is nothing to
		// omit: a binding holds nothing at rest, which is the whole reason
		// federation exists.
		Columns: []string{"ID", "SUBJECT", "AUDIENCE", "PINS", "EXPIRES", "REPLACED"},
		Rows: [][]string{{
			b.Credential.Id, subject, audience, strconv.Itoa(pins),
			renderExpiry(b.Credential), replaced,
		}},
		JSON: b,
	}
}
