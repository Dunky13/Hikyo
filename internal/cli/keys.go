package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// The key-catalogue verbs (#49): `hikyo key …`, with the group verbs under
// `hikyo key group …`.
//
// Spelling note, same disposition as #48's: the api-cli-surface ADR's closed
// v1 taxonomy fixes `key add`; it spells no `key show|list|rename|declare|
// reclassify|group`. Each joins the EXISTING noun-verb family as a declared
// additive spelling under the ADR's own grammar, pre-freeze — the same move
// the flat-model ADR made for `values set --clear`. `create` is used rather
// than the ADR's `add` so the whole CLI has one creation verb; both spellings
// are carried to #27 for confirmation.
//
// Every verb reaches only tenant-scoped routes, so a caller who may not reach
// an object gets exit 5 — indistinguishable from one that is not there. That
// includes the reveal-gated declaration change and declassification: their
// refusal MUST look like a missing key, or the gate becomes the one-bit oracle
// it exists to close.

// keyCreateUsage is the one spelling of `key create`'s required arguments.
// Three copies of it is two chances for one to drift.
const keyCreateUsage = "usage: hikyo key create --name <NAME> --classification secret|config --declaration <json>"

// runKey is the key family. `group` is a nested family rather than a sibling
// verb because a group is a property of the catalogue, not a peer of it.
func runKey(ctx context.Context, ios IO, args []string) error {
	if len(args) > 0 && args[0] == "group" {
		return runKeyGroup(ctx, ios, args[1:])
	}
	sub, rest, err := subverb("key", args,
		"list", "show", "create", "rename", "declare", "reclassify", "update", "set-group", "delete")
	if err != nil {
		return err
	}

	var format, name, declaration, classification, folderPath, description, deprecationNote, groupID, requiredIn, forbiddenIn string
	var deprecated bool
	// `key update` is a PATCH, so it must send only the members the caller
	// actually typed: sending every flag's zero value would clear the folder
	// path, the deprecation flag and the note for someone who set only
	// --description. flag.FlagSet.Visit reports exactly the flags that were
	// SET, which is the only reliable way to tell "" from "not given".
	set := map[string]bool{}
	var fset *flag.FlagSet
	st, flags, err := parseCommon("key "+sub, ios, rest, func(fs *flag.FlagSet) {
		fset = fs
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
			fs.StringVar(&name, "name", "", "key name (uppercase, digits, underscore; no leading digit)")
		}
		if sub == "create" || sub == "declare" {
			fs.StringVar(&declaration, "declaration", "",
				"the value-dependent rules as a JSON document, e.g. {\"rule\":{\"type\":\"string\"}}")
			fs.StringVar(&requiredIn, "required-in", "none", "presence: all|none|<env-id,env-id,...>")
			fs.StringVar(&forbiddenIn, "forbidden-in", "none", "presence: all|none|<env-id,env-id,...>")
		}
		if sub == "create" {
			fs.StringVar(&classification, "classification", "", "secret or config")
			fs.StringVar(&groupID, "group", "", "key group to join")
		}
		if sub == "create" || sub == "update" {
			fs.StringVar(&folderPath, "folder", "", "folder path within the project")
			fs.StringVar(&description, "description", "", "free-text description; may hold a URL")
			fs.BoolVar(&deprecated, "deprecated", false, "mark the key deprecated")
			fs.StringVar(&deprecationNote, "deprecation-note", "", "why the key is deprecated, and what replaces it")
		}
		if sub == "reclassify" {
			fs.StringVar(&classification, "classification", "", "secret or config")
		}
		if sub == "set-group" {
			fs.StringVar(&groupID, "group", "", "key group to join, or empty to leave every group")
		}
	})
	if err != nil {
		return err
	}
	fset.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax first, before any target resolution or session lookup, so an
	// invocation that is simply malformed answers the same exit code whether or
	// not the caller is logged in. There is no --key selector flag, so the key
	// id can only ever be positional; the check still rejects a stray extra one.
	switch sub {
	case "show", "rename", "declare", "reclassify", "update", "set-group", "delete":
		if err := flags.checkTarget("key "+sub, "key", ""); err != nil {
			return err
		}
		if flags.positional() == "" {
			return failf(ExitUsage, "usage: hikyo key %s <key>", sub)
		}
	default:
		if err := flags.checkNoPositionals("key " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "create" && (name == "" || classification == "" || declaration == ""):
		return failf(ExitUsage, keyCreateUsage)
	case sub == "rename" && name == "":
		return failf(ExitUsage, "usage: hikyo key rename <key> --name <NEW_NAME>")
	case sub == "declare" && declaration == "":
		return failf(ExitUsage, "usage: hikyo key declare <key> --declaration <json> [--required-in ...] [--forbidden-in ...]")
	case sub == "reclassify" && classification == "":
		return failf(ExitUsage, "usage: hikyo key reclassify <key> --classification secret|config")
	}

	var decl apigen.KeyDeclaration
	if declaration != "" {
		if err := decodeDeclaration(declaration, &decl); err != nil {
			// A malformed --declaration is a client-side syntax error, refused
			// before any request: sending it would spend a round trip to be told
			// the same thing.
			return failf(ExitUsage, "--declaration is not a JSON declaration document: %v", err)
		}
	}
	presence, err := parsePresence(requiredIn, forbiddenIn)
	if err != nil {
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
	base += "/keys"
	target := base + "/" + url.PathEscape(flags.positional())

	switch sub {
	case "list":
		var list apigen.KeyList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		rows := make([][]string, 0, len(list.Items))
		for _, k := range list.Items {
			rows = append(rows, keyRow(k))
		}
		return Render(ios.Stdout, f, Table{Columns: keyColumns, Rows: rows, JSON: list})

	case "show":
		var key apigen.Key
		if err := client.Do(ctx, http.MethodGet, target, nil, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "create":
		body := apigen.CreateKeyRequest{
			Name:           name,
			Classification: apigen.KeyClassification(classification),
			Declaration:    decl,
			Presence:       &presence,
		}
		body.FolderPath = optional(folderPath)
		body.Description = optional(description)
		body.DeprecationNote = optional(deprecationNote)
		body.GroupId = optional(groupID)
		if deprecated {
			body.Deprecated = &deprecated
		}
		var key apigen.Key
		if err := client.Do(ctx, http.MethodPost, base, body, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "rename":
		var key apigen.Key
		if err := client.Do(ctx, http.MethodPut, target+"/name", apigen.RenameKeyRequest{Name: name}, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "declare":
		var key apigen.Key
		body := apigen.UpdateKeyDeclarationRequest{Declaration: decl, Presence: presence}
		if err := client.Do(ctx, http.MethodPut, target+"/declaration", body, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "reclassify":
		var key apigen.Key
		body := apigen.ReclassifyKeyRequest{Classification: apigen.KeyClassification(classification)}
		if err := client.Do(ctx, http.MethodPut, target+"/classification", body, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "update":
		// `update` carries the NON-semantic metadata only, and deliberately
		// offers no --classification: reclassification is its own ceremony with
		// its own gate and its own audit, and a flag here would be a way around
		// both. The server refuses the field too, for a caller who bypasses the
		// CLI.
		//
		// Only the flags the caller TYPED are sent. An untyped member is absent
		// on the wire and the server leaves that column alone; sending "" would
		// be a caller asking to clear it.
		var body apigen.UpdateKeyMetadataRequest
		if set["folder"] {
			body.FolderPath = &folderPath
		}
		if set["description"] {
			body.Description = &description
		}
		if set["deprecated"] {
			body.Deprecated = &deprecated
		}
		if set["deprecation-note"] {
			body.DeprecationNote = &deprecationNote
		}
		var key apigen.Key
		if err := client.Do(ctx, http.MethodPatch, target, body, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "set-group":
		var key apigen.Key
		if err := client.Do(ctx, http.MethodPut, target+"/group",
			apigen.SetKeyGroupRequest{GroupId: groupID}, &key); err != nil {
			return err
		}
		return renderKey(ios, f, key)

	case "delete":
		if err := client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted key %s\n", flags.positional())
		return nil
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo key: unhandled subverb %q", sub)
}

// runKeyGroup is the nested group family.
func runKeyGroup(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("key group", args, "list", "show", "create", "rename", "delete")
	if err != nil {
		return err
	}
	var format, name string
	st, flags, err := parseCommon("key group "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "rename" {
			fs.StringVar(&name, "name", "", "key group name")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	switch sub {
	case "show", "rename", "delete":
		if err := flags.checkTarget("key group "+sub, "key-group", ""); err != nil {
			return err
		}
		if flags.positional() == "" {
			return failf(ExitUsage, "usage: hikyo key group %s <group>", sub)
		}
	default:
		if err := flags.checkNoPositionals("key group " + sub); err != nil {
			return err
		}
	}
	switch {
	case sub == "create" && name == "":
		return failf(ExitUsage, "usage: hikyo key group create --name <name>")
	case sub == "rename" && name == "":
		return failf(ExitUsage, "usage: hikyo key group rename <group> --name <new-name>")
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	base, err := projectBase(resolved)
	if err != nil {
		return err
	}
	base += "/key-groups"
	target := base + "/" + url.PathEscape(flags.positional())

	switch sub {
	case "list":
		var list apigen.KeyGroupList
		if err := client.Do(ctx, http.MethodGet, base, nil, &list); err != nil {
			return err
		}
		rows := make([][]string, 0, len(list.Items))
		for _, g := range list.Items {
			rows = append(rows, keyGroupRow(g))
		}
		return Render(ios.Stdout, f, Table{Columns: keyGroupColumns, Rows: rows, JSON: list})

	case "show":
		var group apigen.KeyGroup
		if err := client.Do(ctx, http.MethodGet, target, nil, &group); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: keyGroupColumns, Rows: [][]string{keyGroupRow(group)}, JSON: group})

	case "create":
		var group apigen.KeyGroup
		if err := client.Do(ctx, http.MethodPost, base, apigen.CreateKeyGroupRequest{Name: name}, &group); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: keyGroupColumns, Rows: [][]string{keyGroupRow(group)}, JSON: group})

	case "rename":
		var group apigen.KeyGroup
		if err := client.Do(ctx, http.MethodPatch, target, apigen.RenameKeyGroupRequest{Name: name}, &group); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: keyGroupColumns, Rows: [][]string{keyGroupRow(group)}, JSON: group})

	case "delete":
		if err := client.Do(ctx, http.MethodDelete, target, nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "deleted key group %s\n", flags.positional())
		return nil
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo key group: unhandled subverb %q", sub)
}

// decodeDeclaration is STRICT, and that is the whole point of it.
//
// A plain json.Unmarshal drops members it does not recognise, so `patern`
// instead of `pattern` disappears here and the CLI sends a perfectly valid
// declaration with the constraint the operator wrote silently missing. The
// contract's `additionalProperties: false` never sees it, because the typo
// never leaves this process. A rule that appears to enforce something and does
// not is the failure mode the whole schema model exists to refuse — so the
// refusal has to happen where the typo is, which is here.
//
// Trailing content is refused for the same reason: two documents where one was
// expected means the caller's intent is not what the first one says.
func decodeDeclaration(raw string, out *apigen.KeyDeclaration) error {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after the declaration document")
	}
	return nil
}

// parsePresence reads the two presence flags. The spelling is deliberately one
// flag per rule rather than a JSON blob: `all` and `none` are the two answers
// operators actually give, and an id list is the third. `all` stays SYMBOLIC
// all the way to the server, so an environment created tomorrow is covered by
// a rule written today.
func parsePresence(requiredIn, forbiddenIn string) (apigen.KeyPresenceRules, error) {
	required, err := parsePresenceRule("--required-in", requiredIn)
	if err != nil {
		return apigen.KeyPresenceRules{}, err
	}
	forbidden, err := parsePresenceRule("--forbidden-in", forbiddenIn)
	if err != nil {
		return apigen.KeyPresenceRules{}, err
	}
	return apigen.KeyPresenceRules{RequiredIn: required, ForbiddenIn: forbidden}, nil
}

func parsePresenceRule(flagName, spec string) (apigen.KeyPresence, error) {
	switch spec {
	case "", "none":
		return apigen.KeyPresence{Mode: "none"}, nil
	case "all":
		return apigen.KeyPresence{Mode: "all"}, nil
	}
	ids := strings.Split(spec, ",")
	for i, id := range ids {
		ids[i] = strings.TrimSpace(id)
		if ids[i] == "" {
			return apigen.KeyPresence{}, failf(ExitUsage,
				"%s: an environment id is empty; use all, none, or a comma-separated id list", flagName)
		}
	}
	return apigen.KeyPresence{Mode: "explicit", EnvironmentIds: &ids}, nil
}

// optional turns "" into an absent member. The contract distinguishes absent
// from empty for these, and sending an explicit "" would be a caller asking to
// clear the field rather than leave it alone.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var (
	keyColumns      = []string{"ID", "NAME", "CLASS", "TYPE", "FOLDER", "GROUP", "DEPRECATED"}
	keyGroupColumns = []string{"ID", "NAME", "MEMBERS", "INERT"}
)

func keyRow(k apigen.Key) []string {
	return []string{
		k.Id, k.Name, string(k.Classification), declarationType(k.Declaration),
		k.FolderPath, k.GroupId, strconv.FormatBool(k.Deprecated),
	}
}

// declarationType renders the declared type for the table: the primitive, or
// the alternatives joined, so an operator sees the shape without reading JSON.
func declarationType(d apigen.KeyDeclaration) string {
	if d.Rule != nil {
		return schema.TypeExpression([]schema.Type{schema.Type(d.Rule.Type)})
	}
	if d.AnyOf == nil {
		return ""
	}
	types := make([]schema.Type, 0, len(*d.AnyOf))
	for _, alt := range *d.AnyOf {
		types = append(types, schema.Type(alt.Type))
	}
	return schema.TypeExpression(types)
}

func keyGroupRow(g apigen.KeyGroup) []string {
	return []string{g.Id, g.Name, strings.Join(g.Members, ","), strconv.FormatBool(g.Inert)}
}

// renderKey prints one key. The JSON document is the whole key — declaration
// and presence included — because a rule an operator cannot read back is a
// rule they cannot review.
func renderKey(ios IO, f Format, key apigen.Key) error {
	return Render(ios.Stdout, f, Table{Columns: keyColumns, Rows: [][]string{keyRow(key)}, JSON: key})
}
