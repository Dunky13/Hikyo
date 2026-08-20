package cli

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// runReencrypt is the operator's `reencrypt`: walk a scope's ciphertext onto the
// active DEK version and retire the old, completing a rotate-dek. Chunked and
// resumable — safe to re-run.
func runReencrypt(ctx context.Context, ios IO, args []string) error {
	var format string
	var instance bool
	st, flags, err := parseCommon("reencrypt", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&instance, "instance", false, "reencrypt the instance credential tables instead of a project")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("reencrypt"); err != nil {
		return err
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	path := api.PathPrefix + "/instance/reencrypt"
	if !instance {
		org, err := resolved.Require(DimOrg)
		if err != nil {
			return err
		}
		project, err := resolved.Require(DimProject)
		if err != nil {
			return err
		}
		path = api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project) + "/reencrypt"
	}

	var out apigen.ReencryptResult
	if err := client.Do(ctx, http.MethodPost, path, nil, &out); err != nil {
		return err
	}
	target := string(out.Scope)
	if out.Org != nil && out.Project != nil {
		target = *out.Org + "/" + *out.Project
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"SCOPE", "TARGET", "ROWS MOVED"},
		Rows:    [][]string{{string(out.Scope), target, strconv.FormatInt(out.RowsMoved, 10)}},
		JSON:    out,
	})
}
