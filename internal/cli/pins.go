package cli

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

func runPin(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("pin", args, "create", "list", "release")
	if err != nil {
		return err
	}
	var format, workload, expiry string
	var revision int64
	var overrideSchema bool
	st, flags, err := parseCommon("pin "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" {
			fs.StringVar(&workload, "workload", "", "target workload principal id")
			fs.Int64Var(&revision, "revision", 0, "revision to deliver")
			fs.StringVar(&expiry, "expires-at", "", "RFC3339 expiry; omitted uses 180 days")
			fs.BoolVar(&overrideSchema, "override-schema", false, "pin despite current-schema validation failure")
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
	case "create":
		if err := flags.checkNoPositionals("pin create"); err != nil {
			return err
		}
		if workload == "" || revision < 1 {
			return failf(ExitUsage, "usage: hikyo pin create --workload ID --revision N [--expires-at RFC3339] [--override-schema]")
		}
	case "list":
		if err := flags.checkNoPositionals("pin list"); err != nil {
			return err
		}
	case "release":
		if flags.positional() == "" {
			return failf(ExitUsage, "usage: hikyo pin release <workload-principal>")
		}
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	project, err := projectBase(resolved)
	if err != nil {
		return err
	}
	base, err := environmentBase(project, resolved, flags, "pin "+sub)
	if err != nil {
		return err
	}

	switch sub {
	case "create":
		body := apigen.RevisionPinRequest{
			WorkloadPrincipalId: workload, Revision: revision, OverrideSchema: &overrideSchema,
		}
		if expiry != "" {
			parsed, err := time.Parse(time.RFC3339, expiry)
			if err != nil {
				return failf(ExitUsage, "--expires-at must be RFC3339: %v", err)
			}
			body.ExpiresAt = &parsed
		}
		var out apigen.RevisionPinResult
		if err := client.Do(ctx, http.MethodPost, base+"/pins", body, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"ACTION", "WORKLOAD", "REVISION", "EXPIRES", "EXPIRED"},
			Rows: [][]string{{string(out.Action), out.Pin.WorkloadPrincipalId,
				strconv.FormatInt(out.Pin.Revision, 10), out.Pin.ExpiresAt.UTC().Format(time.RFC3339),
				strconv.FormatBool(out.Pin.Expired)}}, JSON: out,
		})
	case "list":
		var out apigen.RevisionPinList
		if err := client.Do(ctx, http.MethodGet, base+"/pins", nil, &out); err != nil {
			return err
		}
		rows := make([][]string, 0, len(out.Items))
		for _, pin := range out.Items {
			rows = append(rows, []string{pin.WorkloadPrincipalId,
				strconv.FormatInt(pin.Revision, 10), pin.ExpiresAt.UTC().Format(time.RFC3339),
				strconv.FormatBool(pin.Expired)})
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"WORKLOAD", "REVISION", "EXPIRES", "EXPIRED"}, Rows: rows, JSON: out,
		})
	case "release":
		if err := client.Do(ctx, http.MethodDelete,
			base+"/pins/"+url.PathEscape(flags.positional()), nil, nil); err != nil {
			return err
		}
		return nil
	}
	return failf(ExitInternal, "hikyo pin: unhandled subverb %q", sub)
}
