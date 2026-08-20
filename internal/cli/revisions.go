package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// The revision surface (#51): `revision list | show`, and the operator's
// `rotate-token-key`.
//
// Both browse verbs are MASKED BY DEFAULT and carry no reveal path at all,
// which is the ADR's rule read literally: history is lineage — numbers,
// publishers, timestamps and which keys moved — and it never carries a value
// in any form. The one verb that discloses a snapshot's values is
// `values export`, and it lives with the other value verbs behind the print
// triad.
//
// `revision rollback` is #52's, with the restore semantics and the
// enumerated-key ceremony it needs.

func runRevision(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("revision", args, "list", "show", "rollback")
	if err != nil {
		return err
	}
	var format, key string
	st, flags, err := parseCommon("revision "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "rollback" {
			fs.StringVar(&key, "key", "", "restore only this key")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	// Syntax before session lookup, so a malformed invocation answers the same
	// exit code whether or not the caller is logged in.
	if sub == "list" {
		if err := flags.checkNoPositionals("revision list"); err != nil {
			return err
		}
	}
	var rollbackRevision int64
	if sub == "rollback" {
		positionals := flags.positionals
		if len(positionals) != 1 {
			return failf(ExitUsage, "usage: hikyo revision rollback <N> [--key KEY]")
		}
		rollbackRevision, err = strconv.ParseInt(positionals[0], 10, 64)
		if err != nil || rollbackRevision < 1 {
			return failf(ExitUsage, "revision rollback requires a positive numeric revision")
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
	base, err := environmentBase(project, resolved, flags, "revision "+sub)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		var out apigen.RevisionList
		if err := client.Do(ctx, http.MethodGet, base+"/revisions", nil, &out); err != nil {
			return err
		}
		rows := make([][]string, 0, len(out.Items))
		for _, rev := range out.Items {
			rows = append(rows, []string{
				strconv.FormatInt(rev.Revision, 10),
				strconv.FormatInt(rev.SchemaRevision, 10),
				rev.PublishedBy,
				rev.PublishedAt.UTC().Format("2006-01-02T15:04:05Z"),
				strconv.Itoa(len(rev.ChangedKeys)),
			})
		}
		return Render(ios.Stdout, f, Table{
			Columns: []string{"REVISION", "SCHEMA", "PUBLISHED BY", "PUBLISHED AT", "CHANGED"},
			Rows:    rows, JSON: out,
		})

	case "show":
		// The positional is a revision number or the literal `latest`; the
		// server owns the grammar, so an unparseable one is refused there
		// rather than reinterpreted here.
		which := flags.positional()
		if which == "" {
			which = "latest"
		}
		var out apigen.RevisionDetail
		if err := client.Do(ctx, http.MethodGet,
			base+"/revisions/"+url.PathEscape(which), nil, &out); err != nil {
			return err
		}
		rows := make([][]string, 0, len(out.ChangedKeys))
		for _, changed := range out.ChangedKeys {
			rows = append(rows, []string{changed.Name, string(changed.Change)})
		}
		// The change token prints because it is NON-SECRET by construction: it
		// is an HMAC under a per-scope key, so it is unforgeable and
		// un-invertible, which is why it is designed to travel in pod
		// annotations. Printing it here is what makes the operator's own
		// change-detection value as readable as the annotation it lands in.
		fmt.Fprintf(ios.Stderr, "revision %d (schema %d) token %s\n",
			out.Revision, out.SchemaRevision, out.ChangeToken)
		return Render(ios.Stdout, f, Table{
			Columns: []string{"KEY", "CHANGE"}, Rows: rows, JSON: out,
		})

	case "rollback":
		body := apigen.RollbackRequest{}
		if key != "" {
			name := apigen.KeyName(key)
			body.Key = &name
		}
		var out apigen.RollbackResult
		if err := client.Do(ctx, http.MethodPost,
			base+"/revisions/"+strconv.FormatInt(rollbackRevision, 10)+"/rollback", body, &out); err != nil {
			return err
		}
		versions := make([]string, 0, len(out.Changes))
		for _, change := range out.Changes {
			versions = append(versions, change.VersionId)
		}
		if out.Preview.Token != "" {
			fmt.Fprintf(ios.Stderr, "impact preview; publish with: hikyo values publish --versions %s --preview-token %s\n",
				strings.Join(versions, ","), out.Preview.Token)
		}
		return Render(ios.Stdout, f, rollbackTable(out))
	}
	// Unreachable: subverb() above admits only the cases enumerated here.
	return failf(ExitInternal, "hikyo revision: unhandled subverb %q", sub)
}

func rollbackTable(out apigen.RollbackResult) Table {
	rows := make([][]string, 0, len(out.Changes))
	for _, environment := range out.Preview.Environments {
		for _, change := range environment.Changes {
			rows = append(rows, []string{
				environment.EnvironmentId,
				strconv.FormatBool(environment.Protected),
				change.VersionId,
				change.Name,
				string(change.Classification),
				string(change.Operation),
				string(change.Status),
				derefString(change.Before),
				derefString(change.After),
			})
		}
	}
	return Table{
		Columns: []string{"ENVIRONMENT", "PROTECTED", "VERSION", "KEY", "CLASS", "OPERATION", "STATUS", "BEFORE", "AFTER"},
		Rows:    rows, JSON: out,
	}
}

// runRotateTokenKey is the operator's `rotate-token-key`.
//
// It WARNS BEFORE PROCEEDING, and the warning states what actually happens:
// every outstanding delivery cursor mismatches once and every consumer performs
// one full fetch. It is NOT a restart wave — the pre-#19 wording said otherwise
// and was superseded — and nothing about any snapshot moves: not its content,
// not its revision number, not its pinned input revisions.
func runRotateTokenKey(ctx context.Context, ios IO, args []string) error {
	var format string
	var confirm bool
	st, flags, err := parseCommon("rotate-token-key", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&confirm, "yes", false, "proceed without the interactive confirmation")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("rotate-token-key"); err != nil {
		return err
	}
	fmt.Fprintln(ios.Stderr,
		"rotate-token-key derives every change token under a new key.\n"+
			"Every outstanding delivery cursor mismatches once and every consumer\n"+
			"performs one full fetch. No snapshot's content, revision number or\n"+
			"pinned input revisions change. This is not a restart wave.")
	if !confirm {
		return failf(ExitRefused, "rotate-token-key needs --yes to proceed")
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	var out apigen.TokenKeyRotation
	if err := client.Do(ctx, http.MethodPost, "/api/v1/instance/rotate-token-key", nil, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"TOKEN KEY VERSION"},
		Rows:    [][]string{{strconv.FormatInt(out.TokenKeyVersion, 10)}},
		JSON:    out,
	})
}

// runRotateScanningKey is the operator's `rotate-scanning-key` (#74).
//
// It WARNS BEFORE PROCEEDING, and the warning states what actually happens:
// every dismissal is dropped, so every "keep as config" acceptance is forgotten
// and those config values warn again on next save. Nothing else moves — no
// value, no declaration, no revision.
func runRotateScanningKey(ctx context.Context, ios IO, args []string) error {
	var format string
	var confirm bool
	st, flags, err := parseCommon("rotate-scanning-key", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&confirm, "yes", false, "proceed without the interactive confirmation")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("rotate-scanning-key"); err != nil {
		return err
	}
	fmt.Fprintln(ios.Stderr,
		"rotate-scanning-key replaces the secret-scanning fingerprint key and\n"+
			"drops EVERY dismissal. Every 'keep as config' acceptance is forgotten,\n"+
			"so those config values warn again on next save. No value, declaration\n"+
			"or revision changes.")
	if !confirm {
		return failf(ExitRefused, "rotate-scanning-key needs --yes to proceed")
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	var out apigen.ScanningKeyRotation
	if err := client.Do(ctx, http.MethodPost, "/api/v1/instance/rotate-scanning-key", nil, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"SCANNING KEY VERSION", "DISMISSALS DROPPED"},
		Rows:    [][]string{{strconv.FormatInt(out.ScanningKeyVersion, 10), strconv.FormatInt(out.DismissalsDropped, 10)}},
		JSON:    out,
	})
}
