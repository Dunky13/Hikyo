package cli

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

var retentionColumns = []string{"MODE", "MAX AGE", "LAST REVISIONS", "INHERITED"}

func runOrgRetention(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("org retention", args, "get", "set")
	if err != nil {
		return err
	}
	var format, maxAge string
	var lastRevisions int
	var unlimited bool
	st, flags, err := parseCommon("org retention "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "set" {
			fs.StringVar(&maxAge, "max-age", "", "maximum payload age as a Go duration")
			fs.IntVar(&lastRevisions, "last-revisions", 0, "number of newest revisions whose payloads remain")
			fs.BoolVar(&unlimited, "unlimited", false, "disable the organisation retention bound")
		}
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("org retention " + sub); err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	var body apigen.RetentionPolicy
	if sub == "set" {
		body, err = orgRetentionRequest(maxAge, lastRevisions, unlimited)
		if err != nil {
			return err
		}
	}
	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	path := api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/retention"
	var out apigen.RetentionPolicy
	if sub == "get" {
		if err := client.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, orgRetentionTable(out))
	}
	if err := client.Do(ctx, http.MethodPut, path, body, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, orgRetentionTable(out))
}

func runProjectRetention(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("project retention", args, "get", "set")
	if err != nil {
		return err
	}
	var format, maxAge string
	var lastRevisions int
	var inherit bool
	st, flags, err := parseCommon("project retention "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "set" {
			fs.StringVar(&maxAge, "max-age", "", "maximum payload age as a Go duration")
			fs.IntVar(&lastRevisions, "last-revisions", 0, "number of newest revisions whose payloads remain")
			fs.BoolVar(&inherit, "inherit", false, "clear the override and follow the organisation policy")
		}
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("project retention " + sub); err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	var body apigen.SetProjectRetentionRequest
	if sub == "set" {
		body, err = projectRetentionRequest(maxAge, lastRevisions, inherit)
		if err != nil {
			return err
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
	path := base + "/retention"
	var out apigen.ProjectRetentionPolicy
	if sub == "get" {
		if err := client.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, projectRetentionTable(out))
	}
	if err := client.Do(ctx, http.MethodPut, path, body, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, projectRetentionTable(out))
}

func boundedRetention(maxAge string, lastRevisions int) (int, error) {
	if maxAge == "" || lastRevisions <= 0 {
		return 0, failf(ExitUsage, "--max-age and a positive --last-revisions are required together")
	}
	d, err := time.ParseDuration(maxAge)
	if err != nil || d <= 0 || d%time.Second != 0 {
		return 0, failf(ExitUsage, "--max-age takes a positive whole-second duration, got %q", maxAge)
	}
	seconds := int(d / time.Second)
	if time.Duration(seconds)*time.Second != d {
		return 0, failf(ExitUsage, "--max-age is too large")
	}
	return seconds, nil
}

func orgRetentionRequest(maxAge string, lastRevisions int, unlimited bool) (apigen.RetentionPolicy, error) {
	if unlimited {
		if maxAge != "" || lastRevisions != 0 {
			return apigen.RetentionPolicy{}, failf(ExitUsage, "--unlimited cannot be combined with --max-age or --last-revisions")
		}
		return apigen.RetentionPolicy{Mode: apigen.RetentionPolicyModeUnlimited}, nil
	}
	seconds, err := boundedRetention(maxAge, lastRevisions)
	if err != nil {
		return apigen.RetentionPolicy{}, err
	}
	return apigen.RetentionPolicy{Mode: apigen.RetentionPolicyModeKeepIfEither, MaxAgeSeconds: &seconds, LastRevisions: &lastRevisions}, nil
}

func projectRetentionRequest(maxAge string, lastRevisions int, inherit bool) (apigen.SetProjectRetentionRequest, error) {
	if inherit {
		if maxAge != "" || lastRevisions != 0 {
			return apigen.SetProjectRetentionRequest{}, failf(ExitUsage, "--inherit cannot be combined with --max-age or --last-revisions")
		}
		return apigen.SetProjectRetentionRequest{Inherited: true}, nil
	}
	seconds, err := boundedRetention(maxAge, lastRevisions)
	if err != nil {
		return apigen.SetProjectRetentionRequest{}, err
	}
	return apigen.SetProjectRetentionRequest{Inherited: false, MaxAgeSeconds: &seconds, LastRevisions: &lastRevisions}, nil
}

func orgRetentionTable(policy apigen.RetentionPolicy) Table {
	return Table{Columns: retentionColumns, Rows: [][]string{{
		string(policy.Mode), optionalDuration(policy.MaxAgeSeconds), optionalInt(policy.LastRevisions), "-",
	}}, JSON: policy}
}

func projectRetentionTable(policy apigen.ProjectRetentionPolicy) Table {
	return Table{Columns: retentionColumns, Rows: [][]string{{
		string(policy.Mode), optionalDuration(policy.MaxAgeSeconds), optionalInt(policy.LastRevisions), strconv.FormatBool(policy.Inherited),
	}}, JSON: policy}
}

func optionalDuration(seconds *int) string {
	if seconds == nil {
		return "-"
	}
	return (time.Duration(*seconds) * time.Second).String()
}

func optionalInt(value *int) string {
	if value == nil {
		return "-"
	}
	return strconv.Itoa(*value)
}
