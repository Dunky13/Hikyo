package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
)

type doctorFinding struct {
	Provider    string  `json:"provider"`
	Code        string  `json:"code"`
	Severity    string  `json:"severity"`
	Message     string  `json:"message"`
	EffectiveAt string  `json:"effective_at"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

type doctorResult struct {
	Status   string          `json:"status"`
	Findings []doctorFinding `json:"findings"`
}

func runDoctor(ctx context.Context, ios IO, args []string) error {
	var format string
	st, flags, err := parseCommon("doctor", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("doctor"); err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	var health apigen.RetentionHealth
	if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/instance/retention-health", nil, &health); err != nil {
		return err
	}
	var providers apigen.SamlProviderList
	if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/instance/saml-providers", nil, &providers); err != nil {
		return err
	}
	result, rows := doctorResults(providers, health, time.Now().UTC())
	if err := Render(ios.Stdout, f, Table{
		Columns: []string{"STATUS", "PROVIDER", "CHECK", "EFFECTIVE AT", "MESSAGE"}, Rows: rows, JSON: result,
	}); err != nil {
		return err
	}
	if result.Status == "error" {
		return failf(ExitRefused, "doctor found provider errors")
	}
	return nil
}

func doctorResults(providers apigen.SamlProviderList, health apigen.RetentionHealth, now time.Time) (doctorResult, [][]string) {
	result := doctorResult{Status: "ok", Findings: []doctorFinding{}}
	rows := make([][]string, 0, 2)
	prune := doctorPruneFinding(health, now)
	result.Findings = append(result.Findings, prune)
	rows = append(rows, []string{prune.Severity, prune.Provider, prune.Code, prune.EffectiveAt, prune.Message})
	if prune.Severity == "warn" {
		result.Status = "warning"
	}
	providerRowStart := len(rows)
	for _, provider := range providers.Providers {
		for _, warning := range provider.Warnings {
			finding := doctorFinding{
				Provider: provider.Slug, Code: string(warning.Code), Severity: string(warning.Severity),
				Message: warning.Message, EffectiveAt: warning.EffectiveAt.UTC().Format(time.RFC3339), Fingerprint: warning.Fingerprint,
			}
			result.Findings = append(result.Findings, finding)
			rows = append(rows, []string{finding.Severity, finding.Provider, finding.Code, finding.EffectiveAt, finding.Message})
			if warning.Severity == apigen.SamlProviderWarningSeverityError {
				result.Status = "error"
			} else if result.Status == "ok" {
				result.Status = "warning"
			}
		}
	}
	if len(rows) == providerRowStart {
		rows = append(rows, []string{"ok", "-", "saml-providers", "-", "no provider warnings"})
	}
	return result, rows
}

func doctorPruneFinding(health apigen.RetentionHealth, now time.Time) doctorFinding {
	finding := doctorFinding{Provider: "-", Code: "retention-prune", Severity: "ok", EffectiveAt: "-"}
	if health.LastPruneSuccess == nil {
		finding.Severity = "warn"
		finding.Message = "never recorded"
		return finding
	}
	at := health.LastPruneSuccess.UTC()
	finding.EffectiveAt = at.Format(time.RFC3339)
	age := now.Sub(at)
	if age < 0 {
		age = 0
	}
	age = age.Truncate(time.Second)
	if health.Stale {
		finding.Severity = "warn"
		finding.Message = fmt.Sprintf("last_prune_success is %s old (> 24h)", age)
		return finding
	}
	finding.Message = fmt.Sprintf("last_prune_success is %s old", age)
	return finding
}
