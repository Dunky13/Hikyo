package cli

import (
	"context"
	"flag"
	"net/http"
	"time"

	"github.com/Dunky13/hikyo/api"
	"github.com/Dunky13/hikyo/api/apigen"
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
	var providers apigen.SamlProviderList
	if err := client.Do(ctx, http.MethodGet, api.PathPrefix+"/instance/saml-providers", nil, &providers); err != nil {
		return err
	}
	result, rows := doctorResults(providers)
	if len(rows) == 0 {
		rows = append(rows, []string{"ok", "-", "saml-providers", "-", "no provider warnings"})
	}
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

func doctorResults(providers apigen.SamlProviderList) (doctorResult, [][]string) {
	result := doctorResult{Status: "ok", Findings: []doctorFinding{}}
	rows := make([][]string, 0)
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
	return result, rows
}
