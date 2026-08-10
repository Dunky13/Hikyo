package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dunky13/hikyo/internal/cli"
)

func TestInstanceConfigProviderGrammar(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "metadata.xml")
	if err := os.WriteFile(metadata, []byte(`<EntityDescriptor/>`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"instance-config needs provider", []string{"instance-config"}, cli.ExitUsage},
		{"provider needs a verb", []string{"instance-config", "provider"}, cli.ExitUsage},
		{"unknown provider verb", []string{"instance-config", "provider", "warp"}, cli.ExitUsage},
		{"create requires kind", []string{"instance-config", "provider", "create", "--name", "corp", "--entity-id", "https://idp.example", "--metadata-file", metadata}, cli.ExitUsage},
		{"create requires name", []string{"instance-config", "provider", "create", "--kind", "saml", "--entity-id", "https://idp.example", "--metadata-file", metadata}, cli.ExitUsage},
		{"create requires entity id", []string{"instance-config", "provider", "create", "--kind", "saml", "--name", "corp", "--metadata-file", metadata}, cli.ExitUsage},
		{"create requires one metadata source", []string{"instance-config", "provider", "create", "--kind", "saml", "--name", "corp", "--entity-id", "https://idp.example"}, cli.ExitUsage},
		{"create refuses two metadata sources", []string{"instance-config", "provider", "create", "--kind", "saml", "--name", "corp", "--entity-id", "https://idp.example", "--metadata-file", metadata, "--metadata-url", "https://idp.example/metadata"}, cli.ExitUsage},
		{"update requires a change", []string{"instance-config", "provider", "update", "corp"}, cli.ExitUsage},
		{"update validates kind", []string{"instance-config", "provider", "update", "corp", "--kind", "ldap", "--enabled=false"}, cli.ExitUsage},
		{"disable requires a name", []string{"instance-config", "provider", "disable"}, cli.ExitUsage},
		{"disable validates kind", []string{"instance-config", "provider", "disable", "corp", "--kind", "ldap"}, cli.ExitUsage},
		{"remove requires a name", []string{"instance-config", "provider", "remove"}, cli.ExitUsage},
		{"refresh requires a name", []string{"instance-config", "provider", "refresh-metadata"}, cli.ExitUsage},
		{"sp key needs a verb", []string{"instance-config", "saml-sp-key"}, cli.ExitUsage},
		{"sp key rejects unknown verb", []string{"instance-config", "saml-sp-key", "warp"}, cli.ExitUsage},
		{"retire requires fingerprint", []string{"instance-config", "saml-sp-key", "retire"}, cli.ExitUsage},
		{"compromise retire requires fingerprint", []string{"instance-config", "saml-sp-key", "compromise-retire"}, cli.ExitUsage},
		{"valid create reaches auth", []string{"instance-config", "provider", "create", "--kind", "saml", "--name", "corp", "--entity-id", "https://idp.example", "--metadata-file", metadata, "--instance", "unknown-ref"}, cli.ExitRefused},
		{"valid list reaches auth", []string{"instance-config", "provider", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
		{"valid sp key list reaches auth", []string{"instance-config", "saml-sp-key", "list", "--instance", "unknown-ref"}, cli.ExitRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ios, _, _ := testIO(t, nil)
			if got := cli.Run(t.Context(), ios, tc.args); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHelpListsLockedSAMLProviderSpellings(t *testing.T) {
	var help strings.Builder
	cli.Usage(&help)
	for _, want := range []string{
		"instance-config provider create --kind saml --name <name>",
		"instance-config provider list|show|update|disable|remove",
		"instance-config provider refresh-metadata <name>",
		"instance-config saml-sp-key list|rotate",
		"instance-config saml-sp-key retire|compromise-retire <fingerprint>",
	} {
		if !strings.Contains(help.String(), want) {
			t.Errorf("help missing %q", want)
		}
	}
}
