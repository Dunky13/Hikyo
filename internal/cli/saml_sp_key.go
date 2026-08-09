package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
)

func runSAMLSPKey(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("instance-config saml-sp-key", args,
		"list", "rotate", "retire", "compromise-retire")
	if err != nil {
		return err
	}
	var format string
	st, flags, err := parseCommon("instance-config saml-sp-key "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	var fingerprint string
	if sub == "list" || sub == "rotate" {
		if err := flags.checkNoPositionals("instance-config saml-sp-key " + sub); err != nil {
			return err
		}
	} else {
		fingerprint, err = spKeyFingerprint(flags, sub)
		if err != nil {
			return err
		}
	}
	client, _, err := authenticatedClient(st, ios, flags)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		var result apigen.SamlSpKeyList
		if err := client.Do(ctx, http.MethodGet, samlSPKeysPath(), nil, &result); err != nil {
			return err
		}
		return renderSAMLSPKeys(ios, f, result)
	case "rotate":
		var result apigen.SamlSpKey
		if err := client.Do(ctx, http.MethodPost, samlSPKeysPath()+"/rotate", nil, &result); err != nil {
			return err
		}
		return renderSAMLSPKey(ios, f, result)
	case "retire":
		if err := client.Do(ctx, http.MethodDelete, samlSPKeyPath(fingerprint), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(ios.Stderr, "retired and erased SAML SP key %s\n", fingerprint)
		return nil
	case "compromise-retire":
		var result apigen.SamlSpKey
		if err := client.Do(ctx, http.MethodPost, samlSPKeyPath(fingerprint)+"/compromise-retire", nil, &result); err != nil {
			return err
		}
		return renderSAMLSPKey(ios, f, result)
	default:
		return failf(ExitInternal, "wenv instance-config saml-sp-key: unhandled verb %q", sub)
	}
}

func spKeyFingerprint(flags commonFlags, sub string) (string, error) {
	if len(flags.positionals) != 1 {
		return "", failf(ExitUsage, "usage: wenv instance-config saml-sp-key %s <fingerprint>", sub)
	}
	return flags.positionals[0], nil
}

func renderSAMLSPKeys(ios IO, format Format, keys apigen.SamlSpKeyList) error {
	rows := make([][]string, 0, len(keys.Keys))
	for _, key := range keys.Keys {
		rows = append(rows, []string{string(key.State), key.Fingerprint, key.CreatedAt.Format("2006-01-02T15:04:05Z")})
	}
	return Render(ios.Stdout, format, Table{
		Columns: []string{"STATE", "FINGERPRINT", "CREATED AT"}, Rows: rows, JSON: keys,
	})
}

func renderSAMLSPKey(ios IO, format Format, key apigen.SamlSpKey) error {
	return Render(ios.Stdout, format, Table{
		Columns: []string{"STATE", "FINGERPRINT", "CREATED AT"},
		Rows:    [][]string{{string(key.State), key.Fingerprint, key.CreatedAt.Format("2006-01-02T15:04:05Z")}},
		JSON:    key,
	})
}

func samlSPKeysPath() string { return api.PathPrefix + "/instance/saml-sp-keys" }

func samlSPKeyPath(fingerprint string) string {
	return samlSPKeysPath() + "/" + url.PathEscape(fingerprint)
}
