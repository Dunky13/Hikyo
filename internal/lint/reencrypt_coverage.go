package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CheckReencryptCoverage is the reencrypt-coverage gate (encryption-model ADR
// § Rotation, invariant 7 / #187). A DEK version is retired only once zero
// ciphertexts reference it, and reencrypt proves that by walking every table
// that holds tier-3-DEK-enveloped ciphertext. If a NEW enveloped column is added
// to the schema but not to the walk, its rows are never moved and never scanned
// by the retire's dryness gate (which scans only the walk's tables) — so the
// retire would destroy a still-referenced key. This gate makes that impossible
// to add silently: every BLOB/BYTEA column in the schema must be classified as
// either reencrypt-covered or explicitly exempt, and an unclassified new column
// fails the build until someone decides which it is.
//
// The covered set must equal reencrypt's walk (service.Reencrypt). The exempt
// set is every other BLOB column, each a reviewed non-target: a wrapped KEY
// (master/tier3 — a different tier, rotated by rotate-master-key/rotate-dek, not
// reencrypt), a hashed/single-use VERIFIER (never envelope-decryptable), a
// short-lived FLOW artifact (OAuth/SAML/WebAuthn transaction state), or PUBLIC
// material (certificates, public keys, opaque handles).
func CheckReencryptCoverage(sqliteMigrationsDir string) []string {
	found, err := scanBlobColumns(sqliteMigrationsDir)
	if err != nil {
		return []string{"reencrypt-coverage: " + err.Error()}
	}
	var findings []string
	for _, tc := range found {
		_, covered := reencryptCovered[tc]
		_, exempt := reencryptExemptBlobs[tc]
		switch {
		case covered && exempt:
			findings = append(findings, fmt.Sprintf("reencrypt-coverage: %s is in BOTH the covered and exempt sets — pick one", tc))
		case !covered && !exempt:
			findings = append(findings, fmt.Sprintf(
				"reencrypt-coverage: %s is an unclassified BLOB column. If it holds tier-3-DEK-enveloped "+
					"ciphertext, add it to the reencrypt walk AND reencryptCovered; otherwise add it to "+
					"reencryptExemptBlobs with a reason.", tc))
		}
	}
	// Every covered pin must still exist in the schema — a renamed/dropped column
	// left in the pin is a stale claim the walk can no longer honor.
	present := map[string]bool{}
	for _, tc := range found {
		present[tc] = true
	}
	for tc := range reencryptCovered {
		if !present[tc] {
			findings = append(findings, fmt.Sprintf("reencrypt-coverage: covered column %s no longer exists in the schema", tc))
		}
	}
	sort.Strings(findings)
	return findings
}

// reencryptCovered is the exact set of tier-3-DEK-enveloped ciphertext columns
// the reencrypt walk moves (service.Reencrypt ReencryptProject + ReencryptInstance).
// Keep this in lockstep with that walk: a column here that the walk does not
// cover, or vice versa, is the exact gap this gate exists to prevent.
var reencryptCovered = map[string]string{
	// project scope (5)
	"value_entries.ciphertext":                          "value",
	"snapshot_entries.ciphertext":                       "snapshot",
	"pending_changes.ciphertext":                        "pending",
	"adapters.credential_ciphertext":                    "adapter",
	"adapter_route_moves.pending_credential_ciphertext": "adapter_route_move",
	// instance scope (6)
	"password_credentials.verifier":      "password",
	"totp_credentials.seed":              "totp",
	"recovery_codes.batch":               "recovery",
	"oidc_providers.client_secret":       "oidc",
	"saml_sp_keys.encrypted_private_key": "saml",
	"remotes.credential_sealed":          "remotes",
}

// reencryptExemptBlobs is every other BLOB column, each a reviewed non-target.
var reencryptExemptBlobs = map[string]string{
	// Wrapped KEYS — a different tier, rotated by rotate-master-key / rotate-dek,
	// never by reencrypt (which moves ciphertext, not keys).
	"master_keys.blob": "master key wrapped by the root; rotate-root/master-key territory",
	"tier3_keys.blob":  "tier-3 DEK wrapped by the master; rotate-dek/master-key territory",
	// Hashed or single-use VERIFIERS — one-way, never envelope-decryptable.
	"sessions.verifier":                   "session artifact verifier (hashed, not enveloped)",
	"sessions.csrf_verifier":              "session CSRF verifier (hashed)",
	"sessions_rebuilt.verifier":           "session verifier on a table-rebuild copy",
	"sessions_rebuilt.csrf_verifier":      "CSRF verifier on a table-rebuild copy",
	"scim_credentials.verifier":           "SCIM bearer verifier (hashed)",
	"machine_credentials.verifier":        "service-account credential verifier (hashed)",
	"machine_credentials_new.verifier":    "machine credential verifier on a table-rebuild copy",
	"instance_connections.verifier":       "remote workspace-session verifier (hashed)",
	"credential_authorities.verifier":     "single-use credential-establishment authority (hashed)",
	"credential_authorities_new.verifier": "credential authority verifier on a table-rebuild copy",
	// Short-lived FLOW artifacts — OAuth / SAML / WebAuthn transaction state,
	// hashed or opaque, expired not rotated.
	"oidc_transactions.browser_binding_verifier": "OIDC browser-binding verifier (flow)",
	"oidc_transactions.state_verifier":           "OIDC state verifier (flow)",
	"oidc_transactions.nonce":                    "OIDC nonce (flow)",
	"saml_transactions.initiator_verifier":       "SAML initiator verifier (flow)",
	"saml_transactions.relay_state_verifier":     "SAML relay-state verifier (flow)",
	"cli_reauth_handoffs.code_verifier":          "CLI reauth PKCE code verifier (flow)",
	"cli_reauth_handoffs.state_verifier":         "CLI reauth state verifier (flow)",
	"workspace_handoffs.code_verifier":           "workspace handoff code verifier (flow)",
	"workspace_handoffs.state_verifier":          "workspace handoff state verifier (flow)",
	"webauthn_ceremonies.challenge_verifier":     "WebAuthn ceremony challenge verifier (flow)",
	"webauthn_ceremonies.session_data":           "WebAuthn ceremony session data (flow)",
	// PUBLIC material — certificates, public keys, opaque handles.
	"saml_providers.signing_certificates":   "IdP signing certificates (public)",
	"saml_sp_keys.certificate_der":          "SP certificate (public)",
	"webauthn_credentials.aaguid":           "authenticator AAGUID (opaque, public)",
	"webauthn_credentials.credential_id":    "WebAuthn credential id (public handle)",
	"webauthn_credentials.public_key":       "WebAuthn public key (public)",
	"accounts.webauthn_user_handle":         "WebAuthn user handle (opaque, non-secret)",
	"scanning_dismissals.value_fingerprint": "keyed scanning fingerprint digest (#74), not an envelope; rotated by rotate-scanning-key",
}

var (
	createTableRe = regexp.MustCompile(`(?i)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?`)
	alterAddRe    = regexp.MustCompile(`(?i)^\s*ALTER\s+TABLE\s+"?([a-z_][a-z0-9_]*)"?\s+ADD\s+COLUMN\s+"?([a-z_][a-z0-9_]*)"?\s+(?:BLOB|BYTEA)\b`)
	blobColRe     = regexp.MustCompile(`(?i)^\s*"?([a-z_][a-z0-9_]*)"?\s+(?:BLOB|BYTEA)\b`)
)

// scanBlobColumns returns the sorted, de-duplicated "table.column" list of every
// BLOB/BYTEA column defined across the migration files.
func scanBlobColumns(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		table := ""
		for _, line := range strings.Split(string(data), "\n") {
			if m := alterAddRe.FindStringSubmatch(line); m != nil {
				seen[m[1]+"."+m[2]] = true
				continue
			}
			if m := createTableRe.FindStringSubmatch(line); m != nil {
				table = m[1]
				continue
			}
			if table == "" {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), ");") {
				table = ""
				continue
			}
			if m := blobColRe.FindStringSubmatch(line); m != nil {
				seen[table+"."+m[1]] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for tc := range seen {
		out = append(out, tc)
	}
	sort.Strings(out)
	return out, nil
}
