package cli

import "strings"

// AuthKind is the closed set of authentication artifacts a CLI command may
// carry. Unauthenticated is included only in policy: it is never an
// AuthArtifact value.
type AuthKind string

const (
	AuthKindUnauthenticated   AuthKind = "unauthenticated"
	AuthKindHumanSession      AuthKind = "human-session"
	AuthKindMachineCredential AuthKind = "machine-credential"
)

type AuthKinds uint8

const (
	authAllowsUnauthenticated AuthKinds = 1 << iota
	authAllowsHumanSession
	authAllowsMachineCredential
)

func (kinds AuthKinds) Allows(kind AuthKind) bool {
	switch kind {
	case AuthKindUnauthenticated:
		return kinds&authAllowsUnauthenticated != 0
	case AuthKindHumanSession:
		return kinds&authAllowsHumanSession != 0
	case AuthKindMachineCredential:
		return kinds&authAllowsMachineCredential != 0
	default:
		return false
	}
}

const (
	humanOnly      = authAllowsHumanSession
	machineOnly    = authAllowsMachineCredential
	humanOrMachine = authAllowsHumanSession | authAllowsMachineCredential
)

// AuthOperation is the canonical leaf command name already owned by each
// handler's parseCommon call (for example, "values export").
type AuthOperation string

type authRuleRow struct {
	Kinds      AuthKinds
	Operations []AuthOperation
}

// authRuleRows is the closed verb x artifact table. Every leaf command is
// listed, including local/pre-auth commands, so a new command defaults denied
// until its eligibility is chosen here.
var authRuleRows = []authRuleRow{
	{Kinds: authAllowsUnauthenticated, Operations: authOperations(
		"login",
		"context create", "context list", "context show", "context delete",
		"account establish-credential", "account recovery begin",
		"account passkey enrol", "account passkey list", "account passkey remove",
		"definitions scaffold",
	)},
	{Kinds: humanOnly, Operations: authOperations(
		"logout", "whoami",
		"account reset-credential", "account factor enrol-totp", "account factor confirm-totp",
		"account factor step-up", "account recovery-codes regenerate",
		"org list", "org show", "org create", "org rename", "org delete",
		"org retention get", "org retention set",
		"project list", "project show", "project create", "project rename", "project delete",
		"project retention get", "project retention set",
		"env list", "env show", "env create", "env rename", "env reorder", "env delete",
		"folder list", "folder show", "folder create", "folder rename", "folder delete",
		"key list", "key show", "key group list", "key group show",
		"values list", "values get", "values set", "values declare", "values diff",
		"values copy", "values import", "values publish", "values pending",
		"revision list", "revision show", "revision rollback",
		"pin create", "pin list", "pin release",
		"rotate-token-key", "rotate-scanning-key", "rotate-dek", "rotate-master-key",
		"rotate-root-key", "reencrypt", "doctor",
		"access grant list", "access grant add", "access grant remove", "access grant template",
		"access member list", "access member remove",
		"project-settings get", "project-settings set",
		"project-settings machine-reveal get", "project-settings machine-reveal set",
		"sa list", "sa create", "sa delete", "sa credential list", "sa credential mint",
		"sa credential rotate", "sa credential revoke", "sa binding create",
		"instance-config credential-policy get", "instance-config credential-policy set",
		"instance-config federation-issuer list", "instance-config federation-issuer add",
		"instance-config federation-issuer update", "instance-config federation-issuer remove",
		"instance-config saml-sp-key list", "instance-config saml-sp-key rotate",
		"instance-config saml-sp-key retire", "instance-config saml-sp-key compromise-retire",
		"instance-config provider create", "instance-config provider list", "instance-config provider show",
		"instance-config provider update", "instance-config provider disable", "instance-config provider remove",
		"instance-config provider refresh-metadata",
		"scim binding create", "scim binding list", "scim binding show", "scim binding delete",
		"scim mapping add", "scim mapping update", "scim mapping remove", "scim mapping list",
		"scim credential mint", "scim credential list", "scim credential show", "scim credential revoke",
		"scim user list", "scim group list",
		"remote add", "remote list", "remote show", "remote remove",
		"remote-credential create", "remote-credential list", "remote-credential show", "remote-credential revoke",
		"import",
		"adapter create", "adapter list", "adapter show", "adapter update", "adapter delete",
		"adapter credential set", "adapter credential revoke",
		"adapter target add", "adapter target list", "adapter target show", "adapter target remove",
		"adapter adopt", "adapter plan", "adapter sync", "adapter test",
		"definitions export",
	)},
	{Kinds: humanOrMachine, Operations: authOperations(
		"definitions check", "definitions plan", "definitions apply",
		"key create", "key rename", "key declare", "key reclassify", "key update", "key set-group", "key delete",
		"key group create", "key group rename", "key group delete",
		"values export", "run",
	)},
	{Kinds: machineOnly, Operations: authOperations(
		"compose render", "compose sync", "compose doctor",
	)},
}

var operationAuthKinds = buildOperationAuthKinds(authRuleRows)

func authOperations(names ...string) []AuthOperation {
	out := make([]AuthOperation, len(names))
	for i, name := range names {
		out[i] = AuthOperation(name)
	}
	return out
}

func buildOperationAuthKinds(rows []authRuleRow) map[AuthOperation]AuthKinds {
	out := make(map[AuthOperation]AuthKinds)
	for _, row := range rows {
		for _, operation := range row.Operations {
			if _, exists := out[operation]; exists {
				panic("duplicate authentication operation " + operation)
			}
			out[operation] = row.Kinds
		}
	}
	return out
}

func authKindsFor(operation AuthOperation) (AuthKinds, error) {
	kinds, ok := operationAuthKinds[operation]
	if !ok {
		return 0, failf(ExitInternal, "hikyo %s has no authentication-kind rule", operation)
	}
	return kinds, nil
}

func topLevelOperation(operation AuthOperation) string {
	return strings.SplitN(string(operation), " ", 2)[0]
}

func selectAuthKind(operation AuthOperation, kinds AuthKinds, choice string, humanPresent, machinePresent bool) (AuthKind, error) {
	switch choice {
	case "human":
		if !kinds.Allows(AuthKindHumanSession) {
			return "", failf(ExitRefused, "hikyo %s does not accept human-session authentication", operation)
		}
		if !humanPresent {
			return "", failf(ExitAuth, "hikyo %s selected --auth=human, but no stored human session is available", operation)
		}
		return AuthKindHumanSession, nil
	case "machine":
		if !kinds.Allows(AuthKindMachineCredential) {
			return "", failf(ExitRefused, "hikyo %s requires a human session; machine credentials are not eligible", operation)
		}
		if !machinePresent {
			return "", failf(ExitAuth, "hikyo %s selected --auth=machine, but no --token-file or HIKYO_TOKEN is available", operation)
		}
		return AuthKindMachineCredential, nil
	}

	humanEligible := humanPresent && kinds.Allows(AuthKindHumanSession)
	machineEligible := machinePresent && kinds.Allows(AuthKindMachineCredential)
	switch {
	case humanEligible && machineEligible:
		return "", failf(ExitRefused,
			"hikyo %s found both a stored human session and a machine credential; pass --auth=human or --auth=machine",
			operation)
	case humanEligible:
		return AuthKindHumanSession, nil
	case machineEligible:
		return AuthKindMachineCredential, nil
	case machinePresent && !kinds.Allows(AuthKindMachineCredential):
		return "", failf(ExitRefused, "hikyo %s requires a human session; machine credentials are not eligible", operation)
	case humanPresent && !kinds.Allows(AuthKindHumanSession):
		return "", failf(ExitRefused, "hikyo %s requires a machine credential; stored human sessions are not eligible", operation)
	case kinds.Allows(AuthKindHumanSession):
		return "", failf(ExitAuth, "no human session is available for hikyo %s: run `hikyo login <url> --local --as <user>`", operation)
	default:
		return "", failf(ExitAuth, "hikyo %s requires --token-file or HIKYO_TOKEN", operation)
	}
}

// AuthArtifact is a sealed human-session | machine-credential sum. Credential
// plaintext deliberately lives only on Client, never in this aggregate.
type AuthArtifact interface {
	authArtifact()
	Kind() AuthKind
	ArtifactOrigin() string
}

type HumanSession struct{ SessionArtifact }

func (HumanSession) authArtifact()            {}
func (HumanSession) Kind() AuthKind           { return AuthKindHumanSession }
func (h HumanSession) ArtifactOrigin() string { return h.Origin }

// CredentialRef identifies the invocation channel without retaining its
// plaintext or a token-file path.
type CredentialRef string

const (
	CredentialRefEnvironment CredentialRef = "HIKYO_TOKEN"
	CredentialRefTokenFile   CredentialRef = "--token-file"
)

func (r CredentialRef) String() string { return string(r) }

type MachineCredential struct {
	Origin        string
	CredentialRef CredentialRef
}

func (MachineCredential) authArtifact()            {}
func (MachineCredential) Kind() AuthKind           { return AuthKindMachineCredential }
func (m MachineCredential) ArtifactOrigin() string { return m.Origin }

func requireHumanSession(action string, artifact AuthArtifact) (SessionArtifact, error) {
	switch value := artifact.(type) {
	case HumanSession:
		return value.SessionArtifact, nil
	case MachineCredential:
		return SessionArtifact{}, failf(ExitRefused,
			"%s requires a stored human CLI session; machine credential %s is not eligible",
			action, value.CredentialRef)
	default:
		return SessionArtifact{}, failf(ExitInternal, "%s received unknown authentication artifact %T", action, artifact)
	}
}

func credentialRef(tokenFile string) CredentialRef {
	if tokenFile != "" {
		return CredentialRefTokenFile
	}
	return CredentialRefEnvironment
}
