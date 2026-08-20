package authz

import (
	"maps"

	"github.com/Hikyo-Org/hikyo/internal/audit"
)

// The wire registry: the probe classification for every non-operation entry
// point (tenant-isolation ADR, invariant 1). Service operations carry their
// class in the operation registry; everything else that can be reached from
// outside — HTTP routes, CLI verbs, background job types, SSE emit sites —
// is classified here. The classification-totality invariant enumerates the
// actual router, the actual CLI verb table and the (currently empty) job and
// SSE registries against this table: an unclassified entry point fails the
// build, and a stale entry here fails it too.

// ClassStub marks a CLI verb that is not an operation yet: it refuses (exit
// 2), reaches no server and no store, and has no entry in the operation
// registry — the totality check enforces exactly that. It is deliberately
// not one of the ADR's four probe classes: classifying an unimplemented
// verb as tenant-scoped or unauthenticated now would let the eventual
// implementation ride in on a stale class without ever meeting its probe
// contract. When a verb's ticket lands, its class here changes and the
// matching probes must exist.
const ClassStub Class = -1

var wireRegistry = map[string]Class{
	"http:GET /healthz": ClassUnauthenticated,
	"http:GET /metrics": ClassUnauthenticated,
	"http:GET /readyz":  ClassUnauthenticated,

	// The contract surface (#47). Every entry below exists in
	// api/openapi.yaml and carries the same class there under
	// `x-hikyo-class`; api.TestContractClassesMatchTheWireRegistry fails the
	// build if the two ever disagree, so the document cannot describe an
	// authorization posture the router does not have.
	//
	// Identity-protocol endpoints are unauthenticated-class: their probe
	// contract is enumeration uniformity — no pre-authentication path may
	// distinguish an existing account, session or authority from a missing
	// one. `logout` and `whoami` take an artifact but are classified here
	// too, because an unresolvable artifact is exactly the case they must not
	// distinguish.
	"http:GET /api/v1/meta":                       ClassUnauthenticated,
	"http:POST /api/v1/auth/credential/establish": ClassUnauthenticated,
	"http:POST /api/v1/auth/local/login":          ClassUnauthenticated,
	"http:POST /api/v1/auth/logout":               ClassUnauthenticated,
	"http:GET /api/v1/auth/whoami":                ClassUnauthenticated,

	// The navigation surface (#56). Self-scoped like whoami and the identity
	// list: it projects the caller's OWN grant rows onto the organisations
	// they name, reaches no chokepoint operation and can disclose nothing the
	// caller does not already hold. Its probe contract is therefore
	// enumeration uniformity — an unresolvable session must be
	// indistinguishable from one whose grants name no org — not tenancy.
	"http:GET /api/v1/me/orgs": ClassUnauthenticated,

	// Factor endpoints (#54). Unauthenticated-class like logout/whoami: they
	// take a session but an unresolvable one is exactly the case they must not
	// distinguish, so their probe contract is enumeration uniformity, not
	// tenancy. `recovery/begin` is fully pre-auth. None reaches an authz
	// operation — the account-security mutations resolve and rotate the acting
	// session, which is resolution rather than authorization, so their audit
	// obligation is discharged directly through wireEvents like every other
	// authentication-surface endpoint.
	"http:POST /api/v1/auth/totp/enrol/start":          ClassUnauthenticated,
	"http:POST /api/v1/auth/totp/enrol/confirm":        ClassUnauthenticated,
	"http:POST /api/v1/auth/totp/step-up":              ClassUnauthenticated,
	"http:DELETE /api/v1/auth/totp":                    ClassUnauthenticated,
	"http:POST /api/v1/auth/recovery-codes/regenerate": ClassUnauthenticated,
	"http:POST /api/v1/auth/recovery/begin":            ClassUnauthenticated,

	// OIDC (#54). Login/callback are pre-auth; link/reauth take a session but an
	// unresolvable one is exactly the case they must not distinguish, so all are
	// unauthenticated-class (enumeration uniformity). methods is public
	// discovery. Provider administration is instance-config (below).
	"http:GET /api/v1/auth/methods":                  ClassUnauthenticated,
	"http:POST /api/v1/auth/oidc/{provider}/start":   ClassUnauthenticated,
	"http:GET /api/v1/auth/oidc/{provider}/callback": ClassUnauthenticated,
	"http:GET /api/v1/auth/identities":               ClassUnauthenticated,
	"http:POST /api/v1/auth/identities/link":         ClassUnauthenticated,
	"http:DELETE /api/v1/auth/identities/{id}":       ClassUnauthenticated,

	// SAML SP (#72). Start and ACS are purpose-polymorphic identity-protocol
	// endpoints: login is pre-auth, while link/reauth bind an existing session;
	// enumeration uniformity is therefore their probe contract. Metadata is
	// documentation-class public material under pre-auth admission. Provider
	// administration is instance-config.
	"http:POST /api/v1/auth/saml/{provider}/start":                      ClassUnauthenticated,
	"http:POST /api/v1/auth/saml/{provider}/acs":                        ClassUnauthenticated,
	"http:GET /api/v1/auth/saml/{provider}/metadata":                    ClassUnauthenticated,
	"http:GET /api/v1/instance/saml-providers":                          ClassInstance,
	"http:GET /api/v1/instance/retention-health":                        ClassInstance,
	"http:GET /api/v1/instance/saml-providers/{slug}":                   ClassInstance,
	"http:PUT /api/v1/instance/saml-providers/{slug}":                   ClassInstance,
	"http:PATCH /api/v1/instance/saml-providers/{slug}":                 ClassInstance,
	"http:DELETE /api/v1/instance/saml-providers/{slug}":                ClassInstance,
	"http:POST /api/v1/instance/saml-providers/{slug}/refresh-metadata": ClassInstance,
	"http:GET /api/v1/instance/saml-sp-keys":                            ClassInstance,

	// SCIM provisioning (#73). Every route is tenant-class at org depth: a
	// binding a caller may not reach answers byte-identically to one that is
	// not there, which is what keeps the mount from being a cross-org oracle.
	// The wire routes are protocol paths — the same closed exception class the
	// authentication ceremonies belong to — and are parity-exempt, but they are
	// NOT unauthenticated: each one presents a provisioning credential.
	"http:GET /api/v1/orgs/{org}/scim-bindings":                               ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim-bindings":                              ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}":                     ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}":                  ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":           ClassTenant,
	"http:PUT /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":         ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":         ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":        ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}":    ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}": ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/users":     ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/groups":    ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ServiceProviderConfig":     ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ResourceTypes":             ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Schemas":                   ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Users":                     ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Users":                    ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                ClassTenant,
	"http:PUT /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":              ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":             ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                    ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                   ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               ClassTenant,
	"http:PUT /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":             ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":            ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Bulk":                     ClassTenant,
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Me":                        ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Users/.search":            ClassTenant,
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups/.search":           ClassTenant,
	"http:POST /api/v1/instance/saml-sp-keys/rotate":                          ClassInstance,
	"http:DELETE /api/v1/instance/saml-sp-keys/{fingerprint}":                 ClassInstance,
	"http:POST /api/v1/instance/saml-sp-keys/{fingerprint}/compromise-retire": ClassInstance,
	// WebAuthn / passkeys (#54). Enrolment, login, step-up, reauth, removal and
	// the credential inventory. Login is fully pre-auth; the rest take a session
	// but an unresolvable one is exactly the case they must not distinguish, so
	// all are unauthenticated-class (enumeration uniformity). None reaches an
	// authz operation — the mutations resolve and rotate the acting session,
	// which is resolution rather than authorization, so their audit obligation
	// is discharged directly through wireEvents.
	"http:POST /api/v1/auth/webauthn/enrol/start":    ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/enrol/finish":   ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/login/start":    ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/login/finish":   ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/step-up/start":  ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/step-up/finish": ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/reauth/start":   ClassUnauthenticated,
	"http:POST /api/v1/auth/webauthn/reauth/finish":  ClassUnauthenticated,
	// The TOTP half of the disclosure ceremony (#58). Unauthenticated-class
	// for the same reason as every other reauth leg: it authenticates a factor
	// rather than acting on a tenant object, and its refusals are uniform.
	"http:POST /api/v1/auth/reauth/totp":                 ClassUnauthenticated,
	"http:GET /api/v1/auth/webauthn/credentials":         ClassUnauthenticated,
	"http:DELETE /api/v1/auth/webauthn/credentials/{id}": ClassUnauthenticated,
	"http:GET /api/v1/instance/oidc-providers":           ClassInstance,
	"http:GET /api/v1/instance/oidc-providers/{slug}":    ClassInstance,
	"http:PUT /api/v1/instance/oidc-providers/{slug}":    ClassInstance,
	"http:DELETE /api/v1/instance/oidc-providers/{slug}": ClassInstance,

	// Credential reset (#54). Unauthenticated-class for its probe contract:
	// the target-principal path parameter makes enumeration uniformity the
	// dominant concern, so every failure that could reveal the target's grant
	// shape answers a uniform 401 (the instance-capability refusal is the one
	// named 403, reached only after the caller is authorized at instance scope).
	// The route dispatches at runtime between two credential-reset operations, so
	// it names no single operation in wireRoutes; its audit obligation is
	// discharged through wireEvents like the account-security surface.
	"http:POST /api/v1/accounts/{principal}/credential-reset": ClassUnauthenticated,

	// Org creation and enumeration are instance-scoped: the probe contract is
	// grant refusal, not tenancy, because no tenant object exists whose
	// nonexistence could be mimicked — a create has no parent tenant and a
	// list of every org spans all of them.
	"http:GET /api/v1/orgs":  ClassInstance,
	"http:POST /api/v1/orgs": ClassInstance,

	// The hierarchy surface (#48). EVERY by-id route is tenant-class, org
	// included: mvp-boundary C1 requires the uniform nonexistent shape at each
	// level, and an org route that answered 403 on grant refusal would leak the
	// existence of every org an operator cannot reach.
	"http:GET /api/v1/orgs/{org}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects":                     ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects":                    ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}":           ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}":         ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}":        ClassTenant,
	"http:GET /api/v1/orgs/{org}/retention":                    ClassTenant,
	"http:PUT /api/v1/orgs/{org}/retention":                    ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/retention": ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/retention": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/environments":                  ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments":                 ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/order":            ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/environments/{environment}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/folders":             ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/folders":            ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/folders/{folder}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/folders/{folder}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/folders/{folder}": ClassTenant,

	// The access surface (#55): grants, role templates, membership inspection
	// and the two `project-settings` knobs. One entry per addressed depth,
	// because the formula differs per depth — the instance ones are
	// instance-class (grant refusal, no tenant object to mimic), every other
	// one is tenant-class (uniform nonexistent).
	"http:GET /api/v1/instance/grants":             ClassInstance,
	"http:POST /api/v1/instance/grants":            ClassInstance,
	"http:DELETE /api/v1/instance/grants":          ClassInstance,
	"http:POST /api/v1/instance/grants/template":   ClassInstance,
	"http:GET /api/v1/orgs/{org}/grants":           ClassTenant,
	"http:POST /api/v1/orgs/{org}/grants":          ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/grants":        ClassTenant,
	"http:POST /api/v1/orgs/{org}/grants/template": ClassTenant,

	// Machine identities (#61). Tenant-class at project depth: an identity
	// surface a caller may not administer answers exactly like a project
	// that is not there. The instance lifetime controls are instance-class
	// under `instance-config`, like every other instance knob.
	"http:GET /api/v1/orgs/{org}/projects/{project}/service-accounts":                                              ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts":                                             ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}":                          ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                 ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials/{credential}": ClassTenant,
	// Multi-instance (#71). The instance surfaces are instance-class; the
	// handoff family joins the auth-protocol exception class and is
	// unauthenticated-class for its probe contract, exactly as the OIDC and
	// SAML transports are. The self-scoped session surface is
	// unauthenticated-class for the reason /api/v1/me/orgs is: enumeration
	// uniformity, not tenancy.
	"http:GET /api/v1/instance/directory":                   ClassInstance,
	"http:GET /api/v1/instance/remotes":                     ClassInstance,
	"http:POST /api/v1/instance/remotes":                    ClassInstance,
	"http:GET /api/v1/instance/remotes/{remote}":            ClassInstance,
	"http:PATCH /api/v1/instance/remotes/{remote}":          ClassInstance,
	"http:DELETE /api/v1/instance/remotes/{remote}":         ClassInstance,
	"http:GET /api/v1/instance/connections":                 ClassInstance,
	"http:POST /api/v1/instance/connections":                ClassInstance,
	"http:GET /api/v1/instance/connections/{connection}":    ClassInstance,
	"http:DELETE /api/v1/instance/connections/{connection}": ClassInstance,
	"http:GET /api/v1/instance/workspace-origins":           ClassInstance,
	"http:POST /api/v1/instance/workspace-origins":          ClassInstance,
	"http:DELETE /api/v1/instance/workspace-origins":        ClassInstance,
	"http:POST /api/v1/auth/workspace/start":                ClassUnauthenticated,
	"http:POST /api/v1/auth/workspace/approve":              ClassUnauthenticated,
	"http:POST /api/v1/auth/workspace/redeem":               ClassUnauthenticated,
	"http:POST /api/v1/auth/cli-reauth/start":               ClassUnauthenticated,
	"http:GET /api/v1/auth/cli-reauth/transactions/{state}": ClassUnauthenticated,
	"http:POST /api/v1/auth/cli-reauth/approve":             ClassUnauthenticated,
	"http:POST /api/v1/auth/cli-reauth/redeem":              ClassUnauthenticated,
	"http:GET /api/v1/me/sessions":                          ClassUnauthenticated,
	"http:DELETE /api/v1/me/sessions/{session}":             ClassUnauthenticated,
	"http:GET /api/v1/instance/credential-policy":           ClassInstance,
	"http:PUT /api/v1/instance/credential-policy":           ClassInstance,

	// OIDC federation (#62). Issuer configuration is instance-class under
	// `instance-config` — the same siting as OIDC and SAML provider
	// administration, and for the same reason #16 gave: an org-scoped issuer
	// would let an org admin add a provider and mint identities authenticating
	// into the instance.
	"http:GET /api/v1/instance/federation-issuers":             ClassInstance,
	"http:POST /api/v1/instance/federation-issuers":            ClassInstance,
	"http:PATCH /api/v1/instance/federation-issuers/{issuer}":  ClassInstance,
	"http:DELETE /api/v1/instance/federation-issuers/{issuer}": ClassInstance,
	// A binding is a credential row, so it is created beside the credentials and
	// listed and revoked THROUGH them. There is no PUT and no PATCH: bindings
	// are immutable, and a change is a replacement mint through this same POST
	// naming the predecessor it supersedes.
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/bindings": ClassTenant,

	// The machine delivery surface (#62). Tenant-class at environment depth: a
	// caller who cannot read the environment gets exactly what a caller
	// addressing an environment that does not exist gets, which is what makes
	// the conditional answer safe to give.
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery":                  ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery/offline-records": ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/grants":                                      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/grants":                                     ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/grants":                                   ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/grants/template":                            ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":          ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":        ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants/template": ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":         ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":         ClassTenant,
	// The key catalogue (#49). Every route is tenant-class at project depth:
	// a key is declared once per project, and a key the caller cannot reach
	// answers byte-identically to one that is not there — including the two
	// reveal-gated routes, whose refusal must be indistinguishable or the gate
	// itself becomes the one-bit oracle it exists to close.
	"http:GET /api/v1/orgs/{org}/projects/{project}/keys":                      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/keys":                     ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/keys/{key}":                ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/keys/{key}":              ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/keys/{key}":             ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/name":           ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/declaration":    ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/classification": ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/group":          ClassTenant,

	// Definitions Git flow (#70). Every route is project-addressed tenant
	// material; grant refusal and a missing project/plan share one wire shape.
	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/export":              ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/check":              ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/plans":              ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}":        ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}/apply": ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/settings":            ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/definitions/settings":            ClassTenant,
	// The flat value model (#50). Tenant-class throughout: a value the caller
	// may not reach answers exactly like one that is not there.
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values":               ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/reveal-window":        ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/reveal":       ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}/reveal": ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/declare":                                 ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/copy":                                    ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/values/diff":                                     ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/diff/reveal":                             ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/clone":                             ClassTenant,
	// The import path (#68). Tenant-class like every other value route: an
	// environment the caller may not read answers exactly like one that is not
	// there, and phase 1's presence read is precisely a read of that
	// environment.
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/occurrences": ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/import":      ClassTenant,

	// Drafts, publishing and revisions (#51). Every one is tenant-class: an
	// environment the caller may not reach answers byte-identically to one that
	// is not there, history included.
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/publish":                       ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pending":                        ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/signals":                        ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions":                      ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}":           ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}/rollback": ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                           ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                          ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins/{workloadPrincipal}":    ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/export":                 ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/events":                                                    ClassTenant,
	// The root token key belongs to the instance, so there is no tenant object
	// whose nonexistence a refusal could mimic.
	"http:POST /api/v1/instance/rotate-token-key": ClassInstance,
	// The scanning fingerprint key is instance-scoped too (#74).
	"http:POST /api/v1/instance/rotate-scanning-key": ClassInstance,

	// Deployment adapters (#65). Every project and target surface is tenant
	// class; dynamic reveal/reauth checks over the adapter's environment set are
	// added by the service after this route-level classification.
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters":                            ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapters":                           ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                  ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":               ClassTenant,
	"http:PUT /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":       ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":    ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":          ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":         ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":            ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":          ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":         ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/plan":      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/sync":      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/test":      ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/adoptions": ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":                ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":              ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":             ClassTenant,

	"http:GET /api/v1/orgs/{org}/projects/{project}/key-groups":            ClassTenant,
	"http:POST /api/v1/orgs/{org}/projects/{project}/key-groups":           ClassTenant,
	"http:GET /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":    ClassTenant,
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":  ClassTenant,
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/key-groups/{group}": ClassTenant,

	// `hikyo admin create`: the bootstrap member of the closed local-authority
	// exception set. System class, whose probe contract is network
	// unreachability — the totality invariant asserts it by finding no HTTP
	// route, which is the guarantee that matters here: a first-administrator
	// endpoint reachable from the network is the trust-on-first-use race the
	// ADR rejected outright.
	"cli:admin": ClassSystem,

	// Process entry points with no principal: boot (server) and migration.
	// Their system-proof mint sites are enumerated in systemSites; the probe
	// contract is network unreachability, which the totality check asserts
	// by finding no HTTP route for them.
	"cli:server":  ClassSystem,
	"cli:migrate": ClassSystem,

	// `hikyo backup` and `hikyo restore` (#76): the operator lifecycle, on the
	// server's own host. System class, and the probe contract that matters is
	// exactly the one the totality invariant asserts by finding no HTTP route
	// — a restore endpoint reachable from the network would be an instance
	// replacement one request away, and the reconciliation that follows a
	// restore is unreachable by any other means anyway, because a restore
	// leaves no principal able to authorize anything.
	"cli:backup":  ClassSystem,
	"cli:restore": ClassSystem,

	// `hikyo version` (#46): local print of build metadata — no principal,
	// no server, no store; the pre-auth contract is trivially total.
	"cli:version": ClassUnauthenticated,

	// Client verbs that reach the server. Their probe contract is the HTTP
	// route they call, classified above; the verb itself carries the class of
	// what it reaches, so a verb whose class is still ClassStub cannot
	// silently start making requests.
	"cli:login":   ClassUnauthenticated,
	"cli:logout":  ClassUnauthenticated,
	"cli:whoami":  ClassUnauthenticated,
	"cli:account": ClassUnauthenticated,
	// `context` is entirely client-local: the trust store and the named
	// contexts live on this box and reach no server.
	"cli:context": ClassUnauthenticated,
	// `org` still reaches the instance-scoped create/list as well as the
	// tenant-scoped by-id routes, so it carries the wider of the two classes:
	// a verb whose class understated its reach would let an instance-scoped
	// call ride in under a tenant probe contract. `project`, `env` and `folder`
	// reach tenant routes exclusively.
	// Multi-instance (#71). Both families are instance-scoped: the viewing
	// side's remotes are instance configuration read under instance-directory,
	// and the serving side's connection credentials are custody under
	// instance-config.
	"cli:remote":            ClassInstance,
	"cli:remote-credential": ClassInstance,
	"cli:org":               ClassInstance,
	"cli:project":           ClassTenant,
	"cli:env":               ClassTenant,
	"cli:folder":            ClassTenant,
	// `key` reaches the catalogue and the group routes, all tenant-class.
	"cli:key": ClassTenant,
	// `values` reaches only the tenant-scoped value routes.
	"cli:values": ClassTenant,
	// `revision` reaches the two tenant-scoped history routes (#51). It
	// discloses no value: history is lineage, and the one verb that reads a
	// snapshot's values is `values export`.
	"cli:revision": ClassTenant,
	"cli:pin":      ClassTenant,
	// `rotate-token-key` reaches one instance-scoped route: the root token key
	// belongs to the instance, so there is no tenant object whose nonexistence
	// a refusal could mimic.
	"cli:rotate-token-key": ClassInstance,
	// `rotate-scanning-key` reaches one instance-scoped route: the scanning
	// fingerprint key belongs to the instance, same shape as rotate-token-key.
	"cli:rotate-scanning-key": ClassInstance,
	"cli:instance-config":     ClassInstance,
	"cli:doctor":              ClassInstance,
	// `access` reaches BOTH classes — the org/project/env grant routes are
	// tenant-class, the instance-scope ones are instance-class. It is
	// classified instance because that is the WEAKER probe contract of the
	// two: a verb that can reach a grant-refusal route must not ride in under
	// the uniform-nonexistent contract it does not always satisfy. The
	// per-route classification above is the authoritative one either way.
	"cli:access": ClassInstance,
	// `project-settings` reaches only the two environment-scoped routes.
	"cli:project-settings": ClassTenant,
	// `sa` reaches the project-scoped identity routes, all tenant-class:
	// a project whose identities the caller may not administer answers
	// exactly like a project that is not there. The instance credential
	// policy rides `instance-config`, not this verb.
	"cli:sa": ClassTenant,
	// `scim` reaches ONLY tenant-class routes: every SCIM administration
	// operation is org-addressed, so a binding the caller may not reach answers
	// exactly like one that is not there. The wire routes are tenant-class too,
	// but no CLI verb reaches them — they are the identity provider's.
	"cli:scim": ClassTenant,
	// `adapter` reaches only project-owned adapter and target routes. Dynamic
	// affected-environment checks happen behind those tenant routes.
	"cli:adapter": ClassTenant,

	// The Compose delivery verbs (#63). `run` and `compose` both reach the
	// tenant-scoped delivery routes (GET .../delivery and its offline-records
	// reconciliation POST) and nothing wider, so both carry ClassTenant: a
	// caller who cannot read the environment gets what an environment that does
	// not exist gives. `compose` dispatches render|sync|doctor internally; the
	// class is the verb's, and every sub-verb reaches only those two routes.
	"cli:run":     ClassTenant,
	"cli:compose": ClassTenant,
	// `adopt` remains not-yet-implemented: still a stub, still in
	// app.ClientVerbs.
	"cli:adopt": ClassStub,
	// `definitions` (#70) reaches only the tenant-scoped export/check/plan/apply
	// routes; server operations own every authorization and audit decision.
	"cli:definitions": ClassTenant,
	// `render` and `sync` are no longer top-level verbs — they are `compose`
	// sub-verbs — but the scaffolded top-level entries stay stubs until removed
	// with the help surface, so a bare `hikyo render` still refuses cleanly.
	"cli:render": ClassStub,
	"cli:sync":   ClassStub,
	// `import` (#68) reaches the tenant-scoped phase-1 presence route and the
	// tenant-scoped phase-2 import route, and nothing else. Its class flipped
	// off ClassStub in the same change that registered its operations — the
	// totality invariant refuses a stub verb that already has operations, which
	// is exactly the "implementation rides in on a stale class" case.
	"cli:import": ClassTenant,

	// Outbox job types and SSE emit sites: none exist. Their registries are
	// this table's "job:" and "sse:" key spaces; the first entry of each
	// kind must arrive with its probe class.
}

// wireEvents maps a wire entry to the audit event types it emits DIRECTLY,
// without an operation registry row behind it.
//
// It exists because authentication is the one surface that cannot be modelled
// as an operation: `authorize()` needs a principal, and these endpoints are
// what produce one. Their audit obligation is real all the same — the
// human-auth ADR requires login success and failure, logout, session
// creation, and credential-establishment mint, consumption and refusal — so
// the completeness invariant reads this table beside the operation registry
// rather than letting an unaudited pre-auth path hide behind "no operation".
//
// Most wire entries are either operation-backed (wireRoutes) or declare their
// events directly here (the authentication surface). The credential-reset route
// (#54) is deliberately BOTH: it is listed in wireRoutes against the two
// operations it dispatches between at runtime — so the operation linkage records
// that it reaches CapCredentialReset (MFA-mandatory) — AND declares its events
// here, because its writes and audit ride the resolution surface (like the
// account-security mutations) rather than a single operation row. It names no
// single x-hikyo-operation in the contract, since two ops of different classes
// cannot be carried by one row; the completeness invariant unions both sources.
var wireEvents = map[string][]audit.EventType{
	// The credential-versus-binding-path mismatch (#73 §8). It is refused
	// BEFORE any operation authorizes — there is no proof and no operation
	// row to hang it on — so like the authentication surface's own events it
	// is declared here, against the mount every wire request enters through.
	//
	// All THREE discovery routes declare it, and they are the only routes that
	// must: their operation (`scim-discovery.read`) declares no events at all
	// (ADR §10 annotates the probe class audited-none-equivalent, pinned in
	// internal/isolation/testdata/audited_exemptions.json), so this is the whole
	// of their audit linkage. Every other wire route inherits an event list from
	// its own operation.
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ServiceProviderConfig": {
		audit.EventSCIMCredentialRefused,
	},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ResourceTypes": {
		audit.EventSCIMCredentialRefused,
	},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Schemas": {
		audit.EventSCIMCredentialRefused,
	},

	// Drafts, publishing and revisions (#51). Staging rides the value routes'
	// existing entries; these routes are the ones that emit something new.
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":                   {audit.EventValueStaged},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":                {audit.EventValueStaged},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/publish":                       {audit.EventRevisionPublished},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/export":                 {audit.EventValueRevealed},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}/rollback": {audit.EventRevisionRestoreStaged, audit.EventValueStaged},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                          {audit.EventPinCreated, audit.EventPinReassigned, audit.EventPinRenewed, audit.EventPinExpiryRefused},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins/{workloadPrincipal}":    {audit.EventPinReleased},
	"http:POST /api/v1/instance/rotate-token-key":                                                              {audit.EventTokenKeyRotated},
	"http:POST /api/v1/instance/rotate-scanning-key":                                                           {audit.EventScanningKeyRotated},

	"http:POST /api/v1/auth/local/login": {
		audit.EventAuthLogin,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	// Multi-instance handoff (#71). These three carry the workspace tier's
	// pre-authentication audit obligation, which no operation can carry for
	// them: start and redeem authenticate nobody, and a handoff FAILURE
	// predates any session at every stage.
	"http:POST /api/v1/auth/workspace/start":   {audit.EventRemoteHandoffFailed},
	"http:POST /api/v1/auth/workspace/approve": {audit.EventRemoteHandoffFailed},
	// Redeem carries two shapes, because a redemption is two acts: an
	// establishment ISSUES a workspace session, while a step-up ELEVATES the one
	// it was bound to and mints nothing — the trail records that as the ordinary
	// reauthentication it is, on the session that was elevated.
	"http:POST /api/v1/auth/workspace/redeem": {
		audit.EventRemoteWorkspaceSessionIssued,
		audit.EventAuthReauthenticated,
		audit.EventRemoteHandoffFailed,
	},
	// The self-scoped revoke. A workspace session's death is a #71 event; an
	// ordinary session's is a logout, already the trail's own vocabulary.
	"http:DELETE /api/v1/me/sessions/{session}": {
		audit.EventAuthLogout,
		audit.EventRemoteWorkspaceSessionRevoked,
	},
	"http:POST /api/v1/auth/logout": {audit.EventAuthLogout},
	"http:POST /api/v1/auth/credential/establish": {
		audit.EventAuthCredentialEstablished,
		audit.EventAuthAuthorityRefused,
	},

	// Factor endpoints (#54). The account-security mutations emit their
	// mutation event plus auth.session_created for the reissued session; step-up
	// emits auth.reauthenticated (it rotates, mints no new session row);
	// recovery/begin emits recovery_code_consumed (success and failure) and
	// mints an establishment authority whose consumption is recorded by the
	// establish path.
	// Each factor ceremony validates a proof under the per-account backoff, so
	// a crossed threshold is an event it can emit — declared here so the
	// audit-completeness contract covers it.
	"http:POST /api/v1/auth/totp/enrol/start": {audit.EventAuthThrottleCrossed},
	"http:POST /api/v1/auth/totp/enrol/confirm": {
		audit.EventAuthFactorEnrolled,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/totp/step-up": {
		audit.EventAuthReauthenticated,
		audit.EventAuthThrottleCrossed,
	},
	"http:DELETE /api/v1/auth/totp": {
		audit.EventAuthFactorRemoved,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/recovery-codes/regenerate": {
		audit.EventAuthRecoveryCodesGenerated,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/recovery/begin": {
		audit.EventAuthRecoveryCodeConsumed,
		// A successful consume mints a recovery-issued credential-establishment
		// authority; the authority coming into existence is its own record.
		audit.EventAuthAuthorityMinted,
		// Pre-auth like login: a crossed per-account backoff threshold is its
		// own event, emitted directly by recordThrottleCrossing.
		audit.EventAuthThrottleCrossed,
	},
	// whoami resolves a session and reports it. It writes nothing and its
	// result duplicates what the login event already recorded, so it is the
	// one auth path with no event of its own — pinned in the exemption
	// fixture with that reason rather than silently absent.

	// OIDC (#54). start emits only a throttle crossing directly; the callback
	// is where a login/link/reauth lands, so it carries the family of outcomes
	// (login success, refusal by cause, link, JIT, the reissued/rotated session,
	// reauth). link start mirrors start; unlink emits the unlink plus the
	// reissued session. Provider administration is operation-modeled (wireRoutes).
	"http:POST /api/v1/auth/oidc/{provider}/start": {audit.EventAuthThrottleCrossed},
	"http:GET /api/v1/auth/oidc/{provider}/callback": {
		audit.EventOIDCLogin,
		audit.EventOIDCRefused,
		audit.EventIdentityLinked,
		audit.EventJITProvisioned,
		audit.EventAuthSessionCreated,
		audit.EventAuthReauthenticated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/identities/link": {audit.EventAuthThrottleCrossed},
	"http:DELETE /api/v1/auth/identities/{id}": {
		audit.EventIdentityUnlinked,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/saml/{provider}/start": {audit.EventAuthThrottleCrossed},
	"http:POST /api/v1/auth/saml/{provider}/acs": {
		audit.EventSAMLLogin,
		audit.EventSAMLReauth,
		audit.EventIdentityLinked,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},

	// Credential reset (#54). A successful reset mints a credential-establishment
	// authority (its own record, factors MEDIUM-7) and records the reset issuance
	// naming the tier. See the exception note above for why this route audits here
	// rather than through an operation row.
	"http:POST /api/v1/accounts/{principal}/credential-reset": {
		audit.EventAuthCredentialResetIssued,
		audit.EventAuthAuthorityMinted,
	},

	// WebAuthn / passkeys (#54). The three start ceremonies and the credential
	// read emit nothing directly and are exemption-pinned; the finish endpoints
	// carry the outcomes. enrol validates a proof under the per-account backoff
	// (a crossed threshold is its own event) and adds a credential + reissues
	// the session; login mints a session and, on a signature-count regression,
	// disables the cloned credential; step-up and reauth append the factor
	// (reauthenticated) and can likewise detect a clone; removal removes the
	// credential and reissues the session.
	"http:POST /api/v1/auth/webauthn/enrol/start": {audit.EventAuthThrottleCrossed},
	"http:POST /api/v1/auth/webauthn/enrol/finish": {
		audit.EventAuthPasskeyAdded,
		audit.EventAuthSessionCreated,
	},
	"http:POST /api/v1/auth/webauthn/login/finish": {
		audit.EventAuthLogin,
		audit.EventAuthSessionCreated,
		audit.EventAuthPasskeyCloned,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/webauthn/step-up/finish": {
		audit.EventAuthReauthenticated,
		audit.EventAuthPasskeyCloned,
	},
	"http:POST /api/v1/auth/webauthn/reauth/finish": {
		audit.EventAuthReauthenticated,
		audit.EventAuthPasskeyCloned,
	},
	"http:POST /api/v1/auth/reauth/totp": {
		audit.EventAuthReauthenticated,
		audit.EventAuthThrottleCrossed,
	},
	"http:POST /api/v1/auth/cli-reauth/start":               {audit.EventAuthCLIReauthHandoff},
	"http:GET /api/v1/auth/cli-reauth/transactions/{state}": {audit.EventAuthCLIReauthHandoff},
	"http:POST /api/v1/auth/cli-reauth/approve":             {audit.EventAuthCLIReauthHandoff},
	"http:POST /api/v1/auth/cli-reauth/redeem":              {audit.EventAuthCLIReauthHandoff},
	"http:DELETE /api/v1/auth/webauthn/credentials/{id}": {
		audit.EventAuthPasskeyRemoved,
		audit.EventAuthSessionCreated,
		audit.EventAuthThrottleCrossed,
	},

	// The bootstrap verb, running on the server's own host under local
	// authority. Its mint is audited including the DELIVERY MODE, because a
	// token that reached a log shipper is a different event from one written
	// to a root-owned file. `hikyo admin reset-credential` (#54 break-glass) is the
	// same local-authority verb group and emits the reset issuance beside the mint.
	// `hikyo admin grant` (#55 break-glass) joins the same local-authority verb
	// group: a recovery grant issued on the host, with no network route.
	"cli:admin": {
		audit.EventAuthAuthorityMinted, audit.EventAuthCredentialResetIssued,
		audit.EventBreakGlassGrant,
	},

	// The operator lifecycle (#76). `backup` writes its export record;
	// `restore` writes the reconstruction and one event per principal the
	// operator reconciles afterwards.
	"cli:backup":  {audit.EventBackupExported, audit.EventBackupExportSkipped},
	"cli:restore": {audit.EventRestoreCompleted, audit.EventRestorePrincipalReconciled},

	// The automatic pre-migration export (ops spec section 11) rides the two
	// entry points that can apply a migration, so both of them now have an
	// auditable act at the operation surface and leave the exemption fixture:
	// an export taken (or LOUDLY SKIPPED for want of recipients) immediately
	// before a schema change is the record that says whether there is
	// anything to fall back to.
	"cli:migrate": {audit.EventBackupExported, audit.EventBackupExportSkipped},
	"cli:server":  {audit.EventBackupExported, audit.EventBackupExportSkipped},

	// The machine delivery route is deliberately in BOTH tables (#62), the same
	// exception credential-reset already is. It reaches an operation —
	// delivery.fetch, which carries its formula and its access record — AND it
	// emits two events with no operation behind them, because they happen BEFORE
	// a principal exists: a federated presentation refused by cause, and the
	// JWKS observations (a tolerated refresh failure, a staleness-bound breach,
	// a throttled unknown-`kid` refresh). Both ride the resolution surface's
	// pre-authentication audit writer, exactly as `auth.oidc_refused` does, so
	// there is no proof to write them under and no operation row to hang them
	// on. The completeness invariant unions both sources.
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery": {
		audit.EventFederationRefused,
		audit.EventJWKSRefreshFailed,
	},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery/offline-records": {
		audit.EventFederationRefused,
		audit.EventJWKSRefreshFailed,
	},
}

// wireRoutes maps an HTTP entry point to the registered operation(s) it reaches.
// The audit-completeness invariant follows it so a domain route inherits its
// operation's audit mapping instead of needing a second declaration that
// could drift from the first. Most routes reach exactly one operation; a route
// that dispatches at runtime between operations (credential reset) lists them
// all, so the linkage records every operation the route can reach.
var wireRoutes = map[string][]Operation{
	"http:POST /api/v1/orgs":         {OpOrgCreate},
	"http:GET /api/v1/orgs":          {OpOrgList},
	"http:GET /api/v1/orgs/{org}":    {OpOrgGet},
	"http:PATCH /api/v1/orgs/{org}":  {OpOrgRename},
	"http:DELETE /api/v1/orgs/{org}": {OpOrgDelete},

	// The hierarchy surface (#48).
	"http:GET /api/v1/orgs/{org}/projects":              {OpProjectList},
	"http:POST /api/v1/orgs/{org}/projects":             {OpProjectCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}":    {OpProjectGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}":  {OpProjectRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}": {OpProjectDelete},

	"http:GET /api/v1/orgs/{org}/projects/{project}/environments":                  {OpEnvList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments":                 {OpEnvCreate},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/order":            {OpEnvReorder},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}":    {OpEnvRead},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/environments/{environment}":  {OpEnvRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}": {OpEnvDelete},

	"http:GET /api/v1/orgs/{org}/projects/{project}/folders":             {OpFolderList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/folders":            {OpFolderCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/folders/{folder}":    {OpFolderGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/folders/{folder}":  {OpFolderRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/folders/{folder}": {OpFolderDelete},

	// The access surface (#55). Each route reaches exactly one operation: the
	// depth is in the path, so there is no runtime dispatch between formulas.
	"http:GET /api/v1/instance/grants":             {OpGrantListInstance},
	"http:POST /api/v1/instance/grants":            {OpGrantCreateInstance},
	"http:DELETE /api/v1/instance/grants":          {OpGrantRevokeInstance},
	"http:POST /api/v1/instance/grants/template":   {OpTemplateApplyInstance},
	"http:GET /api/v1/orgs/{org}/grants":           {OpGrantListOrg},
	"http:POST /api/v1/orgs/{org}/grants":          {OpGrantCreateOrg},
	"http:DELETE /api/v1/orgs/{org}/grants":        {OpGrantRevokeOrg},
	"http:POST /api/v1/orgs/{org}/grants/template": {OpTemplateApplyOrg},

	// Machine identities (#61). One route, one operation: the depth is in the
	// path, so there is no runtime dispatch between formulas.
	"http:GET /api/v1/orgs/{org}/projects/{project}/service-accounts":                                              {OpServiceAccountList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts":                                             {OpServiceAccountCreate},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}":                          {OpServiceAccountDelete},
	"http:GET /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                 {OpCredentialList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                {OpCredentialMint},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials/{credential}": {OpCredentialRevoke},
	// Multi-instance (#71). The handoff routes reach no authz operation: they
	// are pre-authentication by construction, and their audit obligation is
	// discharged through wireEvents like every other identity-protocol
	// endpoint. The session routes reach none for the same reason
	// /api/v1/me/orgs reaches none: they are self-scoped projections.
	"http:GET /api/v1/instance/directory":                   {OpRemoteDirectoryServe},
	"http:GET /api/v1/instance/remotes":                     {OpRemoteList},
	"http:POST /api/v1/instance/remotes":                    {OpRemoteAdd},
	"http:GET /api/v1/instance/remotes/{remote}":            {OpRemoteShow},
	"http:PATCH /api/v1/instance/remotes/{remote}":          {OpRemoteRename},
	"http:DELETE /api/v1/instance/remotes/{remote}":         {OpRemoteRemove},
	"http:GET /api/v1/instance/connections":                 {OpRemoteCredentialList},
	"http:POST /api/v1/instance/connections":                {OpRemoteCredentialCreate},
	"http:GET /api/v1/instance/connections/{connection}":    {OpRemoteCredentialShow},
	"http:DELETE /api/v1/instance/connections/{connection}": {OpRemoteCredentialRevoke},
	"http:GET /api/v1/instance/workspace-origins":           {OpWorkspaceOriginList},
	"http:POST /api/v1/instance/workspace-origins":          {OpWorkspaceOriginAdd},
	"http:DELETE /api/v1/instance/workspace-origins":        {OpWorkspaceOriginRemove},
	"http:GET /api/v1/instance/credential-policy":           {OpCredentialPolicyRead},
	"http:PUT /api/v1/instance/credential-policy":           {OpCredentialPolicyUpdate},

	// OIDC federation (#62). One route, one operation.
	"http:GET /api/v1/instance/federation-issuers":                                                        {OpFederationIssuerList},
	"http:POST /api/v1/instance/federation-issuers":                                                       {OpFederationIssuerCreate},
	"http:PATCH /api/v1/instance/federation-issuers/{issuer}":                                             {OpFederationIssuerUpdate},
	"http:DELETE /api/v1/instance/federation-issuers/{issuer}":                                            {OpFederationIssuerDelete},
	"http:POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/bindings":          {OpBindingCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery":                  {OpDeliveryFetch},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery/offline-records": {OpDeliveryReconcileOffline},

	"http:GET /api/v1/orgs/{org}/projects/{project}/grants":                                      {OpGrantListProject},
	"http:POST /api/v1/orgs/{org}/projects/{project}/grants":                                     {OpGrantCreateProject},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/grants":                                   {OpGrantRevokeProject},
	"http:POST /api/v1/orgs/{org}/projects/{project}/grants/template":                            {OpTemplateApplyProject},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":          {OpGrantCreateEnv},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":        {OpGrantRevokeEnv},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants/template": {OpTemplateApplyEnv},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":         {OpEnvSettingsRead},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":         {OpEnvSettingsUpdate},
	"http:GET /api/v1/orgs/{org}/retention":                                                      {OpOrgRetentionRead},
	"http:PUT /api/v1/orgs/{org}/retention":                                                      {OpOrgRetentionUpdate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/retention":                                   {OpProjectRetentionRead},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/retention":                                   {OpProjectRetentionUpdate},
	// The key catalogue (#49).
	"http:GET /api/v1/orgs/{org}/projects/{project}/keys":            {OpKeyList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/keys":           {OpKeyCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/keys/{key}":      {OpKeyGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/keys/{key}":    {OpKeyUpdateMetadata},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/keys/{key}":   {OpKeyDelete},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/name": {OpKeyRename},
	// These two routes REACH a second operation at runtime - the reveal gate
	// the schema-model ADR puts in front of a value-dependent rule change on a
	// `secret` key, and in front of declassification. Both are listed for the
	// same reason credential-reset lists its pair: the linkage must record
	// every operation a route can reach, or the registry describes an
	// authorization posture the router does not have.
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/declaration":    {OpKeyUpdateDeclaration, OpKeySecretRuleChange},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/classification": {OpKeyReclassify, OpKeyDeclassify},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/group":          {OpKeySetGroup},

	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/export":              {OpDefinitionsExport},
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/check":              {OpDefinitionsCheck},
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/plans":              {OpDefinitionsPlanCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}":        {OpDefinitionsPlanGet},
	"http:POST /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}/apply": {OpDefinitionsApply},
	"http:GET /api/v1/orgs/{org}/projects/{project}/definitions/settings":            {OpDefinitionsSettingsGet},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/definitions/settings":            {OpDefinitionsSettingsSet},
	// The flat value model (#50). Three routes reach TWO operations each,
	// following the credential-reset precedent: a route that reaches a second
	// operation at runtime must say so, or the registry describes an
	// authorization posture the router does not have.
	//
	//   - declare authorizes value.set once PER DESTINATION environment;
	//   - copy authorizes the source leg and each destination leg, and which
	//     destination operation it reaches depends on the CLASSIFICATION of the
	//     material moving (see the registry);
	//   - clone is an environment create that then runs the copy legs.
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values":               {OpValueList},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/reveal-window":        {OpRevealWindowRead},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/reveal":       {OpValueReveal},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         {OpValueRead},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         {OpValueStage},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":      {OpValueStage},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}/reveal": {OpValueReveal},
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/declare":                                 {OpValueSet, OpValuePublish},
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/copy": {
		OpValueList, OpValueCopySource, OpValueCopyDestination,
		OpValueCopyDestinationConfig, OpValuePublish,
	},
	"http:GET /api/v1/orgs/{org}/projects/{project}/values/diff":         {OpValueList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/values/diff/reveal": {OpValueReveal},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/clone": {
		OpEnvCreate, OpValueList, OpValueCopySource, OpValueCopyDestination,
		OpValueCopyDestinationConfig, OpValuePublish,
	},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/occurrences": {OpImportPresence},
	// A manifest-carrying import re-evaluates phase 1's read op for every
	// environment the manifest names, inside its own transaction, so this route
	// genuinely reaches both operations at runtime.
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/import": {
		OpValueImport, OpImportPresence,
	},

	// Drafts, publishing and revisions (#51). A publish authorizes
	// value.publish once per AFFECTED environment, which is the addressed one
	// plus any other environment the selected versions -- or key-group closure
	// -- reach.
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/publish":             {OpValuePublish},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pending":              {OpValuePendingList},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/signals":              {OpRevisionSignals},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions":            {OpRevisionList},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}": {OpRevisionShow},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}/rollback": {
		OpRevisionRestore, OpRevisionRestoreHistory, OpRevisionRestoreCurrent,
	},
	"http:GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                        {OpPinList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                       {OpPinSet, OpPinSetHistory},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins/{workloadPrincipal}": {OpPinRelease},
	"http:POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/export": {
		OpValueExport, OpValueExportReveal, OpValueExportRevealHistory,
	},
	// The stream authorizes twice: once at connect over the project, and once
	// per event over the environment the event names.
	"http:GET /api/v1/orgs/{org}/projects/{project}/events": {OpAdvisoryWatch, OpAdvisoryEvent},
	"http:POST /api/v1/instance/rotate-token-key":           {OpRotateTokenKey},
	"http:POST /api/v1/instance/rotate-scanning-key":        {OpRotateScanningKey},

	"http:GET /api/v1/orgs/{org}/projects/{project}/key-groups":            {OpKeyGroupList},
	"http:POST /api/v1/orgs/{org}/projects/{project}/key-groups":           {OpKeyGroupCreate},
	"http:GET /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":    {OpKeyGroupGet},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":  {OpKeyGroupRename},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/key-groups/{group}": {OpKeyGroupDelete},

	// OIDC provider administration (#54), instance-config.
	"http:GET /api/v1/instance/oidc-providers":           {OpProviderList},
	"http:GET /api/v1/instance/oidc-providers/{slug}":    {OpProviderGet},
	"http:PUT /api/v1/instance/oidc-providers/{slug}":    {OpProviderPut},
	"http:DELETE /api/v1/instance/oidc-providers/{slug}": {OpProviderDelete},

	// SAML provider administration (#72), under the same instance-config atom.
	"http:GET /api/v1/instance/saml-providers":                          {OpSAMLProviderList},
	"http:GET /api/v1/instance/retention-health":                        {OpRetentionHealthRead},
	"http:GET /api/v1/instance/saml-providers/{slug}":                   {OpSAMLProviderGet},
	"http:PUT /api/v1/instance/saml-providers/{slug}":                   {OpSAMLProviderPut},
	"http:PATCH /api/v1/instance/saml-providers/{slug}":                 {OpSAMLProviderPatch},
	"http:DELETE /api/v1/instance/saml-providers/{slug}":                {OpSAMLProviderDelete},
	"http:POST /api/v1/instance/saml-providers/{slug}/refresh-metadata": {OpSAMLProviderRefreshMetadata},
	"http:GET /api/v1/instance/saml-sp-keys":                            {OpSAMLSPKeyList},

	// SCIM provisioning (#73).
	"http:GET /api/v1/orgs/{org}/scim-bindings":                               {OpSCIMBindingList},
	"http:POST /api/v1/orgs/{org}/scim-bindings":                              {OpSCIMBindingCreate},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}":                     {OpSCIMBindingGet},
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}":                  {OpSCIMBindingDelete},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            {OpSCIMMappingList},
	"http:POST /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":           {OpSCIMMappingCreate},
	"http:PUT /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            {OpSCIMMappingUpdate},
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":         {OpSCIMMappingDelete},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":         {OpSCIMCredentialList},
	"http:POST /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":        {OpSCIMCredentialMint},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}":    {OpSCIMCredentialGet},
	"http:DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}": {OpSCIMCredentialRevoke},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/users":     {OpSCIMDirectoryUsers},
	"http:GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/groups":    {OpSCIMDirectoryGroups},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ServiceProviderConfig":     {OpSCIMDiscovery},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/ResourceTypes":             {OpSCIMDiscovery},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Schemas":                   {OpSCIMDiscovery},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Users":                     {OpSCIMUserList},
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Users":                    {OpSCIMUserCreate},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                {OpSCIMUserGet},
	"http:PUT /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                {OpSCIMUserReplace},
	"http:PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":              {OpSCIMUserPatch},
	"http:DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":             {OpSCIMUserDelete},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                    {OpSCIMGroupList},
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                   {OpSCIMGroupCreate},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               {OpSCIMGroupGet},
	"http:PUT /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               {OpSCIMGroupReplace},
	"http:PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":             {OpSCIMGroupPatch},
	"http:DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":            {OpSCIMGroupDelete},
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Bulk":                     {OpSCIMUnsupported},
	"http:GET /api/v1/orgs/{org}/scim/v2/{binding}/Me":                        {OpSCIMUnsupported},
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Users/.search":            {OpSCIMUnsupported},
	"http:POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups/.search":           {OpSCIMUnsupported},
	"http:POST /api/v1/instance/saml-sp-keys/rotate":                          {OpSAMLSPKeyRotate},
	"http:DELETE /api/v1/instance/saml-sp-keys/{fingerprint}":                 {OpSAMLSPKeyRetire},
	"http:POST /api/v1/instance/saml-sp-keys/{fingerprint}/compromise-retire": {OpSAMLSPKeyCompromiseRetire},

	// Deployment adapters (#65). Dynamic reveal and reauthentication checks
	// refine these operations in service, but every route still names the
	// static proof-bearing operation whose audit family it reaches.
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters":                            {OpAdapterInspect},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapters":                           {OpAdapterConfigure},
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                  {OpAdapterInspect},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                {OpAdapterConfigure},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":               {OpAdapterDelete},
	"http:PUT /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":       {OpAdapterCredentialSet},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":    {OpAdapterCredentialRevoke},
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":          {OpAdapterInspect},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":         {OpAdapterConfigure},
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":            {OpAdapterInspect},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":          {OpAdapterConfigure},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":         {OpAdapterDelete},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/plan":      {OpAdapterPlan},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/sync":      {OpAdapterSync},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/test":      {OpAdapterTest},
	"http:POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/adoptions": {OpAdapterAdopt},
	"http:GET /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":                {OpAdapterInspect},
	"http:PATCH /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":              {OpAdapterConfigure},
	"http:DELETE /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":             {OpAdapterConfigure},

	// Credential reset (#54). ONE route dispatches at runtime between the
	// org-scoped and instance-scoped credential-reset operations by the target's
	// grant classification, resolved under the target-row lock inside the
	// handler's tx. Both are mapped here so the operation linkage records that
	// this route reaches CapCredentialReset (MFA-mandatory): the chokepoint —
	// authorize(), which the service calls on the chosen op inside that tx —
	// enforces capability + MFA + assurance. The route keeps its unauthenticated
	// probe class (enumeration uniformity is its dominant contract, reinforced by
	// B2's uniform refusal) and carries no single x-hikyo-operation, since two ops
	// of different classes cannot be named by one contract row; its audit events
	// also ride wireEvents below.
	"http:POST /api/v1/accounts/{principal}/credential-reset": {OpCredentialReset, OpCredentialResetInstance},
}

// WireRoutes returns the route→operation(s) mapping for the invariant tests and
// the contract cross-check.
func (RegistryFacts) WireRoutes() map[string][]Operation {
	return maps.Clone(wireRoutes)
}

// WireEvents returns the direct wire→event mapping for the invariant tests.
func (RegistryFacts) WireEvents() map[string][]audit.EventType {
	return maps.Clone(wireEvents)
}

// Cache is one registered cache holding derived tenant material
// (tenant-isolation ADR invariant 12). Registration is mandatory: the
// invariant test fails on any cache-shaped declaration in the module that
// is not listed here, so a new cache cannot appear without stating how it
// is keyed and who may reach it.
type Cache struct {
	// KeyConstructor is the single function that builds its keys. The ADR's
	// keying rule: the full id chain to the owning scope, structured and
	// injectively encoded (length-prefixed — bare concatenation is how
	// (org "a", project "bc") and (org "ab", project "c") collide).
	KeyConstructor string
	// ProofGatedAt names the layer that supplies the proof for reads and
	// writes. For the DEK LRU this is deliberately NOT inside the cache:
	// internal/crypto is a locked leaf package (encryption-model ADR; enforced by
	// the boundary test) and may not import the authorization package, so
	// its accessors cannot take an authz.Proof. The access rule is therefore
	// discharged one layer up, at the service seam that resolves a scope
	// before asking crypto to seal for it.
	ProofGatedAt string
}

// caches is the closed cache registry.
var caches = map[string]Cache{
	"crypto.dek-lru": {
		KeyConstructor: "internal/crypto.dekScope",
		// No tenant-facing caller exists yet: the DEK LRU is reachable only
		// from Keyring.ForProject, whose only callers today are crypto's own
		// tests and the boot path. The first tenant consumer is #50 (flat
		// encrypted values), which MUST resolve the scope through
		// authorize() and pass the proof's chain — a cache hit must not be a
		// proof-free path to tenant material.
		ProofGatedAt: "service seam (#50); no tenant caller today",
	},
	"oidcfed.jwks": {
		// Keyed by the BYTE-EXACT issuer string, and that string IS the whole
		// key: an issuer is instance configuration under a unique index, so it
		// is already an injective identifier with no chain to compose.
		KeyConstructor: "internal/oidcfed.Issuer.Issuer (byte-exact issuer string)",
		// Not proof-gated, and here that is the right answer rather than a
		// deferral. The contents are the PUBLIC signing keys an issuer publishes
		// at a well-known URL — no tenant material, nothing a proof could
		// protect. What the cache governs is the FRESHNESS of the answer, which
		// is the staleness bound. And it is read pre-authentication by
		// construction: validating the presented token is what produces a
		// principal, so no proof can exist yet.
		ProofGatedAt: "not proof-gated: public issuer signing keys, read pre-authentication (#62)",
	},
}

// Caches returns the cache registry for the invariant test.
func (RegistryFacts) Caches() map[string]Cache {
	return maps.Clone(caches)
}

// Wire returns the wire registry for the invariant tests.
func (RegistryFacts) Wire() map[string]Class {
	return maps.Clone(wireRegistry)
}
