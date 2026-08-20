package api_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-chi/chi/v5"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/server"
)

// Acceptance criterion 6 of the multi-instance ADR (#71), in the form the MVP
// boundary's M6 row recasts it:
//
//	"[CI] route-table/OpenAPI closure (no server-side proxy endpoint exists)"
//
// The criterion itself reads "No endpoint on either instance returns another
// instance's secret values to a server", and the ADR notes it is "vacuously
// testable: the surface does not exist". A test that asserted nothing because
// nothing exists would be worthless — it would go green forever, including on
// the day someone adds the endpoint. So this asserts CLOSURE instead: the
// contract's shape makes a proxy endpoint unrepresentable, and adding one
// fails here.
//
// This matters because the rejected design is genuinely tempting. A
// server-side proxy is the obvious way to build a multi-instance UI, and the
// ADR rejected it precisely because "a compromised main becomes plaintext
// access to every connected instance". The whole two-tier architecture — the
// browser talking to the remote directly, the directory credential confined to
// metadata — exists to avoid it. The one thing that keeps it avoided over time
// is that re-introducing it must be loud.

// proxyShapedSegments are path segments that name relaying as an act. A path
// containing one is refused by name.
var proxyShapedSegments = []string{
	"proxy", "proxies", "forward", "relay", "passthrough", "tunnel", "upstream",
}

// passthroughParams are path-parameter names that would let a caller choose
// what an endpoint talks to or reaches for. A remote's identifier is fine — the
// server looks the entry up and the entry's URL is immutable — but a parameter
// naming a URL, host or arbitrary path is the credential-redirect shape the
// ADR closed, expressed in the contract instead of the database.
var passthroughParams = []string{
	"url", "uri", "host", "origin", "endpoint", "target", "upstream", "path",
}

func TestNoServerSideProxyEndpointExists(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("the contract has no operations — this check would be vacuously green")
	}

	for _, op := range ops {
		lower := strings.ToLower(op.Path)
		for _, seg := range proxyShapedSegments {
			if strings.Contains(lower, "/"+seg) {
				t.Errorf("%s %s: the path names relaying (%q). No hikyo server proxies another "+
					"instance's API — the multi-instance ADR rejected exactly this design, because "+
					"a compromised viewing instance would become plaintext access to every "+
					"connected instance", op.Method, op.Path, seg)
			}
		}
		for _, param := range passthroughParams {
			if strings.Contains(lower, "{"+param+"}") {
				// An adapter target is a server-minted local configuration row,
				// not a caller-chosen network target. The deployment-adapter ADR
				// and public resource grammar deliberately call it `target`.
				if param == "target" && strings.Contains(lower, "/adapter-targets/{target}") {
					continue
				}
				t.Errorf("%s %s: the path takes a caller-chosen %q. An endpoint whose target is "+
					"named by the request is a proxy whatever it is called; a remote is addressed "+
					"by its stored entry, whose URL is immutable by design",
					op.Method, op.Path, param)
			}
		}
	}
}

// The remote family's contract surface, pinned. Every endpoint the multi-
// instance work adds under a `remote`/`workspace` name must be listed here,
// which is what makes "no proxy endpoint" a reviewed claim rather than a
// pattern match that a creatively-named route could slip past.
//
// Each entry below was added by confirming the thing the pin exists to
// confirm: THIS ENDPOINT RETURNS THIS INSTANCE'S OWN METADATA, A STORED
// SNAPSHOT, OR A LOCALLY-ISSUED ARTIFACT — never another instance's values, and
// never a response assembled by calling another instance on the caller's
// behalf. The confirmation per entry:
//
//   - serveDirectory: this instance's own identity, version and org/project
//     NAMES. Its response schema (DirectoryListing) has no field that could
//     carry a value, key, environment, membership, setting or audit row.
//   - listRemotes / showRemote: this instance's own configuration rows plus the
//     LAST-KNOWN SNAPSHOT it stored from its own pinned fetch. The fetch is
//     server-to-server under the entry's credential and returns only what
//     serveDirectory serves; nothing the caller supplies decides what is
//     reached, because the entry's URL is immutable.
//   - addRemote / renameRemote / removeRemote: writes to this instance's own
//     configuration. addRemote performs ONE verifying fetch of the same
//     metadata-only listing before committing.
//   - the connection family: this instance's own minted principals and their
//     credential METADATA. The value is disclosed exactly once, at mint, and no
//     statement reads a verifier back out.
//   - the workspace-origin family: this instance's own consent list.
//   - the handoff family: transactions and sessions THIS instance issues, on
//     its own origin, for its own data. The front channel carries code and
//     state only.
//
// Anything added here later must earn the same sentence.
var pinnedRemoteSurface = map[string]bool{
	"GET /api/v1/instance/directory": true,

	"GET /api/v1/instance/remotes":             true,
	"POST /api/v1/instance/remotes":            true,
	"GET /api/v1/instance/remotes/{remote}":    true,
	"PATCH /api/v1/instance/remotes/{remote}":  true,
	"DELETE /api/v1/instance/remotes/{remote}": true,

	"GET /api/v1/instance/connections":                 true,
	"POST /api/v1/instance/connections":                true,
	"GET /api/v1/instance/connections/{connection}":    true,
	"DELETE /api/v1/instance/connections/{connection}": true,

	"GET /api/v1/instance/workspace-origins":    true,
	"POST /api/v1/instance/workspace-origins":   true,
	"DELETE /api/v1/instance/workspace-origins": true,

	"POST /api/v1/auth/workspace/start":   true,
	"POST /api/v1/auth/workspace/approve": true,
	"POST /api/v1/auth/workspace/redeem":  true,
}

func TestRemoteContractSurfaceIsPinned(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}

	for _, op := range ops {
		lower := strings.ToLower(op.Path)
		// SCIM (#73) owns the word "directory" for a different thing entirely —
		// the identity provider's own directory, PUSHED to this instance and
		// stored here — so its paths are not multi-instance surface and are not
		// reviewed against a multi-instance question. Nothing escapes by this
		// exclusion: TestContractRouteSurfaceIsExhaustivelyPinned pins the whole
		// contract as a set, so every SCIM route is still written down and still
		// had to be confirmed once by hand. What this narrower check adds is a
		// SECOND, multi-instance-specific confirmation, and asking it about a
		// route it does not describe would only train the reader to wave it
		// through.
		if strings.Contains(lower, "/scim") {
			continue
		}
		if !strings.Contains(lower, "remote") && !strings.Contains(lower, "workspace") &&
			!strings.Contains(lower, "directory") {
			continue
		}
		key := op.Method + " " + op.Path
		if !pinnedRemoteSurface[key] {
			t.Errorf("%s is a multi-instance endpoint that is not in the pinned remote surface. "+
				"Add it to pinnedRemoteSurface in this file, and while doing so confirm the thing "+
				"the pin exists to confirm: that it returns this instance's own metadata or a "+
				"stored snapshot, and never another instance's secret values", key)
		}
	}
}

// There is deliberately NO separate vocabulary check over the wire registry
// here. There used to be one, and it was strictly weaker than what now closes
// the same gap: TestLiveRouterSurfaceIsExhaustivelyPinned below pins the live
// chi router as a set, and internal/isolation's
// TestInvariant01ClassificationTotality asserts that the wire registry and the
// live router are the SAME set of `http:` keys in both directions — every
// walked route must be classified, and every classified route must be walked.
// A wire entry therefore cannot exist without a route, and no route escapes
// the pin, whatever either is named. Two half-strength closures over one
// surface is one closure nobody re-reads.

// THE COMPLETE ROUTE SURFACE, PINNED AS A SET.
//
// The vocabulary checks above are defence in depth and they are not the
// closure: they refuse a path that CALLS ITSELF a proxy. `POST
// /api/v1/fleet/{peer}/execute` calls itself nothing of the sort, and neither
// does a generic `/api/v1/actions` that takes its target in a request body. M6
// asks for something stronger — that a proxy-shaped endpoint cannot enter
// unnoticed REGARDLESS OF NAMING — and only an exhaustive pin gives that:
// every path and method the contract declares is listed here, so ANY addition
// fails this test until a human writes it down.
//
// This is a set EQUALITY. A removed endpoint fails too, because a stale pin is
// a pin nobody re-reads, and the whole value of the mechanism is that adding a
// line to it is a moment where somebody has to think about what the endpoint
// returns.
//
// What to confirm when adding a line, in one sentence: this endpoint returns
// THIS instance's own data — its configuration, its metadata, a snapshot it
// stored — and never fetches, relays or forwards on behalf of the caller.
var pinnedContractSurface = map[string]bool{
	// Deployment adapters (#65): these rows, plans, jobs and conflict
	// artifacts are this instance's own durable state. Plan/test contact only
	// the immutable origin stored on the addressed adapter; no request member
	// selects an arbitrary upstream and no response relays provider values.
	"GET /api/v1/orgs/{org}/projects/{project}/adapters":                                                      true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapters":                                                     true,
	"GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                                            true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                                          true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}":                                         true,
	"PUT /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":                                 true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/credential":                              true,
	"GET /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":                                    true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapters/{adapter}/targets":                                   true,
	"GET /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":                                      true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":                                    true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}":                                   true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/plan":                                true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/sync":                                true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/test":                                true,
	"POST /api/v1/orgs/{org}/projects/{project}/adapter-targets/{target}/adoptions":                           true,
	"GET /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":                                          true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":                                        true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/adapter-moves/{move}":                                       true,
	"POST /api/v1/auth/cli-reauth/start":                                                                      true,
	"GET /api/v1/auth/cli-reauth/transactions/{state}":                                                        true,
	"POST /api/v1/auth/cli-reauth/approve":                                                                    true,
	"POST /api/v1/auth/cli-reauth/redeem":                                                                     true,
	"DELETE /api/v1/auth/identities/{id}":                                                                     true,
	"DELETE /api/v1/auth/totp":                                                                                true,
	"DELETE /api/v1/auth/webauthn/credentials/{id}":                                                           true,
	"DELETE /api/v1/instance/connections/{connection}":                                                        true,
	"DELETE /api/v1/instance/grants":                                                                          true,
	"DELETE /api/v1/instance/oidc-providers/{slug}":                                                           true,
	"DELETE /api/v1/instance/remotes/{remote}":                                                                true,
	"DELETE /api/v1/instance/saml-providers/{slug}":                                                           true,
	"DELETE /api/v1/instance/saml-sp-keys/{fingerprint}":                                                      true,
	"DELETE /api/v1/instance/workspace-origins":                                                               true,
	"DELETE /api/v1/me/sessions/{session}":                                                                    true,
	"DELETE /api/v1/orgs/{org}":                                                                               true,
	"DELETE /api/v1/orgs/{org}/grants":                                                                        true,
	"DELETE /api/v1/orgs/{org}/projects/{project}":                                                            true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}":                                 true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":                          true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/folders/{folder}":                                           true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/grants":                                                     true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":                                         true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/keys/{key}":                                                 true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}":                          true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials/{credential}": true,
	"GET /api/v1/auth/identities":                                                                             true,
	"GET /api/v1/auth/methods":                                                                                true,
	"GET /api/v1/auth/oidc/{provider}/callback":                                                               true,
	"GET /api/v1/auth/saml/{provider}/metadata":                                                               true,
	"GET /api/v1/auth/totp":                                                                                   true,
	"GET /api/v1/auth/webauthn/credentials":                                                                   true,
	"GET /api/v1/auth/whoami":                                                                                 true,
	"GET /api/v1/instance/connections":                                                                        true,
	"GET /api/v1/instance/connections/{connection}":                                                           true,
	"GET /api/v1/instance/credential-policy":                                                                  true,
	"GET /api/v1/instance/directory":                                                                          true,
	"GET /api/v1/instance/grants":                                                                             true,
	"GET /api/v1/instance/oidc-providers":                                                                     true,
	"GET /api/v1/instance/oidc-providers/{slug}":                                                              true,
	"GET /api/v1/instance/remotes":                                                                            true,
	"GET /api/v1/instance/remotes/{remote}":                                                                   true,
	"GET /api/v1/instance/saml-providers":                                                                     true,
	"GET /api/v1/instance/retention-health":                                                                   true,
	"GET /api/v1/instance/saml-providers/{slug}":                                                              true,
	"GET /api/v1/instance/saml-sp-keys":                                                                       true,
	"GET /api/v1/instance/workspace-origins":                                                                  true,
	"GET /api/v1/me/orgs":                                                                                     true,
	"GET /api/v1/me/sessions":                                                                                 true,
	"GET /api/v1/meta":                                                                                        true,
	"GET /api/v1/orgs":                                                                                        true,
	"GET /api/v1/orgs/{org}":                                                                                  true,
	"GET /api/v1/orgs/{org}/grants":                                                                           true,
	"GET /api/v1/orgs/{org}/projects":                                                                         true,
	"GET /api/v1/orgs/{org}/projects/{project}":                                                               true,
	"GET /api/v1/orgs/{org}/projects/{project}/retention":                                                     true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments":                                                  true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}":                                    true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":                           true,
	"GET /api/v1/orgs/{org}/projects/{project}/folders":                                                       true,
	"GET /api/v1/orgs/{org}/projects/{project}/folders/{folder}":                                              true,
	"GET /api/v1/orgs/{org}/projects/{project}/grants":                                                        true,
	"GET /api/v1/orgs/{org}/projects/{project}/key-groups":                                                    true,
	"GET /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":                                            true,
	"GET /api/v1/orgs/{org}/projects/{project}/keys":                                                          true,
	"GET /api/v1/orgs/{org}/projects/{project}/keys/{key}":                                                    true,
	"GET /api/v1/orgs/{org}/projects/{project}/service-accounts":                                              true,
	"GET /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                 true,
	"GET /api/v1/orgs/{org}/retention":                                                                        true,
	"PATCH /api/v1/instance/remotes/{remote}":                                                                 true,
	"PATCH /api/v1/instance/saml-providers/{slug}":                                                            true,
	"PATCH /api/v1/orgs/{org}":                                                                                true,
	"PATCH /api/v1/orgs/{org}/projects/{project}":                                                             true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/environments/{environment}":                                  true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/folders/{folder}":                                            true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/key-groups/{group}":                                          true,
	"PATCH /api/v1/orgs/{org}/projects/{project}/keys/{key}":                                                  true,
	"PUT /api/v1/orgs/{org}/projects/{project}/retention":                                                     true,
	"PUT /api/v1/orgs/{org}/retention":                                                                        true,
	"POST /api/v1/accounts/{principal}/credential-reset":                                                      true,
	"POST /api/v1/auth/credential/establish":                                                                  true,
	"POST /api/v1/auth/identities/link":                                                                       true,
	"POST /api/v1/auth/local/login":                                                                           true,
	"POST /api/v1/auth/logout":                                                                                true,
	"POST /api/v1/auth/oidc/{provider}/start":                                                                 true,
	"POST /api/v1/auth/recovery-codes/regenerate":                                                             true,
	"POST /api/v1/auth/recovery/begin":                                                                        true,
	"POST /api/v1/auth/saml/{provider}/acs":                                                                   true,
	"POST /api/v1/auth/saml/{provider}/start":                                                                 true,
	"POST /api/v1/auth/totp/enrol/confirm":                                                                    true,
	"POST /api/v1/auth/totp/enrol/start":                                                                      true,
	"POST /api/v1/auth/totp/step-up":                                                                          true,
	"POST /api/v1/auth/webauthn/enrol/finish":                                                                 true,
	"POST /api/v1/auth/webauthn/enrol/start":                                                                  true,
	"POST /api/v1/auth/webauthn/login/finish":                                                                 true,
	"POST /api/v1/auth/webauthn/login/start":                                                                  true,
	"POST /api/v1/auth/webauthn/reauth/finish":                                                                true,
	"POST /api/v1/auth/webauthn/reauth/start":                                                                 true,
	"POST /api/v1/auth/webauthn/step-up/finish":                                                               true,
	"POST /api/v1/auth/webauthn/step-up/start":                                                                true,
	"POST /api/v1/auth/workspace/approve":                                                                     true,
	"POST /api/v1/auth/workspace/redeem":                                                                      true,
	"POST /api/v1/auth/workspace/start":                                                                       true,
	"POST /api/v1/instance/connections":                                                                       true,
	"POST /api/v1/instance/grants":                                                                            true,
	"POST /api/v1/instance/grants/template":                                                                   true,
	"POST /api/v1/instance/remotes":                                                                           true,
	"POST /api/v1/instance/saml-providers/{slug}/refresh-metadata":                                            true,
	"POST /api/v1/instance/saml-sp-keys/rotate":                                                               true,
	"POST /api/v1/instance/saml-sp-keys/{fingerprint}/compromise-retire":                                      true,
	"POST /api/v1/instance/workspace-origins":                                                                 true,
	"POST /api/v1/orgs":                                                                                       true,
	"POST /api/v1/orgs/{org}/grants":                                                                          true,
	"POST /api/v1/orgs/{org}/grants/template":                                                                 true,
	"POST /api/v1/orgs/{org}/projects":                                                                        true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments":                                                 true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants":                            true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/grants/template":                   true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/import":                     true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/occurrences":                true,
	"POST /api/v1/orgs/{org}/projects/{project}/folders":                                                      true,
	"POST /api/v1/orgs/{org}/projects/{project}/grants":                                                       true,
	"POST /api/v1/orgs/{org}/projects/{project}/grants/template":                                              true,
	"POST /api/v1/orgs/{org}/projects/{project}/key-groups":                                                   true,
	"POST /api/v1/orgs/{org}/projects/{project}/keys":                                                         true,
	"POST /api/v1/orgs/{org}/projects/{project}/service-accounts":                                             true,
	"POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/credentials":                true,
	"PUT /api/v1/instance/credential-policy":                                                                  true,
	"PUT /api/v1/instance/oidc-providers/{slug}":                                                              true,
	"PUT /api/v1/instance/saml-providers/{slug}":                                                              true,
	"PUT /api/v1/orgs/{org}/projects/{project}/environments/order":                                            true,
	"PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/settings":                           true,
	"PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/classification":                                     true,
	"PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/declaration":                                        true,
	"PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/group":                                              true,
	"PUT /api/v1/orgs/{org}/projects/{project}/keys/{key}/name":                                               true,

	// Definitions Git flow (#70). Every route reads or writes this instance's
	// own project state; provenance labels are data, never network locations,
	// and no route fetches, relays, or forwards for the caller.
	"GET /api/v1/orgs/{org}/projects/{project}/definitions/export":              true,
	"POST /api/v1/orgs/{org}/projects/{project}/definitions/check":              true,
	"POST /api/v1/orgs/{org}/projects/{project}/definitions/plans":              true,
	"GET /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}":        true,
	"POST /api/v1/orgs/{org}/projects/{project}/definitions/plans/{plan}/apply": true,
	"GET /api/v1/orgs/{org}/projects/{project}/definitions/settings":            true,
	"PUT /api/v1/orgs/{org}/projects/{project}/definitions/settings":            true,
	// The per-project machine-reveal opt-in: reads and writes one column of
	// this instance's own project row; fetches, relays and forwards nothing.
	"GET /api/v1/orgs/{org}/projects/{project}/machine-reveal": true,
	"PUT /api/v1/orgs/{org}/projects/{project}/machine-reveal": true,

	// OIDC federation and the delivery surface (#62). The issuer rows are THIS
	// instance's own configuration; delivery returns this instance's stored
	// snapshot, and offline reconciliation writes records into this instance's
	// own trail. Neither fetches anything on the caller's behalf: a federated
	// assertion and offline records arrive IN the request, they are not gone and got.
	"GET /api/v1/instance/federation-issuers":                                                        true,
	"POST /api/v1/instance/federation-issuers":                                                       true,
	"PATCH /api/v1/instance/federation-issuers/{issuer}":                                             true,
	"DELETE /api/v1/instance/federation-issuers/{issuer}":                                            true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery":                  true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/delivery/offline-records": true,
	"POST /api/v1/orgs/{org}/projects/{project}/service-accounts/{serviceAccount}/bindings":          true,

	// The reveal ceremony's TOTP opener (#58). It opens a window on THIS
	// instance's own session; nothing crosses a network.
	"POST /api/v1/auth/reauth/totp": true,

	// The value surface and its disclosure ceremonies (#40, #58). Every one of
	// these reads or writes THIS instance's own sealed cells, under this
	// instance's own keyring — a value is an envelope bound to its own row and
	// cannot be opened anywhere else, so there is nothing here that could be
	// fetched from elsewhere even in principle.
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values":               true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         true,
	"PUT /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":         true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}":      true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/reveal":       true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/{key}/reveal": true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/reveal-window":        true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/clone":                             true,
	"GET /api/v1/orgs/{org}/projects/{project}/values/diff":                                     true,
	"POST /api/v1/orgs/{org}/projects/{project}/values/diff/reveal":                             true,
	"POST /api/v1/orgs/{org}/projects/{project}/values/copy":                                    true,
	"POST /api/v1/orgs/{org}/projects/{project}/values/declare":                                 true,

	// Revisions and publishing (#51): every route reads or mutates this
	// instance's own pending changes, immutable snapshots, or advisory event
	// stream. Export discloses a local committed snapshot; none names or dials a
	// remote origin. Token-key rotation changes only this instance's root key.
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/publish":                       true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pending":                        true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/signals":                        true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions":                      true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}":           true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/revisions/{revision}/rollback": true,
	"GET /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                           true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins":                          true,
	"DELETE /api/v1/orgs/{org}/projects/{project}/environments/{environment}/pins/{workloadPrincipal}":    true,
	"POST /api/v1/orgs/{org}/projects/{project}/environments/{environment}/values/export":                 true,
	"GET /api/v1/orgs/{org}/projects/{project}/events":                                                    true,
	"POST /api/v1/instance/rotate-token-key":                                                              true,
	// rotate-scanning-key (#74): replaces this instance's own scanning key and
	// drops this instance's own dismissal rows. It returns this instance's own
	// data and never fetches, relays or forwards on the caller's behalf.
	"POST /api/v1/instance/rotate-scanning-key": true,
	// rotate-dek and rotate-master-key act only on this instance's own key
	// hierarchy — they touch local key rows and forward nothing on the caller's
	// behalf.
	"POST /api/v1/instance/rotate-dek":        true,
	"POST /api/v1/instance/rotate-master-key": true,
	"POST /api/v1/instance/rotate-root-key":   true,
	// reencrypt walks this instance's own ciphertext onto the active DEK
	// version; it forwards nothing on the caller's behalf.
	"POST /api/v1/instance/reencrypt":                      true,
	"POST /api/v1/orgs/{org}/projects/{project}/reencrypt": true,

	// SCIM provisioning (#73): the administrative binding surface and the
	// standards-mandated SCIM 2.0 wire surface. The DIRECTION here is the
	// opposite of a proxy and is worth stating once for the whole family: an
	// identity provider PUSHES to these endpoints, and the two
	// `scim-bindings/{binding}/directory/*` reads project rows this instance
	// was pushed and already stores. Nothing is fetched from the provider.
	"GET /api/v1/orgs/{org}/scim-bindings":                               true,
	"POST /api/v1/orgs/{org}/scim-bindings":                              true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}":                     true,
	"DELETE /api/v1/orgs/{org}/scim-bindings/{binding}":                  true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":         true,
	"POST /api/v1/orgs/{org}/scim-bindings/{binding}/credentials":        true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}":    true,
	"DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/credentials/{id}": true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            true,
	"POST /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":           true,
	"PUT /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":            true,
	"DELETE /api/v1/orgs/{org}/scim-bindings/{binding}/mappings":         true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/groups":    true,
	"GET /api/v1/orgs/{org}/scim-bindings/{binding}/directory/users":     true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/ServiceProviderConfig":     true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/ResourceTypes":             true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Schemas":                   true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Me":                        true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Users":                     true,
	"POST /api/v1/orgs/{org}/scim/v2/{binding}/Users":                    true,
	"POST /api/v1/orgs/{org}/scim/v2/{binding}/Users/.search":            true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                true,
	"PUT /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":                true,
	"PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":              true,
	"DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Users/{id}":             true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                    true,
	"POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups":                   true,
	"POST /api/v1/orgs/{org}/scim/v2/{binding}/Groups/.search":           true,
	"GET /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               true,
	"PUT /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":               true,
	"PATCH /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":             true,
	"DELETE /api/v1/orgs/{org}/scim/v2/{binding}/Groups/{id}":            true,
	"POST /api/v1/orgs/{org}/scim/v2/{binding}/Bulk":                     true,
}

func TestContractRouteSurfaceIsExhaustivelyPinned(t *testing.T) {
	ops, err := api.Operations()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	if len(ops) == 0 {
		t.Fatal("the contract declares no operations - this check would be vacuously green")
	}
	seen := map[string]bool{}
	for _, op := range ops {
		key := op.Method + " " + op.Path
		seen[key] = true
		if !pinnedContractSurface[key] {
			t.Errorf("%s is a NEW endpoint that is not in the pinned contract surface. Add it to "+
				"pinnedContractSurface in this file, and while doing so confirm the thing the pin "+
				"exists to confirm: that it returns this instance's own data and never fetches, "+
				"relays or forwards on the caller's behalf. Criterion 6 is a closure claim, and a "+
				"closure a new path can slip through by being named something innocuous is not one.", key)
		}
	}
	for key := range pinnedContractSurface {
		if !seen[key] {
			t.Errorf("%s is pinned but no longer in the contract - remove it. A stale pin is one "+
				"nobody re-reads, and re-reading it is the entire mechanism.", key)
		}
	}
}

// THE LIVE ROUTER'S SURFACE, PINNED AS A SET.
//
// The pin above reads api/openapi.yaml, and a route that never enters the
// document is invisible to it. That is not a hypothetical hole: server.New
// registers /healthz, /readyz and the asset handler with plain chi calls
// OUTSIDE the generated API group, so `r.Get("/fetch", …)` next to them would
// be served by a real binary while every contract-derived check stayed green.
//
// Nor do the neighbouring tests catch it on their own. internal/isolation's
// TestInvariant01ClassificationTotality walks the router, but demands only
// that each route be CLASSIFIED — adding the matching wire-registry line
// satisfies it — and it walks with a nil `ui`, so the ui-gated asset route is
// outside its view entirely. internal/isolation's contract cross-check skips
// every route that is not under the /api/v1 prefix, which is exactly where a
// Go-first route would sit. Today, `r.Get("/fetch")` plus one registry line
// passes that whole chain.
//
// So this walks the router server.New actually assembles, with a `ui` present
// so the ui-gated routes are included, and asserts SET EQUALITY against the
// union of the contract pin above and the short non-API allowlist below.
// Anything else — any method, any pattern, named anything — fails here.
//
// Not walked, and correctly so: chi.Walk reports registered ROUTES, and the
// SPA fallback is r.NotFound / r.MethodNotAllowed. A fallback serves the
// document or a uniform 404; it dispatches on nothing the caller names, so it
// cannot be the door a proxy enters through.
//
// Each entry below is a route that legitimately has no contract entry, with
// the reason it has none.
var pinnedNonContractRoutes = map[string]string{
	"GET /healthz": "liveness probe: no principal, no contract entry, and " +
		"deliberately outside the API middleware so a login flood cannot restart-loop the process",
	"GET /metrics": "Prometheus operational metrics: no principal, no contract entry, and no identity labels",
	"GET /readyz": "readiness probe: same partition as /healthz; answers only whether " +
		"this instance's own dependencies respond",
}

// assetRoutePattern is allowlisted by PATTERN rather than method+pattern:
// r.Handle registers every method chi knows, so the walk emits ten entries for
// one registration. It serves bytes out of the embedded build output under a
// hashed-name prefix and reaches no network and no store — see serveAsset in
// internal/server/spa.go, which refuses any name outside the prefix.
const assetRoutePattern = "/assets/*"

func TestLiveRouterSurfaceIsExhaustivelyPinned(t *testing.T) {
	// A non-nil ui so the ui-gated routes are registered; the contents are
	// irrelevant because chi.Walk never invokes a handler, and for the same
	// reason a nil ReadyChecker is safe.
	handler := server.New(nil, &server.API{}, fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}})
	routes, ok := handler.(chi.Routes)
	if !ok {
		t.Fatal("server.New no longer returns a chi router; this closure must be updated, not deleted")
	}

	walked := map[string]bool{}
	sawAssetRoute := false
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route == assetRoutePattern {
			sawAssetRoute = true
			return nil
		}
		key := method + " " + route
		walked[key] = true
		if pinnedContractSurface[key] || pinnedNonContractRoutes[key] != "" {
			return nil
		}
		t.Errorf("%s is a LIVE ROUTE that is in neither the pinned contract surface nor the "+
			"non-API allowlist. If it belongs in the contract, describe it in api/openapi.yaml and "+
			"pin it there; if it is genuinely a non-API route, add it to pinnedNonContractRoutes "+
			"with the one thing that pin exists to record — that it returns this instance's own "+
			"data and never fetches, relays or forwards on the caller's behalf. Criterion 6 is a "+
			"closure claim, and a route registered in Go rather than in the document is precisely "+
			"the way one gets made without anyone writing it down.", key)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(walked) == 0 {
		t.Fatal("the router registered no routes — this check would be vacuously green")
	}
	if !sawAssetRoute {
		t.Errorf("no %q route was registered; if the asset handler is gone, delete assetRoutePattern "+
			"rather than leaving an allowlist entry nothing checks", assetRoutePattern)
	}

	// The other direction, so the pins cannot outlive what they describe.
	for key := range pinnedContractSurface {
		if !walked[key] {
			t.Errorf("%s is pinned in the contract surface but the live router does not serve it — "+
				"the document and the binary disagree", key)
		}
	}
	for key, reason := range pinnedNonContractRoutes {
		if !walked[key] {
			t.Errorf("%s is allowlisted as a non-API route (%s) but is not registered — remove the "+
				"entry. A stale allowlist is where a future route quietly inherits an exemption "+
				"nobody granted it", key, reason)
		}
	}
}

// THE DIRECTORY LISTING'S FIELDS, PINNED.
//
// The two route pins above close the surface by SHAPE, and a route set does
// not change when an existing operation starts returning more. That is the
// remaining half of M6, because criterion 6 is about VALUES, not paths: "no
// endpoint on either instance returns another instance's secret values to a
// server".
//
// The directory listing is the whole of the data half. It is the only payload
// that crosses an instance boundary: serveDirectory is the single operation
// the instance-connection credential may reach (pinned in internal/isolation's
// TestArtifactConfinementTableShape), and a remote's stored snapshot is that
// same listing fetched server-to-server. Every other endpoint answers a caller
// who is already inside this instance.
//
// So the field set below IS the boundary. A field added to DirectoryListing —
// an environment name, a key label, a membership, a setting — widens every
// connection credential in circulation, on every deployment, without a single
// grant changing and without any route moving.
//
// `Remote` is pinned alongside it because it does NOT reference
// DirectoryListing: the snapshot half is INLINED onto the entry as optional
// fields (identity, version, org_count, project_count, orgs), so it is a second
// struct through which another instance's values reach a response, and a pin
// naming only DirectoryListing would leave it unwatched. Its remaining fields
// are this instance's own configuration row; the two halves are marked below,
// and a new field in either half has to be justified before this goes green.
//
// Reflected over the GENERATED structs rather than read out of the YAML,
// because these are the fields that actually serialize: a property added to
// api/openapi.yaml carries no bytes until codegen runs, and a field
// hand-added to the generated file carries bytes with no property at all. Both
// land here. The Go TYPE is pinned alongside the name, since `projects
// []string` becoming `[]somethingRicher` smuggles data through a field set
// that never changed.
func TestDirectoryListingFieldsArePinned(t *testing.T) {
	// json tag -> Go type. Every line is a value that crosses an instance
	// boundary; adding one means answering, in the #71 ADR's terms, why a
	// connection credential should now disclose it.
	pins := []struct {
		typ    reflect.Type
		fields map[string]string
	}{
		{reflect.TypeOf(apigen.DirectoryListing{}), map[string]string{
			"identity":      "string",                // this instance's own opaque id
			"version":       "string",                // display only
			"orgs":          "[]apigen.DirectoryOrg", // names only, see below
			"org_count":     "int",                   // a count of the above
			"project_count": "int",                   // a count of the above
		}},
		{reflect.TypeOf(apigen.DirectoryOrg{}), map[string]string{
			"name":     "string",   // an org NAME, never its id, members or settings
			"projects": "[]string", // project NAMES, and nothing hanging off them
		}},
		{reflect.TypeOf(apigen.Remote{}), map[string]string{
			// The snapshot half: the remote instance's own values, inlined.
			// Each must be a field DirectoryListing above also carries.
			"identity":      "*string",
			"version":       "*string",
			"org_count":     "*int",
			"project_count": "*int",
			"orgs":          "*[]apigen.DirectoryOrg",
			// The local half: this instance's configuration row and the
			// outcome of its own last fetch. Nothing here came from the remote
			// except by this instance observing whether it answered.
			"id":                "string",
			"name":              "string",
			"url":               "string",
			"spki_pin":          "string",
			"created_at":        "time.Time",
			"created_by":        "string",
			"state":             "apigen.RemoteState",
			"last_attempt_at":   "time.Time",
			"observed_at":       "*time.Time",
			"stale":             "bool",
			"stale_for_seconds": "*int",
		}},
	}

	// The snapshot half of `Remote` may only ever carry what the listing
	// carries. Asserted rather than asserted-by-eye, because the two structs
	// are generated from separate YAML blocks and nothing else makes them
	// agree: a field added to `Remote`'s snapshot half with no counterpart in
	// DirectoryListing would be a value this instance shows for a remote that
	// the remote never agreed to serve.
	listing := pins[0].fields
	for _, name := range []string{"identity", "version", "org_count", "project_count", "orgs"} {
		if _, ok := listing[name]; !ok {
			t.Errorf("apigen.Remote inlines snapshot field %q, which DirectoryListing does not "+
				"declare — the entry projects a value the directory endpoint never serves", name)
		}
	}

	for _, pin := range pins {
		got := map[string]string{}
		for i := range pin.typ.NumField() {
			field := pin.typ.Field(i)
			tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if tag == "" {
				tag = field.Name
			}
			got[tag] = field.Type.String()
		}
		for name, typ := range got {
			want, pinned := pin.fields[name]
			if !pinned {
				t.Errorf("%s gained field %q (%s). The directory listing is the ONLY payload that "+
					"crosses an instance boundary, so its field set is criterion 6's data half: a "+
					"new field widens every connection credential already issued, with no grant "+
					"changing and no route moving. If it genuinely carries nothing an operator of "+
					"one instance may not learn about another, pin it here and say why.",
					pin.typ, name, typ)
				continue
			}
			if want != typ {
				t.Errorf("%s field %q changed type from %s to %s. A richer type on an unchanged "+
					"field name is the same widening as a new field, and it is the one a field-name "+
					"pin alone would miss.", pin.typ, name, want, typ)
			}
		}
		for name := range pin.fields {
			if _, ok := got[name]; !ok {
				t.Errorf("%s no longer has pinned field %q — update the pin. A stale pin is one "+
					"nobody re-reads, and re-reading it is the entire mechanism.", pin.typ, name)
			}
		}
	}
}
