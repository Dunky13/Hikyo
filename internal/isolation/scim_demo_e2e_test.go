package isolation

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/internal/cli"
	"github.com/Hikyo-Org/hikyo/internal/scimproto"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

// runSCIMDemo drives the whole SCIM surface through the REAL CLI over the real
// socket, and then drives the identity provider's own wire with the credential
// that CLI minted. It is the only fixture that exercises
// CLI -> HTTP -> service -> store for #73; every other test asserts one layer.
//
// The wire half is deliberately raw HTTP rather than a client helper: an
// identity provider is not a Hikyo client, and a helper that shared code with
// the server would prove less than a request built the way Okta builds one.
// It deliberately does NOT re-login at the end: nothing here grants the acting
// administrator anything, so their session survives — which is itself the
// point that a sync grants the PROVISIONED human, not the operator.
func runSCIMDemo(t *testing.T, db *store.DB, ios func() cli.IO, baseURL, orgID string) {
	t.Helper()

	run := func(args ...string) (string, int) {
		t.Helper()
		out, errOut := &strings.Builder{}, &strings.Builder{}
		io := ios()
		io.Stdout, io.Stderr = out, errOut
		code := cli.Run(t.Context(), io, args)
		if code != cli.ExitOK {
			return out.String() + errOut.String(), code
		}
		return out.String(), code
	}
	mustRun := func(args ...string) string {
		t.Helper()
		out, code := run(args...)
		if code != cli.ExitOK {
			t.Fatalf("hikyo %s exited %d\n%s", strings.Join(args, " "), code, out)
		}
		return out
	}
	decode := func(raw string, into any) {
		t.Helper()
		if err := json.Unmarshal([]byte(raw), into); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, raw)
		}
	}

	org := struct{ Id string }{Id: orgID}
	seedSCIMProvider(t, db, "demo-idp", "https://demo-idp.example.test", true)

	// 1. Create the binding.
	var binding struct {
		Id            string
		ProviderSlug  string `json:"provider_slug"`
		SubjectSource string `json:"subject_source"`
		Attention     []struct{ State string }
	}
	// `--kind` is required, not defaulted: a provider name is unique only
	// within its family, so naming one without its kind identifies nothing.
	if out, code := run("scim", "binding", "create", "--org", org.Id,
		"--provider", "demo-idp", "-o", "json"); code == cli.ExitOK {
		t.Fatalf("a binding create with no --kind must be refused:\n%s", out)
	}
	decode(mustRun("scim", "binding", "create", "--org", org.Id,
		"--provider", "demo-idp", "--kind", "oidc", "-o", "json"), &binding)
	if binding.SubjectSource != "externalId" {
		t.Fatalf("binding subject source = %q", binding.SubjectSource)
	}
	// A brand-new binding is NOT stale: §9 makes staleness a threshold measured
	// from creation, and a warning that fires the moment a binding exists says
	// nothing about the identity provider's health.
	if strings.Contains(strings.Join(attentionStates(binding.Attention), ","), "stale") {
		t.Fatalf("a brand-new binding must not be stale before the threshold: %+v", binding.Attention)
	}

	// 2. Mint the display-once credential through the print triad. The
	//    destination preparation runs BEFORE the mint, so a credential is never created and
	//    then dropped for want of somewhere to put it (the refusal leg itself
	//    is #54's fixture; this demo has a terminal available, which is the
	//    triad's third leg).
	minted := mustRun("scim", "credential", "mint", binding.Id, "--org", org.Id,
		"--dangerously-print", "-o", "json")
	token := extractSCIMToken(t, minted)
	if !strings.HasPrefix(token, "hik_1_scim_") {
		t.Fatalf("minted credential does not carry the hik_<v>_scim_ grammar: %q", token)
	}
	// The reauthentication evidence is SINGLE-USE and is consumed inside the
	// mint transaction. The terminal answers the prompt with the same code it
	// just used — which is exactly what a stolen elevated session replaying one
	// observed code would do — and the second mint is refused. Without the
	// in-transaction consume this succeeded, and one code minted an unbounded
	// number of year-long bearers.
	if out, code := run("scim", "credential", "mint", binding.Id, "--org", org.Id,
		"--dangerously-print", "-o", "json"); code == cli.ExitOK {
		t.Fatalf("a replayed reauthentication proof must not mint a second credential:\n%s", out)
	}

	// 3. The identity provider's own wire, with that credential.
	wire := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(raw)
		}
		url := baseURL + api.PathPrefix + "/orgs/" + org.Id + "/scim/v2/" + binding.Id + path
		req, err := http.NewRequestWithContext(t.Context(), method, url, reader)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", scimproto.MediaType)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		out := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			_ = json.Unmarshal(raw, &out)
		}
		return res.StatusCode, out
	}

	// Discovery advertises the closed truth, and the absences are real.
	status, spc := wire(http.MethodGet, "/ServiceProviderConfig", nil)
	if status != http.StatusOK {
		t.Fatalf("ServiceProviderConfig = %d %v", status, spc)
	}
	if bulk, _ := spc["bulk"].(map[string]any); bulk == nil || bulk["supported"] != false {
		t.Fatalf("ServiceProviderConfig must advertise Bulk as absent: %v", spc["bulk"])
	}
	if status, body := wire(http.MethodPost, "/Bulk", map[string]any{}); status != http.StatusNotImplemented {
		t.Fatalf("Bulk = %d %v, want 501", status, body)
	} else if _, hasType := body["scimType"]; hasType {
		t.Fatalf("a 501 must carry no scimType: %v", body)
	}

	// Provision a user and a group, the way a connector does.
	status, created := wire(http.MethodPost, "/Users", map[string]any{
		"schemas":  []string{scimproto.SchemaUser},
		"userName": "demo@idp.test", "externalId": "demo-sub", "active": true,
		"name": map[string]any{"givenName": "Demo"},
	})
	if status != http.StatusCreated {
		t.Fatalf("user create = %d %v", status, created)
	}
	userID, _ := created["id"].(string)
	if userID == "" {
		t.Fatalf("user create returned no id: %v", created)
	}
	// `groups` is response-only and always present, so a connector never has to
	// distinguish absent from empty.
	if _, ok := created["groups"]; !ok {
		t.Fatalf("the User response must carry `groups`: %v", created)
	}

	// The `password` attribute is refused BY NAME.
	if status, body := wire(http.MethodPost, "/Users", map[string]any{
		"userName": "nope@idp.test", "externalId": "nope", "password": "hunter2",
	}); status != http.StatusBadRequest || body["scimType"] != scimproto.TypeInvalidValue {
		t.Fatalf("password must be refused with invalidValue: %d %v", status, body)
	}

	status, group := wire(http.MethodPost, "/Groups", map[string]any{
		"schemas": []string{scimproto.SchemaGroup}, "displayName": "Demo Engineers",
		"members": []any{map[string]any{"value": userID}},
	})
	if status != http.StatusCreated {
		t.Fatalf("group create = %d %v", status, group)
	}
	groupID, _ := group["id"].(string)

	// The `displayName eq` discovery probe both Okta and Entra issue.
	status, list := wire(http.MethodGet, `/Groups?filter=displayName+eq+%22Demo+Engineers%22`, nil)
	if status != http.StatusOK {
		t.Fatalf("group filter = %d %v", status, list)
	}
	if total, _ := list["totalResults"].(float64); total != 1 {
		t.Fatalf("displayName eq must resolve to exactly one group: %v", list)
	}
	// An unsupported filter is `invalidFilter`, never a silently wrong set.
	if status, body := wire(http.MethodGet, `/Users?filter=userName+sw+%22demo%22`, nil); status != http.StatusBadRequest ||
		body["scimType"] != scimproto.TypeInvalidFilter {
		t.Fatalf("an unsupported filter must be invalidFilter: %d %v", status, body)
	}
	// Sorting is advertised absent and refused by name.
	if status, body := wire(http.MethodGet, "/Users?sortBy=userName", nil); status != http.StatusNotImplemented {
		t.Fatalf("sortBy must be refused with 501: %d %v", status, body)
	}
	// A PATCH cell outside the closed matrix is `invalidPath`.
	if status, body := wire(http.MethodPatch, "/Users/"+userID, map[string]any{
		"schemas":    []string{scimproto.SchemaPatchOp},
		"Operations": []any{map[string]any{"op": "add", "path": "members", "value": []any{}}},
	}); status != http.StatusBadRequest || body["scimType"] != scimproto.TypeInvalidPath {
		t.Fatalf("`members` on a User must be invalidPath: %d %v", status, body)
	}

	// 3b. The ACCEPTED cells of the closed PATCH matrix, over the wire. The
	//     per-cell parse fixtures live in internal/scimproto; these prove the
	//     fold BEHIND them — the pathless merge, the member-set union, the
	//     single-reference removal, and Entra's stringified booleans — reaches
	//     the desired state a connector expects.
	patch := func(path string, ops ...map[string]any) (int, map[string]any) {
		t.Helper()
		return wire(http.MethodPatch, path, map[string]any{
			"schemas": []string{scimproto.SchemaPatchOp}, "Operations": ops,
		})
	}

	// `active` with Entra's stringified booleans, both directions. This is also
	// the deprovision/reactivate transition driven through PATCH.
	if status, body := patch("/Users/"+userID,
		map[string]any{"op": "replace", "path": "active", "value": "False"}); status != http.StatusOK {
		t.Fatalf(`PATCH active="False" = %d %v`, status, body)
	} else if body["active"] != false {
		t.Fatalf(`Entra's "False" must normalize to false: %v`, body["active"])
	}
	if status, body := patch("/Users/"+userID,
		map[string]any{"op": "replace", "path": "active", "value": "True"}); status != http.StatusOK {
		t.Fatalf(`PATCH active="True" = %d %v`, status, body)
	} else if body["active"] != true {
		t.Fatalf(`Entra's "True" must normalize to true: %v`, body["active"])
	}

	// The pathless value object merges, and the merged attribute round-trips as
	// display metadata.
	if status, body := patch("/Users/"+userID,
		map[string]any{"op": "add", "value": map[string]any{"nickName": "Dee"}}); status != http.StatusOK {
		t.Fatalf("PATCH pathless merge = %d %v", status, body)
	}
	if status, body := wire(http.MethodGet, "/Users/"+userID, nil); status != http.StatusOK ||
		body["nickName"] != "Dee" {
		t.Fatalf("a merged attribute must round-trip: %d %v", status, body)
	}

	// A second provisioned user, so `add` on `members` can be shown to UNION
	// rather than replace — the distinction the matrix's two cells exist for.
	status, second := wire(http.MethodPost, "/Users", map[string]any{
		"userName": "second@idp.test", "externalId": "second-sub", "active": true,
	})
	if status != http.StatusCreated {
		t.Fatalf("second user create = %d %v", status, second)
	}
	secondID, _ := second["id"].(string)

	if status, body := patch("/Groups/"+groupID, map[string]any{
		"op": "add", "path": "members", "value": []any{map[string]any{"value": secondID}},
	}); status != http.StatusOK {
		t.Fatalf("PATCH add members = %d %v", status, body)
	} else if got := memberValues(body); len(got) != 2 {
		t.Fatalf("`add` on members must UNION with the stored set, got %v", got)
	}

	// `members[value eq "…"]` removes exactly one reference, leaving the rest.
	if status, body := patch("/Groups/"+groupID, map[string]any{
		"op": "remove", "path": `members[value eq "` + secondID + `"]`,
	}); status != http.StatusOK {
		t.Fatalf("PATCH remove members[value eq] = %d %v", status, body)
	} else if got := memberValues(body); len(got) != 1 || got[0] != userID {
		t.Fatalf("the filtered remove must drop exactly one reference, got %v", got)
	}

	// PUT is RFC replacement, over the wire: omitted mutables clear, an omitted
	// `active` reactivates, and the subject source is EXEMPT — a PUT that never
	// mentions `externalId` must not be read as an identifier migration.
	if status, put := wire(http.MethodPut, "/Users/"+userID, map[string]any{
		"schemas": []string{scimproto.SchemaUser}, "userName": "demo@idp.test",
	}); status != http.StatusOK {
		t.Fatalf("PUT = %d %v", status, put)
	} else {
		if put["externalId"] != "demo-sub" {
			t.Fatalf("the subject source is exempt from replacement: %v", put["externalId"])
		}
		if put["active"] != true {
			t.Fatalf("an omitted `active` must reactivate: %v", put["active"])
		}
		if _, cleared := put["nickName"]; cleared {
			t.Fatalf("PUT must clear omitted mutable attributes: %v", put)
		}
	}
	// An explicit DIFFERENT subject is still the migration attempt the identity
	// model refuses, with `mutability`.
	if status, body := wire(http.MethodPut, "/Users/"+userID, map[string]any{
		"userName": "demo@idp.test", "externalId": "moved-sub",
	}); status != http.StatusBadRequest || body["scimType"] != scimproto.TypeMutability {
		t.Fatalf("an explicit subject change must be `mutability`: %d %v", status, body)
	}
	// A group whose displayName contains a logical operator: created, and found
	// by the discovery probe a quote-blind filter parser would have refused.
	if status, body := wire(http.MethodPost, "/Groups", map[string]any{
		"displayName": "Sales and Marketing",
	}); status != http.StatusCreated {
		t.Fatalf("group create = %d %v", status, body)
	}
	if status, body := wire(http.MethodGet,
		`/Groups?filter=displayName+eq+%22Sales+and+Marketing%22`, nil); status != http.StatusOK {
		t.Fatalf("quoted-value filter = %d %v", status, body)
	} else if total, _ := body["totalResults"].(float64); total != 1 {
		t.Fatalf("a value containing `and` must still resolve: %v", body)
	}

	// 4. Map the group to a template. The consequence language is
	//    server-authored and the grants exist by the time this returns.
	var mapped struct {
		Mapping struct {
			Id           string
			Capabilities []string
		}
		Warnings []struct {
			Code     string
			Severity string
			Message  string
		}
		MembersAffected int `json:"members_affected"`
		GrantsCreated   int `json:"grants_created"`
	}
	// No scope named is a usage error: an org-scoped row is the widest a
	// binding can create and must be asked for explicitly.
	if out, code := run("scim", "mapping", "add", binding.Id, "--org", org.Id,
		"--group", groupID, "--template", "viewer", "-o", "json"); code == cli.ExitOK {
		t.Fatalf("a mapping row with no named scope must be refused:\n%s", out)
	}
	decode(mustRun("scim", "mapping", "add", binding.Id, "--org", org.Id,
		"--group", groupID, "--template", "viewer", "--org-scope", "-o", "json"), &mapped)
	if mapped.MembersAffected != 1 || mapped.GrantsCreated == 0 {
		t.Fatalf("the mapping must grant the group's current members: %+v", mapped)
	}
	if len(mapped.Warnings) == 0 {
		t.Fatalf("an org-scoped row must carry the consequence language: %+v", mapped)
	}
	var sawOrgScope bool
	for _, w := range mapped.Warnings {
		if w.Code == "org_scope" && w.Message != "" {
			sawOrgScope = true
		}
	}
	if !sawOrgScope {
		t.Fatalf("the org-scope warning is missing or empty: %+v", mapped.Warnings)
	}

	// 5. The directory view shows the provisioned human, and the membership
	//    surface shows the grants the mapping caused with their origin chips.
	var users struct {
		Items []struct {
			Id       string
			UserName string `json:"user_name"`
			Groups   []string
		}
	}
	decode(mustRun("scim", "user", "list", binding.Id, "--org", org.Id, "-o", "json"), &users)
	// Two provisioned users: the mapped one, and the second the member-union
	// fixture created and then removed from the group again.
	if len(users.Items) != 2 {
		t.Fatalf("directory view = %+v", users.Items)
	}
	var mappedMember bool
	for _, u := range users.Items {
		if u.UserName == "demo@idp.test" && len(u.Groups) == 1 {
			mappedMember = true
		}
		if u.UserName == "second@idp.test" && len(u.Groups) != 0 {
			t.Fatalf("the filtered remove must have left no membership: %+v", u)
		}
	}
	if !mappedMember {
		t.Fatalf("the mapped user is missing its group membership: %+v", users.Items)
	}
	var members struct {
		Items []struct {
			Capability string
			Origins    []struct{ Kind string }
		}
	}
	decode(mustRun("access", "grant", "list", "--org", org.Id, "-o", "json"), &members)
	var sawSCIMOrigin bool
	for _, m := range members.Items {
		for _, o := range m.Origins {
			if o.Kind == "scim" {
				sawSCIMOrigin = true
			}
		}
	}
	if !sawSCIMOrigin {
		t.Fatal("the membership surface must show a `scim` origin chip for a sync-created grant")
	}

	// 6. Revoking a SCIM-held grant by hand is REFUSED, and the surface says
	//    WHY: the membership line carries the `scim` origin chip, which is the
	//    ADR's own answer to "why can they?".
	//
	//    The refusal TEXT naming both remediations is the service-layer
	//    sentinel (service.ErrSCIMOriginOnly, fixtured in
	//    TestSCIMMappingReconciliation). It cannot ride this response body:
	//    the locked wire rule is a FIXED message per error code, and only
	//    `bad_request` — decided before any tenant resolution — may carry a
	//    detail. Recorded as a deviation in the handoff rather than smuggled
	//    past the rule with a bespoke code.
	if _, code := run("access", "grant", "remove", "--org", org.Id,
		"--principal", scimDemoPrincipal(t, db, userID), "--capability", "read"); code == cli.ExitOK {
		t.Fatal("a hand revoke of a SCIM-held grant must be refused")
	}
	if !sawSCIMOrigin {
		t.Fatal("the refusal is only actionable because the membership line names the origin")
	}

	// 7. Teardown through the CLI, and the credential dies with the binding.
	mustRun("scim", "mapping", "remove", binding.Id, "--org", org.Id,
		"--group", groupID, "--org-scope", "-o", "json")
	if _, code := run("scim", "binding", "delete", binding.Id, "--org", org.Id); code != cli.ExitOK {
		t.Fatal("binding delete failed")
	}
	if status, _ := wire(http.MethodGet, "/Users", nil); status != http.StatusUnauthorized &&
		status != http.StatusNotFound {
		t.Fatalf("the credential must be dead after its binding is deleted, got %d", status)
	}
}

func attentionStates(in []struct{ State string }) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.State)
	}
	return out
}

// extractSCIMToken pulls the display-once value out of the mint output. The
// print triad writes the secret to stdout beside the JSON document, so the
// token is found by its grammar rather than by position.
func extractSCIMToken(t *testing.T, out string) string {
	t.Helper()
	for _, field := range strings.Fields(out) {
		trimmed := strings.Trim(field, `",`)
		if strings.HasPrefix(trimmed, "hik_1_scim_") {
			return trimmed
		}
	}
	t.Fatalf("no provisioning credential in the mint output:\n%s", out)
	return ""
}

func scimDemoPrincipal(t *testing.T, db *store.DB, scimUserID string) string {
	t.Helper()
	return string(principalOf(t, db, accountOf(t, db, scimUserID)))
}

// memberValues pulls the member ids out of a rendered Group resource.
func memberValues(body map[string]any) []string {
	raw, _ := body["members"].([]any)
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		if ref, ok := m.(map[string]any); ok {
			if v, ok := ref["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}
