package audit

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

// --- token-grammar redaction (CI invariant 4: round-trip over the hik_
// grammar including embedded-in-noise cases) ---

func TestRedactTokens(t *testing.T) {
	token := "hik_1_wl_" + strings.Repeat("Ab3", 15) + "x9"
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare token", token, RedactionMarker},
		{"embedded in user agent", "curl/8.1 (auth: " + token + ") linux", "curl/8.1 (auth: " + RedactionMarker + ") linux"},
		{"embedded in noise no delimiters", "xx" + token, "xx" + RedactionMarker},
		{"two tokens", token + " and " + token, RedactionMarker + " and " + RedactionMarker},
		{"automation type", "hik_1_au_" + strings.Repeat("Z", 40), RedactionMarker},
		{"bootstrap type", "hik_2_bs_" + strings.Repeat("k", 30), RedactionMarker},
		{"scim type (amended grammar)", "hik_1_scim_" + strings.Repeat("q", 30), RedactionMarker},
		{"legacy artifact remains secret", "ew_1_wl_" + strings.Repeat("L", 40), RedactionMarker},
		{"prose mentioning hik_ is kept", "the hik_ prefix marks tokens", "the hik_ prefix marks tokens"},
		{"short body is not a token", "hik_1_wl_short", "hik_1_wl_short"},
		{"no match", "ordinary free text", "ordinary free text"},
	}
	for _, c := range cases {
		if got := RedactTokens(c.in); got != c.want {
			t.Errorf("%s: RedactTokens(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestSanitizeFreeText(t *testing.T) {
	if got := SanitizeFreeText("a\x00b\r\nc"); got != "abc" {
		t.Errorf("control characters survive: %q", got)
	}
	if got := SanitizeFreeText("bad\xffutf8"); got != "bad�utf8" {
		t.Errorf("invalid UTF-8 not replaced: %q", got)
	}
	long := strings.Repeat("é", FreeTextBound) // 2 bytes each — must cut on a rune boundary
	got := SanitizeFreeText(long)
	if len(got) > FreeTextBound {
		t.Errorf("bound not applied: %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "é") {
		t.Errorf("truncation split a rune: %q", got[len(got)-4:])
	}
	// Idempotence: the write boundary re-checks by comparing against a
	// second sanitization pass, so the function must be a fixpoint.
	inputs := []string{"plain", "tok hik_1_wl_" + strings.Repeat("A", 40), strings.Repeat("x", 2*FreeTextBound), "c\x01c"}
	for _, in := range inputs {
		once := SanitizeFreeText(in)
		if twice := SanitizeFreeText(once); twice != once {
			t.Errorf("not idempotent on %q: %q != %q", in, twice, once)
		}
	}
}

// --- registry well-formedness (CI invariants 1, 10, 12) ---

func TestRegistryWellFormed(t *testing.T) {
	for _, typ := range Types() {
		spec, _ := Spec(typ)
		cat, action, ok := strings.Cut(string(typ), ".")
		if !ok || cat == "" || action == "" {
			t.Errorf("%s: not category.action shaped", typ)
		}
		if spec.SchemaVersion < 1 {
			t.Errorf("%s: schema version %d", typ, spec.SchemaVersion)
		}
		// Class totality (invariant 10): exactly one retention class.
		if spec.Retention != RetentionAccess && spec.Retention != RetentionSecurity {
			t.Errorf("%s: unclassed retention %q", typ, spec.Retention)
		}
		if len(spec.Outcomes) == 0 {
			t.Errorf("%s: no licensed outcomes", typ)
		}
		if len(spec.Trails) == 0 {
			t.Errorf("%s: no trail declared", typ)
		}
		// Outcome licensing (invariant 12): intent / unknown / disconnected
		// only where the envelope section licenses them.
		if spec.Outcomes[OutcomeIntent] && typ != EventAuditExportStarted && typ != EventAdapterPushIntent {
			t.Errorf("%s: intent outcome licensed outside the INTENT-phase set", typ)
		}
		if spec.Outcomes[OutcomeUnknown] && typ != EventAdapterPushOutcome {
			t.Errorf("%s: unknown outcome licensed outside adapter.push_outcome", typ)
		}
		if spec.Outcomes[OutcomeDisconnected] && typ != EventAuditExportCompleted {
			t.Errorf("%s: disconnected outcome licensed outside audit.export_completed", typ)
		}
	}
}

func TestAdapterCatalogueIsClosedAndLicensesExternalEffectPhases(t *testing.T) {
	want := map[EventType]bool{
		EventAdapterConfigure: true, EventAdapterCredentialReplace: true, EventAdapterCredentialRevoke: true,
		EventAdapterAdopt: true, EventAdapterInspect: true, EventAdapterPlan: true, EventAdapterTest: true,
		EventAdapterSyncRequested: true, EventAdapterPushIntent: true, EventAdapterPushOutcome: true,
		EventAdapterKeyDelivered: true, EventAdapterAbort: true, EventAdapterScrub: true, EventAdapterSuperseded: true,
	}
	for _, typ := range Types() {
		if typ.Category() == "adapter" {
			if !want[typ] {
				t.Errorf("unexpected adapter event %q", typ)
			}
			delete(want, typ)
		}
	}
	for missing := range want {
		t.Errorf("missing adapter event %q", missing)
	}
	intent, _ := Spec(EventAdapterPushIntent)
	outcome, _ := Spec(EventAdapterPushOutcome)
	if len(intent.Outcomes) != 1 || !intent.Outcomes[OutcomeIntent] {
		t.Errorf("push intent outcomes = %v", intent.Outcomes)
	}
	if !outcome.Outcomes[OutcomeUnknown] || outcome.Outcomes[OutcomeIntent] {
		t.Errorf("push outcome outcomes = %v", outcome.Outcomes)
	}
	exact := map[EventType][]Outcome{
		EventAdapterConfigure:         {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterCredentialReplace: {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterCredentialRevoke:  {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterAdopt:             {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterInspect:           {OutcomeSuccess, OutcomeDenied},
		EventAdapterPlan:              {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterTest:              {OutcomeSuccess, OutcomeDenied, OutcomeFailure},
		EventAdapterSyncRequested:     {OutcomeSuccess, OutcomeDenied},
		EventAdapterPushIntent:        {OutcomeIntent},
		EventAdapterPushOutcome:       {OutcomeSuccess, OutcomeFailure, OutcomeUnknown},
		EventAdapterKeyDelivered:      {OutcomeSuccess},
		EventAdapterAbort:             {OutcomeFailure},
		EventAdapterScrub:             {OutcomeSuccess, OutcomeFailure},
		EventAdapterSuperseded:        {OutcomeSuccess},
	}
	for typ, allowed := range exact {
		spec, _ := Spec(typ)
		if len(spec.Outcomes) != len(allowed) {
			t.Errorf("%s outcomes = %v, want exactly %v", typ, spec.Outcomes, allowed)
			continue
		}
		for _, value := range allowed {
			if !spec.Outcomes[value] {
				t.Errorf("%s outcomes = %v, missing %s", typ, spec.Outcomes, value)
			}
		}
	}
}

func TestAdapterAuthorityAuditSchemasAreClosed(t *testing.T) {
	credential, _ := Spec(EventAdapterCredentialReplace)
	wantCredential := map[string]bool{"credential_present": true, "previous_authority": true, "authority": true}
	if len(credential.Schema) != len(wantCredential) {
		t.Fatalf("credential_replace fields=%v, want exactly %v", credential.Schema, wantCredential)
	}
	for field := range wantCredential {
		got, ok := credential.Schema[field]
		if !ok || !got.Required {
			t.Errorf("credential_replace field %q=%+v, want required", field, got)
		}
	}
	configure, _ := Spec(EventAdapterConfigure)
	if got := configure.Schema["previous_authority"]; got.Required {
		t.Fatalf("configure previous_authority=%+v, narrowing must be able to omit it", got)
	}
	if got := configure.Schema["authority"]; !got.Required {
		t.Fatalf("configure authority=%+v, want required", got)
	}
}

func TestCLIReauthHandoffAuditSchemaIsClosed(t *testing.T) {
	spec, ok := Spec(EventAuthCLIReauthHandoff)
	if !ok {
		t.Fatal("auth.cli_reauth_handoff is not registered")
	}
	if len(spec.Outcomes) != 2 || !spec.Outcomes[OutcomeSuccess] || !spec.Outcomes[OutcomeFailure] {
		t.Fatalf("outcomes=%v, want exactly success|failure", spec.Outcomes)
	}
	want := map[string]bool{
		"phase": true, "handoff_id": false, "operation": false,
		"environment_ids": false, "cause": false,
	}
	if len(spec.Schema) != len(want) {
		t.Fatalf("fields=%v, want exactly %v", spec.Schema, want)
	}
	for field, required := range want {
		got, ok := spec.Schema[field]
		if !ok || got.Required != required {
			t.Errorf("field %q=%+v, required=%t", field, got, required)
		}
	}
	if got := spec.Schema["phase"].Enum; !slices.Equal(got, []string{"start", "inspect", "approve", "redeem"}) {
		t.Errorf("phase enum=%v", got)
	}
	if got := spec.Schema["cause"].Enum; !slices.Equal(got, []string{"invalid_request", "unauthenticated", "unauthorized", "invalid_or_expired", "reauth_required", "pkce_mismatch", "already_consumed"}) {
		t.Errorf("cause enum=%v", got)
	}
	for _, forbidden := range []string{"state", "code", "verifier", "bearer", "credential"} {
		if _, ok := spec.Schema[forbidden]; ok {
			t.Errorf("forbidden handoff payload field %q is registered", forbidden)
		}
	}
}

// TestRegistryForbiddenPayloadContent is invariant 4's schema half: no
// registered payload schema may declare a field whose name suggests it
// carries the forbidden content classes (secret plaintext, bearer/credential
// material, password/MFA material, instance-derived JSON paths).
func TestRegistryForbiddenPayloadContent(t *testing.T) {
	forbidden := []string{
		"value", "plaintext", "secret", "token", "bearer", "password",
		"verifier", "mfa", "seed", "recovery_code", "json_path", "path",
	}
	for _, typ := range Types() {
		for field := range mustSpec(typ).Schema {
			lower := strings.ToLower(field)
			for _, bad := range forbidden {
				if lower == bad || strings.HasSuffix(lower, "_"+bad) || strings.HasPrefix(lower, bad+"_") {
					t.Errorf("%s: payload field %q matches forbidden content class %q", typ, field, bad)
				}
			}
		}
	}
}

// TestRegistryNoOutcomeShadow: no payload field may shadow the envelope
// outcome (invariant 12).
func TestRegistryNoOutcomeShadow(t *testing.T) {
	for _, typ := range Types() {
		for field := range mustSpec(typ).Schema {
			if strings.EqualFold(field, "outcome") {
				t.Errorf("%s: payload field %q shadows the envelope outcome", typ, field)
			}
		}
	}
}

// --- envelope validation ---

func validEvent() (Event, domain.Scope) {
	return Event{
		ID:            "evt_0198b6de-0000-7000-8000-000000000001",
		Type:          EventGrantDenied,
		SchemaVersion: 1,
		OccurredAt:    time.Now().UTC(),
		Actor:         Actor{ID: "usr_a", Class: ActorHuman, CredentialID: "ses_a"},
		Outcome:       OutcomeDenied,
		Origin:        OriginAPI,
		Payload: Payload{
			"operation":  "environment.read",
			"formula":    "read@environment",
			"resolution": "resolvable",
		},
	}, domain.Scope{Org: "org_a"}
}

func TestValidateAccepts(t *testing.T) {
	e, scope := validEvent()
	if err := Validate(e, TrailTenant, scope); err != nil {
		t.Fatalf("valid event refused: %v", err)
	}
}

func TestValidateRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Event, *domain.Scope)
		trail Trail
		want  string
	}{
		{"unregistered type", func(e *Event, _ *domain.Scope) { e.Type = "nope.nope" }, TrailTenant, "closed registry"},
		{"missing id", func(e *Event, _ *domain.Scope) { e.ID = "" }, TrailTenant, "without an id"},
		{"schema version drift", func(e *Event, _ *domain.Scope) { e.SchemaVersion = 2 }, TrailTenant, "schema version"},
		{"unlicensed outcome", func(e *Event, _ *domain.Scope) { e.Outcome = OutcomeSuccess }, TrailTenant, "not licensed"},
		{"zero occurred_at", func(e *Event, _ *domain.Scope) { e.OccurredAt = time.Time{} }, TrailTenant, "occurred_at"},
		{"unknown actor class", func(e *Event, _ *domain.Scope) { e.Actor.Class = "robot" }, TrailTenant, "actor class"},
		{"unauthenticated with principal", func(e *Event, _ *domain.Scope) { e.Actor = Actor{ID: "x", Class: ActorUnauthenticated} }, TrailTenant, "unauthenticated"},
		{"unknown origin", func(e *Event, _ *domain.Scope) { e.Origin = "carrier-pigeon" }, TrailTenant, "origin"},
		{"tenant event without chain", func(_ *Event, s *domain.Scope) { *s = domain.Scope{} }, TrailTenant, "org chain"},
		{"gapped chain", func(_ *Event, s *domain.Scope) { *s = domain.Scope{Org: "o", Env: "e"} }, TrailTenant, "scope"},
		{"instance event with chain", func(e *Event, _ *domain.Scope) { e.Payload["resolution"] = "unresolvable" }, TrailInstance, "tenant chain"},
		{"unregistered payload field", func(e *Event, _ *domain.Scope) { e.Payload["grants_missing"] = "reveal" }, TrailTenant, "not in the registered schema"},
		{"missing required field", func(e *Event, _ *domain.Scope) { delete(e.Payload, "formula") }, TrailTenant, "required field"},
		{"kind mismatch", func(e *Event, _ *domain.Scope) { e.Payload["operation"] = 7 }, TrailTenant, "want string"},
		{"unsanitized free text", func(e *Event, _ *domain.Scope) { e.Payload["claimed_org"] = "org\x00evil" }, TrailTenant, "sanitized"},
		{"token in free text", func(e *Event, _ *domain.Scope) { e.Payload["claimed_org"] = "hik_1_wl_" + strings.Repeat("A", 40) }, TrailTenant, "sanitized"},
		{"unsanitized user agent", func(e *Event, _ *domain.Scope) { e.UserAgent = "agent\x07" }, TrailTenant, "user_agent"},
	}
	for _, c := range cases {
		e, scope := validEvent()
		c.mut(&e, &scope)
		err := Validate(e, c.trail, scope)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestValidateWrongTrail(t *testing.T) {
	e, _ := validEvent()
	e.Type = EventProjectCreated
	e.Payload = Payload{"name": "proj"}
	e.Outcome = OutcomeSuccess
	if err := Validate(e, TrailInstance, domain.Scope{}); err == nil {
		t.Fatal("tenant-only type accepted on the instance trail")
	}
}

func TestScopeClass(t *testing.T) {
	for _, c := range []struct {
		scope domain.Scope
		trail Trail
		want  string
	}{
		{domain.Scope{}, TrailInstance, "instance"},
		{domain.Scope{Org: "o"}, TrailTenant, "org"},
		{domain.Scope{Org: "o", Project: "p"}, TrailTenant, "project"},
		{domain.Scope{Org: "o", Project: "p", Env: "e"}, TrailTenant, "env"},
	} {
		got, err := ScopeClass(c.trail, c.scope)
		if err != nil || got != c.want {
			t.Errorf("ScopeClass(%v, %v) = %q, %v; want %q", c.trail, c.scope, got, err, c.want)
		}
	}
	if _, err := ScopeClass(TrailTenant, domain.Scope{}); err == nil {
		t.Error("empty tenant scope accepted")
	}
}

func mustSpec(t EventType) TypeSpec {
	spec, ok := Spec(t)
	if !ok {
		panic("unregistered type in test: " + string(t))
	}
	return spec
}
