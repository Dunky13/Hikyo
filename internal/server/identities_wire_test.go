package server

import (
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/service"
)

// The credential RENDER function, tested where the bug was.
//
// #67 found `listMachineCredentials` dropping every binding member the schema
// says an `oidc-federation` row carries — issuer, subject, audience, the pinned
// claims and the restore predicate's instant — while the service layer beneath
// it had them all. That is a transport defect, so a service-level test can pass
// with the wire still empty; this one runs the render itself.
//
// It is an INTERNAL test (`package server`) because `wireCredential` is
// unexported, which it should stay: it is the single place the never-return-a-
// value rule is kept, and a second caller is exactly what would let a value
// escape.

func TestWireCredentialCarriesTheBindingMembers(t *testing.T) {
	reactivated := time.Date(2026, 8, 4, 2, 0, 0, 0, time.UTC)
	event := "pull_request_target"
	repo := int64(4242)
	view := service.CredentialView{
		ID:        "mcr_00000000-0000-0000-0000-000000000001",
		Kind:      domain.CredentialOIDCFederation,
		Lifetime:  domain.LifetimeFinite,
		ExpiresAt: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy: domain.PrincipalID("pr_00000000-0000-0000-0000-000000000002"),
		Issuer:    "https://token.actions.githubusercontent.com",
		Subject:   "repo:acme/service:ref:refs/heads/main",
		Audience:  "hikyo.example.org/main",
		RequiredClaims: []service.ClaimPin{
			{Claim: "event_name", String: &event},
			{Claim: "repository_id", Number: &repo},
		},
		ReactivatedAt: reactivated,
	}

	out := wireCredential(view)

	if out.Issuer == nil || *out.Issuer != view.Issuer {
		t.Fatalf("issuer = %v, want the byte-exact %q", out.Issuer, view.Issuer)
	}
	if out.Subject == nil || *out.Subject != view.Subject {
		t.Fatalf("subject = %v, want %q", out.Subject, view.Subject)
	}
	if out.Audience == nil || *out.Audience != view.Audience {
		t.Fatalf("audience = %v, want %q", out.Audience, view.Audience)
	}
	// The restore predicate's instant is the reason a workload stopped
	// authenticating; a surface that cannot see it cannot explain the outage.
	if out.ReactivatedAt == nil || !out.ReactivatedAt.Equal(reactivated) {
		t.Fatalf("reactivated_at = %v, want %v", out.ReactivatedAt, reactivated)
	}
	// A binding has no minted value to hint at.
	if out.PrefixHint != nil {
		t.Fatalf("prefix_hint = %q on a binding row, want absent", *out.PrefixHint)
	}

	if out.RequiredClaims == nil {
		t.Fatal("required_claims absent, want both pins")
	}
	pins := map[string]struct {
		str *string
		num *int64
	}{}
	for _, pin := range *out.RequiredClaims {
		pins[pin.Claim] = struct {
			str *string
			num *int64
		}{pin.StringValue, pin.NumberValue}
	}
	// The VALUE, not merely the presence of the pin: `event_name` is the whole
	// CI rule, and an operator auditing a binding has to see which event it
	// admits — a render that carried the claim names and dropped the scalars
	// would look complete and say nothing.
	if got := pins["event_name"].str; got == nil || *got != event {
		t.Fatalf("event_name pin = %v, want %q", got, event)
	}
	// And the discriminated scalar is not folded: `repository_id` is the number
	// 4242 and must never arrive as the string "4242".
	if got := pins["repository_id"].num; got == nil || *got != repo {
		t.Fatalf("repository_id pin = %v, want the number %d", got, repo)
	}
	if pins["repository_id"].str != nil {
		t.Fatalf("repository_id arrived as a string %q; the scalar was folded", *pins["repository_id"].str)
	}
}

func TestWireCredentialLeavesABearerRowWithoutBindingMembers(t *testing.T) {
	// The other direction. Every binding member is the zero value on a bearer
	// credential, and `optional` must render each one ABSENT rather than as an
	// empty string — a client cannot tell "" from "the issuer is unset", and
	// only one of those is a fact.
	out := wireCredential(service.CredentialView{
		ID:         "mcr_00000000-0000-0000-0000-000000000003",
		Kind:       domain.CredentialHikyoToken,
		PrefixHint: "hik_1_wl_9fK2mQ",
		Lifetime:   domain.LifetimeFinite,
		CreatedAt:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		CreatedBy:  domain.PrincipalID("pr_00000000-0000-0000-0000-000000000002"),
	})

	if out.Issuer != nil || out.Subject != nil || out.Audience != nil {
		t.Fatalf("a bearer credential carried binding members: %+v", out)
	}
	if out.RequiredClaims != nil {
		t.Fatalf("a bearer credential carried pinned claims: %+v", *out.RequiredClaims)
	}
	if out.ReactivatedAt != nil {
		t.Fatalf("a bearer credential carried a restore predicate: %v", *out.ReactivatedAt)
	}
	if out.PrefixHint == nil || *out.PrefixHint != "hik_1_wl_9fK2mQ" {
		t.Fatalf("prefix_hint = %v, want the bearer row's hint", out.PrefixHint)
	}
	// And still no value member exists to render — the generated type has none,
	// which is what makes the rule structural rather than a convention.
}
