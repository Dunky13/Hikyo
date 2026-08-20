package api_test

import (
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/api"
)

// Secret-scanning contract sweep (#74, SS3 no-blanket-override / SS4
// non-disclosure). It proves two structural properties of the wire contract:
//
//   - the ONLY secret-scanning acknowledgement input anywhere is the
//     per-finding `acknowledgements` token array; no boolean "ignore all
//     findings", "disable scanning" or "skip scan" input exists on any request
//     schema (a blanket override is structurally impossible, ADR §4);
//   - the finding DTO carries a rule id and a locator and NOTHING derived from
//     the matched material — no match text, offset, length, excerpt, or value
//     field (ADR §4, SS4).

func TestNoBlanketScanOverrideInput(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	// Any request property whose name suggests a blanket toggle over scanning is
	// forbidden. The per-finding token array `acknowledgements` is the only
	// sanctioned input and is explicitly allowed.
	// Scanning-specific verbs only: a blanket toggle names scanning or findings.
	// A field unrelated to scanning (e.g. SAML `force_sign_requests`) is not one.
	banned := []string{"ignore_finding", "ignore_scan", "skip_scan",
		"skip_finding", "disable_scan", "disable_finding", "bypass_scan",
		"suppress_finding", "suppress_scan", "ignore_all_finding", "override_all_finding"}
	for name, ref := range doc.Components.Schemas {
		if ref.Value == nil {
			continue
		}
		for prop := range ref.Value.Properties {
			lower := strings.ToLower(prop)
			for _, b := range banned {
				if strings.Contains(lower, b) {
					t.Errorf("schema %s carries a blanket scan-override input %q; only the per-finding acknowledgements array is permitted", name, prop)
				}
			}
		}
	}
}

func TestAcknowledgementsIsAPerFindingTokenArray(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	acks := doc.Components.Schemas["Acknowledgements"]
	if acks == nil || acks.Value == nil {
		t.Fatal("Acknowledgements schema is missing")
	}
	if !acks.Value.Type.Is("array") {
		t.Fatalf("Acknowledgements must be an array of tokens, got type %v — a boolean here would be a blanket override", acks.Value.Type)
	}
	if acks.Value.Items == nil || acks.Value.Items.Value == nil || !acks.Value.Items.Value.Type.Is("string") {
		t.Fatal("Acknowledgements items must be strings (opaque tokens)")
	}
}

func TestScanFindingCarriesNoMatchedContent(t *testing.T) {
	doc, err := api.Doc()
	if err != nil {
		t.Fatal(err)
	}
	finding := doc.Components.Schemas["ScanFinding"]
	if finding == nil || finding.Value == nil {
		t.Fatal("ScanFinding schema is missing")
	}
	// The closed field set: rule_id, surface, locator, acknowledgement. Anything
	// that could carry matched material is banned by construction.
	for _, banned := range []string{"match", "matched_text", "matched", "offset",
		"length", "excerpt", "value", "content", "plaintext", "fingerprint"} {
		for prop := range finding.Value.Properties {
			if strings.Contains(strings.ToLower(prop), banned) {
				t.Errorf("ScanFinding carries a disclosing field %q (matches banned token %q)", prop, banned)
			}
		}
	}
	for _, want := range []string{"rule_id", "surface", "locator"} {
		if finding.Value.Properties[want] == nil {
			t.Errorf("ScanFinding is missing the required field %q", want)
		}
	}
}
