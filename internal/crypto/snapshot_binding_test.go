package crypto

import (
	"strings"
	"testing"
)

func baseSnapshotScope() SnapshotBindingScope {
	return SnapshotBindingScope{
		StorageDir:            "/state/compose/acme",
		InstanceOrigin:        "https://hikyo.example.internal",
		OrgID:                 "org_1",
		ProjectID:             "prj_1",
		EnvironmentID:         "env_1",
		CredentialFingerprint: "fp_1",
		ConfigOnly:            false,
		TargetNames:           []string{"worker", "api", "api"},
	}
}

func baseSnapshotDelivery() SnapshotBindingDelivery {
	return SnapshotBindingDelivery{
		CredentialID:   "cred_1",
		PinnedRevision: 7,
		ChangeToken:    "v1:manifest-token-1",
		Projection:     []string{"reveal", "read", "reveal"},
		IssuedAt:       "2026-08-19T10:00:00Z",
		ExpiresAt:      "2026-08-26T10:00:00Z",
	}
}

func completeSnapshotBinding(t *testing.T) SnapshotBinding {
	t.Helper()
	binding, err := NewSnapshotBinding(baseSnapshotScope())
	if err != nil {
		t.Fatal(err)
	}
	binding, err = binding.WithDelivery(baseSnapshotDelivery())
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestSnapshotBindingConstructorRejectsImpossibleStates(t *testing.T) {
	for name, mutate := range map[string]func(*SnapshotBindingScope){
		"instance":               func(s *SnapshotBindingScope) { s.InstanceOrigin = "" },
		"storage":                func(s *SnapshotBindingScope) { s.StorageDir = "" },
		"org":                    func(s *SnapshotBindingScope) { s.OrgID = "" },
		"project":                func(s *SnapshotBindingScope) { s.ProjectID = "" },
		"environment":            func(s *SnapshotBindingScope) { s.EnvironmentID = "" },
		"credential fingerprint": func(s *SnapshotBindingScope) { s.CredentialFingerprint = "" },
		"targets":                func(s *SnapshotBindingScope) { s.TargetNames = nil },
		"empty target":           func(s *SnapshotBindingScope) { s.TargetNames = []string{"api", ""} },
	} {
		t.Run("scope/"+name, func(t *testing.T) {
			scope := baseSnapshotScope()
			mutate(&scope)
			if _, err := NewSnapshotBinding(scope); err == nil {
				t.Fatal("constructor accepted invalid scope")
			}
		})
	}

	base, err := NewSnapshotBinding(baseSnapshotScope())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SnapshotBindingDelivery){
		"credential":       func(d *SnapshotBindingDelivery) { d.CredentialID = "" },
		"revision":         func(d *SnapshotBindingDelivery) { d.PinnedRevision = -1 },
		"change token":     func(d *SnapshotBindingDelivery) { d.ChangeToken = "" },
		"projection":       func(d *SnapshotBindingDelivery) { d.Projection = nil },
		"empty projection": func(d *SnapshotBindingDelivery) { d.Projection = []string{"read", ""} },
		"issued at":        func(d *SnapshotBindingDelivery) { d.IssuedAt = "not-a-time" },
		"expires at":       func(d *SnapshotBindingDelivery) { d.ExpiresAt = "not-a-time" },
		"window":           func(d *SnapshotBindingDelivery) { d.ExpiresAt = d.IssuedAt },
	} {
		t.Run("delivery/"+name, func(t *testing.T) {
			delivery := baseSnapshotDelivery()
			mutate(&delivery)
			if _, err := base.WithDelivery(delivery); err == nil {
				t.Fatal("constructor accepted invalid delivery binding")
			}
		})
	}
}

func TestSnapshotBindingCanonicalAADMatchesLegacyGolden(t *testing.T) {
	scope := baseSnapshotScope()
	binding := completeSnapshotBinding(t)

	// Existing HKS1 headers depend on this field order and spelling.
	const golden = `{"instance_origin":"https://hikyo.example.internal","org_id":"org_1","project_id":"prj_1","environment_id":"env_1","credential_id":"cred_1","credential_fingerprint":"fp_1","config_only":false,"target_names":["api","worker"],"pinned_revision":7,"change_token":"v1:manifest-token-1","projection":["read","reveal"],"issued_at":"2026-08-19T10:00:00Z","expires_at":"2026-08-26T10:00:00Z"}`
	got, err := binding.CanonicalAAD()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != golden {
		t.Fatalf("canonical AAD changed:\n got %s\nwant %s", got, golden)
	}

	parsed, err := ParseSnapshotBinding("/state/compose/acme", []byte(golden))
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := parsed.CanonicalAAD()
	if err != nil {
		t.Fatal(err)
	}
	if string(roundTrip) != golden {
		t.Fatalf("parsed AAD changed: %s", roundTrip)
	}

	// Constructor owns copies and canonical order; caller mutation cannot alter it.
	scope.TargetNames[0] = "mutated"
	if strings.Contains(string(got), "mutated") {
		t.Fatal("binding retained caller-owned target slice")
	}
}

func TestSnapshotBindingCanonicalizesEquivalentTimestamps(t *testing.T) {
	base, err := NewSnapshotBinding(baseSnapshotScope())
	if err != nil {
		t.Fatal(err)
	}
	delivery := baseSnapshotDelivery()
	delivery.IssuedAt = "2026-08-19T12:00:00+02:00"
	delivery.ExpiresAt = "2026-08-26T12:00:00+02:00"
	binding, err := base.WithDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := binding.AAD()
	if err != nil {
		t.Fatal(err)
	}
	if aad.IssuedAt != "2026-08-19T10:00:00Z" || aad.ExpiresAt != "2026-08-26T10:00:00Z" {
		t.Fatalf("timestamps not canonical UTC: issued=%q expires=%q", aad.IssuedAt, aad.ExpiresAt)
	}
}

func TestSnapshotBindingContextMatchesCanonicalScope(t *testing.T) {
	complete := completeSnapshotBinding(t)
	for name, mutate := range map[string]func(*SnapshotBindingScope){
		"instance":    func(s *SnapshotBindingScope) { s.InstanceOrigin = "https://other.example" },
		"org":         func(s *SnapshotBindingScope) { s.OrgID = "org_2" },
		"project":     func(s *SnapshotBindingScope) { s.ProjectID = "prj_2" },
		"environment": func(s *SnapshotBindingScope) { s.EnvironmentID = "env_2" },
		"credential":  func(s *SnapshotBindingScope) { s.CredentialFingerprint = "fp_2" },
		"mode":        func(s *SnapshotBindingScope) { s.ConfigOnly = true },
		"targets":     func(s *SnapshotBindingScope) { s.TargetNames = []string{"api"} },
	} {
		t.Run(name, func(t *testing.T) {
			scope := baseSnapshotScope()
			mutate(&scope)
			expect, err := NewSnapshotBinding(scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := complete.ContextMatches(expect); err == nil {
				t.Fatal("mismatched scope accepted")
			}
		})
	}

	expect, err := NewSnapshotBinding(baseSnapshotScope())
	if err != nil {
		t.Fatal(err)
	}
	if err := complete.ContextMatches(expect); err != nil {
		t.Fatalf("matching canonical scope rejected: %v", err)
	}
}

func TestSnapshotBindingScopeCannotProduceAAD(t *testing.T) {
	binding, err := NewSnapshotBinding(baseSnapshotScope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CanonicalAAD(); err == nil {
		t.Fatal("scope-only binding produced cryptographic AAD")
	}
}
