package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

func TestValidateConfigValueReturnsSchemaLeafInCallerSafeNamedDetail(t *testing.T) {
	const submitted = `{"unexpected":"caller-visible-config"}`
	err := validateValue(store.CatalogueKey{
		Name:           "APP_CONFIG",
		Classification: "config",
		Declaration:    `{"rule":{"type":"json","json_schema":{"type":"object","additionalProperties":false}}}`,
	}, submitted)
	if err == nil || !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("validateValue error = %v, want domain.ErrInvalid", err)
	}
	carrier, ok := err.(interface{ SafeDetail() string })
	if !ok {
		t.Fatalf("validateValue error %T has no caller-safe detail", err)
	}
	detail := carrier.SafeDetail()
	if !strings.HasPrefix(detail, `value for "APP_CONFIG" is invalid (`) {
		t.Fatalf("detail = %q, want named APP_CONFIG refusal", detail)
	}
	const leaf = "json_schema/additionalProperties: at '': additional properties 'unexpected' not allowed"
	if !strings.Contains(detail, leaf) {
		t.Fatalf("detail = %q, want schema-derived leaf %q", detail, leaf)
	}
}

func TestValidateSecretValueReturnsCallerSafeNamedDetail(t *testing.T) {
	const (
		plaintext = `{"tenant-leaf-9f4a":"DO-NOT-ECHO-secret-7c31"}`
		fragment  = "tenant-leaf-9f4a"
	)
	err := validateValue(store.CatalogueKey{
		Name:           "API_SECRET",
		Classification: "secret",
		Declaration:    `{"rule":{"type":"json","json_schema":{"type":"object","additionalProperties":false}}}`,
	}, plaintext)
	if err == nil || !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("validateValue error = %v, want domain.ErrInvalid", err)
	}
	carrier, ok := err.(interface{ SafeDetail() string })
	if !ok {
		t.Fatalf("validateValue error %T has no caller-safe detail", err)
	}
	detail := carrier.SafeDetail()
	if !strings.HasPrefix(detail, `value for "API_SECRET" is invalid (`) {
		t.Fatalf("detail = %q, want named API_SECRET refusal", detail)
	}
	if strings.Contains(detail, plaintext) || strings.Contains(detail, fragment) || strings.Contains(detail, "DO-NOT-ECHO-secret-7c31") {
		t.Fatalf("secret validation detail leaked submitted instance data: %q", detail)
	}
}
