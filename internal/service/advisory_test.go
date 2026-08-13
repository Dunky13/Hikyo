package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Dunky13/hikyo/internal/domain"
)

func TestAdvisoryConnectionCaps(t *testing.T) {
	t.Run("principal", func(t *testing.T) {
		a := NewAdvisory()
		var cancels []func()
		for i := 0; i < advisoryPrincipalLimit; i++ {
			_, cancel, err := a.subscribe("org", domain.ProjectID(fmt.Sprintf("project-%d", i)), "principal")
			if err != nil {
				t.Fatal(err)
			}
			cancels = append(cancels, cancel)
		}
		if _, _, err := a.subscribe("org", "overflow", "principal"); !errors.Is(err, ErrAdvisoryPrincipalLimit) {
			t.Fatalf("principal cap refusal = %v", err)
		}
		cancels[0]()
		if _, cancel, err := a.subscribe("org", "replacement", "principal"); err != nil {
			t.Fatalf("released principal slot stayed occupied: %v", err)
		} else {
			cancel()
		}
	})

	t.Run("organization", func(t *testing.T) {
		a := NewAdvisory()
		for i := 0; i < advisoryOrgLimit; i++ {
			if _, _, err := a.subscribe("org", "project", domain.PrincipalID(fmt.Sprintf("principal-%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := a.subscribe("org", "project", "overflow"); !errors.Is(err, ErrAdvisoryOrgLimit) {
			t.Fatalf("organization cap refusal = %v", err)
		}
	})

	t.Run("instance", func(t *testing.T) {
		a := NewAdvisory()
		for i := 0; i < advisoryInstanceWideLimit; i++ {
			org := domain.OrgID(fmt.Sprintf("org-%d", i/advisoryOrgLimit))
			principal := domain.PrincipalID(fmt.Sprintf("principal-%d", i))
			if _, _, err := a.subscribe(org, "project", principal); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := a.subscribe("another-org", "project", "overflow"); !errors.Is(err, ErrAdvisoryInstanceLimit) {
			t.Fatalf("instance cap refusal = %v", err)
		}
	})
}
