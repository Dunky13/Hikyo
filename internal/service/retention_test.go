package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
)

func TestValidateProjectRetentionAgainstOrgCap(t *testing.T) {
	org := RetentionPolicy{MaxAge: 90 * 24 * time.Hour, LastRevisions: 10}
	tests := []struct {
		name string
		want RetentionPolicy
		err  bool
	}{
		{name: "equal", want: org},
		{name: "stricter in both dimensions", want: RetentionPolicy{MaxAge: 30 * 24 * time.Hour, LastRevisions: 5}},
		{name: "age exceeds cap", want: RetentionPolicy{MaxAge: 91 * 24 * time.Hour, LastRevisions: 5}, err: true},
		{name: "count exceeds cap", want: RetentionPolicy{MaxAge: 30 * 24 * time.Hour, LastRevisions: 11}, err: true},
		{name: "project unlimited", want: RetentionPolicy{Unlimited: true}, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProjectRetention(org, tt.want)
			if !tt.err && err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !tt.err {
				return
			}
			if !errors.Is(err, domain.ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), "org retention cap") {
				t.Fatalf("error %q does not name the org retention cap", err)
			}
		})
	}
}

// TestHealthStorageWarnBoundary pins the § 141 warn threshold: health.StorageWarn
// flips at exactly ProjectStorageWarnBytes (1 GiB), the `>=` boundary the doctor,
// metric, and UI banner all read.
func TestHealthStorageWarnBoundary(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	s := &Retention{Now: func() time.Time { return now }}
	tests := []struct {
		name string
		peak int64
		warn bool
	}{
		{"below", ProjectStorageWarnBytes - 1, false},
		{"at", ProjectStorageWarnBytes, true},
		{"above", ProjectStorageWarnBytes + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.health(now, true, tt.peak)
			if got.StorageWarn != tt.warn {
				t.Fatalf("peak %d: StorageWarn = %v, want %v", tt.peak, got.StorageWarn, tt.warn)
			}
			if got.PeakProjectBytes != tt.peak {
				t.Fatalf("peak %d: PeakProjectBytes = %d", tt.peak, got.PeakProjectBytes)
			}
		})
	}
}

func TestValidateProjectRetentionAllowsBoundedOverrideUnderUnlimitedOrg(t *testing.T) {
	err := validateProjectRetention(
		RetentionPolicy{Unlimited: true},
		RetentionPolicy{MaxAge: 365 * 24 * time.Hour, LastRevisions: 100},
	)
	if err != nil {
		t.Fatalf("bounded project policy under unlimited org: %v", err)
	}
}
