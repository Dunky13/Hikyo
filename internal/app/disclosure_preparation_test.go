package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hikyo-Org/hikyo/internal/disclose"
)

func TestLocalMintPreparationFailurePrecedesStateAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "already-owned")
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{
			name: "admin create",
			run: func() error {
				return runAdminCreate(t.Context(), nil, nil,
					[]string{"create", "--username", "alice", "--output-file", path}, io.Discard, nil, nil)
			},
		},
		{
			name: "admin reset",
			run: func() error {
				return runAdminReset(t.Context(), nil, nil,
					[]string{"reset-credential", "--principal", "usr_1", "--output-file", path}, io.Discard, nil, nil)
			},
		},
		{
			name: "backup keygen",
			run: func() error {
				return runBackupKeygen([]string{"keygen", "--output-file", path}, io.Discard, nil, nil)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Nil app config/logger make any state or mint access fail loudly;
			// destination refusal must happen before either is touched.
			if err := tc.run(); !errors.Is(err, disclose.ErrFileExists) {
				t.Fatalf("error = %v, want ErrFileExists before state access", err)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "owned" {
				t.Fatalf("existing destination changed: body=%q err=%v", body, err)
			}
		})
	}
}
