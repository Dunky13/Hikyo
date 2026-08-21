package store

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRestoreSQLiteConcurrentAttemptsOwnDistinctStaging(t *testing.T) {
	archive := sqliteRestoreArchive(t, nil)
	target := filepath.Join(t.TempDir(), "restored.db")
	entered := make(chan string, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	restore := func() {
		_, err := RestoreSQLite(t.Context(), bytes.NewReader(archive), target, func(ctx context.Context, db *DB) error {
			staging, err := sqliteDatabasePath(ctx, db)
			if err != nil {
				return err
			}
			entered <- staging
			<-release
			return nil
		})
		results <- err
	}

	go restore()
	first := receiveBefore(t, entered, 10*time.Second, "first restore did not reach mutation barrier")
	go restore()
	second := receiveBefore(t, entered, 10*time.Second, "second restore did not reach mutation barrier")

	close(release)
	released = true
	firstErr := receiveBefore(t, results, 10*time.Second, "first restore did not finish")
	secondErr := receiveBefore(t, results, 10*time.Second, "second restore did not finish")

	if first == second {
		t.Fatalf("concurrent restores shared staging path %q", first)
	}
	for _, staging := range []string{first, second} {
		sameDirectory, err := pathsShareDirectory(staging, target)
		if err != nil {
			t.Fatal(err)
		}
		if !sameDirectory {
			t.Errorf("staging path %q is outside destination directory %q", staging, filepath.Dir(target))
		}
	}

	successes := 0
	conflicts := 0
	for _, err := range []error{firstErr, secondErr} {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrTargetNotEmpty):
			conflicts++
		default:
			t.Errorf("concurrent restore returned unexpected error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent restore results: successes=%d target conflicts=%d; want 1 each", successes, conflicts)
	}
	assertNoRestoreStaging(t, target)
}

func TestRestoreSQLiteCleansOwnedStagingOnFailure(t *testing.T) {
	stagingCreationFailure := errors.New("injected staging creation failure")
	stagingCloseFailure := errors.New("injected staging close failure")
	mutationFailure := errors.New("injected mutation failure")
	databaseCloseFailure := errors.New("injected database close failure")
	fsyncFailure := errors.New("injected fsync failure")
	publicationFailure := errors.New("injected publication failure")
	cleanupFailure := errors.New("injected cleanup failure")
	tests := []struct {
		name              string
		payload           []byte
		archive           func(t *testing.T, payload []byte) []byte
		configure         func(*sqliteRestoreOperations)
		mutate            func(target string) func(context.Context, *DB) error
		wantError         error
		wantErrorText     string
		wantTargetContent []byte
	}{
		{
			name: "staging creation",
			configure: func(operations *sqliteRestoreOperations) {
				operations.createTemp = func(string, string) (*os.File, error) {
					return nil, stagingCreationFailure
				}
			},
			wantError: stagingCreationFailure,
		},
		{
			name:          "payload extraction",
			payload:       bytes.Repeat([]byte("x"), 1024),
			archive:       truncatedSQLiteRestoreArchive,
			wantErrorText: "unexpected EOF",
		},
		{
			name: "staging close",
			configure: func(operations *sqliteRestoreOperations) {
				operations.closeFile = func(file *os.File) error {
					return errors.Join(file.Close(), stagingCloseFailure)
				}
			},
			wantError: stagingCloseFailure,
		},
		{
			name:    "database open",
			payload: []byte("not a sqlite database"),
			mutate: func(string) func(context.Context, *DB) error {
				return func(context.Context, *DB) error { return nil }
			},
			wantErrorText: "open restored snapshot",
		},
		{
			name: "mutation",
			mutate: func(string) func(context.Context, *DB) error {
				return func(context.Context, *DB) error { return mutationFailure }
			},
			wantError: mutationFailure,
		},
		{
			name: "database close",
			configure: func(operations *sqliteRestoreOperations) {
				operations.closeDatabase = func(db *DB) error {
					return errors.Join(db.Close(), databaseCloseFailure)
				}
			},
			mutate: func(string) func(context.Context, *DB) error {
				return func(context.Context, *DB) error { return nil }
			},
			wantError: databaseCloseFailure,
		},
		{
			name: "fsync",
			configure: func(operations *sqliteRestoreOperations) {
				operations.fsyncFile = func(string) error { return fsyncFailure }
			},
			wantError: fsyncFailure,
		},
		{
			name: "publication conflict",
			mutate: func(target string) func(context.Context, *DB) error {
				return func(context.Context, *DB) error {
					return os.WriteFile(target, []byte("existing database"), 0o600)
				}
			},
			wantError:         ErrTargetNotEmpty,
			wantTargetContent: []byte("existing database"),
		},
		{
			name: "publication failure",
			configure: func(operations *sqliteRestoreOperations) {
				operations.link = func(string, string) error { return publicationFailure }
			},
			wantError: publicationFailure,
		},
		{
			name: "cleanup",
			configure: func(operations *sqliteRestoreOperations) {
				injected := false
				operations.remove = func(path string) error {
					err := os.Remove(path)
					if !injected && !errors.Is(err, os.ErrNotExist) {
						injected = true
						return errors.Join(err, cleanupFailure)
					}
					return err
				}
			},
			wantError: cleanupFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "restored.db")
			archiveBuilder := tt.archive
			if archiveBuilder == nil {
				archiveBuilder = sqliteRestoreArchive
			}
			archive := archiveBuilder(t, tt.payload)
			operations := defaultSQLiteRestoreOperations()
			if tt.configure != nil {
				tt.configure(&operations)
			}
			var mutate func(context.Context, *DB) error
			if tt.mutate != nil {
				mutate = tt.mutate(target)
			}

			_, err := restoreSQLite(t.Context(), bytes.NewReader(archive), target, mutate, operations)
			if err == nil {
				t.Fatal("restoreSQLite() returned nil error")
			}
			if tt.wantError != nil && !errors.Is(err, tt.wantError) {
				t.Errorf("restoreSQLite() error = %v, want matching %v", err, tt.wantError)
			}
			if tt.wantErrorText != "" && !strings.Contains(err.Error(), tt.wantErrorText) {
				t.Errorf("restoreSQLite() error = %v, want containing %q", err, tt.wantErrorText)
			}
			if tt.wantTargetContent != nil {
				got, readErr := os.ReadFile(target)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if !bytes.Equal(got, tt.wantTargetContent) {
					t.Errorf("restore target content = %q, want %q", got, tt.wantTargetContent)
				}
			}
			assertNoRestoreStaging(t, target)
		})
	}
}

func TestRestoreSQLitePublishesPrivateDatabase(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restored.db")
	if _, err := RestoreSQLite(t.Context(), bytes.NewReader(sqliteRestoreArchive(t, nil)), target, nil); err != nil {
		t.Fatalf("RestoreSQLite() error = %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("restored database permissions = %04o, want 0600", got)
	}
	assertNoRestoreStaging(t, target)
}

func pathsShareDirectory(first, second string) (bool, error) {
	firstDirectory, err := os.Stat(filepath.Dir(first))
	if err != nil {
		return false, fmt.Errorf("stat first directory: %w", err)
	}
	secondDirectory, err := os.Stat(filepath.Dir(second))
	if err != nil {
		return false, fmt.Errorf("stat second directory: %w", err)
	}
	return os.SameFile(firstDirectory, secondDirectory), nil
}

func sqliteDatabasePath(ctx context.Context, db *DB) (string, error) {
	var sequence int
	var name string
	var path string
	if err := db.sqRead.QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		return "", fmt.Errorf("read sqlite database path: %w", err)
	}
	return path, nil
}

func sqliteRestoreArchive(t *testing.T, payload []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	writeTarMember(t, tw, manifestMember, sqliteRestoreManifest(t))
	writeTarMember(t, tw, sqliteMember, payload)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func truncatedSQLiteRestoreArchive(t *testing.T, payload []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	writeTarMember(t, tw, manifestMember, sqliteRestoreManifest(t))
	if err := tw.WriteHeader(&tar.Header{Name: sqliteMember, Mode: 0o600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload[:len(payload)/2]); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func sqliteRestoreManifest(t *testing.T) []byte {
	t.Helper()
	manifest, err := json.Marshal(Manifest{
		Format:    ArchiveFormat,
		Engine:    EngineSQLite,
		CreatedAt: time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeTarMember(t *testing.T, tw *tar.Writer, name string, body []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
}

func assertNoRestoreStaging(t *testing.T, target string) {
	t.Helper()
	matches, err := filepath.Glob(target + ".restoring-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("restore left staging artifacts: %v", matches)
	}
}

func receiveBefore[T any](t *testing.T, ch <-chan T, timeout time.Duration, message string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(timeout):
		t.Fatal(message)
		var zero T
		return zero
	}
}
