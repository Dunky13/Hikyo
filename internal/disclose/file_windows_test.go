//go:build windows

package disclose

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPreparedFileOwnsHandleUntilAbort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}

	competing, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		_ = competing.Close()
		t.Fatal("a competing writer opened the prepared Windows destination")
	}
	if err := sink.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused Windows reservation remains after Abort: %v", err)
	}
}

func TestWindowsPreparedFileWritesThroughReservedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	sink, err := Prepare(Options{OutputFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sink.WriteOnce("Token", "hik_1_bs_secret"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hik_1_bs_secret\n" {
		t.Fatalf("Windows disclosure file = %q", body)
	}
}
