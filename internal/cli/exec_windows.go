//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
)

// execRun is the Windows counterpart of the unix syscall.Exec: Windows has no
// exec-in-place, so hikyo spawns the child with inherited stdio, waits, and
// exits with the child's exit code — the closest achievable equivalent of "no
// hikyo process, the child's status is the invocation's". A spawn failure is
// returned (the caller maps it to 126); on any child exit this never returns.
func execRun(argv0 string, argv, env []string) error {
	cmd := exec.Command(argv0, argv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		os.Exit(0)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	// The binary was found by LookPath but could not be started.
	return err
}
