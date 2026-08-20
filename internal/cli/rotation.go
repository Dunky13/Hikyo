package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strconv"

	"github.com/Hikyo-Org/hikyo/api/apigen"
)

// runRotateDEK is the operator's `rotate-dek`: append a new DEK version for one
// project or the instance scope. New writes seal under it at once; ciphertext
// under the old version stays readable until `reencrypt` walks it. The warning
// says exactly that — a rotate-dek on its own protects nothing already written.
func runRotateDEK(ctx context.Context, ios IO, args []string) error {
	var format string
	var confirm, instance bool
	st, flags, err := parseCommon("rotate-dek", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&confirm, "yes", false, "proceed without the interactive confirmation")
		fs.BoolVar(&instance, "instance", false, "rotate the instance DEK instead of a project DEK")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("rotate-dek"); err != nil {
		return err
	}

	client, _, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	body := apigen.RotateDEKRequest{}
	if instance {
		body.Scope = apigen.RotateDEKRequestScopeInstance
	} else {
		org, err := resolved.Require(DimOrg)
		if err != nil {
			return err
		}
		project, err := resolved.Require(DimProject)
		if err != nil {
			return err
		}
		body.Scope = apigen.RotateDEKRequestScopeProject
		body.Org, body.Project = &org, &project
	}

	fmt.Fprintln(ios.Stderr,
		"rotate-dek appends a new DEK version. New writes use it immediately, but\n"+
			"ciphertext under the old version stays readable until `reencrypt` walks\n"+
			"it. Rotate-dek on its own protects nothing already written — follow it\n"+
			"with `reencrypt` on the same scope.")
	if !confirm {
		return failf(ExitRefused, "rotate-dek needs --yes to proceed")
	}

	var out apigen.DEKRotation
	if err := client.Do(ctx, http.MethodPost, "/api/v1/instance/rotate-dek", body, &out); err != nil {
		return err
	}
	scope := string(out.Scope)
	target := scope
	if out.Org != nil && out.Project != nil {
		target = *out.Org + "/" + *out.Project
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"SCOPE", "TARGET", "KEY VERSION"},
		Rows:    [][]string{{scope, target, strconv.FormatInt(out.KeyVersion, 10)}},
		JSON:    out,
	})
}

// runRotateMasterKey is the operator's `rotate-master-key`. It warns that every
// tier-3 key is re-wrapped — bounded by the number of projects, so seconds —
// and that it is refused while a root rotation is mid-flight.
func runRotateMasterKey(ctx context.Context, ios IO, args []string) error {
	var format string
	var confirm bool
	st, flags, err := parseCommon("rotate-master-key", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&confirm, "yes", false, "proceed without the interactive confirmation")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("rotate-master-key"); err != nil {
		return err
	}
	fmt.Fprintln(ios.Stderr,
		"rotate-master-key generates a new master key and re-wraps every tier-3\n"+
			"key under it. It is refused while a root-key rotation is mid-flight —\n"+
			"finalize that first. No data is re-encrypted; DEK versions are unchanged.")
	if !confirm {
		return failf(ExitRefused, "rotate-master-key needs --yes to proceed")
	}
	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	var out apigen.MasterKeyRotation
	if err := client.Do(ctx, http.MethodPost, "/api/v1/instance/rotate-master-key", nil, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"MASTER KEY VERSION"},
		Rows:    [][]string{{strconv.FormatInt(out.KeyVersion, 10)}},
		JSON:    out,
	})
}

// runRotateRootKey is the operator's `rotate-root-key`, one phase per run. No
// key material crosses the wire: --prepare reads the new root from the server's
// HIKYO_NEW_ROOT_KEY_FILE, --verify re-reads the primary source after the
// operator installs the new root there, --finalize retires the old wrapper.
func runRotateRootKey(ctx context.Context, ios IO, args []string) error {
	var format string
	var prepare, verify, finalize, confirm bool
	st, flags, err := parseCommon("rotate-root-key", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		fs.BoolVar(&prepare, "prepare", false, "seal the master under the new root (HIKYO_NEW_ROOT_KEY_FILE)")
		fs.BoolVar(&verify, "verify", false, "confirm the new root is installed at the primary source")
		fs.BoolVar(&finalize, "finalize", false, "retire the old root wrapper, completing the rotation")
		fs.BoolVar(&confirm, "yes", false, "proceed without the interactive confirmation")
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("rotate-root-key"); err != nil {
		return err
	}
	var phase apigen.RotateRootKeyRequestPhase
	switch {
	case prepare && !verify && !finalize:
		phase = apigen.RotateRootKeyRequestPhasePrepare
	case verify && !prepare && !finalize:
		phase = apigen.RotateRootKeyRequestPhaseVerify
	case finalize && !prepare && !verify:
		phase = apigen.RotateRootKeyRequestPhaseFinalize
	default:
		return failf(ExitUsage, "rotate-root-key needs exactly one of --prepare, --verify, --finalize")
	}
	if phase == apigen.RotateRootKeyRequestPhaseFinalize {
		fmt.Fprintln(ios.Stderr,
			"rotate-root-key --finalize retires the old root wrapper. After it, the\n"+
				"old root no longer boots this instance. Run --verify first and confirm\n"+
				"the new root is installed at the primary source.")
	}
	if !confirm {
		return failf(ExitRefused, "rotate-root-key needs --yes to proceed")
	}

	client, _, _, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	var out apigen.RootKeyRotation
	if err := client.Do(ctx, http.MethodPost, "/api/v1/instance/rotate-root-key",
		apigen.RotateRootKeyRequest{Phase: phase}, &out); err != nil {
		return err
	}
	return Render(ios.Stdout, f, Table{
		Columns: []string{"PHASE", "ROOT KEY EPOCH"},
		Rows:    [][]string{{string(out.Phase), strconv.FormatInt(out.RootKeyEpoch, 10)}},
		JSON:    out,
	})
}
