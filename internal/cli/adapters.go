package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/api"
	"github.com/Hikyo-Org/hikyo/api/apigen"
	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

type adapterCredentialSource struct {
	stdin bool
	file  string
}

func renderAdapterTargetMutation(out io.Writer, format Format, payload []byte) error {
	var discriminator struct {
		Kind *apigen.AdapterMoveKind `json:"kind"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil {
		return failf(ExitInternal, "the server's response did not match the contract: %v", err)
	}
	if discriminator.Kind != nil {
		var move apigen.AdapterMove
		if err := json.Unmarshal(payload, &move); err != nil {
			return failf(ExitInternal, "the server's move response did not match the contract: %v", err)
		}
		return Render(out, format, adapterMoveTable(move))
	}
	var target apigen.AdapterTarget
	if err := json.Unmarshal(payload, &target); err != nil {
		return failf(ExitInternal, "the server's target response did not match the contract: %v", err)
	}
	return Render(out, format, targetTable(apigen.AdapterTargetList{Items: []apigen.AdapterTarget{target}}))
}

func (s adapterCredentialSource) read(ios IO) ([]byte, error) {
	if s.stdin && s.file != "" {
		return nil, failf(ExitUsage, "--stdin and --value-file are mutually exclusive")
	}
	var raw []byte
	var err error
	switch {
	case s.stdin:
		raw, err = io.ReadAll(io.LimitReader(ios.Stdin, 4097))
	case s.file != "":
		raw, err = os.ReadFile(s.file)
	default:
		var value string
		value, err = ios.readPassword("Deployment provider credential: ")
		raw = []byte(value)
	}
	if err != nil {
		return nil, failf(ExitRefused, "reading adapter credential: %v", err)
	}
	if len(raw) > 4096 {
		return nil, failf(ExitRefused, "adapter credential exceeds 4096 bytes")
	}
	raw = []byte(strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"))
	if len(raw) == 0 || strings.ContainsAny(string(raw), "\r\n") {
		return nil, failf(ExitRefused, "adapter credential must be one non-empty line")
	}
	return raw, nil
}

func adapterBase(org, project string) string {
	return api.PathPrefix + "/orgs/" + url.PathEscape(org) + "/projects/" + url.PathEscape(project)
}
func adapterTargetInput(env, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys string) (apigen.AdapterTargetInput, error) {
	ids := splitAdapterKeys(keys)
	if env == "" || kind == "" || owner == "" || len(ids) == 0 {
		return apigen.AdapterTargetInput{}, failf(ExitUsage, "target requires --env, --kind, --owner, and a non-empty --keys list")
	}
	repositoryIDs, err := splitAdapterRepositoryIDs(selectedRepositories)
	if err != nil {
		return apigen.AdapterTargetInput{}, err
	}
	switch kind {
	case "repository":
		if repo == "" || destinationEnvironment != "" || visibility != "" || len(repositoryIDs) != 0 {
			return apigen.AdapterTargetInput{}, failf(ExitUsage, "repository target requires --repo and refuses environment/visibility routing")
		}
	case "organization":
		if repo != "" || destinationEnvironment != "" || (visibility != "all" && visibility != "private" && visibility != "selected") {
			return apigen.AdapterTargetInput{}, failf(ExitUsage, "organization target requires --visibility all|private|selected and refuses --repo/--destination-environment")
		}
		if (visibility == "selected") != (len(repositoryIDs) != 0) {
			return apigen.AdapterTargetInput{}, failf(ExitUsage, "--selected-repository-ids is required exactly for selected visibility")
		}
	case "environment":
		if repo == "" || destinationEnvironment == "" || visibility != "" || len(repositoryIDs) != 0 {
			return apigen.AdapterTargetInput{}, failf(ExitUsage, "environment target requires --repo and --destination-environment and refuses visibility routing")
		}
	default:
		return apigen.AdapterTargetInput{}, failf(ExitUsage, "--kind must be repository, organization, or environment")
	}
	out := apigen.AdapterTargetInput{EnvironmentId: apigen.ID(env), DestinationKind: apigen.AdapterDestinationKind(kind), DestinationOwner: owner, DestinationName: repo, DestinationEnvironment: destinationEnvironment, Visibility: apigen.AdapterTargetInputVisibility(visibility), SelectedRepositoryIds: repositoryIDs, NamePrefix: prefix}
	for _, id := range ids {
		out.KeyIds = append(out.KeyIds, apigen.ID(id))
	}
	return out, nil
}

func splitAdapterRepositoryIDs(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return []int64{}, nil
	}
	seen := map[int64]bool{}
	var out []int64
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || id <= 0 || seen[id] {
			return nil, failf(ExitUsage, "--selected-repository-ids must be unique positive numeric GitHub repository ids")
		}
		seen[id] = true
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

func splitAdapterKeys(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		id := strings.TrimSpace(part)
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func runAdapterCeremony(ctx context.Context, ios IO, client *Client, st *State, artifact SessionArtifact, base, adapterID, operation string, additional ...string) error {
	// Command tests and embedded callers may deliberately omit the browser
	// adapter. The shipped binary always supplies it; omission keeps this
	// transport seam injectable without launching a real browser in tests.
	if ios.OpenURL == nil {
		return nil
	}
	if artifact.Instance == "" {
		return failf(ExitRefused, "adapter reauthentication requires a stored human CLI session")
	}
	environments := append([]string(nil), additional...)
	if adapterID != "" {
		var current apigen.Adapter
		if err := client.Do(ctx, http.MethodGet, base+"/adapters/"+url.PathEscape(adapterID), nil, &current); err != nil {
			return err
		}
		for _, target := range current.Targets {
			environments = append(environments, string(target.EnvironmentId))
		}
	}
	slices.Sort(environments)
	environments = slices.Compact(environments)
	if len(environments) == 0 {
		return failf(ExitRefused, "adapter reauthentication requires at least one target environment")
	}
	return runCLIAdapterReauth(ctx, client, st, artifact, operation, environments, ios.OpenURL)
}

func runAdapter(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("adapter", args, "create", "list", "show", "update", "delete", "credential", "target", "adopt", "plan", "sync", "test")
	if err != nil {
		return err
	}
	switch sub {
	case "credential":
		return runAdapterCredential(ctx, ios, rest)
	case "target":
		return runAdapterTarget(ctx, ios, rest)
	case "adopt":
		return runAdapterAdopt(ctx, ios, rest)
	case "plan", "sync", "test":
		return runAdapterAction(ctx, ios, sub, rest)
	}
	var format, provider, origin, target, moveID, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys string
	var keepRemote, cancelMove bool
	var source adapterCredentialSource
	st, flags, err := parseCommon("adapter "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "o", "table", "output format: table or json")
		if sub == "create" || sub == "update" {
			fs.StringVar(&origin, "origin", "", "canonical Forgejo https origin")
		}
		if sub == "create" {
			fs.StringVar(&provider, "provider", "forgejo", "forgejo or github-actions")
		}
		if sub == "update" {
			fs.StringVar(&target, "target", "", "target id to mutate")
			fs.StringVar(&moveID, "move", "", "attention-required move id to resume")
			fs.BoolVar(&cancelMove, "cancel-move", false, "cancel the move and reconverge the old route")
		}
		if sub == "create" || sub == "update" {
			fs.StringVar(&kind, "kind", "", "repository, organization, or environment")
			fs.StringVar(&owner, "owner", "", "provider owner or organization")
			fs.StringVar(&repo, "repo", "", "provider repository")
			fs.StringVar(&destinationEnvironment, "destination-environment", "", "GitHub Actions environment name")
			fs.StringVar(&visibility, "visibility", "", "GitHub organization visibility: all, private, or selected")
			fs.StringVar(&selectedRepositories, "selected-repository-ids", "", "comma-separated GitHub numeric repository ids")
			fs.StringVar(&prefix, "prefix", "", "structural name prefix")
			fs.StringVar(&keys, "keys", "", "comma-separated immutable key ids")
		}
		if sub == "create" || sub == "update" {
			fs.BoolVar(&source.stdin, "stdin", false, "read credential from stdin")
			fs.StringVar(&source.file, "value-file", "", "read credential from file")
		}
		if sub == "delete" || sub == "update" {
			fs.BoolVar(&keepRemote, "keep-remote", false, "release custody without deleting remote names")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	switch sub {
	case "show", "update", "delete":
		if len(flags.positionals) != 1 {
			return failf(ExitUsage, "usage: hikyo adapter %s <adapter> ...", sub)
		}
	default:
		if err := flags.checkNoPositionals("adapter " + sub); err != nil {
			return err
		}
	}
	if sub == "create" && origin == "" {
		return failf(ExitUsage, "adapter create requires --origin")
	}
	if sub == "update" {
		targetFields := kind != "" || owner != "" || repo != "" || destinationEnvironment != "" || visibility != "" || selectedRepositories != "" || prefix != "" || keys != "" || flags.Env != ""
		credentialFields := source.stdin || source.file != ""
		if cancelMove {
			if moveID == "" || target != "" || origin != "" || targetFields || credentialFields || keepRemote {
				return failf(ExitUsage, "--cancel-move requires only --move <id>")
			}
		} else {
			if target != "" && (origin != "" || credentialFields) {
				return failf(ExitUsage, "adapter update refuses mixing --target with adapter-level origin or credential fields")
			}
			if target == "" && targetFields {
				return failf(ExitUsage, "target mutation fields require --target")
			}
			if target != "" && !targetFields {
				return failf(ExitUsage, "target update requires the full target fields including --keys")
			}
			if target == "" && origin == "" {
				return failf(ExitUsage, "adapter update requires --origin or --target")
			}
			if moveID != "" && keepRemote {
				return failf(ExitUsage, "--keep-remote applies only when starting a move, not when resuming --move")
			}
		}
	}
	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	base := adapterBase(org, project)
	adapterID := flags.positional()
	var selectedMove apigen.AdapterMove
	if sub == "update" && moveID != "" {
		if err := client.Do(ctx, http.MethodGet, base+"/adapter-moves/"+url.PathEscape(moveID), nil, &selectedMove); err != nil {
			return err
		}
		if string(selectedMove.AdapterId) != adapterID {
			return failf(ExitRefused, "move %s belongs to adapter %s, not %s", moveID, selectedMove.AdapterId, adapterID)
		}
	}
	switch sub {
	case "list":
		var out apigen.AdapterList
		if err := client.Do(ctx, http.MethodGet, base+"/adapters", nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, adapterListTable(out))
	case "show":
		var out apigen.Adapter
		if err := client.Do(ctx, http.MethodGet, base+"/adapters/"+url.PathEscape(adapterID), nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, adapterDetailTable(out))
	case "create":
		if provider != "forgejo" && provider != "github-actions" {
			return failf(ExitUsage, "--provider must be forgejo or github-actions")
		}
		envID, err := resolved.Require(DimEnv)
		if err != nil {
			return err
		}
		input, err := adapterTargetInput(envID, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys)
		if err != nil {
			return err
		}
		if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, "", "adapter.configure", envID); err != nil {
			return err
		}
		credential, err := source.read(ios)
		if err != nil {
			return err
		}
		defer zeroBytes(credential)
		var out apigen.Adapter
		if err := client.Do(ctx, http.MethodPost, base+"/adapters", apigen.CreateAdapterRequest{Provider: apigen.AdapterProvider(provider), Origin: origin, Credential: string(credential), Target: input}, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, adapterListTable(apigen.AdapterList{Items: []apigen.Adapter{out}}))
	case "delete":
		var out apigen.AdapterTeardown
		path := base + "/adapters/" + url.PathEscape(adapterID)
		if keepRemote {
			path += "?keep_remote=true"
		}
		if err := client.Do(ctx, http.MethodDelete, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, teardownTable(out))
	case "update":
		if cancelMove {
			if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, adapterID, "adapter.configure"); err != nil {
				return err
			}
			var out apigen.AdapterMove
			if err := client.Do(ctx, http.MethodDelete, base+"/adapter-moves/"+url.PathEscape(moveID), nil, &out); err != nil {
				return err
			}
			return Render(ios.Stdout, f, adapterMoveTable(out))
		}
		if target == "" {
			if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, adapterID, "adapter.configure"); err != nil {
				return err
			}
			if moveID != "" && string(selectedMove.Kind) != "origin" {
				return failf(ExitRefused, "move %s is not an origin move", moveID)
			}
			credential, err := source.read(ios)
			if err != nil {
				return err
			}
			defer zeroBytes(credential)
			var out apigen.AdapterMove
			path := base + "/adapters/" + url.PathEscape(adapterID)
			var body any = apigen.UpdateAdapterOriginRequest{Origin: origin, Credential: string(credential), KeepRemote: &keepRemote}
			if moveID != "" {
				path = base + "/adapter-moves/" + url.PathEscape(moveID)
				body = resumeAdapterOriginBody(origin, credential)
			}
			if err := client.Do(ctx, http.MethodPatch, path, body, &out); err != nil {
				return err
			}
			return Render(ios.Stdout, f, adapterMoveTable(out))
		}
		envID, err := resolved.Require(DimEnv)
		if err != nil {
			return err
		}
		input, err := adapterTargetInput(envID, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys)
		if err != nil {
			return err
		}
		if moveID != "" && (string(selectedMove.Kind) != "target" || len(selectedMove.Targets) != 1 || string(selectedMove.Targets[0].TargetId) != target) {
			return failf(ExitRefused, "move %s is not the pending move for target %s", moveID, target)
		}
		var out apigen.AdapterMove
		path := base + "/adapter-moves/" + url.PathEscape(moveID)
		var body any = resumeAdapterTargetBody(target, input)
		if moveID != "" {
			if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, adapterID, "adapter.configure"); err != nil {
				return err
			}
		} else {
			var current apigen.AdapterTargetDetail
			if err := client.Do(ctx, http.MethodGet, base+"/adapter-targets/"+url.PathEscape(target), nil, &current); err != nil {
				return err
			}
			if input.EnvironmentId != current.Target.EnvironmentId {
				return failf(ExitRefused, "target environment is immutable; remove and add the target")
			}
			existing := make([]string, 0, len(current.Mapping))
			for _, mapping := range current.Mapping {
				existing = append(existing, string(mapping.KeyId))
			}
			widened := false
			for _, id := range input.KeyIds {
				if !slices.Contains(existing, string(id)) {
					widened = true
					break
				}
			}
			destinationChanged := input.DestinationKind != current.Target.DestinationKind || input.DestinationOwner != current.Target.DestinationOwner || input.DestinationName != current.Target.DestinationName || input.DestinationEnvironment != current.Target.DestinationEnvironment
			full := destinationChanged || input.NamePrefix != current.Target.NamePrefix || widened || adapter.RecipientSetNeedsCeremony(string(current.Target.Visibility), current.Target.SelectedRepositoryIds, string(input.Visibility), input.SelectedRepositoryIds)
			if full {
				if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, adapterID, "adapter.configure"); err != nil {
					return err
				}
			}
			if !destinationChanged && keepRemote {
				return failf(ExitUsage, "--keep-remote applies only to a destination move")
			}
			path = base + "/adapter-targets/" + url.PathEscape(target)
			body = apigen.UpdateAdapterTargetRequest{EnvironmentId: input.EnvironmentId, DestinationKind: input.DestinationKind, DestinationOwner: input.DestinationOwner, DestinationName: input.DestinationName, DestinationEnvironment: input.DestinationEnvironment, Visibility: apigen.UpdateAdapterTargetRequestVisibility(input.Visibility), SelectedRepositoryIds: input.SelectedRepositoryIds, NamePrefix: input.NamePrefix, KeyIds: input.KeyIds, ExpectedGeneration: current.Target.Generation, KeepRemote: &keepRemote}
			var response []byte
			if err := client.Do(ctx, http.MethodPatch, path, body, &response); err != nil {
				return err
			}
			return renderAdapterTargetMutation(ios.Stdout, f, response)
		}
		if err := client.Do(ctx, http.MethodPatch, path, body, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, adapterMoveTable(out))
	}
	return failf(ExitInternal, "unhandled adapter verb")
}

func runAdapterCredential(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("adapter credential", args, "set", "revoke")
	if err != nil {
		return err
	}
	var adapterID, moveID string
	var source adapterCredentialSource
	st, flags, err := parseCommon("adapter credential "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&adapterID, "adapter", "", "adapter id")
		if sub == "set" {
			fs.StringVar(&moveID, "move", "", "attention-required origin move id to resume")
			fs.BoolVar(&source.stdin, "stdin", false, "read credential from stdin")
			fs.StringVar(&source.file, "value-file", "", "read credential from file")
		}
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("adapter credential " + sub); err != nil {
		return err
	}
	if adapterID == "" {
		return failf(ExitUsage, "adapter credential %s requires --adapter", sub)
	}
	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	path := adapterBase(org, project) + "/adapters/" + url.PathEscape(adapterID) + "/credential"
	if sub == "revoke" {
		return client.Do(ctx, http.MethodDelete, path, nil, nil)
	}
	if err := runAdapterCeremony(ctx, ios, client, st, artifact, adapterBase(org, project), adapterID, "adapter.credential-set"); err != nil {
		return err
	}
	credential, err := source.read(ios)
	if err != nil {
		return err
	}
	defer zeroBytes(credential)
	if moveID != "" {
		base := adapterBase(org, project)
		var move apigen.AdapterMove
		if err := client.Do(ctx, http.MethodGet, base+"/adapter-moves/"+url.PathEscape(moveID), nil, &move); err != nil {
			return err
		}
		if string(move.AdapterId) != adapterID || string(move.Kind) != "origin" || move.PendingOrigin == "" {
			return failf(ExitRefused, "move %s is not a pending origin move for adapter %s", moveID, adapterID)
		}
		var out apigen.AdapterMove
		if err := client.Do(ctx, http.MethodPatch, base+"/adapter-moves/"+url.PathEscape(moveID), resumeAdapterOriginBody(move.PendingOrigin, credential), &out); err != nil {
			return err
		}
		return Render(ios.Stdout, FormatTable, adapterMoveTable(out))
	}
	return client.Do(ctx, http.MethodPut, path, apigen.SetAdapterCredentialRequest{Credential: string(credential)}, nil)
}

func resumeAdapterOriginBody(origin string, credential []byte) apigen.ResumeAdapterMoveRequest {
	var body apigen.ResumeAdapterMoveRequest
	_ = body.FromResumeAdapterOriginMoveRequest(apigen.ResumeAdapterOriginMoveRequest{Origin: origin, Credential: string(credential)})
	return body
}

func resumeAdapterTargetBody(targetID string, input apigen.AdapterTargetInput) apigen.ResumeAdapterMoveRequest {
	var body apigen.ResumeAdapterMoveRequest
	_ = body.FromResumeAdapterTargetMoveRequest(apigen.ResumeAdapterTargetMoveRequest{
		TargetId: targetID, EnvironmentId: input.EnvironmentId, DestinationKind: input.DestinationKind,
		DestinationOwner: input.DestinationOwner, DestinationName: input.DestinationName, DestinationEnvironment: input.DestinationEnvironment,
		Visibility: apigen.ResumeAdapterTargetMoveRequestVisibility(input.Visibility), SelectedRepositoryIds: input.SelectedRepositoryIds,
		NamePrefix: input.NamePrefix, KeyIds: input.KeyIds,
	})
	return body
}

func runAdapterTarget(ctx context.Context, ios IO, args []string) error {
	sub, rest, err := subverb("adapter target", args, "add", "list", "show", "remove")
	if err != nil {
		return err
	}
	var adapterID, format, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys, outFormat string
	var keep bool
	st, flags, err := parseCommon("adapter target "+sub, ios, rest, func(fs *flag.FlagSet) {
		fs.StringVar(&adapterID, "adapter", "", "adapter id")
		fs.StringVar(&outFormat, "o", "table", "output format: table or json")
		if sub == "show" {
			fs.StringVar(&format, "format", "detail", "detail or workflow")
		}
		if sub == "add" {
			fs.StringVar(&kind, "kind", "", "repository, organization, or environment")
			fs.StringVar(&owner, "owner", "", "provider owner or organization")
			fs.StringVar(&repo, "repo", "", "provider repository")
			fs.StringVar(&destinationEnvironment, "destination-environment", "", "GitHub Actions environment name")
			fs.StringVar(&visibility, "visibility", "", "GitHub organization visibility: all, private, or selected")
			fs.StringVar(&selectedRepositories, "selected-repository-ids", "", "comma-separated GitHub numeric repository ids")
			fs.StringVar(&prefix, "prefix", "", "structural prefix")
			fs.StringVar(&keys, "keys", "", "comma-separated key ids")
		}
		if sub == "remove" {
			fs.BoolVar(&keep, "keep-remote", false, "release custody without deleting remote names")
		}
	})
	if err != nil {
		return err
	}
	f, err := ParseFormat(outFormat)
	if err != nil {
		return err
	}
	if sub == "show" || sub == "remove" {
		if len(flags.positionals) != 1 {
			return failf(ExitUsage, "adapter target %s takes one positional target", sub)
		}
	} else if err := flags.checkNoPositionals("adapter target " + sub); err != nil {
		return err
	}
	if (sub == "add" || sub == "list") && adapterID == "" {
		return failf(ExitUsage, "adapter target %s requires --adapter", sub)
	}
	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	base := adapterBase(org, project)
	switch sub {
	case "list":
		var out apigen.AdapterTargetList
		if err := client.Do(ctx, http.MethodGet, base+"/adapters/"+url.PathEscape(adapterID)+"/targets", nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, targetTable(out))
	case "add":
		envID, err := resolved.Require(DimEnv)
		if err != nil {
			return err
		}
		if err := runAdapterCeremony(ctx, ios, client, st, artifact, base, adapterID, "adapter.configure", envID); err != nil {
			return err
		}
		input, err := adapterTargetInput(envID, kind, owner, repo, destinationEnvironment, visibility, selectedRepositories, prefix, keys)
		if err != nil {
			return err
		}
		var out apigen.AdapterTarget
		if err := client.Do(ctx, http.MethodPost, base+"/adapters/"+url.PathEscape(adapterID)+"/targets", input, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, targetTable(apigen.AdapterTargetList{Items: []apigen.AdapterTarget{out}}))
	case "show":
		target := flags.positional()
		path := base + "/adapter-targets/" + url.PathEscape(target)
		if format == "workflow" {
			path += "?format=workflow"
			var raw string
			if err := client.Do(ctx, http.MethodGet, path, nil, &raw); err != nil {
				return err
			}
			_, err = fmt.Fprint(ios.Stdout, raw)
			return err
		}
		if format != "detail" {
			return failf(ExitUsage, "--format must be detail or workflow")
		}
		var out apigen.AdapterTargetDetail
		if err := client.Do(ctx, http.MethodGet, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, targetTable(apigen.AdapterTargetList{Items: []apigen.AdapterTarget{out.Target}}))
	case "remove":
		path := base + "/adapter-targets/" + url.PathEscape(flags.positional())
		if keep {
			path += "?keep_remote=true"
		}
		var out apigen.AdapterTeardown
		if err := client.Do(ctx, http.MethodDelete, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, teardownTable(out))
	}
	return nil
}

func runAdapterAction(ctx context.Context, ios IO, sub string, args []string) error {
	var target, format string
	st, flags, err := parseCommon("adapter "+sub, ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&target, "target", "", "target id")
		fs.StringVar(&format, "o", "table", "output format")
	})
	if err != nil {
		return err
	}
	if err := flags.checkNoPositionals("adapter " + sub); err != nil {
		return err
	}
	if target == "" {
		return failf(ExitUsage, "adapter %s requires --target", sub)
	}
	f, err := ParseFormat(format)
	if err != nil {
		return err
	}
	client, artifact, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	path := adapterBase(org, project) + "/adapter-targets/" + url.PathEscape(target) + "/" + sub
	switch sub {
	case "plan":
		var out apigen.AdapterPlan
		if err := client.Do(ctx, http.MethodPost, path, nil, &out); err != nil {
			return err
		}
		rows := [][]string{}
		for _, c := range out.Changes {
			rows = append(rows, []string{string(c.Surface), c.EffectiveName, string(c.Disposition)})
		}
		for _, warning := range out.Warnings {
			fmt.Fprintf(ios.Stderr, "warning: %s\n", warning)
		}
		return Render(ios.Stdout, f, Table{Columns: []string{"SURFACE", "NAME", "DISPOSITION"}, Rows: rows, JSON: out})
	case "sync":
		var detail apigen.AdapterTargetDetail
		if err := client.Do(ctx, http.MethodGet, adapterBase(org, project)+"/adapter-targets/"+url.PathEscape(target), nil, &detail); err != nil {
			return err
		}
		if err := runAdapterCeremony(ctx, ios, client, st, artifact, adapterBase(org, project), string(detail.Target.AdapterId), "adapter.sync"); err != nil {
			return err
		}
		var out apigen.AdapterJob
		if err := client.Do(ctx, http.MethodPost, path, nil, &out); err != nil {
			return err
		}
		return Render(ios.Stdout, f, Table{Columns: []string{"JOB", "GENERATION"}, Rows: [][]string{{string(out.JobId), fmt.Sprint(out.Generation)}}, JSON: out})
	case "test":
		var out apigen.AdapterConnection
		if err := client.Do(ctx, http.MethodPost, path, nil, &out); err != nil {
			return err
		}
		expires := ""
		if out.CredentialExpiresAt != nil {
			expires = out.CredentialExpiresAt.Format(time.RFC3339)
		}
		return Render(ios.Stdout, f, Table{Columns: []string{"VERSION", "DESTINATION", "CREDENTIAL EXPIRES"}, Rows: [][]string{{out.Version, fmt.Sprint(out.DestinationId), expires}}, JSON: out})
	}
	return nil
}

func runAdapterAdopt(ctx context.Context, ios IO, args []string) error {
	var target, artifact string
	st, flags, err := parseCommon("adapter adopt", ios, args, func(fs *flag.FlagSet) {
		fs.StringVar(&target, "target", "", "target id")
		fs.StringVar(&artifact, "artifact", "", "explicit conflict artifact id")
	})
	if err != nil {
		return err
	}
	names := append([]string(nil), flags.positionals...)
	slices.Sort(names)
	if target == "" || len(names) == 0 {
		return failf(ExitUsage, "adapter adopt requires --target and one or more exact names")
	}
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			return failf(ExitUsage, "adapter adopt names must be unique")
		}
	}
	client, artifactSession, resolved, err := authenticatedTarget(st, ios, flags)
	if err != nil {
		return err
	}
	org, err := resolved.Require(DimOrg)
	if err != nil {
		return err
	}
	project, err := resolved.Require(DimProject)
	if err != nil {
		return err
	}
	base := adapterBase(org, project) + "/adapter-targets/" + url.PathEscape(target)
	var detail apigen.AdapterTargetDetail
	if err := client.Do(ctx, http.MethodGet, base, nil, &detail); err != nil {
		return err
	}
	eligible := []apigen.AdapterConflictArtifact{}
	for _, candidate := range detail.Conflicts {
		candidateNames := []string{}
		seen := map[string]bool{}
		for _, entry := range candidate.Entries {
			if !seen[entry.EffectiveName] {
				seen[entry.EffectiveName] = true
				candidateNames = append(candidateNames, entry.EffectiveName)
			}
		}
		slices.Sort(candidateNames)
		if slices.Equal(candidateNames, names) && (artifact == "" || string(candidate.Id) == artifact) {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) != 1 {
		return failf(ExitRefused, "adoption requires exactly one eligible exact-match artifact; found %d (use --artifact <id> to select)", len(eligible))
	}
	if err := runAdapterCeremony(ctx, ios, client, st, artifactSession, adapterBase(org, project), string(detail.Target.AdapterId), "adapter.adopt"); err != nil {
		return err
	}
	selected := eligible[0]
	body := apigen.AdapterAdoptionRequest{ArtifactId: selected.Id, TargetGeneration: selected.TargetGeneration, DestinationId: selected.DestinationId, RepositoryId: selected.RepositoryId, Entries: selected.Entries}
	var job apigen.AdapterJob
	if err := client.Do(ctx, http.MethodPost, base+"/adoptions", body, &job); err != nil {
		return err
	}
	return Render(ios.Stdout, FormatTable, Table{Columns: []string{"JOB", "GENERATION"}, Rows: [][]string{{string(job.JobId), fmt.Sprint(job.Generation)}}, JSON: job})
}

func adapterListTable(list apigen.AdapterList) Table {
	rows := [][]string{}
	for _, a := range list.Items {
		expires := ""
		if a.CredentialExpiresAt != nil {
			expires = a.CredentialExpiresAt.Format(time.RFC3339)
		}
		rows = append(rows, []string{string(a.Id), string(a.Provider), a.Origin, fmt.Sprint(a.CredentialPresent), expires, fmt.Sprint(len(a.Targets))})
	}
	return Table{Columns: []string{"ID", "PROVIDER", "ORIGIN", "CREDENTIAL", "CREDENTIAL EXPIRES", "TARGETS"}, Rows: rows, JSON: list}
}
func targetTable(list apigen.AdapterTargetList) Table {
	rows := [][]string{}
	for _, t := range list.Items {
		destination := t.DestinationOwner
		if t.DestinationName != "" {
			destination += "/" + t.DestinationName
		}
		revision := ""
		if t.ConvergedRevision != nil {
			revision = fmt.Sprint(*t.ConvergedRevision)
		}
		rows = append(rows, []string{string(t.Id), string(t.EnvironmentId), destination, t.NamePrefix, string(t.SyncStatus), revision, strings.Join(t.FailureNames, ","), strings.Join(t.Warnings, ","), strings.Join(adapterConflictNames(t.Conflicts), ",")})
	}
	return Table{Columns: []string{"ID", "ENVIRONMENT", "DESTINATION", "PREFIX", "STATUS", "REVISION", "FAILURES", "WARNINGS", "CONFLICTS"}, Rows: rows, JSON: list}
}

func adapterDetailTable(in apigen.Adapter) Table {
	rows := make([][]string, 0, len(in.Targets))
	for _, target := range in.Targets {
		expires := ""
		if in.CredentialExpiresAt != nil {
			expires = in.CredentialExpiresAt.Format(time.RFC3339)
		}
		destination := target.DestinationOwner
		if target.DestinationName != "" {
			destination += "/" + target.DestinationName
		}
		revision := ""
		if target.ConvergedRevision != nil {
			revision = fmt.Sprint(*target.ConvergedRevision)
		}
		rows = append(rows, []string{string(in.Id), in.Origin, expires, string(target.Id), string(target.EnvironmentId), destination, string(target.SyncStatus), revision, strings.Join(target.FailureNames, ","), strings.Join(target.Warnings, ","), strings.Join(adapterConflictNames(target.Conflicts), ",")})
	}
	if len(rows) == 0 {
		rows = append(rows, []string{string(in.Id), in.Origin, "", "", "", "", "", "", "", "", ""})
	}
	return Table{Columns: []string{"ADAPTER", "ORIGIN", "CREDENTIAL EXPIRES", "TARGET", "ENVIRONMENT", "DESTINATION", "STATUS", "REVISION", "FAILURES", "WARNINGS", "CONFLICTS"}, Rows: rows, JSON: in}
}

func adapterConflictNames(artifacts []apigen.AdapterConflictArtifact) []string {
	var names []string
	for _, artifact := range artifacts {
		for _, entry := range artifact.Entries {
			names = append(names, string(entry.Surface)+":"+entry.EffectiveName)
		}
	}
	return names
}
func teardownTable(out apigen.AdapterTeardown) Table {
	return Table{Columns: []string{"ORPHANED"}, Rows: [][]string{{strings.Join(out.Orphaned, ",")}}, JSON: out}
}
func adapterMoveTable(out apigen.AdapterMove) Table {
	rows := make([][]string, 0, len(out.Targets))
	for _, target := range out.Targets {
		destination := target.DestinationOwner
		if target.DestinationName != "" {
			destination += "/" + target.DestinationName
		}
		jobs := make([]string, 0, len(target.Jobs))
		for _, job := range target.Jobs {
			jobs = append(jobs, fmt.Sprintf("%s:%s:%s", job.Kind, job.Id, job.State))
		}
		rows = append(rows, []string{
			string(out.Id), string(out.State), string(out.Kind), out.PendingOrigin,
			string(target.TargetId), destination, strings.Join(jobs, ","), strings.Join(target.OrphanedNames, ","),
		})
	}
	return Table{
		Columns: []string{"MOVE", "STATE", "KIND", "PENDING ORIGIN", "TARGET", "DESTINATION", "JOBS", "ORPHANED"},
		Rows:    rows,
		JSON:    out,
	}
}
func zeroBytes(v []byte) {
	for i := range v {
		v[i] = 0
	}
}
