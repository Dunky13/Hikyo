package importer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/schema"
	"github.com/hashicorp/vault/api/cliconfig"
	"github.com/hashicorp/vault/api/tokenhelper"
	baoapi "github.com/openbao/openbao/api/v2"
)

const vaultSource = "vault"

type vaultConnector struct{}

func (vaultConnector) Name() string { return vaultSource }

type vaultCapture struct {
	Path          string         `json:"path"`
	Mount         string         `json:"mount"`
	EngineVersion int            `json:"engine_version"`
	SecretVersion *int           `json:"secret_version,omitempty"`
	Deleted       bool           `json:"deleted"`
	Destroyed     bool           `json:"destroyed"`
	Data          map[string]any `json:"data"`
}

func (vaultConnector) Read(ctx context.Context, in Input, b *Budget) (Result, error) {
	scanner := bufio.NewScanner(bytes.NewReader(in.Data))
	scanner.Buffer(make([]byte, 64<<10), MaxFileBytes)
	var captures []vaultCapture
	for line := 1; scanner.Scan(); line++ {
		if err := ctx.Err(); err != nil {
			return Result{}, failure(vaultSource, CodeBound, in.Path,
				"the run exceeded the %s whole-run deadline", RunDeadline)
		}
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		where := in.Path + " line " + strconv.Itoa(line)
		if err := rejectDuplicateMembers(raw, vaultSource, where); err != nil {
			return Result{}, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		dec.UseNumber()
		var capture vaultCapture
		if err := dec.Decode(&capture); err != nil {
			return Result{}, failure(vaultSource, CodeMalformed, where,
				"the line is not one pinned Vault/OpenBao capture record; see "+
					"docs/handoff/69-import-live-connectors.md#vaultopenbao-capture-recipe")
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return Result{}, failure(vaultSource, CodeMalformed, where,
				"the line carries trailing content after its capture record")
		}
		if err := validateVaultCapture(capture, where); err != nil {
			return Result{}, err
		}
		if capture.Deleted || capture.Destroyed {
			if err := b.Record(where); err != nil {
				return Result{}, err
			}
		} else {
			for _, name := range sortedVaultFieldNames(capture.Data) {
				if err := b.Record(where + " field " + quoteName(name)); err != nil {
					return Result{}, err
				}
			}
		}
		captures = append(captures, capture)
	}
	if err := scanner.Err(); err != nil {
		return Result{}, failure(vaultSource, CodeBound, in.Path,
			"a capture line exceeds the %d-byte per-file cap", MaxFileBytes)
	}
	if len(captures) == 0 {
		return Result{}, failure(vaultSource, CodeMalformed, in.Path,
			"the file holds no Vault/OpenBao JSON Lines capture record")
	}
	slices.SortFunc(captures, func(a, b vaultCapture) int { return strings.Compare(a.Path, b.Path) })
	mount, version := captures[0].Mount, captures[0].EngineVersion
	paths := make([][]string, 0, len(captures))
	for _, capture := range captures {
		if capture.Mount != mount || capture.EngineVersion != version {
			return Result{}, failure(vaultSource, CodeProvenance, in.Path,
				"one capture file must describe one mount and one KV engine version")
		}
		paths = append(paths, pathSegments(capture.Path))
	}
	prefix := commonPathPrefix(paths)

	var records []Record
	var skipped []string
	for _, capture := range captures {
		where := "secret " + quoteName(capture.Path)
		if capture.Deleted || capture.Destroyed {
			skipped = append(skipped, capture.Path)
			continue
		}
		folder := pathSegments(strings.TrimPrefix(capture.Path, prefix))
		for _, name := range sortedVaultFieldNames(capture.Data) {
			fieldWhere := where + " field " + quoteName(name)
			value, typ, err := vaultValue(b, fieldWhere, capture.Data[name])
			if err != nil {
				return Result{}, err
			}
			sourceVersion := ""
			if capture.SecretVersion != nil {
				sourceVersion = strconv.Itoa(*capture.SecretVersion)
			}
			records = append(records, Record{
				Folder: folder, SourceName: name, Value: value, Type: typ, Version: sourceVersion,
			})
		}
	}
	if len(records) == 0 {
		return Result{}, failure(vaultSource, CodeMalformed, in.Path,
			"the capture holds no current Vault/OpenBao KV field")
	}
	return Result{
		Records: records, Skipped: skipped,
		Scope: Scope{Mount: mount, PathPrefix: prefix, KVVersion: version},
	}, nil
}

func validateVaultCapture(capture vaultCapture, where string) error {
	if capture.Mount == "" || strings.Contains(capture.Mount, "/") {
		return failure(vaultSource, CodeProvenance, where,
			"the capture record carries no single mount name")
	}
	if !canonicalSourcePath(capture.Path) {
		return failure(vaultSource, CodeProvenance, where,
			"the capture record carries no canonical secret path")
	}
	if capture.EngineVersion != 1 && capture.EngineVersion != 2 {
		return failure(vaultSource, CodeProvenance, where,
			"the capture record's engine_version is neither 1 nor 2")
	}
	if capture.EngineVersion == 1 && capture.SecretVersion != nil {
		return failure(vaultSource, CodeProvenance, where,
			"a KV v1 capture record carries a v2 secret_version")
	}
	if capture.EngineVersion == 2 && (capture.SecretVersion == nil || *capture.SecretVersion < 1) {
		return failure(vaultSource, CodeProvenance, where,
			"a KV v2 capture record carries no positive secret_version")
	}
	if !capture.Deleted && !capture.Destroyed && len(capture.Data) == 0 {
		return failure(vaultSource, CodeMalformed, where,
			"a current capture record carries no data fields")
	}
	return nil
}

func commonPathPrefix(paths [][]string) string {
	prefix := append([]string{}, paths[0]...)
	for _, candidate := range paths[1:] {
		limit := min(len(prefix), len(candidate))
		i := 0
		for i < limit && prefix[i] == candidate[i] {
			i++
		}
		prefix = prefix[:i]
	}
	return strings.Join(prefix, "/")
}

type requestMeter struct {
	count int
}

func (m *requestMeter) take(where string) error {
	m.count++
	if m.count > MaxLivePages {
		return failure(vaultSource, CodeBound, where,
			"live traversal exceeds the %d-page/request cap", MaxLivePages)
	}
	return nil
}

func (vaultConnector) ReadLive(ctx context.Context, in LiveInput, b *Budget) (Result, error) {
	mount := strings.Trim(in.Mount, "/")
	if mount == "" || mount == "." || mount == ".." || strings.Contains(mount, "/") {
		return Result{}, failure(vaultSource, CodeProvenance, "", "live mode requires --mount <mount>")
	}
	prefix := strings.Trim(in.Path, "/")
	if prefix != "" && !canonicalSourcePath(prefix) {
		return Result{}, failure(vaultSource, CodeProvenance, quoteName(prefix),
			"--path is not a canonical Vault/OpenBao path prefix")
	}
	if in.KVVersion != 0 && in.KVVersion != 1 && in.KVVersion != 2 {
		return Result{}, failure(vaultSource, CodeProvenance, mount,
			"--kv-version is neither 1 nor 2")
	}

	client, origin, resolution, err := newVaultClient(ctx)
	if err != nil {
		return Result{}, err
	}
	meter := &requestMeter{}
	kvVersion := in.KVVersion
	if kvVersion == 0 {
		kvVersion, err = detectKVVersion(ctx, client, meter, mount, origin)
		if err != nil {
			return Result{}, err
		}
	}

	reader := vaultTreeReader{
		ctx: ctx, client: client, budget: b, requests: meter,
		mount: mount, prefix: prefix, kvVersion: kvVersion, origin: origin,
	}
	if err := reader.walk(""); err != nil {
		return Result{}, err
	}
	if len(reader.records) == 0 && len(reader.skipped) == 0 {
		// LIST on a single leaf returns nil on both Vault and OpenBao. Treat the
		// selected prefix as that leaf, preserving the ADR's single-secret case.
		if err := reader.readLeaf(prefix); err != nil {
			return Result{}, err
		}
	}
	if len(reader.records) == 0 {
		return Result{}, failure(vaultSource, CodeMalformed, quoteName(prefix),
			"the live selection holds no current Vault/OpenBao KV field")
	}
	slices.Sort(reader.skipped)
	return Result{
		Records: reader.records, Skipped: reader.skipped,
		Scope:      Scope{Mount: mount, PathPrefix: prefix, KVVersion: kvVersion},
		Identity:   origin,
		Resolution: resolution,
	}, nil
}

func newVaultClient(ctx context.Context) (*baoapi.Client, string, string, error) {
	cfg := baoapi.DefaultConfig()
	if cfg == nil || cfg.Error != nil {
		return nil, "", "", failure(vaultSource, CodeProvenance, "ambient configuration",
			"Vault/OpenBao client configuration is invalid")
	}
	cfg.Timeout = RequestDeadline
	cfg.MaxRetries = 0
	cfg.DisableRedirects = true
	if cfg.HttpClient == nil || cfg.HttpClient.Transport == nil {
		return nil, "", "", failure(vaultSource, CodeProvenance, "ambient configuration",
			"Vault/OpenBao transport configuration is unavailable")
	}
	cfg.HttpClient.Transport = cappedRoundTripper{next: cfg.HttpClient.Transport}
	cfg.HttpClient.CheckRedirect = refuseCredentialRedirect
	client, err := baoapi.NewClient(cfg)
	if err != nil {
		return nil, "", "", failure(vaultSource, CodeProvenance, "ambient configuration",
			"Vault/OpenBao client configuration is invalid")
	}
	parsed, err := url.Parse(client.Address())
	if err != nil || parsed.User != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, "", "", failure(vaultSource, CodeProvenance, "ambient configuration",
			"VAULT_ADDR/BAO_ADDR does not name a credential-safe origin")
	}
	addressResolution := ambientVariableResolution(baoapi.EnvVaultAddress, "default address")
	namespaceResolution := ambientVariableResolution(baoapi.EnvVaultNamespace, "no namespace")
	tokenResolution := ambientVariableResolution(baoapi.EnvVaultToken, "")
	if client.Token() == "" {
		token, resolution, err := ambientVaultToken(ctx, client.Address())
		if err != nil {
			return nil, "", "", err
		}
		client.SetToken(token)
		tokenResolution = resolution
	}
	if client.Token() == "" {
		return nil, "", "", failure(vaultSource, CodeProvenance, originOf(parsed),
			"ambient Vault/OpenBao credentials are absent")
	}
	resolution := fmt.Sprintf("address=%s, token=%s, namespace=%s",
		addressResolution, tokenResolution, namespaceResolution)
	return client, originOf(parsed), resolution, nil
}

func ambientVariableResolution(baoName, fallback string) string {
	if value, present := os.LookupEnv(baoName); present {
		if value != "" {
			return baoName
		}
		return fallback
	}
	upstream := baoapi.UpstreamVariableName(baoName)
	if value, present := os.LookupEnv(upstream); present && value != "" {
		return upstream
	}
	return fallback
}

func ambientVaultToken(ctx context.Context, address string) (string, string, error) {
	if tokenPath := baoapi.ReadBaoVariable(baoapi.EnvTokenPath); tokenPath != "" {
		raw, err := ReadFile(tokenPath)
		if err != nil {
			return "", "", failure(vaultSource, CodeProvenance, "token file",
				"the ambient token file could not be read")
		}
		return strings.TrimSpace(string(raw)), ambientVariableResolution(baoapi.EnvTokenPath, "token file"), nil
	}
	helper, resolution, err := ambientTokenHelper()
	if err != nil {
		return "", "", failure(vaultSource, CodeProvenance, "token helper",
			"the ambient token helper could not be configured")
	}
	token, err := readVaultTokenHelper(ctx, helper, address)
	return token, resolution, err
}

func ambientTokenHelper() (tokenhelper.TokenHelper, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	baoConfig := filepath.Join(home, ".bao")
	explicitBaoConfig, baoConfigSet := os.LookupEnv("BAO_CONFIG_PATH")
	if baoConfigSet && explicitBaoConfig != "" {
		baoConfig = explicitBaoConfig
	}
	_, statErr := os.Stat(baoConfig)
	useBaoConfig := baoConfigSet || statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, "", statErr
	}
	if useBaoConfig {
		prior, present := os.LookupEnv("VAULT_CONFIG_PATH")
		if err := os.Setenv("VAULT_CONFIG_PATH", baoConfig); err != nil {
			return nil, "", err
		}
		defer func() {
			if present {
				_ = os.Setenv("VAULT_CONFIG_PATH", prior)
				return
			}
			_ = os.Unsetenv("VAULT_CONFIG_PATH")
		}()
		helper, err := cliconfig.DefaultTokenHelper()
		return helper, "OpenBao token helper config", err
	}
	helper, err := cliconfig.DefaultTokenHelper()
	return helper, "Vault token helper config", err
}

func readVaultTokenHelper(ctx context.Context, helper tokenhelper.TokenHelper, address string) (string, error) {
	if external, ok := helper.(*tokenhelper.ExternalTokenHelper); ok {
		wrapped, err := wrapVaultTokenHelper(ctx, external, address)
		if err != nil {
			return "", err
		}
		helper = wrapped
	} else if _, internal := helper.(*tokenhelper.InternalTokenHelper); !internal {
		return "", failure(vaultSource, CodeProvenance, "token helper",
			"the ambient token helper kind is unsupported")
	}
	raw, err := helper.Get()
	if err != nil {
		if code, bounded := boundedSubprocessExit(err); bounded {
			if code == subprocessExitOverflow {
				return "", failure(vaultSource, CodeBound, "token helper",
					"the ambient token helper response exceeds the %d-byte cap", MaxValueBytes)
			}
			return "", failure(vaultSource, CodeBound, "token helper",
				"the ambient token helper exceeded the %s per-request deadline", RequestDeadline)
		}
		return "", failure(vaultSource, CodeProvenance, "token helper",
			"the ambient token helper failed")
	}
	if len(raw) > MaxValueBytes {
		return "", failure(vaultSource, CodeBound, "token helper",
			"the ambient token helper response exceeds the %d-byte cap", MaxValueBytes)
	}
	return strings.TrimSpace(raw), nil
}

func wrapVaultTokenHelper(ctx context.Context, helper *tokenhelper.ExternalTokenHelper, address string) (tokenhelper.TokenHelper, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, failure(vaultSource, CodeProvenance, "token helper",
			"the bounded ambient token helper runner is unavailable")
	}
	encoded, err := encodeSubprocessSpec(newSubprocessSpec(ctx, helper.BinaryPath, helper.Args, MaxValueBytes))
	if err != nil {
		return nil, failure(vaultSource, CodeProvenance, "token helper",
			"the bounded ambient token helper runner could not be configured")
	}
	env := append([]string{}, helper.Env...)
	if helper.Env == nil {
		env = os.Environ()
	}
	env = replaceEnv(env, "BAO_ADDR", address)
	env = replaceEnv(env, "VAULT_ADDR", address)
	env = replaceEnv(env, subprocessSpecEnv, encoded)
	return &tokenhelper.ExternalTokenHelper{
		BinaryPath: executable,
		Args:       []string{internalSubprocessMode},
		Env:        env,
	}, nil
}

func detectKVVersion(ctx context.Context, client *baoapi.Client, meter *requestMeter,
	mount, origin string,
) (int, error) {
	where := "mount " + quoteName(mount)
	if err := meter.take(where); err != nil {
		return 0, err
	}
	secret, err := client.Logical().ReadWithContext(ctx, path.Join("sys/internal/ui/mounts", mount))
	if err != nil {
		return 0, vaultLiveFailure(err, origin)
	}
	if secret == nil {
		return 0, failure(vaultSource, CodeProvenance, where,
			"the mount metadata is unavailable; pass --kv-version 1 or 2 explicitly")
	}
	options, ok := object(secret.Data["options"])
	if !ok {
		return 0, failure(vaultSource, CodeProvenance, where,
			"the mount metadata does not state a KV engine version; pass --kv-version 1 or 2 explicitly")
	}
	version, ok := stringValue(options["version"])
	if !ok || (version != "1" && version != "2") {
		return 0, failure(vaultSource, CodeProvenance, where,
			"the mount metadata does not state KV engine version 1 or 2")
	}
	parsed, _ := strconv.Atoi(version)
	return parsed, nil
}

type vaultTreeReader struct {
	ctx       context.Context
	client    *baoapi.Client
	budget    *Budget
	requests  *requestMeter
	mount     string
	prefix    string
	kvVersion int
	origin    string
	records   []Record
	skipped   []string
}

func (r *vaultTreeReader) walk(relative string) error {
	if err := r.budget.Depth(relative, len(pathSegments(relative))); err != nil {
		return err
	}
	providerPath := r.providerPath("list", joinSourcePath(r.prefix, relative))
	if err := r.requests.take(quoteName(providerPath)); err != nil {
		return err
	}
	secret, err := r.client.Logical().ListWithContext(r.ctx, providerPath)
	if err != nil {
		return vaultLiveFailure(err, r.origin)
	}
	if secret == nil {
		return nil
	}
	keys, ok := stringList(secret.Data["keys"])
	if !ok {
		return failure(vaultSource, CodeMalformed, quoteName(providerPath),
			"the provider list response carries no string `keys` list")
	}
	slices.Sort(keys)
	for _, key := range keys {
		child := strings.TrimSuffix(key, "/")
		if child == "" || child == "." || child == ".." || strings.Contains(child, "/") {
			return failure(vaultSource, CodeMalformed, quoteName(providerPath),
				"the provider list response carries an invalid child name")
		}
		next := joinSourcePath(relative, child)
		if strings.HasSuffix(key, "/") {
			if err := r.walk(next); err != nil {
				return err
			}
			continue
		}
		if err := r.readLeaf(joinSourcePath(r.prefix, next)); err != nil {
			return err
		}
	}
	return nil
}

func (r *vaultTreeReader) readLeaf(sourcePath string) error {
	where := "secret " + quoteName(sourcePath)
	version := ""
	if r.kvVersion == 2 {
		if err := r.requests.take(where + " metadata"); err != nil {
			return err
		}
		meta, err := r.client.Logical().ReadWithContext(r.ctx, r.providerPath("metadata", sourcePath))
		if err != nil {
			return vaultLiveFailure(err, r.origin)
		}
		if meta == nil {
			return failure(vaultSource, CodeMalformed, where, "the latest-version metadata is absent")
		}
		var ok bool
		version, ok = integerString(meta.Data["current_version"])
		if !ok {
			return failure(vaultSource, CodeMalformed, where,
				"the latest-version metadata carries no integer current version")
		}
		versions, ok := object(meta.Data["versions"])
		if !ok {
			return failure(vaultSource, CodeMalformed, where,
				"the latest-version metadata carries no versions map")
		}
		state, ok := object(versions[version])
		if !ok {
			return failure(vaultSource, CodeMalformed, where,
				"the latest-version metadata omits its current version")
		}
		deleted, _ := stringValue(state["deletion_time"])
		destroyed, _ := state["destroyed"].(bool)
		if deleted != "" || destroyed {
			r.skipped = append(r.skipped, sourcePath)
			return nil
		}
	}
	if err := r.requests.take(where + " data"); err != nil {
		return err
	}
	var secret *baoapi.Secret
	var err error
	if r.kvVersion == 2 {
		secret, err = r.client.Logical().ReadWithDataWithContext(r.ctx,
			r.providerPath("data", sourcePath), map[string][]string{"version": {version}})
	} else {
		secret, err = r.client.Logical().ReadWithContext(r.ctx, r.providerPath("data", sourcePath))
	}
	if err != nil {
		return vaultLiveFailure(err, r.origin)
	}
	if secret == nil {
		return failure(vaultSource, CodeMalformed, where, "the latest secret value is absent")
	}
	data := secret.Data
	if r.kvVersion == 2 {
		var ok bool
		data, ok = object(secret.Data["data"])
		if !ok {
			return failure(vaultSource, CodeMalformed, where,
				"the latest secret response carries no data object")
		}
		metadata, ok := object(secret.Data["metadata"])
		if !ok {
			return failure(vaultSource, CodeMalformed, where,
				"the pinned secret response carries no metadata object")
		}
		returnedVersion, ok := integerString(metadata["version"])
		if !ok || returnedVersion != version {
			return failure(vaultSource, CodeProvenance, where,
				"the pinned secret response does not match metadata version %s", version)
		}
	}
	folder := pathSegments(strings.TrimPrefix(sourcePath, r.prefix))
	for _, name := range sortedVaultFieldNames(data) {
		fieldWhere := where + " field " + quoteName(name)
		value, typ, err := vaultValue(r.budget, fieldWhere, data[name])
		if err != nil {
			return err
		}
		if err := r.budget.Record(fieldWhere); err != nil {
			return err
		}
		r.records = append(r.records, Record{
			Folder: folder, SourceName: name, Value: value, Type: typ, Version: version,
		})
	}
	return nil
}

func sortedVaultFieldNames(data map[string]any) []string {
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func (r *vaultTreeReader) providerPath(operation, sourcePath string) string {
	if r.kvVersion == 1 {
		return joinSourcePath(r.mount, sourcePath)
	}
	segment := "data"
	if operation == "list" || operation == "metadata" {
		segment = "metadata"
	}
	return joinSourcePath(r.mount, segment, sourcePath)
}

func vaultValue(b *Budget, where string, value any) (string, schema.Type, error) {
	if text, ok := value.(string); ok {
		if err := b.Bytes(where, len(text)); err != nil {
			return "", "", err
		}
		return text, schema.TypeString, nil
	}
	encoded, err := canonicalJSON(b, where, value)
	if err != nil {
		return "", "", err
	}
	return encoded, schema.TypeJSON, nil
}

func vaultLiveFailure(err error, origin string) error {
	var redirect *refusedRedirect
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &redirect):
		return failure(vaultSource, CodeProvenance, "",
			"credential-bearing redirect from %s to %s was refused", redirect.from, redirect.to)
	case errors.Is(err, errLiveResponseTooLarge), errors.As(err, &tooLarge):
		return failure(vaultSource, CodeBound, origin,
			"a provider response exceeds the %d-byte per-response cap", MaxResponseBytes)
	case errors.Is(err, context.DeadlineExceeded):
		return failure(vaultSource, CodeBound, origin,
			"a provider request exceeded the %s per-request deadline", RequestDeadline)
	default:
		return failure(vaultSource, CodeMalformed, origin, "the Vault/OpenBao API read failed")
	}
}

func object(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func stringValue(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	default:
		return "", false
	}
}

func integerString(value any) (string, bool) {
	switch value := value.(type) {
	case json.Number:
		if _, err := value.Int64(); err == nil {
			return value.String(), true
		}
	case float64:
		if value == float64(int64(value)) {
			return strconv.FormatInt(int64(value), 10), true
		}
	case int:
		return strconv.Itoa(value), true
	}
	return "", false
}

func stringList(value any) ([]string, bool) {
	switch values := value.(type) {
	case []string:
		return append([]string{}, values...), true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}

func joinSourcePath(parts ...string) string {
	var clean []string
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			clean = append(clean, part)
		}
	}
	return strings.Join(clean, "/")
}

func pathSegments(value string) []string {
	value = strings.Trim(value, "/")
	if value == "" {
		return nil
	}
	return strings.Split(value, "/")
}

func canonicalSourcePath(value string) bool {
	segments := pathSegments(value)
	if len(segments) == 0 || joinSourcePath(segments...) != value {
		return false
	}
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
