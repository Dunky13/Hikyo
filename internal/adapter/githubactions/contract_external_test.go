package githubactions

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

//go:embed testdata/hikyo-contract-consume.yml
var contractWorkflowFixture []byte

type githubContractConfig struct {
	owner, repository, environment, workflowPath, ref                                    string
	repositoryToken, organizationToken, environmentToken                                 string
	repositoryDeniedToken, organizationDeniedToken, environmentDeniedToken, harnessToken string
}

// TestGitHubDotComContract is intentionally destructive and opt-in. The gate
// is all-or-nothing: partial credentials never produce a partial contract-pass
// claim. The dedicated repository must contain contractWorkflowFixture at
// workflowPath/ref. The harness token needs Contents read, Actions read/write,
// and Administration write; delivery tokens carry only the documented floor
// for their destination kind. Each denied token is a valid fine-grained PAT
// with one required permission omitted from that kind. Provider values are
// never read or logged; workflow artifacts contain SHA-256 hashes only.
func TestGitHubDotComContract(t *testing.T) {
	cfg, ok := loadGitHubContractConfig(t)
	if !ok {
		return
	}
	harness := newContractHTTP(cfg)
	harness.assertWorkflowFixture(t)

	repositoryClient := newContractClient(t, cfg.repositoryToken)
	organizationClient := newContractClient(t, cfg.organizationToken)
	environmentClient := newContractClient(t, cfg.environmentToken)
	adminClient := newContractClient(t, cfg.harnessToken)
	repositoryDeniedClient := newContractClient(t, cfg.repositoryDeniedToken)
	organizationDeniedClient := newContractClient(t, cfg.organizationDeniedToken)
	environmentDeniedClient := newContractClient(t, cfg.environmentDeniedToken)

	repository := adapter.Destination{Kind: adapter.Repository, Owner: cfg.owner, Name: cfg.repository}
	repositoryIdentity, err := repositoryClient.ResolveDestination(t.Context(), repository)
	if err != nil || repositoryIdentity.ID <= 0 {
		t.Fatalf("resolve dedicated repository identity: id=%d error=%v", repositoryIdentity.ID, err)
	}
	repository.NumericID = repositoryIdentity.ID

	organization := adapter.Destination{Kind: adapter.Organization, Owner: cfg.owner, Visibility: "selected", SelectedRepositoryIDs: []int64{repositoryIdentity.ID}}
	organizationIdentity, err := organizationClient.ResolveDestination(t.Context(), organization)
	if err != nil || organizationIdentity.ID <= 0 {
		t.Fatalf("resolve dedicated organization identity: id=%d error=%v", organizationIdentity.ID, err)
	}
	organization.NumericID = organizationIdentity.ID

	environment := adapter.Destination{Kind: adapter.Environment, Owner: cfg.owner, Name: cfg.repository, Environment: cfg.environment, RepositoryID: repositoryIdentity.ID}
	environmentIdentity, err := environmentClient.ResolveDestination(t.Context(), environment)
	if err != nil || environmentIdentity.ID <= 0 || environmentIdentity.RepositoryID != repositoryIdentity.ID {
		t.Fatalf("resolve protected environment identity: repo=%d environment=%d error=%v", environmentIdentity.RepositoryID, environmentIdentity.ID, err)
	}
	environment.NumericID = environmentIdentity.ID

	// Validate every static premise before the first provider mutation.
	assertNoVariableReadSurface(t)
	assertConnectionContract(t, repositoryClient, cfg.repositoryToken, repository, repositoryIdentity.ID, repositoryIdentity.ID)
	assertConnectionContract(t, organizationClient, cfg.organizationToken, organization, organizationIdentity.ID, 0)
	assertConnectionContract(t, environmentClient, cfg.environmentToken, environment, environmentIdentity.ID, repositoryIdentity.ID)
	assertNamedPermissionRefusal(t, repositoryDeniedClient, cfg.repositoryDeniedToken, repository, "Secrets: write", "Variables: write")
	assertNamedPermissionRefusal(t, organizationDeniedClient, cfg.organizationDeniedToken, organization, "Secrets: write", "Variables: write")
	assertNamedPermissionRefusal(t, environmentDeniedClient, cfg.environmentDeniedToken, environment, "Environments: write", "Actions: read")

	before := harness.environmentProtection(t, cfg.environment)
	if !before.protected {
		t.Fatal("dedicated contract environment has no protection rules; configure a protected, unattended environment before enabling the harness")
	}
	if !before.unattended {
		t.Fatal("dedicated contract environment requires reviewers; use unattended branch protection so workflow consumption can complete")
	}
	if err := adminClient.CreateEnvironment(t.Context(), environment); err != nil {
		t.Fatalf("settings-free PUT against protected environment: %v", err)
	}
	after := harness.environmentProtection(t, cfg.environment)
	if !bytes.Equal(before.canonical, after.canonical) {
		t.Fatal("settings-free environment PUT changed reviewers, wait timers, or branch policy")
	}

	suffix := strings.ToUpper(strconv.FormatInt(time.Now().UTC().UnixNano(), 36))
	prefix := "HIKYO_CONTRACT_" + suffix + "_"
	t.Run("repository minimum token and workflow consumption", func(t *testing.T) {
		runGitHubScopeContract(t, repositoryClient, harness, repository, prefix+"REPO_")
	})
	t.Run("organization minimum token and workflow consumption", func(t *testing.T) {
		if err := organizationClient.VerifySelectedRepositories(t.Context(), organization); err != nil {
			t.Fatalf("verify immutable selected repository ids: %v", err)
		}
		runGitHubScopeContract(t, organizationClient, harness, organization, prefix+"ORG_")
	})
	t.Run("protected environment minimum token and workflow consumption", func(t *testing.T) {
		runGitHubScopeContract(t, environmentClient, harness, environment, prefix+"ENV_")
	})
	t.Run("administration token auto-create identity pin", func(t *testing.T) {
		name := strings.ToLower(prefix) + "autocreate"
		destination := adapter.Destination{Kind: adapter.Environment, Owner: cfg.owner, Name: cfg.repository, Environment: name, RepositoryID: repositoryIdentity.ID}
		if err := adminClient.CreateEnvironment(t.Context(), destination); err != nil {
			t.Fatalf("settings-free environment create: %v", err)
		}
		t.Cleanup(func() {
			if err := harness.deleteEnvironment(context.Background(), name); err != nil {
				t.Errorf("teardown auto-created environment: %v", err)
			}
		})
		identity, err := adminClient.ResolveDestination(t.Context(), destination)
		if err != nil || identity.ID <= 0 || identity.RepositoryID != repositoryIdentity.ID {
			t.Fatalf("post-PUT identity pin=(%d,%d): %v", identity.RepositoryID, identity.ID, err)
		}
	})
}

func loadGitHubContractConfig(t *testing.T) (githubContractConfig, bool) {
	t.Helper()
	if os.Getenv("HIKYO_GITHUB_CONTRACT") != "1" {
		t.Skip("EXTERNAL github.com contract SKIPPED LOUDLY: set HIKYO_GITHUB_CONTRACT=1 only for the dedicated all-or-nothing harness")
		return githubContractConfig{}, false
	}
	cfg := githubContractConfig{
		owner:                   os.Getenv("HIKYO_GITHUB_CONTRACT_OWNER"),
		repository:              os.Getenv("HIKYO_GITHUB_CONTRACT_REPOSITORY"),
		environment:             os.Getenv("HIKYO_GITHUB_CONTRACT_ENVIRONMENT"),
		workflowPath:            os.Getenv("HIKYO_GITHUB_CONTRACT_WORKFLOW_PATH"),
		ref:                     os.Getenv("HIKYO_GITHUB_CONTRACT_REF"),
		repositoryToken:         os.Getenv("HIKYO_GITHUB_CONTRACT_REPOSITORY_TOKEN"),
		organizationToken:       os.Getenv("HIKYO_GITHUB_CONTRACT_ORGANIZATION_TOKEN"),
		environmentToken:        os.Getenv("HIKYO_GITHUB_CONTRACT_ENVIRONMENT_TOKEN"),
		repositoryDeniedToken:   os.Getenv("HIKYO_GITHUB_CONTRACT_REPOSITORY_DENIED_TOKEN"),
		organizationDeniedToken: os.Getenv("HIKYO_GITHUB_CONTRACT_ORGANIZATION_DENIED_TOKEN"),
		environmentDeniedToken:  os.Getenv("HIKYO_GITHUB_CONTRACT_ENVIRONMENT_DENIED_TOKEN"),
		harnessToken:            os.Getenv("HIKYO_GITHUB_CONTRACT_HARNESS_TOKEN"),
	}
	missing := make([]string, 0, 12)
	for name, value := range map[string]string{
		"OWNER": cfg.owner, "REPOSITORY": cfg.repository, "ENVIRONMENT": cfg.environment,
		"WORKFLOW_PATH": cfg.workflowPath, "REF": cfg.ref, "REPOSITORY_TOKEN": cfg.repositoryToken,
		"ORGANIZATION_TOKEN": cfg.organizationToken, "ENVIRONMENT_TOKEN": cfg.environmentToken,
		"REPOSITORY_DENIED_TOKEN": cfg.repositoryDeniedToken, "ORGANIZATION_DENIED_TOKEN": cfg.organizationDeniedToken,
		"ENVIRONMENT_DENIED_TOKEN": cfg.environmentDeniedToken, "HARNESS_TOKEN": cfg.harnessToken,
	} {
		if value == "" {
			missing = append(missing, "HIKYO_GITHUB_CONTRACT_"+name)
		}
	}
	if len(missing) != 0 {
		slices.Sort(missing)
		t.Skipf("EXTERNAL github.com contract SKIPPED LOUDLY: dedicated all-or-nothing configuration is missing %s", strings.Join(missing, ", "))
		return githubContractConfig{}, false
	}
	tokens := []string{cfg.repositoryToken, cfg.organizationToken, cfg.environmentToken, cfg.repositoryDeniedToken, cfg.organizationDeniedToken, cfg.environmentDeniedToken, cfg.harnessToken}
	for i := range tokens {
		for j := i + 1; j < len(tokens); j++ {
			if tokens[i] == tokens[j] {
				t.Fatal("EXTERNAL github.com contract configuration invalid: minimum, one-permission-less, and harness tokens must all be distinct")
			}
		}
	}
	return cfg, true
}

func newContractClient(t *testing.T, token string) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{Origin: "https://api.github.com", Credential: token, Deadline: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Forget)
	return client
}

func assertNoVariableReadSurface(t *testing.T) {
	t.Helper()
	typeOf := reflect.TypeOf((*API)(nil)).Elem()
	for i := range typeOf.NumMethod() {
		name := typeOf.Method(i).Name
		if strings.Contains(name, "Variable") && (strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List")) {
			t.Fatalf("provider boundary unexpectedly exposes variable values through %s", name)
		}
	}
}

func assertConnectionContract(t *testing.T, client *Client, token string, destination adapter.Destination, destinationID, repositoryID int64) {
	t.Helper()
	connection, err := (&Module{API: client}).TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: destination, Access: adapter.Access{Credential: token}, Gate: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("minimum connection permissions or identity contract failed: %v", err)
	}
	if connection.DestinationID != destinationID || connection.RepositoryID != repositoryID {
		t.Fatalf("connection identity=(%d,%d), want (%d,%d)", connection.RepositoryID, connection.DestinationID, repositoryID, destinationID)
	}
}

func assertNamedPermissionRefusal(t *testing.T, client *Client, token string, destination adapter.Destination, permissionNames ...string) {
	t.Helper()
	_, err := (&Module{API: client}).TestConnection(t.Context(), adapter.ConnectionRequest{
		Destination: destination, Access: adapter.Access{Credential: token}, Gate: func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatalf("permission-less %s token unexpectedly passed", destination.Kind)
	}
	for _, name := range permissionNames {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("permission-less %s refusal did not name %q: %v", destination.Kind, name, err)
		}
	}
}

func workflowByteClasses() []struct{ name, value string } {
	return []struct{ name, value string }{
		{name: "EMPTY", value: ""},
		{name: "CRLF", value: "line-one\r\nline-two\r\n"},
		{name: "LONE_CR", value: "line-one\rline-two"},
		{name: "TRAILING_WHITESPACE", value: "value \t  "},
		{name: "UNICODE", value: "雪-☃-e\u0301"},
		{name: "LIMIT_48K", value: strings.Repeat("x", 48*1024)},
	}
}

func runGitHubScopeContract(t *testing.T, client *Client, harness *contractHTTP, destination adapter.Destination, prefix string) {
	t.Helper()
	variable := prefix + "VARIABLE"
	missing := prefix + "MISSING"
	adoption := prefix + "ADOPTION"
	created, err := client.CreateVariable(t.Context(), destination, variable, "contract-value-not-logged")
	if err != nil || created.Status != http.StatusCreated {
		t.Fatalf("variable POST status=%d: %v", created.Status, err)
	}
	configureSelectedRecipients(t, client, destination, adapter.Variable, variable)
	t.Cleanup(func() {
		cleanupContractName(t, client.DeleteVariable(context.Background(), destination, variable), "variable")
	})
	if _, err := client.CreateVariable(t.Context(), destination, variable, "contract-value-not-logged"); !IsStatus(err, http.StatusConflict) {
		t.Fatalf("duplicate variable POST did not return exact 409: %v", err)
	}
	if _, err := client.UpdateVariable(t.Context(), destination, missing, "contract-value-not-logged"); !IsStatus(err, http.StatusNotFound) {
		t.Fatalf("missing variable PATCH did not return exact 404: %v", err)
	}

	key, err := client.PublicKey(t.Context(), destination)
	if err != nil {
		t.Fatalf("public key with minimum destination permission: %v", err)
	}
	for _, row := range workflowByteClasses() {
		name := prefix + row.name
		if result, err := client.CreateVariable(t.Context(), destination, name, row.value); err != nil || result.Status != http.StatusCreated {
			t.Fatalf("workflow byte class %s variable status=%d: %v", row.name, result.Status, err)
		}
		configureSelectedRecipients(t, client, destination, adapter.Variable, name)
		t.Cleanup(func() {
			cleanupContractName(t, client.DeleteVariable(context.Background(), destination, name), "workflow variable")
		})

		secretName := prefix + "SECRET_" + row.name
		sealed, err := SealSecret([]byte(row.value), key)
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.PutSecret(t.Context(), destination, secretName, sealed, key.ID)
		if err != nil || (result.Status != http.StatusCreated && result.Status != http.StatusNoContent) {
			t.Fatalf("workflow byte class %s secret status=%d: %v", row.name, result.Status, err)
		}
		configureSelectedRecipients(t, client, destination, adapter.Secret, secretName)
		t.Cleanup(func() {
			cleanupContractName(t, client.DeleteSecret(context.Background(), destination, secretName), "workflow secret")
		})
		harness.assertWorkflowHashes(t, destination, secretName, name, row.value)
	}

	sealed, err := SealSecret([]byte("contract-secret-not-logged"), key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.PutSecret(t.Context(), destination, adoption, sealed, key.ID)
	if err != nil || (result.Status != http.StatusCreated && result.Status != http.StatusNoContent) {
		t.Fatalf("adoption secret PUT status=%d: %v", result.Status, err)
	}
	configureSelectedRecipients(t, client, destination, adapter.Secret, adoption)
	t.Cleanup(func() {
		cleanupContractName(t, client.DeleteSecret(context.Background(), destination, adoption), "adoption secret")
	})
	plan, err := (&Module{API: client}).Plan(t.Context(), adapter.PlanRequest{
		Target: adapter.Target{Destination: destination}, Gate: func(context.Context) error { return nil },
		Manifest: []adapter.ManifestEntry{{CanonicalName: adoption, Classification: adapter.SecretClassification}},
	})
	if err != nil {
		t.Fatalf("adoption preflight plan: %v", err)
	}
	if !containsContractConflict(plan.Changes, adoption) {
		t.Fatalf("pre-existing secret was not classified for explicit adoption")
	}
}

func configureSelectedRecipients(t *testing.T, client *Client, destination adapter.Destination, surface adapter.Surface, name string) {
	t.Helper()
	if destination.Kind == adapter.Organization && destination.Visibility == "selected" {
		if err := client.ReplaceSelectedRepositories(t.Context(), destination, surface, name); err != nil {
			t.Fatalf("selected %s recipient full replacement: %v", surface, err)
		}
	}
}

func containsContractConflict(changes []adapter.Change, name string) bool {
	for _, change := range changes {
		if change.EffectiveName == name && change.Disposition == adapter.Conflict {
			return true
		}
	}
	return false
}

func cleanupContractName(t *testing.T, err error, kind string) {
	t.Helper()
	if err != nil && !IsStatus(err, http.StatusNotFound) {
		t.Errorf("teardown %s: %v", kind, err)
	}
}

type contractHTTP struct {
	cfg    githubContractConfig
	client *http.Client
}

func newContractHTTP(cfg githubContractConfig) *contractHTTP {
	return &contractHTTP{cfg: cfg, client: &http.Client{Timeout: 45 * time.Second}}
}

func (c *contractHTTP) api(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, reader)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+c.cfg.harnessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, responseCap))
		return response.StatusCode, fmt.Errorf("github contract %s %s status %d", method, path, response.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, responseCap))
		return response.StatusCode, nil
	}
	return response.StatusCode, json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(out)
}

func escapeContractPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func (c *contractHTTP) repoPath(suffix string) string {
	return "/repos/" + url.PathEscape(c.cfg.owner) + "/" + url.PathEscape(c.cfg.repository) + suffix
}

func (c *contractHTTP) assertWorkflowFixture(t *testing.T) {
	t.Helper()
	var response struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	path := c.repoPath("/contents/"+escapeContractPath(c.cfg.workflowPath)) + "?ref=" + url.QueryEscape(c.cfg.ref)
	if _, err := c.api(t.Context(), http.MethodGet, path, nil, &response); err != nil {
		t.Fatalf("read installed workflow fixture: %v", err)
	}
	if response.Encoding != "base64" {
		t.Fatalf("installed workflow fixture encoding=%q, want base64", response.Encoding)
	}
	installed, err := base64.StdEncoding.DecodeString(response.Content)
	if err != nil {
		t.Fatalf("decode installed workflow fixture: %v", err)
	}
	if !bytes.Equal(installed, contractWorkflowFixture) {
		t.Fatalf("installed workflow fixture differs from testdata/hikyo-contract-consume.yml")
	}
}

type environmentProtection struct {
	canonical  []byte
	protected  bool
	unattended bool
}

func (c *contractHTTP) environmentProtection(t *testing.T, name string) environmentProtection {
	t.Helper()
	var response struct {
		ProtectionRules []struct {
			Type string `json:"type"`
		} `json:"protection_rules"`
		DeploymentBranchPolicy *struct {
			ProtectedBranches    bool `json:"protected_branches"`
			CustomBranchPolicies bool `json:"custom_branch_policies"`
		} `json:"deployment_branch_policy"`
		RawProtectionRules json.RawMessage
	}
	var raw map[string]json.RawMessage
	path := c.repoPath("/environments/" + url.PathEscape(name))
	if _, err := c.api(t.Context(), http.MethodGet, path, nil, &raw); err != nil {
		t.Fatalf("read protected environment settings: %v", err)
	}
	projection := map[string]json.RawMessage{
		"protection_rules":         raw["protection_rules"],
		"deployment_branch_policy": raw["deployment_branch_policy"],
		"can_admins_bypass":        raw["can_admins_bypass"],
		"prevent_self_review":      raw["prevent_self_review"],
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if value := raw["protection_rules"]; len(value) != 0 {
		if err := json.Unmarshal(value, &response.ProtectionRules); err != nil {
			t.Fatalf("decode environment protection rules: %v", err)
		}
	}
	if value := raw["deployment_branch_policy"]; len(value) != 0 && string(value) != "null" {
		if err := json.Unmarshal(value, &response.DeploymentBranchPolicy); err != nil {
			t.Fatalf("decode environment branch policy: %v", err)
		}
	}
	protected := len(response.ProtectionRules) != 0 || (response.DeploymentBranchPolicy != nil && (response.DeploymentBranchPolicy.ProtectedBranches || response.DeploymentBranchPolicy.CustomBranchPolicies))
	unattended := true
	for _, rule := range response.ProtectionRules {
		if rule.Type == "required_reviewers" {
			unattended = false
		}
	}
	return environmentProtection{canonical: encoded, protected: protected, unattended: unattended}
}

func (c *contractHTTP) assertWorkflowHashes(t *testing.T, destination adapter.Destination, secretName, variableName, value string) {
	t.Helper()
	nonce := strings.ToLower(strconv.FormatInt(time.Now().UTC().UnixNano(), 36))
	environmentName := ""
	if destination.Kind == adapter.Environment {
		environmentName = destination.Environment
	}
	started := time.Now().UTC().Add(-5 * time.Second)
	body := map[string]any{"ref": c.cfg.ref, "inputs": map[string]string{
		"nonce": nonce, "secret_name": secretName, "variable_name": variableName, "environment_name": environmentName,
	}}
	workflowID := url.PathEscape(path.Base(c.cfg.workflowPath))
	if status, err := c.api(t.Context(), http.MethodPost, c.repoPath("/actions/workflows/"+workflowID+"/dispatches"), body, nil); err != nil || status != http.StatusNoContent {
		t.Fatalf("dispatch hash-only workflow status=%d: %v", status, err)
	}
	runID := c.waitForWorkflow(t, workflowID, nonce, started)
	artifactID, archiveURL := c.waitForArtifact(t, runID, nonce)
	got := c.downloadHashes(t, archiveURL)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
	if got.Secret != want || got.Variable != want {
		t.Fatalf("workflow byte hash mismatch for %s (secret_match=%t variable_match=%t)", destination.Kind, got.Secret == want, got.Variable == want)
	}
	if _, err := c.api(t.Context(), http.MethodDelete, c.repoPath("/actions/artifacts/"+strconv.FormatInt(artifactID, 10)), nil, nil); err != nil {
		t.Errorf("delete hash-only artifact: %v", err)
	}
}

func (c *contractHTTP) waitForWorkflow(t *testing.T, workflowID, nonce string, started time.Time) int64 {
	t.Helper()
	deadline := time.Now().Add(12 * time.Minute)
	title := "hikyo-contract-" + nonce
	for time.Now().Before(deadline) {
		var response struct {
			Runs []struct {
				ID           int64     `json:"id"`
				DisplayTitle string    `json:"display_title"`
				Status       string    `json:"status"`
				Conclusion   string    `json:"conclusion"`
				CreatedAt    time.Time `json:"created_at"`
			} `json:"workflow_runs"`
		}
		path := c.repoPath("/actions/workflows/"+workflowID+"/runs") + "?event=workflow_dispatch&per_page=50"
		if _, err := c.api(t.Context(), http.MethodGet, path, nil, &response); err != nil {
			t.Fatalf("poll workflow run: %v", err)
		}
		for _, run := range response.Runs {
			if run.DisplayTitle != title || run.CreatedAt.Before(started) {
				continue
			}
			if run.Status == "completed" {
				if run.Conclusion != "success" {
					t.Fatalf("hash-only workflow run concluded %q", run.Conclusion)
				}
				return run.ID
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(5 * time.Second):
		}
	}
	t.Fatal("timed out waiting for hash-only workflow run")
	return 0
}

func (c *contractHTTP) waitForArtifact(t *testing.T, runID int64, nonce string) (int64, string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	name := "hikyo-contract-" + nonce
	for time.Now().Before(deadline) {
		var response struct {
			Artifacts []struct {
				ID                 int64  `json:"id"`
				Name               string `json:"name"`
				ArchiveDownloadURL string `json:"archive_download_url"`
				Expired            bool   `json:"expired"`
			} `json:"artifacts"`
		}
		if _, err := c.api(t.Context(), http.MethodGet, c.repoPath("/actions/runs/"+strconv.FormatInt(runID, 10)+"/artifacts"), nil, &response); err != nil {
			t.Fatalf("poll workflow artifact: %v", err)
		}
		for _, artifact := range response.Artifacts {
			if artifact.Name == name && !artifact.Expired {
				return artifact.ID, artifact.ArchiveDownloadURL
			}
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(2 * time.Second):
		}
	}
	t.Fatal("timed out waiting for hash-only workflow artifact")
	return 0, ""
}

type workflowHashes struct {
	Secret   string `json:"secret"`
	Variable string `json:"variable"`
}

func (c *contractHTTP) downloadHashes(t *testing.T, archiveURL string) workflowHashes {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, archiveURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+c.cfg.harnessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := c.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download hash-only artifact status=%d", response.StatusCode)
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range reader.File {
		if file.Name != "hashes.json" {
			continue
		}
		opened, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		var hashes workflowHashes
		err = json.NewDecoder(io.LimitReader(opened, 1024)).Decode(&hashes)
		_ = opened.Close()
		if err != nil {
			t.Fatal(err)
		}
		return hashes
	}
	t.Fatal("hash-only artifact omitted hashes.json")
	return workflowHashes{}
}

func (c *contractHTTP) deleteEnvironment(ctx context.Context, environment string) error {
	status, err := c.api(ctx, http.MethodDelete, c.repoPath("/environments/"+url.PathEscape(environment)), nil, nil)
	if err != nil && status != http.StatusNotFound {
		return err
	}
	return nil
}
