package importer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/api/tokenhelper"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestK8sLiveFixtureImportsSecretPages(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer fixture-token" {
			t.Errorf("authorization = %q, want kubeconfig bearer token", got)
		}
		if r.URL.Path != "/api/v1/namespaces/demo/secrets" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("continue") {
		case "":
			fmt.Fprintf(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{"continue":"next"},"items":[{"metadata":{"name":"api","namespace":"demo","resourceVersion":"17"},"data":{"api-key":"%s"}}]}`,
				base64.StdEncoding.EncodeToString([]byte("api-secret")))
		case "next":
			fmt.Fprintf(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{},"items":[{"metadata":{"name":"db","namespace":"demo","resourceVersion":"23"},"data":{"DB_URL":"%s"}}]}`,
				base64.StdEncoding.EncodeToString([]byte("postgres://fixture")))
		default:
			t.Fatalf("unexpected continue token %q", r.URL.Query().Get("continue"))
		}
	}))
	t.Cleanup(server.Close)

	kubeconfig := filepath.Join(t.TempDir(), "config")
	contextName := "fixture-context\n\x1b[2J"
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: %q
  context:
    cluster: fixture-cluster
    user: fixture-user
current-context: %q
users:
- name: fixture-user
  user:
    token: fixture-token
`, server.URL, contextName, contextName)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	result, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 paged reads", requests)
	}
	if result.Identity != "fixture-cluster/"+contextName {
		t.Fatalf("identity = %q", result.Identity)
	}
	if strings.ContainsAny(result.Resolution, "\n\r\x1b") || !strings.Contains(result.Resolution, quoteName(contextName)) {
		t.Fatalf("unsafe or missing context in resolution = %q", result.Resolution)
	}
	if !reflect.DeepEqual(result.Scope, Scope{Namespace: "demo", Names: []string{"api", "db"}}) {
		t.Fatalf("scope = %+v", result.Scope)
	}
	want := []Record{
		{Folder: []string{"api"}, SourceName: "api-key", Value: "api-secret", Type: "string", Version: "17"},
		{Folder: []string{"db"}, SourceName: "DB_URL", Value: "postgres://fixture", Type: "string", Version: "23"},
	}
	if !reflect.DeepEqual(result.Records, want) {
		t.Fatalf("records = %#v, want %#v", result.Records, want)
	}
}

func TestK8sLiveStopsWhileStreamingAtAggregateRecordBound(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		start, count, next := 0, 4000, "second"
		if r.URL.Query().Get("continue") == "second" {
			start, count, next = 4000, 1001, "must-not-be-requested"
		}
		fmt.Fprintf(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{"continue":%q},"items":[`, next)
		for i := 0; i < count; i++ {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"metadata":{"name":"secret-%04d","namespace":"demo","resourceVersion":"1"},"data":{"KEY":"eA=="}}`, start+i)
		}
		fmt.Fprint(w, `]}`)
	}))
	t.Cleanup(server.Close)

	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: fixture-user}
current-context: fixture-context
users:
- name: fixture-user
  user: {token: fixture-token}
`, server.URL)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	_, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo"})
	if err == nil {
		t.Fatal("aggregate record overflow was accepted")
	}
	wantCode(t, err, CodeBound)
	if requests != 2 {
		t.Fatalf("requests = %d, want traversal to stop on second page", requests)
	}
}

func TestK8sLiveContextOverrideBindsClientIdentityAndExecClusterInfo(t *testing.T) {
	wrongRequests := 0
	wrong := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		wrongRequests++
	}))
	t.Cleanup(wrong.Close)
	selectedRequests := 0
	selected := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selectedRequests++
		if got := r.Header.Get("Authorization"); got != "Bearer selected-token" {
			t.Errorf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app","namespace":"demo","resourceVersion":"9"},"data":{"KEY":"dmFsdWU="}}`)
	}))
	t.Cleanup(selected.Close)

	dir := t.TempDir()
	helper := filepath.Join(dir, "credential-helper")
	script := `#!/bin/sh
case "$KUBERNETES_EXEC_INFO" in
  *"$EXPECTED_CLUSTER"*) ;;
  *) exit 75 ;;
esac
printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"selected-token"}}'
`
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	kubeconfig := filepath.Join(dir, "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: current-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
- name: selected-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: current
  context: {cluster: current-cluster, user: current-user}
- name: selected
  context: {cluster: selected-cluster, user: selected-user}
current-context: current
users:
- name: current-user
  user: {token: wrong-token}
- name: selected-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      provideClusterInfo: true
      command: %q
      env:
      - name: EXPECTED_CLUSTER
        value: %q
`, wrong.URL, selected.URL, helper, selected.URL)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	result, err := RunLive(t.Context(), k8sSource,
		LiveInput{Context: "selected", Namespace: "demo", Name: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if wrongRequests != 0 || selectedRequests != 1 {
		t.Fatalf("wrong requests = %d, selected requests = %d", wrongRequests, selectedRequests)
	}
	if result.Identity != "selected-cluster/selected" {
		t.Fatalf("identity = %q", result.Identity)
	}
	if result.Resolution != `kubeconfig context="selected"` {
		t.Fatalf("resolution = %q", result.Resolution)
	}
}

func TestK8sLiveExecPluginRunsAtSanitizedSharedPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer exec-fixture-token" {
			t.Errorf("authorization = %q, want exec-plugin token", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app","namespace":"demo","resourceVersion":"1"},"data":{"KEY":"dmFsdWU="}}`)
	}))
	t.Cleanup(server.Close)

	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: IfAvailable
      command: /bin/sh
      args:
      - -c
      - 'if env | grep -q "^HIKYO_"; then exit 71; fi; printf %%s "$KUBERNETES_EXEC_INFO" | grep -q ''"interactive":false'' || exit 72; printf ''{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"exec-fixture-token"}}'''
`, server.URL)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("HIKYO_TOKEN", "hikyo_token_must_not_reach_exec_plugin")

	result, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 || result.Records[0].Value != "value" {
		t.Fatalf("records = %#v", result.Records)
	}
	if os.Getenv("HIKYO_TOKEN") != "hikyo_token_must_not_reach_exec_plugin" {
		t.Fatal("shared sanitized scope did not restore Hikyo environment")
	}
}

func TestK8sExecWrapperPreservesOriginalPluginPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy clientcmdapi.PluginPolicy
		ok     bool
	}{
		{name: "deny all", policy: clientcmdapi.PluginPolicy{PolicyType: clientcmdapi.PluginPolicyDenyAll}},
		{name: "matching allowlist", policy: clientcmdapi.PluginPolicy{
			PolicyType: clientcmdapi.PluginPolicyAllowlist,
			Allowlist:  []clientcmdapi.AllowlistEntry{{Command: "/bin/sh"}},
		}, ok: true},
		{name: "mismatched allowlist", policy: clientcmdapi.PluginPolicy{
			PolicyType: clientcmdapi.PluginPolicyAllowlist,
			Allowlist:  []clientcmdapi.AllowlistEntry{{Command: "/bin/false"}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plugin := &clientcmdapi.ExecConfig{Command: "/bin/sh", PluginPolicy: test.policy}
			err := wrapKubeExecProvider(t.Context(), plugin)
			if !test.ok {
				wantCode(t, err, CodeProvenance)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plugin.Command == "/bin/sh" || plugin.PluginPolicy.PolicyType != clientcmdapi.PluginPolicyAllowAll {
				t.Fatalf("validated plugin was not safely rewritten: %+v", plugin)
			}
			if !plugin.StdinUnavailable || !strings.Contains(plugin.StdinUnavailableMessage, "does not permit interactive") {
				t.Fatalf("wrapped plugin did not disable interactive stdin: %+v", plugin)
			}
		})
	}
}

func TestK8sAlwaysInteractiveExecPluginFailsBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "interactive-plugin-ran")
	kubeconfig := filepath.Join(dir, "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Always
      command: /bin/sh
      args: [-c, %q]
`, "touch "+marker)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	_, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"})
	wantCode(t, err, CodeProvenance, marker)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("interactive plugin ran: %v", statErr)
	}
}

func TestK8sLiveStaticTokenSuppressesUnusedExecPlugin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer static-token" {
			t.Errorf("authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app","namespace":"demo","resourceVersion":"1"},"data":{"KEY":"dmFsdWU="}}`)
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	marker := filepath.Join(dir, "exec-ran")
	kubeconfig := filepath.Join(dir, "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: fixture-user}
current-context: fixture-context
users:
- name: fixture-user
  user:
    token: static-token
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: /bin/sh
      args: [-c, %q]
`, server.URL, "touch "+marker+"; exit 72")
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	if _, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused exec plugin ran: %v", err)
	}
}

func TestK8sLiveExecPluginRefreshesAfterUnauthorized(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "calls")
	helper := filepath.Join(dir, "credential-helper")
	script := fmt.Sprintf(`#!/bin/sh
count=0
if [ -f %q ]; then count=$(cat %q); fi
count=$((count+1))
printf '%%s' "$count" > %q
if [ "$count" -eq 1 ]; then token=first-token; else token=second-token; fi
printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"%%s"}}' "$token"
`, counter, counter, counter)
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "Bearer first-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Unauthorized","code":401}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer second-token" {
			t.Errorf("authorization = %q, want refreshed token", got)
		}
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"app","namespace":"demo","resourceVersion":"1"},"data":{"KEY":"dmFsdWU="}}`)
	}))
	t.Cleanup(server.Close)

	kubeconfig := filepath.Join(dir, "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: %q
`, server.URL, helper)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	result, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(result.Records) != 1 {
		t.Fatalf("requests = %d, records = %#v", requests, result.Records)
	}
	if raw, err := os.ReadFile(counter); err != nil || string(raw) != "2" {
		t.Fatalf("credential helper calls = %q, err = %v", raw, err)
	}
}

func TestK8sLiveExecPluginRefreshesExpiredCredentialBetweenPages(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "calls")
	helper := filepath.Join(dir, "credential-helper")
	expires := time.Now().Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	script := fmt.Sprintf(`#!/bin/sh
count=0
if [ -f %q ]; then count=$(cat %q); fi
count=$((count+1))
printf '%%s' "$count" > %q
if [ "$count" -eq 1 ]; then
  printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"first-token","expirationTimestamp":%q}}'
else
  printf '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"second-token"}}'
fi
`, counter, counter, counter, expires)
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("continue") == "" {
			if got := r.Header.Get("Authorization"); got != "Bearer first-token" {
				t.Errorf("first authorization = %q", got)
			}
			time.Sleep(700 * time.Millisecond)
			fmt.Fprint(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{"continue":"next"},"items":[{"metadata":{"name":"one","namespace":"demo","resourceVersion":"1"},"data":{"KEY":"MQ=="}}]}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer second-token" {
			t.Errorf("second authorization = %q, want refreshed token", got)
		}
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"SecretList","metadata":{},"items":[{"metadata":{"name":"two","namespace":"demo","resourceVersion":"2"},"data":{"KEY":"Mg=="}}]}`)
	}))
	t.Cleanup(server.Close)

	kubeconfig := filepath.Join(dir, "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: %q
`, server.URL, helper)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	result, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("records = %#v", result.Records)
	}
	if raw, err := os.ReadFile(counter); err != nil || string(raw) != "2" {
		t.Fatalf("credential helper calls = %q, err = %v", raw, err)
	}
}

func TestK8sLiveExecCredentialV1RequiresInteractiveMode(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := `apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/true
`
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	_, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"})
	if err == nil {
		t.Fatal("v1 exec credential without interactiveMode was accepted")
	}
	wantCode(t, err, CodeProvenance)
}

func TestK8sLiveExecPluginCannotOutrunConnectorDeadline(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := `apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: /bin/sh
      args: [-c, "sleep 30"]
`
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := RunLive(ctx, k8sSource, LiveInput{Namespace: "demo"})
	if err == nil {
		t.Fatal("hung exec plugin was accepted")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("exec plugin ignored connector deadline for %s", elapsed)
	}
	wantCode(t, err, CodeBound)
}

func TestK8sLiveExecPluginCannotExceedOutputCap(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := `apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: "https://127.0.0.1:1", insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: exec-user}
current-context: fixture-context
users:
- name: exec-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      interactiveMode: Never
      command: /bin/sh
      args: [-c, "while :; do printf 0123456789; done"]
`
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	_, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo"})
	wantCode(t, err, CodeBound)
	if !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("overflow refusal does not name response cap: %v", err)
	}
}

func TestK8sLiveProviderErrorCannotDiscloseBody(t *testing.T) {
	const hostile = "sk_live_kubernetes_body_must_not_escape"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"message":%q}`, hostile)
	}))
	t.Cleanup(server.Close)
	kubeconfig := filepath.Join(t.TempDir(), "config")
	config := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: fixture-cluster
  cluster: {server: %q, insecure-skip-tls-verify: true}
contexts:
- name: fixture-context
  context: {cluster: fixture-cluster, user: fixture-user}
current-context: fixture-context
users:
- name: fixture-user
  user: {token: fixture-token}
`, server.URL)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)

	_, err := RunLive(t.Context(), k8sSource, LiveInput{Namespace: "demo", Name: "app"})
	if err == nil {
		t.Fatal("hostile provider failure was accepted")
	}
	if strings.Contains(err.Error(), hostile) || !strings.Contains(err.Error(), "Kubernetes API read failed") {
		t.Fatalf("unsanitized provider error: %v", err)
	}
}

func TestK8sLiveFailurePreservesInternalRefusal(t *testing.T) {
	want := failure(k8sSource, CodeBound, "namespace demo",
		"live traversal exceeds the %d-page/request cap", MaxLivePages)
	got := k8sLiveFailure(want, &url.URL{Scheme: "https", Host: "cluster.example.test"})
	if got != want {
		t.Fatalf("internal refusal = %v, want preserved %v", got, want)
	}
}

func TestVaultOpenBaoLiveFixtureImportsKVv2Tree(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "bao-fixture-token" {
			t.Errorf("token = %q, want BAO_TOKEN value", got)
		}
		if got := r.Header.Get("X-Vault-Namespace"); got != "team-a" {
			t.Errorf("namespace = %q, want BAO_NAMESPACE value", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/secret/metadata/apps":
			fmt.Fprint(w, `{"data":{"keys":["db/","top"]}}`)
		case "/v1/secret/metadata/apps/db":
			fmt.Fprint(w, `{"data":{"keys":["main"]}}`)
		case "/v1/secret/metadata/apps/db/main":
			fmt.Fprint(w, `{"data":{"current_version":4,"versions":{"4":{"deletion_time":"","destroyed":false}}}}`)
		case "/v1/secret/data/apps/db/main":
			if got := r.URL.Query().Get("version"); got != "4" {
				t.Errorf("version = %q, want pinned 4", got)
			}
			fmt.Fprint(w, `{"data":{"data":{"DB_URL":"postgres://fixture","OPTIONS":{"pool":5,"ssl":true}},"metadata":{"version":4}}}`)
		case "/v1/secret/metadata/apps/top":
			fmt.Fprint(w, `{"data":{"current_version":2,"versions":{"2":{"deletion_time":"","destroyed":false}}}}`)
		case "/v1/secret/data/apps/top":
			if got := r.URL.Query().Get("version"); got != "2" {
				t.Errorf("version = %q, want pinned 2", got)
			}
			fmt.Fprint(w, `{"data":{"data":{"API_KEY":"top-secret"},"metadata":{"version":2}}}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv("BAO_ADDR", server.URL)
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "bao-fixture-token")
	t.Setenv("VAULT_TOKEN", "wrong-vault-token")
	t.Setenv("BAO_NAMESPACE", "team-a")

	result, err := RunLive(t.Context(), vaultSource, LiveInput{
		Mount: "secret", Path: "apps", KVVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Identity != server.URL {
		t.Fatalf("identity = %q, want %q", result.Identity, server.URL)
	}
	if result.Resolution != "address=BAO_ADDR, token=BAO_TOKEN, namespace=BAO_NAMESPACE" {
		t.Fatalf("resolution = %q", result.Resolution)
	}
	if !reflect.DeepEqual(result.Scope, Scope{Mount: "secret", PathPrefix: "apps", KVVersion: 2}) {
		t.Fatalf("scope = %+v", result.Scope)
	}
	want := []Record{
		{Folder: []string{"db", "main"}, SourceName: "DB_URL", Value: "postgres://fixture", Type: "string", Version: "4"},
		{Folder: []string{"db", "main"}, SourceName: "OPTIONS", Value: `{"pool":5,"ssl":true}`, Type: "json", Version: "4"},
		{Folder: []string{"top"}, SourceName: "API_KEY", Value: "top-secret", Type: "string", Version: "2"},
	}
	if !reflect.DeepEqual(result.Records, want) {
		t.Fatalf("records = %#v, want %#v", result.Records, want)
	}
}

func TestVaultLiveRefusesDataThatMovedAfterMetadataRead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/secret/metadata/apps":
			fmt.Fprint(w, `{"data":{"keys":["service"]}}`)
		case "/v1/secret/metadata/apps/service":
			fmt.Fprint(w, `{"data":{"current_version":4,"versions":{"4":{"deletion_time":"","destroyed":false}}}}`)
		case "/v1/secret/data/apps/service":
			if got := r.URL.Query().Get("version"); got != "4" {
				t.Errorf("version = %q, want pinned 4", got)
			}
			fmt.Fprint(w, `{"data":{"data":{"KEY":"moved"},"metadata":{"version":5}}}`)
		default:
			t.Fatalf("unexpected %s", r.URL.String())
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("BAO_ADDR", server.URL)
	t.Setenv("BAO_TOKEN", "fixture-token")

	_, err := RunLive(t.Context(), vaultSource, LiveInput{Mount: "secret", Path: "apps", KVVersion: 2})
	if err == nil {
		t.Fatal("moved KV v2 response was accepted")
	}
	wantCode(t, err, CodeProvenance)
	if !strings.Contains(err.Error(), "metadata version 4") {
		t.Fatalf("movement refusal does not name the pinned version: %v", err)
	}
}

func TestVaultLiveAutoDetectsKVv1FromVaultAmbientFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "vault-fixture-token" {
			t.Errorf("token = %q, want VAULT_TOKEN fallback", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/internal/ui/mounts/legacy":
			fmt.Fprint(w, `{"data":{"options":{"version":"1"}}}`)
		case "/v1/legacy/team":
			fmt.Fprint(w, `{"data":{"keys":["app"]}}`)
		case "/v1/legacy/team/app":
			fmt.Fprint(w, `{"data":{"LOG_LEVEL":"info"}}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(server.Close)

	withoutEnv(t, "BAO_ADDR")
	withoutEnv(t, "BAO_TOKEN")
	withoutEnv(t, "BAO_NAMESPACE")
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "vault-fixture-token")

	result, err := RunLive(t.Context(), vaultSource, LiveInput{Mount: "legacy", Path: "team"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Scope.KVVersion != 1 {
		t.Fatalf("kv version = %d, want auto-detected v1", result.Scope.KVVersion)
	}
	want := []Record{{
		Folder: []string{"app"}, SourceName: "LOG_LEVEL", Value: "info", Type: "string",
	}}
	if !reflect.DeepEqual(result.Records, want) {
		t.Fatalf("records = %#v, want %#v", result.Records, want)
	}
}

func TestVaultLiveProviderErrorCannotDiscloseBodyOrCredential(t *testing.T) {
	const hostile = "sk_live_provider_body_must_not_escape"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"errors":[%q]}`, hostile)
	}))
	t.Cleanup(server.Close)
	t.Setenv("BAO_ADDR", server.URL)
	t.Setenv("BAO_TOKEN", "bao_credential_must_not_escape")

	_, err := RunLive(t.Context(), vaultSource, LiveInput{Mount: "secret", Path: "apps", KVVersion: 1})
	if err == nil {
		t.Fatal("hostile provider failure was accepted")
	}
	for _, leak := range []string{hostile, "bao_credential_must_not_escape", `{"errors"`} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("sanitized error contains %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), "Vault/OpenBao API read failed") {
		t.Fatalf("sanitized error does not name the failed operation: %v", err)
	}
}

func TestVaultLiveRefusesCredentialRedirectBeforeFollowing(t *testing.T) {
	var targetRequests int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests++
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/capture")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	t.Setenv("BAO_ADDR", source.URL)
	t.Setenv("BAO_TOKEN", "redirect-fixture-token")

	_, err := RunLive(t.Context(), vaultSource, LiveInput{Mount: "secret", Path: "apps", KVVersion: 1})
	if err == nil {
		t.Fatal("credential-bearing redirect was accepted")
	}
	if targetRequests != 0 {
		t.Fatalf("redirect target received %d credential-bearing request(s)", targetRequests)
	}
	for _, origin := range []string{source.URL, target.URL} {
		if !strings.Contains(err.Error(), origin) {
			t.Fatalf("redirect refusal does not name origin %q: %v", origin, err)
		}
	}
}

func TestVaultExternalTokenHelperUsesSanitizedBoundedPath(t *testing.T) {
	t.Setenv("HIKYO_TOKEN", "hikyo_token_must_not_reach_vault_helper")
	helper := &tokenhelper.ExternalTokenHelper{
		BinaryPath: "/bin/sh",
		Args:       []string{"-c", `if env | grep -q '^HIKYO_'; then exit 71; fi; printf 'helper-fixture-token'`},
	}
	token, err := readVaultTokenHelper(t.Context(), helper, "https://vault.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if token != "helper-fixture-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestVaultExternalTokenHelperMapsWrapperBounds(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		helper := &tokenhelper.ExternalTokenHelper{
			BinaryPath: "/bin/sh", Args: []string{"-c", "sleep 30"},
		}
		started := time.Now()
		_, err := readVaultTokenHelper(ctx, helper, "https://vault.example.test")
		wantCode(t, err, CodeBound)
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("token helper ignored connector deadline for %s", elapsed)
		}
	})

	t.Run("stdout cap", func(t *testing.T) {
		helper := &tokenhelper.ExternalTokenHelper{
			BinaryPath: "/bin/sh",
			Args:       []string{"-c", "while :; do printf 0123456789; done"},
		}
		_, err := readVaultTokenHelper(t.Context(), helper, "https://vault.example.test")
		wantCode(t, err, CodeBound)
		if !strings.Contains(err.Error(), "response exceeds") {
			t.Fatalf("overflow refusal does not name response cap: %v", err)
		}
	})
}

func TestVaultLiveAndCapturePreserveSameJSONNumbers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "LIST" || r.URL.Query().Get("list") == "true" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errors":[]}`)
			return
		}
		if r.URL.Path != "/v1/secret/apps/numbers" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.String())
		}
		fmt.Fprint(w, `{"data":{"DECIMAL":0.12345678901234567890123456789,"LARGE_INTEGER":9007199254740993}}`)
	}))
	t.Cleanup(server.Close)
	t.Setenv("BAO_ADDR", server.URL)
	t.Setenv("BAO_TOKEN", "fixture-token")

	live, err := RunLive(t.Context(), vaultSource, LiveInput{
		Mount: "secret", Path: "apps/numbers", KVVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	file, err := run(t, vaultSource, "vault-capture-numbers.jsonl", "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(live.Records, file.Records) {
		t.Fatalf("live records = %#v, file records = %#v", live.Records, file.Records)
	}
}

func TestVaultOpenBaoConfigTokenHelperWinsAndReceivesSelectedAddress(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "bao-helper")
	script := `#!/bin/sh
if env | grep -q '^HIKYO_'; then exit 71; fi
if [ "$BAO_ADDR" != "$VAULT_ADDR" ]; then exit 72; fi
printf 'openbao-helper-token'
`
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "bao-config")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("token_helper = %q\n", helper)), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != "openbao-helper-token" {
			t.Errorf("token = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/secret/apps":
			fmt.Fprint(w, `{"data":{"keys":["service"]}}`)
		case "/v1/secret/apps/service":
			fmt.Fprint(w, `{"data":{"KEY":"value"}}`)
		default:
			t.Fatalf("unexpected %s", r.URL.String())
		}
	}))
	t.Cleanup(server.Close)
	withoutEnv(t, "BAO_TOKEN")
	withoutEnv(t, "VAULT_TOKEN")
	withoutEnv(t, "BAO_TOKEN_PATH")
	withoutEnv(t, "VAULT_TOKEN_PATH")
	t.Setenv("BAO_ADDR", server.URL)
	t.Setenv("BAO_CONFIG_PATH", config)
	t.Setenv("HIKYO_TOKEN", "must-not-reach-helper")

	result, err := RunLive(t.Context(), vaultSource, LiveInput{Mount: "secret", Path: "apps", KVVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Resolution, "token=OpenBao token helper config") {
		t.Fatalf("resolution = %q", result.Resolution)
	}
}

func withoutEnv(t *testing.T, name string) {
	t.Helper()
	value, present := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(name, value)
			return
		}
		_ = os.Unsetenv(name)
	})
}
