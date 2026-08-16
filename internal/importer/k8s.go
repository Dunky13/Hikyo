package importer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/schema"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	authv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	authv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	clientexec "k8s.io/client-go/plugin/pkg/client/auth/exec"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// The Kubernetes Secret connector (import-paths ADR § Per-source structural
// mapping, K8s row): manifest-file mode plus read-only live kubeconfig mode.
//
// Input: a YAML or JSON file holding one or more Kubernetes Secret manifests,
// as `kubectl get secret -o yaml` emits them (multi-document `---` streams
// included). JSON is accepted because YAML is a JSON superset and yaml.v3
// parses both; there is no separate JSON path to keep in step.
//
// The mapping, exactly:
//
//   - one Secret → one folder named after the Secret; a single-Secret import
//     may target the environment root (Plan decides that, not this file);
//   - `data` is base64-decoded, then `stringData` is OVERLAID on top and
//     STRINGDATA WINS. That is Kubernetes' own admission semantics, not a
//     preference: the API server merges stringData over data when it writes
//     the object, so a manifest carrying both means what stringData says;
//   - a document whose `kind` is not `Secret` is refused BY NAME;
//   - a name declared twice inside one Secret is refused;
//   - a value that is not UTF-8 text, or carries NUL, is refused BY NAME —
//     per key, never per import (the framework's uniform rule, in Run).
//
// File parsing stays yaml.v3 plus four field reads. Live mode uses client-go,
// but the file path does not route through Kubernetes runtime decoding; this
// keeps its strict duplicate-key and content-safe error behavior unchanged.

const k8sSource = "k8s"

type k8sConnector struct{}

func (k8sConnector) Name() string { return k8sSource }

func (k8sConnector) ReadLive(ctx context.Context, in LiveInput, b *Budget) (Result, error) {
	if in.Namespace == "" {
		return Result{}, failure(k8sSource, CodeProvenance, "", "live mode requires --namespace <namespace>")
	}
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	if in.Context != "" {
		overrides.CurrentContext = in.Context
	}
	deferred := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, overrides)
	raw, err := deferred.RawConfig()
	if err != nil {
		return Result{}, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the ambient kubeconfig could not be loaded")
	}
	contextName := raw.CurrentContext
	if in.Context != "" {
		contextName = in.Context
	}
	selected, ok := raw.Contexts[contextName]
	if !ok || selected == nil {
		return Result{}, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected context is not defined")
	}
	clusterName := selected.Cluster
	if _, ok := raw.Clusters[clusterName]; !ok {
		return Result{}, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected context's cluster is not defined")
	}

	cfg, err := deferred.ClientConfig()
	if err != nil {
		return Result{}, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected context could not produce a client configuration")
	}
	serverURL, err := url.Parse(cfg.Host)
	if err != nil || serverURL.User != nil || serverURL.Scheme == "" || serverURL.Host == "" {
		return Result{}, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected cluster does not name a credential-safe origin")
	}
	// Match client-go's credential precedence: an exec plugin is ignored when
	// the selected user already has bearer, basic, or complete certificate
	// authentication. Besides compatibility, this avoids executing third-party
	// code that the kubeconfig did not actually select.
	if cfg.BearerToken != "" || cfg.BearerTokenFile != "" || cfg.Username != "" ||
		((len(cfg.TLSClientConfig.CertData) != 0 || cfg.TLSClientConfig.CertFile != "") &&
			(len(cfg.TLSClientConfig.KeyData) != 0 || cfg.TLSClientConfig.KeyFile != "")) {
		cfg.ExecProvider = nil
	}
	baseCfg := rest.CopyConfig(cfg)
	execConfigured := baseCfg.ExecProvider != nil
	var client typedcorev1.CoreV1Interface
	var credentialExpiry time.Time
	refreshClient := func(force bool) (typedcorev1.CoreV1Interface, error) {
		if !force && client != nil && (credentialExpiry.IsZero() || time.Now().Before(credentialExpiry)) {
			return client, nil
		}
		candidate := rest.CopyConfig(baseCfg)
		expiry, err := resolveKubeExecCredential(ctx, candidate, raw.Clusters[clusterName])
		if err != nil {
			return nil, err
		}
		configured, err := newKubeClient(candidate)
		if err != nil {
			return nil, err
		}
		client = configured
		credentialExpiry = expiry
		return client, nil
	}
	if _, err := refreshClient(false); err != nil {
		return Result{}, err
	}
	requests := 0
	takeRequest := func(where string) error {
		requests++
		if requests > MaxLivePages {
			return failure(k8sSource, CodeBound, where,
				"live traversal exceeds the %d-page/request cap", MaxLivePages)
		}
		return nil
	}
	getSecret := func(name string) (*corev1.Secret, error) {
		where := "Secret " + quoteName(name)
		if err := takeRequest(where); err != nil {
			return nil, err
		}
		current, err := refreshClient(false)
		if err != nil {
			return nil, err
		}
		secret, err := current.Secrets(in.Namespace).Get(ctx, name, metav1.GetOptions{})
		if !apierrors.IsUnauthorized(err) || !execConfigured {
			return secret, err
		}
		if err := takeRequest(where + " credential retry"); err != nil {
			return nil, err
		}
		current, err = refreshClient(true)
		if err != nil {
			return nil, err
		}
		return current.Secrets(in.Namespace).Get(ctx, name, metav1.GetOptions{})
	}
	listSecrets := func(options metav1.ListOptions) (*corev1.SecretList, error) {
		where := "namespace " + quoteName(in.Namespace)
		if err := takeRequest(where); err != nil {
			return nil, err
		}
		current, err := refreshClient(false)
		if err != nil {
			return nil, err
		}
		list, err := current.Secrets(in.Namespace).List(ctx, options)
		if !apierrors.IsUnauthorized(err) || !execConfigured {
			return list, err
		}
		if err := takeRequest(where + " credential retry"); err != nil {
			return nil, err
		}
		current, err = refreshClient(true)
		if err != nil {
			return nil, err
		}
		return current.Secrets(in.Namespace).List(ctx, options)
	}

	var records []Record
	var names []string
	seenNames := make(map[string]struct{})
	appendSecret := func(secret corev1.Secret) error {
		if secret.Name == "" {
			return failure(k8sSource, CodeMalformed, in.Namespace,
				"a live Secret carries no metadata.name")
		}
		if _, exists := seenNames[secret.Name]; exists {
			return failure(k8sSource, CodeMalformed, in.Namespace,
				"the live traversal returned Secret %s more than once", quoteName(secret.Name))
		}
		if len(names) >= MaxRecords {
			return failure(k8sSource, CodeBound, in.Namespace,
				"Secret count exceeds the %d-record traversal cap", MaxRecords)
		}
		seenNames[secret.Name] = struct{}{}
		names = append(names, secret.Name)
		keys := make([]string, 0, len(secret.Data))
		for key := range secret.Data {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			where := fmt.Sprintf("namespace %s secret %s key %s",
				quoteName(in.Namespace), quoteName(secret.Name), quoteName(key))
			if err := b.Bytes(where, len(secret.Data[key])); err != nil {
				return err
			}
			if err := b.Record(where); err != nil {
				return err
			}
			records = append(records, Record{
				Folder: []string{secret.Name}, SourceName: key,
				Value: string(secret.Data[key]), Type: schema.TypeString,
				Version: secret.ResourceVersion,
			})
		}
		return nil
	}

	selectedNames := append([]string{}, in.Names...)
	if in.Name != "" {
		selectedNames = append(selectedNames, in.Name)
	}
	slices.Sort(selectedNames)
	selectedNames = slices.Compact(selectedNames)
	if len(selectedNames) > 0 {
		if len(selectedNames) > MaxLivePages {
			return Result{}, failure(k8sSource, CodeBound, in.Namespace,
				"named Secret selection exceeds the %d-page/request cap", MaxLivePages)
		}
		for _, selectedName := range selectedNames {
			secret, err := getSecret(selectedName)
			if err != nil {
				return Result{}, k8sLiveFailure(err, serverURL)
			}
			if err := appendSecret(*secret); err != nil {
				return Result{}, err
			}
		}
	} else {
		continueToken := ""
		for {
			list, err := listSecrets(metav1.ListOptions{
				Limit: 500, Continue: continueToken,
			})
			if err != nil {
				return Result{}, k8sLiveFailure(err, serverURL)
			}
			for _, secret := range list.Items {
				if err := appendSecret(secret); err != nil {
					return Result{}, err
				}
			}
			continueToken = list.Continue
			if continueToken == "" {
				break
			}
		}
	}
	if len(names) == 0 {
		return Result{}, failure(k8sSource, CodeMalformed, in.Namespace,
			"the live selection holds no Kubernetes Secret")
	}
	if len(records) == 0 {
		return Result{}, failure(k8sSource, CodeMalformed, in.Namespace,
			"the live selection holds no Kubernetes Secret entry")
	}
	slices.Sort(names)
	sort.Slice(records, func(i, j int) bool {
		if records[i].Folder[0] != records[j].Folder[0] {
			return records[i].Folder[0] < records[j].Folder[0]
		}
		return records[i].SourceName < records[j].SourceName
	})
	return Result{
		Records:    records,
		Scope:      Scope{Namespace: in.Namespace, Names: names},
		Identity:   clusterName + "/" + contextName,
		Resolution: "kubeconfig context=" + quoteName(contextName),
	}, nil
}

const maxExecCredentialBytes = 1 << 20

type execCredentialStatus struct {
	token      string
	cert       string
	key        string
	expiration time.Time
}

func newKubeClient(cfg *rest.Config) (typedcorev1.CoreV1Interface, error) {
	cfg.Timeout = RequestDeadline
	priorWrap := cfg.WrapTransport
	cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
		if priorWrap != nil {
			rt = priorWrap(rt)
		}
		return cappedRoundTripper{next: rt}
	}
	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return nil, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected context could not configure transport security")
	}
	httpClient.CheckRedirect = refuseCredentialRedirect
	client, err := typedcorev1.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, failure(k8sSource, CodeProvenance, "kubeconfig",
			"the selected context could not create a Kubernetes client")
	}
	return client, nil
}

func resolveKubeExecCredential(ctx context.Context, cfg *rest.Config,
	cluster *clientcmdapi.Cluster,
) (time.Time, error) {
	plugin := cfg.ExecProvider
	if plugin == nil {
		return time.Time{}, nil
	}
	where := "kube exec plugin " + quoteName(plugin.Command)
	if err := clientexec.ValidatePluginPolicy(plugin.PluginPolicy); err != nil {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential-plugin policy is invalid")
	}
	if !credentialPluginAllowed(plugin) {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential-plugin policy does not allow this command")
	}
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	switch plugin.InteractiveMode {
	case clientcmdapi.NeverExecInteractiveMode:
		interactive = false
	case clientcmdapi.IfAvailableExecInteractiveMode:
	case "":
		if plugin.APIVersion == "client.authentication.k8s.io/v1" {
			return time.Time{}, failure(k8sSource, CodeProvenance, where,
				"a v1 credential plugin must declare interactiveMode")
		}
	case clientcmdapi.AlwaysExecInteractiveMode:
		if !interactive {
			return time.Time{}, failure(k8sSource, CodeProvenance, where,
				"the credential plugin requires an interactive terminal")
		}
	default:
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin has an unknown interactive mode")
	}
	execInfo, err := encodeExecInfo(plugin, cluster, interactive)
	if err != nil {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin input could not be encoded")
	}

	env := append([]string{}, os.Environ()...)
	for _, item := range plugin.Env {
		env = append(env, item.Name+"="+item.Value)
	}
	env = SanitizedEnv(env)
	env = replaceEnv(env, "KUBERNETES_EXEC_INFO", string(execInfo))
	commandCtx, cancel := context.WithTimeout(ctx, RequestDeadline)
	defer cancel()
	cmd := exec.CommandContext(commandCtx, plugin.Command, plugin.Args...)
	cmd.Env = env
	cmd.Stderr = io.Discard
	if interactive {
		cmd.Stdin = os.Stdin
	}
	stdout := &cappedOutput{max: maxExecCredentialBytes}
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		switch {
		case errors.Is(commandCtx.Err(), context.DeadlineExceeded):
			return time.Time{}, failure(k8sSource, CodeBound, where,
				"the credential plugin exceeded the %s per-request deadline", RequestDeadline)
		default:
			return time.Time{}, failure(k8sSource, CodeProvenance, where,
				"the credential plugin failed")
		}
	}
	if stdout.overflow {
		return time.Time{}, failure(k8sSource, CodeBound, where,
			"the credential plugin response exceeds the %d-byte cap", maxExecCredentialBytes)
	}
	status, err := decodeExecCredential(plugin.APIVersion, stdout.buf.Bytes())
	if err != nil {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin returned no valid ExecCredential")
	}
	if status.token == "" && status.cert == "" && status.key == "" {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin returned no token or client certificate")
	}
	if (status.cert == "") != (status.key == "") {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin returned an incomplete client certificate pair")
	}
	if !status.expiration.IsZero() && !time.Now().Before(status.expiration) {
		return time.Time{}, failure(k8sSource, CodeProvenance, where,
			"the credential plugin returned already-expired credentials")
	}
	if status.token != "" {
		cfg.BearerToken = status.token
		cfg.BearerTokenFile = ""
	}
	if status.cert != "" {
		cfg.TLSClientConfig.CertData = []byte(status.cert)
		cfg.TLSClientConfig.KeyData = []byte(status.key)
		cfg.TLSClientConfig.CertFile = ""
		cfg.TLSClientConfig.KeyFile = ""
	}
	cfg.ExecProvider = nil
	return status.expiration, nil
}

func credentialPluginAllowed(plugin *clientcmdapi.ExecConfig) bool {
	switch plugin.PluginPolicy.PolicyType {
	case "", clientcmdapi.PluginPolicyAllowAll:
		return true
	case clientcmdapi.PluginPolicyDenyAll:
		return false
	case clientcmdapi.PluginPolicyAllowlist:
		command, err := exec.LookPath(filepath.Clean(plugin.Command))
		if err != nil {
			return false
		}
		for _, entry := range plugin.PluginPolicy.Allowlist {
			allowed, err := exec.LookPath(filepath.Clean(entry.Command))
			if err == nil && allowed == command {
				return true
			}
		}
	}
	return false
}

func encodeExecInfo(plugin *clientcmdapi.ExecConfig, cluster *clientcmdapi.Cluster, interactive bool) ([]byte, error) {
	switch plugin.APIVersion {
	case "client.authentication.k8s.io/v1":
		credential := authv1.ExecCredential{
			TypeMeta: metav1.TypeMeta{APIVersion: plugin.APIVersion, Kind: "ExecCredential"},
			Spec:     authv1.ExecCredentialSpec{Interactive: interactive},
		}
		if plugin.ProvideClusterInfo {
			credential.Spec.Cluster = &authv1.Cluster{
				Server: cluster.Server, TLSServerName: cluster.TLSServerName,
				InsecureSkipTLSVerify:    cluster.InsecureSkipTLSVerify,
				CertificateAuthorityData: append([]byte{}, cluster.CertificateAuthorityData...),
				ProxyURL:                 cluster.ProxyURL, DisableCompression: cluster.DisableCompression,
				Config: runtime.RawExtension{Object: plugin.Config},
			}
		}
		return json.Marshal(credential)
	case "client.authentication.k8s.io/v1beta1":
		credential := authv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{APIVersion: plugin.APIVersion, Kind: "ExecCredential"},
			Spec:     authv1beta1.ExecCredentialSpec{Interactive: interactive},
		}
		if plugin.ProvideClusterInfo {
			credential.Spec.Cluster = &authv1beta1.Cluster{
				Server: cluster.Server, TLSServerName: cluster.TLSServerName,
				InsecureSkipTLSVerify:    cluster.InsecureSkipTLSVerify,
				CertificateAuthorityData: append([]byte{}, cluster.CertificateAuthorityData...),
				ProxyURL:                 cluster.ProxyURL, DisableCompression: cluster.DisableCompression,
				Config: runtime.RawExtension{Object: plugin.Config},
			}
		}
		return json.Marshal(credential)
	default:
		return nil, errors.New("unsupported ExecCredential API version")
	}
}

func decodeExecCredential(apiVersion string, raw []byte) (execCredentialStatus, error) {
	switch apiVersion {
	case "client.authentication.k8s.io/v1":
		var credential authv1.ExecCredential
		if err := json.Unmarshal(raw, &credential); err != nil || credential.APIVersion != apiVersion ||
			credential.Kind != "ExecCredential" || credential.Status == nil {
			return execCredentialStatus{}, errors.New("invalid ExecCredential")
		}
		expiration := time.Time{}
		if credential.Status.ExpirationTimestamp != nil {
			expiration = credential.Status.ExpirationTimestamp.Time
		}
		return execCredentialStatus{
			token: credential.Status.Token, cert: credential.Status.ClientCertificateData,
			key: credential.Status.ClientKeyData, expiration: expiration,
		}, nil
	case "client.authentication.k8s.io/v1beta1":
		var credential authv1beta1.ExecCredential
		if err := json.Unmarshal(raw, &credential); err != nil || credential.APIVersion != apiVersion ||
			credential.Kind != "ExecCredential" || credential.Status == nil {
			return execCredentialStatus{}, errors.New("invalid ExecCredential")
		}
		expiration := time.Time{}
		if credential.Status.ExpirationTimestamp != nil {
			expiration = credential.Status.ExpirationTimestamp.Time
		}
		return execCredentialStatus{
			token: credential.Status.Token, cert: credential.Status.ClientCertificateData,
			key: credential.Status.ClientKeyData, expiration: expiration,
		}, nil
	default:
		return execCredentialStatus{}, errors.New("unsupported ExecCredential API version")
	}
}

func replaceEnv(env []string, name, value string) []string {
	prefix := name + "="
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, prefix) {
			out = append(out, item)
		}
	}
	return append(out, prefix+value)
}

func k8sLiveFailure(err error, origin *url.URL) error {
	var internal *Error
	var redirect *refusedRedirect
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &internal):
		return internal
	case errors.As(err, &redirect):
		return failure(k8sSource, CodeProvenance, "",
			"credential-bearing redirect from %s to %s was refused", redirect.from, redirect.to)
	case errors.Is(err, errLiveResponseTooLarge), errors.As(err, &tooLarge):
		return failure(k8sSource, CodeBound, originOf(origin),
			"a provider response exceeds the %d-byte per-response cap", MaxResponseBytes)
	case errors.Is(err, context.DeadlineExceeded):
		return failure(k8sSource, CodeBound, originOf(origin),
			"a provider request exceeded the %s per-request deadline", RequestDeadline)
	default:
		return failure(k8sSource, CodeMalformed, originOf(origin),
			"the Kubernetes API read failed")
	}
}

// k8sSecret is the exact subset of a Secret manifest this connector reads.
// Unknown fields are IGNORED rather than refused: a manifest carries
// server-populated metadata (creationTimestamp, uid, managedFields) that no
// importer should have an opinion about, and refusing them would refuse every
// real `kubectl get -o yaml` output.
type k8sSecret struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name            string `yaml:"name"`
		Namespace       string `yaml:"namespace"`
		ResourceVersion string `yaml:"resourceVersion"`
	} `yaml:"metadata"`
	Type       string            `yaml:"type"`
	Data       map[string]string `yaml:"data"`
	StringData map[string]string `yaml:"stringData"`
}

func (k8sConnector) Read(ctx context.Context, in Input, b *Budget) (Result, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(in.Data)))
	var records []Record
	var namespaces, names []string
	for doc := 0; ; doc++ {
		if err := ctx.Err(); err != nil {
			return Result{}, failure(k8sSource, CodeBound, in.Path,
				"the run exceeded the %s whole-run deadline", RunDeadline)
		}
		where := fmt.Sprintf("%s document %d", in.Path, doc)
		// Parse to a Node first. Two reasons, both load-bearing:
		//
		//   - a duplicate mapping key is refused HERE, with its own code. Node
		//     parsing accepts duplicates, so the check is ours to make; letting
		//     Decode's own "already defined" error stand would make the code a
		//     string match on someone else's message.
		//   - Decode's failures echo content. yaml.v3 renders a type mismatch as
		//     "cannot unmarshal !!str `sk_live...` into map[string]string" — a
		//     value prefix on stderr. Every such error is DROPPED below, never
		//     wrapped, and this is the empirical reason why.
		var node yaml.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Result{}, failure(k8sSource, CodeMalformed, where,
				"the document is not parseable as YAML or JSON")
		}
		// The budget is charged HERE, over the parsed node graph, BEFORE
		// node.Decode materializes anything. That ordering is the whole point:
		// a YAML alias expands during Decode, so a document whose aliases
		// multiply a kilobyte into a gigabyte has already allocated it by the
		// time a post-hoc length check runs. Walking the node graph sees the
		// expansion as a graph — an alias node names its anchor's size without
		// copying it — and refuses at the named bound with nothing materialized.
		if err := chargeNode(b, where, &node, 0); err != nil {
			return Result{}, err
		}
		if err := checkNoDuplicateKeys(b, where, &node, 0); err != nil {
			return Result{}, err
		}
		var secret k8sSecret
		if err := node.Decode(&secret); err != nil {
			return Result{}, failure(k8sSource, CodeMalformed, where,
				"the document is not shaped like a Kubernetes Secret manifest")
		}
		// An empty document — a trailing `---`, or a `---\n` separator with
		// nothing after it — is skipped rather than refused. `kubectl` emits
		// them and refusing would make the common capture unusable.
		if secret.Kind == "" && secret.Metadata.Name == "" && secret.Data == nil && secret.StringData == nil {
			continue
		}
		if secret.Kind != "Secret" {
			// The refused value is NOT echoed. `kind` is a foreign field whose
			// content this connector has no reason to trust or to render: a
			// document can put a live token, or a terminal escape sequence,
			// where a kind belongs. Naming the FIELD and the expected value says
			// everything an operator needs and discloses nothing.
			return Result{}, failure(k8sSource, CodeKind, where,
				"the document's `kind` is not `Secret`; this connector reads Kubernetes Secret manifests only")
		}
		if secret.Metadata.Name == "" {
			return Result{}, failure(k8sSource, CodeMalformed, where,
				"the Secret carries no metadata.name; one Secret maps onto one folder named after it")
		}
		folder := []string{secret.Metadata.Name}
		if err := b.Depth(where, len(folder)); err != nil {
			return Result{}, err
		}
		names = append(names, secret.Metadata.Name)
		if secret.Metadata.Namespace != "" {
			namespaces = append(namespaces, secret.Metadata.Namespace)
		}

		// `data` first, decoded; then `stringData` overlaid. Both are walked in
		// sorted order so the record list is deterministic — a map range would
		// make the emitted artifacts differ run to run for identical input.
		merged := map[string]string{}
		for _, name := range sortedKeys(secret.Data) {
			keyWhere := fmt.Sprintf("%s secret %s key %s", in.Path, quoteName(secret.Metadata.Name), quoteName(name))
			raw, err := base64.StdEncoding.DecodeString(secret.Data[name])
			if err != nil {
				return Result{}, failure(k8sSource, CodeMalformed, keyWhere,
					"the `data` entry is not valid base64")
			}
			if err := b.Bytes(keyWhere, len(raw)); err != nil {
				return Result{}, err
			}
			merged[name] = string(raw)
		}
		for _, name := range sortedKeys(secret.StringData) {
			keyWhere := fmt.Sprintf("%s secret %s key %s", in.Path, quoteName(secret.Metadata.Name), quoteName(name))
			if err := b.Bytes(keyWhere, len(secret.StringData[name])); err != nil {
				return Result{}, err
			}
			// stringData wins, silently and correctly — this is the admission
			// merge, not a collision. A DUPLICATE within one map is a different
			// thing and yaml.v3 already refuses it (see below).
			merged[name] = secret.StringData[name]
		}

		for _, name := range sortedKeys(merged) {
			keyWhere := fmt.Sprintf("%s secret %s key %s", in.Path, quoteName(secret.Metadata.Name), quoteName(name))
			if err := b.Record(keyWhere); err != nil {
				return Result{}, err
			}
			records = append(records, Record{
				Folder:     folder,
				SourceName: name,
				Value:      merged[name],
				Type:       schema.TypeString,
				Version:    secret.Metadata.ResourceVersion,
			})
		}
	}
	if len(records) == 0 {
		return Result{}, failure(k8sSource, CodeMalformed, in.Path,
			"the file holds no Kubernetes Secret manifest with any entry")
	}
	// The k8s scope the mapping template records is `{namespace, names[]}`, per
	// the spellings spec — not a file digest. It is read off the manifests
	// themselves, which is the only place file mode has it.
	slices.Sort(names)
	slices.Sort(namespaces)
	scope := Scope{Names: slices.Compact(names)}
	if unique := slices.Compact(namespaces); len(unique) == 1 {
		scope.Namespace = unique[0]
	}
	return Result{Records: records, Scope: scope}, nil
}

// chargeNode charges the decoded size of a parsed document against the budget
// before anything is materialized, and bounds depth on the way down.
//
// An ALIAS node is charged its anchor's already-counted size again, which is
// exactly right: the expansion is what Decode will allocate, so the budget must
// see it. That is what makes an alias bomb fail at the bound instead of in the
// allocator.
func chargeNode(b *Budget, where string, n *yaml.Node, depth int) error {
	if err := b.Depth(where, depth); err != nil {
		return err
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return b.Bytes(where, len(n.Value))
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil
		}
		return chargeNode(b, where, n.Alias, depth+1)
	}
	for _, child := range n.Content {
		if err := chargeNode(b, where, child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// checkNoDuplicateKeys walks a parsed document and refuses a mapping that
// declares one key twice — "duplicate keys within one Secret refused", stated
// by the ADR for the Secret's own maps and enforced here for every mapping in
// the document, because a duplicate anywhere means the capture is not what its
// author thinks it is.
//
// It doubles as the tree-depth bound's enforcement point: depth is checked
// while descending, before the record count can be reached.
func checkNoDuplicateKeys(b *Budget, where string, n *yaml.Node, depth int) error {
	if err := b.Depth(where, depth); err != nil {
		return err
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if err := checkNoDuplicateKeys(b, where, child, depth+1); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		seen := make(map[string]bool, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			name := n.Content[i].Value
			if seen[name] {
				return failure(b.source, CodeDuplicateKey, where,
					"key %s is declared more than once in one mapping", quoteName(name))
			}
			seen[name] = true
			if err := checkNoDuplicateKeys(b, where, n.Content[i+1], depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// sortedKeys is the deterministic walk order for a source map.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
