package importer

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Dunky13/hikyo/internal/schema"
	"gopkg.in/yaml.v3"
)

// The Kubernetes Secret manifest connector (import-paths ADR § Per-source
// structural mapping, K8s row). FILE MODE ONLY in this ticket — live mode
// (kubeconfig) rides with #69.
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
// Deliberately NOT imported: client-go. Parsing a manifest is yaml.v3 plus four
// field reads; pulling the Kubernetes client library into a file parser would
// add a dependency tree the size of the rest of this binary for nothing.

const k8sSource = "k8s"

type k8sConnector struct{}

func (k8sConnector) Name() string { return k8sSource }

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
