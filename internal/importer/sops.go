package importer

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Dunky13/hikyo/internal/schema"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/decrypt"
	"gopkg.in/yaml.v3"
)

// The SOPS connector (import-paths ADR § Per-source structural mapping, SOPS
// row). FILE ONLY — SOPS *is* a file; there is no live mode to defer.
//
// Decryption goes through the getsops/sops v3 library's stable `decrypt`
// package with the AMBIENT keyring, exactly as `sops -d` resolves it: age, GPG,
// KMS. Two disclosures the ADR requires and this comment makes concrete:
//
//   - a file encrypted to a KMS or Vault Transit key CONTACTS THAT KEY SERVICE.
//     File mode is offline only for age/GPG-encrypted material.
//   - the GPG key source EXECS `gpg`, inside the library, with no hook for the
//     child's environment. That exec is covered by WithSanitized (spawn.go),
//     which strips Hikyo credentials, contexts and trust material from this
//     process for the duration of the call — so the child cannot see them
//     whoever spawns it.
//
// The mapping:
//
//   - nested map levels → a folder chain; scalar leaves → keys;
//   - array and object leaves → `json`-typed values through canonicalJSON, the
//     ONE deterministic serialization every connector shares;
//   - a leaf's PLAINTEXT STATUS is recorded as a classification HINT and
//     nothing more. A plaintext leaf in a partially-encrypted file proves an
//     at-rest policy choice, not that the value is safe for every future holder
//     of plain `read`. Flag mode performs zero downgrades; the mapping template
//     is the only thing that can declare one.

const sopsSource = "sops"

// sopsEncMarker is how SOPS spells an encrypted scalar in the file at rest.
// A leaf WITHOUT it was stored in plaintext, which is the whole of the
// plaintext hint — read off the file as it sits, with no reach into the
// library's internals.
const sopsEncMarker = "ENC["

type sopsConnector struct{}

func (sopsConnector) Name() string { return sopsSource }

func (sopsConnector) Read(ctx context.Context, in Input, b *Budget) (Result, error) {
	format := formats.FormatForPathOrString(in.Path, "")
	switch format {
	case formats.Yaml, formats.Json:
	case formats.Dotenv:
		return Result{}, failure(sopsSource, CodeUnmappableName, in.Path,
			"a dotenv-shaped SOPS file carries no folder structure; use the `.env` scaffold path instead")
	default:
		return Result{}, failure(sopsSource, CodeMalformed, in.Path,
			"only YAML and JSON SOPS files map onto folders and keys; INI and binary files do not")
	}

	// The plaintext hints come from the file AS IT SITS, before decryption:
	// a scalar without the ENC[ marker was never encrypted.
	hints, err := sopsPlaintextHints(in, b)
	if err != nil {
		return Result{}, err
	}

	plain, err := sopsDecrypt(ctx, in, format)
	if err != nil {
		return Result{}, err
	}
	root, err := decodeSOPSPlaintext(in.Path, plain, b)
	if err != nil {
		return Result{}, err
	}
	// `sops` is the metadata branch. The store strips it on load, so this is
	// belt-and-braces — but a metadata branch imported as a folder of keys would
	// be a folder full of key fingerprints.
	delete(root, "sops")

	var records []Record
	if err := sopsWalk(ctx, in.Path, root, nil, hints, b, &records); err != nil {
		return Result{}, err
	}
	if len(records) == 0 {
		return Result{}, failure(sopsSource, CodeMalformed, in.Path,
			"the decrypted document holds no leaf values")
	}
	return Result{Records: records}, nil
}

// decodeSOPSPlaintext meters the decrypted YAML node graph before Decode
// materializes aliases into Go maps and slices. It deliberately uses the same
// chargeNode walk as Kubernetes: an alias charges its target recursively, so a
// small decrypted alias graph cannot expand past the decoded-bytes cap first.
func decodeSOPSPlaintext(path string, plain []byte, b *Budget) (map[string]any, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(plain, &node); err != nil {
		return nil, failure(sopsSource, CodeMalformed, path,
			"the decrypted document is not parseable as YAML or JSON")
	}
	if err := chargeNode(b, path, &node, 0); err != nil {
		return nil, err
	}
	var root map[string]any
	if err := node.Decode(&root); err != nil {
		return nil, failure(sopsSource, CodeMalformed, path,
			"the decrypted document is not a mapping at its root; SOPS files map onto folders only from a mapping")
	}
	return root, nil
}

// sopsWalk descends the decrypted tree: maps become folder levels, everything
// else becomes a leaf. Keys are walked in sorted order so the emitted artifacts
// are byte-identical run to run.
func sopsWalk(ctx context.Context, path string, node map[string]any, folder []string,
	hints map[string]bool, b *Budget, out *[]Record) error {
	where := fmt.Sprintf("%s at %s", path, quoteName(strings.Join(folder, "/")))
	if err := ctx.Err(); err != nil {
		return failure(sopsSource, CodeBound, path,
			"the run exceeded the %s whole-run deadline", RunDeadline)
	}
	if err := b.Depth(where, len(folder)); err != nil {
		return err
	}
	names := make([]string, 0, len(node))
	for name := range node {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		child := node[name]
		leafPath := strings.Join(append(append([]string{}, folder...), name), "/")
		leafWhere := fmt.Sprintf("%s at %s", path, quoteName(leafPath))
		if nested, ok := child.(map[string]any); ok {
			if err := sopsWalk(ctx, path, nested, append(append([]string{}, folder...), name), hints, b, out); err != nil {
				return err
			}
			continue
		}
		value, typ, err := sopsLeaf(b, leafWhere, child)
		if err != nil {
			return err
		}
		if err := b.Bytes(leafWhere, len(value)); err != nil {
			return err
		}
		if err := b.Record(leafWhere); err != nil {
			return err
		}
		*out = append(*out, Record{
			Folder:        append([]string{}, folder...),
			SourceName:    name,
			Value:         value,
			Type:          typ,
			PlaintextHint: hints[leafPath],
		})
	}
	return nil
}

// sopsLeaf renders one leaf. A scalar arrives as its exact string; an array or
// object goes through the canonical JSON conversion and is typed `json`. No
// byte-verbatim claim is made for material that arrived as a parsed tree.
func sopsLeaf(b *Budget, where string, v any) (string, schema.Type, error) {
	switch t := v.(type) {
	case string:
		return t, schema.TypeString, nil
	case nil:
		// A null leaf has no value to import. Refusing by name beats importing
		// the empty string, which is a different fact.
		return "", "", failure(sopsSource, CodeMalformed, where,
			"the leaf is null; there is no value to import")
	case map[string]any, map[any]any, []any:
		out, err := canonicalJSON(b, where, t)
		if err != nil {
			return "", "", err
		}
		return out, schema.TypeJSON, nil
	default:
		// Numbers and booleans. YAML typed them; Hikyo delivers strings, and
		// the declared type is `string` in flag mode regardless — the template
		// is where a richer type is declared.
		return fmt.Sprintf("%v", t), schema.TypeString, nil
	}
}

// sopsPlaintextHints walks the file at rest and records, per leaf path, whether
// the scalar there was stored WITHOUT the ENC[ marker.
//
// It is a hint and only a hint: nothing downstream may downgrade a
// classification from it, and the plan records it beside the key rather than
// acting on it.
func sopsPlaintextHints(in Input, b *Budget) (map[string]bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(in.Data, &root); err != nil {
		return nil, failure(sopsSource, CodeMalformed, in.Path,
			"the file is not parseable as YAML or JSON")
	}
	hints := map[string]bool{}
	var walk func(n *yaml.Node, path []string, depth int) error
	walk = func(n *yaml.Node, path []string, depth int) error {
		if err := b.Depth(in.Path, depth); err != nil {
			return err
		}
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				if err := walk(c, path, depth+1); err != nil {
					return err
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				name := n.Content[i].Value
				if len(path) == 0 && name == "sops" {
					continue
				}
				child := n.Content[i+1]
				next := append(append([]string{}, path...), name)
				if child.Kind == yaml.MappingNode {
					if err := walk(child, next, depth+1); err != nil {
						return err
					}
					continue
				}
				hints[strings.Join(next, "/")] = allPlaintext(child)
			}
		}
		return nil
	}
	if err := walk(&root, nil, 0); err != nil {
		return nil, err
	}
	return hints, nil
}

// allPlaintext reports whether every scalar under a leaf node was stored
// WITHOUT the ENC[ marker.
//
// A sequence leaf is the case that makes this a walk rather than one string
// check: `allowed_origins` is a SequenceNode whose own `.Value` is empty, so a
// naive check on the node itself reads "no marker, therefore plaintext" for a
// leaf whose every item is encrypted. That is the WRONG DIRECTION for a
// downgrade hint, which is the only direction that matters here — the hint's
// entire job is to suggest secret→config, so it errs toward "not plaintext"
// and a leaf with any encrypted scalar under it is not a plaintext leaf.
func allPlaintext(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return !strings.Contains(n.Value, sopsEncMarker)
	case yaml.SequenceNode, yaml.MappingNode:
		for _, child := range n.Content {
			if !allPlaintext(child) {
				return false
			}
		}
		return len(n.Content) > 0
	default:
		// An alias or an unset node: nothing this can vouch for, so it vouches
		// for nothing.
		return false
	}
}

// sopsDecrypt runs the library's decryption under the run deadline.
//
// `decrypt.DataWithFormat` takes no context — it is the stable API and it
// predates one — and it can block indefinitely on a KMS round trip or on a `gpg`
// that is waiting for a pinentry nobody is watching. Running it in a goroutine
// and selecting on ctx is what makes RunDeadline an actual deadline rather than
// a number in a comment.
//
// ponytail: the abandoned goroutine may linger until the library returns. That
// is acceptable HERE and only here — `hikyo import` is a one-shot client-local
// process that exits immediately after — and it is the same trade the schema
// engine's evaluation deadline makes. A server-side caller would need a slot
// ceiling like MaxConcurrentJSONSchemaEvaluations; there is no server-side
// caller.
func sopsDecrypt(ctx context.Context, in Input, format formats.Format) ([]byte, error) {
	type outcome struct {
		plain []byte
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		var plain []byte
		err := WithSanitized(func() error {
			out, derr := decrypt.DataWithFormat(in.Data, format)
			plain = out
			return derr
		})
		done <- outcome{plain, err}
	}()
	select {
	case <-ctx.Done():
		return nil, failure(sopsSource, CodeBound, in.Path,
			"decryption exceeded the %s whole-run deadline", RunDeadline)
	case got := <-done:
		if got.err != nil {
			// The library's error is DROPPED, not wrapped. It can carry a key
			// service's response body, a file fragment, or a MAC comparison
			// rendering both macs — none of which belongs on stderr.
			return nil, failure(sopsSource, CodeDecrypt, in.Path,
				"decryption failed: no ambient key (age, GPG, KMS) opened this file, or its integrity check did not hold")
		}
		return got.plain, nil
	}
}
