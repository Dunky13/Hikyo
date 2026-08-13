package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Dunky13/hikyo/internal/schema"
)

// The four phase-1 artifacts (import-paths ADR § The two-phase invariant;
// serializations fixed by api-cli-spellings.md § 3).
//
// Three of them are COMMITTABLE and value-free — the mapping template, the run
// manifest, and the additive definitions bundle. One is not: the per-environment
// values file carries plaintext and travels under the secret-file discipline
// (dirfd-parent-checked O_EXCL, 0600) that internal/disclose owns. This file
// serializes; the CLI writes.
//
// The template and manifest serializations below are the spec's, field for
// field. Unknown fields REJECT LOUDLY NAMING A VERSION MISMATCH: an artifact
// written by a newer build and silently truncated by an older one would replay
// a migration under choices nobody made.

// FormatVersion is the artifact format version carried by all four artifacts.
const FormatVersion = 1

// ConnectorContractVersion is the connector-behaviour version. It advances when
// a connector's mapping changes — a replay recorded against a different mapping
// is not the same run, and the template says so rather than quietly re-mapping.
const ConnectorContractVersion = 1

// ---------------------------------------------------------------------------
// mapping.json — the portable record of every CHOICE. Never values.
// ---------------------------------------------------------------------------

// Scope is the connector-shaped source selector. Every field is optional
// because the shape is per connector: k8s uses {namespace, names}; sops and
// infisical use {file_digest}, infisical additionally {env_slug}.
type Scope struct {
	Namespace  string   `json:"namespace,omitempty"`
	Names      []string `json:"names,omitempty"`
	FileDigest string   `json:"file_digest,omitempty"`
	EnvSlug    string   `json:"env_slug,omitempty"`
}

// EnvironmentMapping is one source-environment → target-environment row.
// Source is a POINTER so a source with no environment concept serializes as
// `null` rather than as the empty string, which is a different fact.
type EnvironmentMapping struct {
	Source *string `json:"source"`
	Target string  `json:"target"`
	Create bool    `json:"create"`
}

// FolderMapping is one source path → target path row.
type FolderMapping struct {
	SourcePath string `json:"source_path"`
	TargetPath string `json:"target_path"`
}

// ClassificationChoice records a key's classification and whether it was
// DOWNGRADED from the uniform `secret` default. Flag mode never downgrades;
// only a template can, and this is where the record of it lives.
type ClassificationChoice struct {
	Key        string `json:"key"`
	Class      string `json:"class"`
	Downgraded bool   `json:"downgraded"`
}

// TypeChoice records a declared type. Accepted is the wizard's
// suggestion-applied-on-human-accept bit; flag mode writes `string` with
// accepted true, because nothing was suggested.
type TypeChoice struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Accepted bool   `json:"accepted"`
}

// KeyEnvironment is the (key, environment) pair the overwrite and trim lists
// are made of.
type KeyEnvironment struct {
	Key         string `json:"key"`
	Environment string `json:"environment"`
}

// Template is `mapping.json`, exactly as api-cli-spellings.md § 3 spells it.
type Template struct {
	FormatVersion            int                    `json:"format_version"`
	ConnectorContractVersion int                    `json:"connector_contract_version"`
	Source                   string                 `json:"source"`
	Scope                    Scope                  `json:"scope"`
	Project                  string                 `json:"project"`
	Environments             []EnvironmentMapping   `json:"environments"`
	Folders                  []FolderMapping        `json:"folders"`
	Renames                  []Rename               `json:"renames"`
	Classifications          []ClassificationChoice `json:"classifications"`
	Types                    []TypeChoice           `json:"types"`
	Overwrites               []KeyEnvironment       `json:"overwrites"`
	TrimAcknowledgements     []KeyEnvironment       `json:"trim_acknowledgements"`
}

// ---------------------------------------------------------------------------
// run-manifest.json — the bound record of one RUN, and the phase-2 precondition.
// ---------------------------------------------------------------------------

// TemplateReference binds a run to the template it replayed.
type TemplateReference struct {
	Digest string `json:"digest"`
}

// SourceIdentity is the non-secret identity of the source, as far as the
// connector can state it: for the file connectors, the export file's digest.
type SourceIdentity struct {
	Kind    string `json:"kind"`
	Context string `json:"context"`
}

// SourceVersion is one per-record source version identifier where the source
// provides one (K8s `resourceVersion`, an Infisical secret id).
type SourceVersion struct {
	Key         string `json:"key"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
}

// TargetKey names one target key and its server-owned id where one exists.
// ID is a pointer: a key that does not exist yet serializes as `null`, which
// is a different fact from an empty id.
type TargetKey struct {
	Name string  `json:"name"`
	ID   *string `json:"id"`
}

// Target is the run's target identity.
type Target struct {
	Project      string      `json:"project"`
	Environments []string    `json:"environments"`
	Keys         []TargetKey `json:"keys"`
}

// ManifestOccurrence is one server-minted opaque occurrence token, per
// (key, environment). It is named for the artifact it lives in, because
// internal/delivery owns a different `Occurrence` — the canonical ENCODING the
// token is computed over — and two types with one name across a package
// boundary is how a reviewer reads the wrong one. It names the exact resolved state phase 1 observed — a
// specific value occurrence, or the specific absence. It is NOT a bucket label:
// `set` → `set` with a changed value preserves the bucket, and a bucket-checked
// "reviewed overwrite" would still clobber the newer value.
type ManifestOccurrence struct {
	Key         string `json:"key"`
	Environment string `json:"environment"`
	Token       string `json:"token"`
}

// PhaseCompletion records how far a run got, so a resumed migration knows where
// it stopped.
type PhaseCompletion struct {
	Authored bool            `json:"authored"`
	Applied  bool            `json:"applied"`
	Imported map[string]bool `json:"imported"`
}

// Manifest is `run-manifest.json`, exactly as api-cli-spellings.md § 3 spells it.
type Manifest struct {
	FormatVersion            int                  `json:"format_version"`
	ConnectorContractVersion int                  `json:"connector_contract_version"`
	Template                 TemplateReference    `json:"template"`
	SourceIdentity           SourceIdentity       `json:"source_identity"`
	SourceVersions           []SourceVersion      `json:"source_versions"`
	Target                   Target               `json:"target"`
	DefinitionsRevision      int64                `json:"definitions_revision"`
	Occurrences              []ManifestOccurrence `json:"occurrences"`
	PhaseCompletion          PhaseCompletion      `json:"phase_completion"`
}

// ---------------------------------------------------------------------------
// The additive definitions bundle.
// ---------------------------------------------------------------------------

// BundleKey is one declaration the bundle creates. Names are the portable
// logical handles; there are no server-owned ids and no base revision, which
// is exactly what MAKES this bundle additive (source-of-truth ADR § Additive
// bundles): it creates, it cannot delete, and it refuses to modify a
// declaration it was not computed against.
type BundleKey struct {
	Name           string             `json:"name"`
	FolderPath     string             `json:"folder_path"`
	Classification string             `json:"classification"`
	Declaration    schema.Declaration `json:"declaration"`
}

// Bundle is the project-wide additive definitions bundle. ONE bundle per target
// project, not one per environment: keys, types and classifications are
// project-scoped and only presence varies by environment.
//
// This is a MINIMAL versioned format authored by this ticket, because no bundle
// format exists in the tree yet. `definitions plan|apply` (#70) owns the real
// one; the two must be reconciled there. It deliberately carries NO base
// revision — that absence is the additive semantics, not an omission — and no
// `base` field of any kind, which the flat-model ADR deleted from the bundle
// schema outright.
type Bundle struct {
	FormatVersion int         `json:"format_version"`
	Project       string      `json:"project"`
	Keys          []BundleKey `json:"keys"`
}

// ---------------------------------------------------------------------------
// The per-environment values file. NEVER committable.
// ---------------------------------------------------------------------------

// ValuesEntry is one key's imported plaintext.
type ValuesEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ValuesFile is one target environment's material for `values import`. It is
// the ONLY artifact this package produces that carries plaintext, and the CLI
// writes it through the secret-file discipline — never to stdout.
type ValuesFile struct {
	FormatVersion int           `json:"format_version"`
	Project       string        `json:"project"`
	Environment   string        `json:"environment"`
	Entries       []ValuesEntry `json:"entries"`
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

// Encode renders an artifact canonically: two-space indent, HTML escaping off,
// exactly one trailing newline. Byte-stable for identical input, which is what
// makes a template digest mean anything.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("import: serializing an artifact: %w", err)
	}
	return buf.Bytes(), nil
}

// Digest is the artifact digest spelling used by the manifest's template
// reference and by the file-digest scope.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseTemplate reads a mapping template strictly.
//
// Unknown fields reject loudly NAMING A VERSION MISMATCH, which is the spec's
// own requirement. It is stated as a version mismatch rather than as "unknown
// field" because that is what it always means for these two artifacts: they are
// written by this tool and read by this tool, so a field this build does not
// know is a field a different build wrote.
func ParseTemplate(raw []byte) (Template, error) {
	var t Template
	if err := strictDecode(raw, "mapping.json", &t); err != nil {
		return Template{}, err
	}
	if err := checkVersions("mapping.json", t.FormatVersion, t.ConnectorContractVersion); err != nil {
		return Template{}, err
	}
	if t.Source == "" {
		return Template{}, failure("import", CodeMalformed, "mapping.json", "the template names no `source`")
	}
	if _, ok := connectors[t.Source]; !ok {
		return Template{}, failure("import", CodeMalformed, "mapping.json",
			"the template names source %q, which this build does not serve; served sources are %v",
			t.Source, Sources())
	}
	if t.Project == "" {
		return Template{}, failure("import", CodeMalformed, "mapping.json", "the template names no `project`")
	}
	if len(t.Environments) == 0 {
		return Template{}, failure("import", CodeMalformed, "mapping.json",
			"the template names no target environment")
	}
	for i, env := range t.Environments {
		if env.Target == "" {
			return Template{}, failure("import", CodeMalformed, "mapping.json",
				"environment mapping %d names no target environment", i+1)
		}
	}
	for _, c := range t.Classifications {
		if c.Class != string(schema.Secret) && c.Class != string(schema.Config) {
			return Template{}, failure("import", CodeMalformed, "mapping.json",
				"key %s declares classification %s, which is neither `secret` nor `config`",
				quoteName(c.Key), quoteName(c.Class))
		}
	}
	for _, ty := range t.Types {
		if !isDeclarableType(ty.Type) {
			return Template{}, failure("import", CodeMalformed, "mapping.json",
				"key %s declares type %s, which is not one of the six declarable types",
				quoteName(ty.Key), quoteName(ty.Type))
		}
	}
	for _, r := range t.Renames {
		if r.Transform != TransformAuto && r.Transform != TransformManual {
			return Template{}, failure("import", CodeMalformed, "mapping.json",
				"rename of %s records transform %s, which is neither `auto` nor `manual`",
				quoteName(r.From), quoteName(string(r.Transform)))
		}
		if err := schema.CheckKeyName(r.To); err != nil {
			return Template{}, failure("import", CodeUnmappableName, quoteName(r.From),
				"the template renames it to %s, which the canonical grammar refuses", quoteName(r.To))
		}
	}
	return t, nil
}

// ParseManifest reads a run manifest strictly, under the same version rule.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if err := strictDecode(raw, "run-manifest.json", &m); err != nil {
		return Manifest{}, err
	}
	if err := checkVersions("run-manifest.json", m.FormatVersion, m.ConnectorContractVersion); err != nil {
		return Manifest{}, err
	}
	if m.Target.Project == "" {
		return Manifest{}, failure("import", CodeMalformed, "run-manifest.json",
			"the manifest names no target project")
	}
	if len(m.Target.Environments) == 0 {
		return Manifest{}, failure("import", CodeMalformed, "run-manifest.json",
			"the manifest names no target environment; the precondition re-evaluates read(E) for every environment it names")
	}
	for i, env := range m.Target.Environments {
		if env == "" {
			return Manifest{}, failure("import", CodeMalformed, "run-manifest.json",
				"target environment %d is empty", i+1)
		}
	}
	return m, nil
}

// ParseValuesFile reads a values file strictly. It is the phase-2 input, so it
// gets the same closed treatment: a field this build does not know means the
// file was written by a different one.
func ParseValuesFile(raw []byte) (ValuesFile, error) {
	var v ValuesFile
	if err := strictDecode(raw, "values file", &v); err != nil {
		return ValuesFile{}, err
	}
	if v.FormatVersion != FormatVersion {
		return ValuesFile{}, failure("import", CodeVersion, "values file",
			"format version %d is not this build's %d: version mismatch", v.FormatVersion, FormatVersion)
	}
	if v.Project == "" {
		return ValuesFile{}, failure("import", CodeMalformed, "values file",
			"the values file names no project")
	}
	if v.Environment == "" {
		return ValuesFile{}, failure("import", CodeMalformed, "values file",
			"the values file names no environment; `values import` is per environment")
	}
	if len(v.Entries) == 0 {
		return ValuesFile{}, failure("import", CodeMalformed, "values file", "the values file holds no entries")
	}
	seen := make(map[string]bool, len(v.Entries))
	for _, e := range v.Entries {
		if seen[e.Key] {
			return ValuesFile{}, failure("import", CodeDuplicateKey, "values file",
				"key %s appears more than once", quoteName(e.Key))
		}
		seen[e.Key] = true
	}
	return v, nil
}

func strictDecode(raw []byte, what string, into any) error {
	if err := rejectDuplicateMembers(raw, "import", what); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "unknown field") {
			return failure("import", CodeVersion, what,
				"it carries a field this build does not know (%s): version mismatch — "+
					"this artifact was written by a different Hikyo version", msg)
		}
		return failure("import", CodeMalformed, what, "it is not a well-formed artifact of this kind")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return failure("import", CodeMalformed, what, "trailing content after the document")
	}
	return nil
}

// rejectDuplicateMembers walks the raw JSON token stream before decoding into
// a Go value. encoding/json otherwise accepts duplicate object members with
// last-one-wins semantics, which is unsafe for reviewed artifacts.
func rejectDuplicateMembers(raw []byte, source, what string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSONValue(dec, source, what); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return failure(source, CodeMalformed, what, "trailing content after the document")
	}
	return nil
}

func walkJSONValue(dec *json.Decoder, source, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			member, err := dec.Token()
			if err != nil {
				return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
			}
			key, ok := member.(string)
			if !ok {
				return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
			}
			folded := foldJSONMember(key)
			if _, duplicate := seen[folded]; duplicate {
				return failure(source, CodeDuplicateKey, what,
					"object member %s appears more than once", quoteName(key))
			}
			seen[folded] = struct{}{}
			if err := walkJSONValue(dec, source, what); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec, source, what); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
		}
	default:
		return failure(source, CodeMalformed, what, "it is not a well-formed artifact of this kind")
	}
	return nil
}

// foldJSONMember mirrors encoding/json's case-insensitive struct-field match.
// Exact and case-variant spellings must occupy one logical member slot before
// the later struct decode can apply last-value-wins semantics to them.
func foldJSONMember(name string) string {
	return strings.Map(func(r rune) rune {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				return next
			}
			r = next
		}
	}, name)
}

func checkVersions(what string, format, contract int) error {
	if format != FormatVersion {
		return failure("import", CodeVersion, what,
			"format_version %d is not this build's %d: version mismatch", format, FormatVersion)
	}
	if contract != ConnectorContractVersion {
		return failure("import", CodeVersion, what,
			"connector_contract_version %d is not this build's %d: version mismatch",
			contract, ConnectorContractVersion)
	}
	return nil
}

// isDeclarableType answers the six-type check the template's `types` list needs.
func isDeclarableType(t string) bool {
	switch schema.Type(t) {
	case schema.TypeString, schema.TypeInteger, schema.TypeBoolean,
		schema.TypeEnum, schema.TypeURL, schema.TypeJSON:
		return true
	}
	return false
}
