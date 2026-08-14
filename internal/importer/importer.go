// Package importer is the client-side import framework (#68, import-paths ADR
// as amended by the flat-model ADR).
//
// It is a pure library over foreign bytes: a connector parses an export the
// user produced with the source's own tooling and returns records; the
// framework enforces the uniform bounds, applies the canonical key grammar,
// and authors the four phase-1 artifacts. It contacts no server — the CLI does
// that, with the server-minted material this package records.
//
// Two invariants govern every line here:
//
//   - CONNECTORS ARE STRICTLY READ-ONLY. The interface exposes no write
//     operation to implement, which is what makes "a migration tool cannot
//     destroy the thing being migrated from" structural rather than a
//     per-connector courtesy.
//   - EVERY FOREIGN BYTE IS SECRET FROM FIRST READ UNTIL CLASSIFIED. No error
//     built in this package carries source content. Errors name keys, paths,
//     bounds and codes — never a YAML snippet, never a value fragment, never a
//     decoder's echo of what it choked on. That is why no parser error is ever
//     wrapped: yaml.v3 renders a type mismatch as "cannot unmarshal !!str
//     sk_live... into map[string]string", which puts a value prefix on stderr.
//     Structural facts (a document index, a bound, a key name) are the whole
//     vocabulary.
package importer

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// The uniform connector bounds (import-paths ADR § Architecture: "Connector
// work is bounded ... Exceeding a bound fails loud, naming the bound"). They
// are enforced AT THE INTERFACE — in Run and in Budget — rather than per
// connector, so a new connector inherits them by construction and cannot forget
// one.
//
// The values are this ticket's, chosen against the ops spec's Pi-4 floor, and
// they join the ops spec's composable-maxima catalogue (docs/handoff/68).
// Resource exhaustion must be impossible BEFORE a bundle exists, so every
// bound is checked while parsing, not after.
const (
	// MaxFileBytes bounds one export file. A K8s manifest dump, a SOPS file
	// and an Infisical export are all human-scale documents; four megabytes is
	// already an order of magnitude past any of them.
	MaxFileBytes = 4 << 20
	// MaxDecodedBytes bounds expansion AFTER decoding — base64 `data` blocks,
	// YAML alias expansion, a decrypted SOPS tree. The file cap alone does not
	// bound this: a small document can expand enormously, which is the whole
	// decompression-bomb class.
	MaxDecodedBytes = 16 << 20
	// MaxRecords bounds how many leaves one import may carry. A project's key
	// catalogue is itself capped at schema.MaxKeysPerProject; this is that
	// bound with room for a multi-Secret manifest that maps onto fewer keys.
	MaxRecords = 5000
	// MaxDepth bounds the source's tree depth — a SOPS map chain, an Infisical
	// folder path. It bounds recursion before the record count can.
	MaxDepth = 32
	// MaxValueBytes is the largest single leaf value. It is the schema
	// package's own value bound: importing something the value engine would
	// then refuse is a failure discovered at the wrong end.
	MaxValueBytes = schema.MaxValueBytes
	// RunDeadline is the whole-run wall clock. It covers decryption (which may
	// contact a KMS or run gpg) as well as parsing, so a hung key service fails
	// loud instead of hanging a migration.
	RunDeadline = 60 * time.Second
)

// Code is the stable, content-free machine code on every refusal this package
// produces. It is what makes "errors name codes, never content" checkable: a
// fixture asserts the code, so no test ever needs the prose to carry a value.
type Code string

const (
	// CodeBound: a uniform bound was exceeded. Detail names which.
	CodeBound Code = "bound-exceeded"
	// CodeMalformed: the input is not the format the connector was told to
	// read. Deliberately coarse — a finer taxonomy would be built from the
	// parser's own message, which is the content channel.
	CodeMalformed Code = "malformed"
	// CodeKind: a document of the wrong kind (a ConfigMap where a Secret was
	// expected).
	CodeKind Code = "wrong-kind"
	// CodeDuplicateKey: one source container declares a name twice.
	CodeDuplicateKey Code = "duplicate-key"
	// CodeBinaryValue: a value that is not valid UTF-8, or carries NUL.
	CodeBinaryValue Code = "binary-value"
	// CodeProvenance: an export lacking the folder/environment provenance the
	// pinned format requires, or one whose personal overrides were already
	// resolved into values.
	CodeProvenance Code = "provenance-missing"
	// CodeUnmappableName: a source name the documented transform cannot
	// resolve. Requires an explicit rename in the mapping template.
	CodeUnmappableName Code = "unmappable-name"
	// CodeNameCollision: two source names landing on one target name.
	CodeNameCollision Code = "name-collision"
	// CodeTrim: a value the write-time trim would alter, unacknowledged.
	CodeTrim Code = "trim-would-alter"
	// CodeDecrypt: decryption failed. The underlying error is dropped, not
	// wrapped: a key service's error text is foreign content.
	CodeDecrypt Code = "decrypt-failed"
	// CodeVersion: an artifact whose format or connector-contract version this
	// build does not implement.
	CodeVersion Code = "version-mismatch"
	// CodeIncompatible: an existing declaration this import disagrees with.
	// Import never modifies a declaration, so the conflict is the human's to
	// resolve — in the mapping template, or with the reclassification ceremony.
	CodeIncompatible Code = "incompatible-declaration"
)

// Error is every refusal this package produces. Where is structural — a
// document index, a folder path, a key name — and Detail is assembled from
// constants and structural facts only.
type Error struct {
	Source string
	Code   Code
	Where  string
	Detail string
}

func (e *Error) Error() string {
	if e.Where == "" {
		return fmt.Sprintf("%s: %s: %s", e.Source, e.Code, e.Detail)
	}
	return fmt.Sprintf("%s: %s at %s: %s", e.Source, e.Code, e.Where, e.Detail)
}

func failure(source string, code Code, where, format string, args ...any) *Error {
	return &Error{Source: source, Code: code, Where: where, Detail: fmt.Sprintf(format, args...)}
}

// Budget is the decoded-bytes and record-count meter a connector charges as it
// parses. It is passed IN rather than checked after, because "bounded after
// decoding" is only true if the expansion is metered while it happens — and
// "while" means BEFORE the expanded bytes are materialized, not after. A
// connector that decodes into a string and then charges its length has already
// paid the memory; every charge site below is reached with the SIZE in hand and
// the bytes not yet built.
type Budget struct {
	source   string
	decoded  int
	records  int
	maxBytes int
	maxCount int
}

// Bytes charges n decoded bytes and fails loud, naming the bound, on overrun.
func (b *Budget) Bytes(where string, n int) error {
	b.decoded += n
	if b.decoded > b.maxBytes {
		return failure(b.source, CodeBound, where,
			"decoded bytes exceed the %d-byte decoded-bytes cap", b.maxBytes)
	}
	return nil
}

// Record charges one record.
func (b *Budget) Record(where string) error {
	b.records++
	if b.records > b.maxCount {
		return failure(b.source, CodeBound, where,
			"record count exceeds the %d-record cap", b.maxCount)
	}
	return nil
}

// Depth checks a tree depth against the cap. Every tree walk in this package
// routes through it rather than re-implementing the comparison: three copies of
// one bound is three places for it to drift.
func (b *Budget) Depth(where string, depth int) error {
	if depth > MaxDepth {
		return failure(b.source, CodeBound, where,
			"tree depth exceeds the %d-level cap", MaxDepth)
	}
	return nil
}

// Input is one connector invocation's source material. Data arrives already
// read and already size-capped by Run — a connector never opens a file, which
// keeps the per-file bound at the interface where the ADR puts it.
type Input struct {
	// Path is the source path, for error placement only. It is not opened here.
	Path string
	// Data is the export's bytes.
	Data []byte
	// EnvSlug is `--env`: the source-side environment slice, Infisical only.
	EnvSlug string
}

// Record is one leaf a connector found, in the source's own vocabulary. The
// name is the SOURCE name, untransformed: the rename transform runs in the
// framework so every connector renames identically.
type Record struct {
	// Folder is the target folder chain this leaf maps onto, connector-assigned
	// (one K8s Secret → one folder; a SOPS map chain → a folder chain).
	Folder []string
	// SourceName is the leaf's name as the source spells it.
	SourceName string
	// Value is the leaf's value. Secret from this moment until classified.
	Value string
	// Type is `string` for scalar leaves and `json` for structured ones, which
	// arrive through the canonical serialization (canonicalJSON).
	Type schema.Type
	// PlaintextHint records that the source stored this leaf in plaintext (a
	// SOPS leaf outside `encrypted_regex`). It is a CLASSIFICATION HINT and
	// never a default: flag mode performs no downgrades at all.
	PlaintextHint bool
	// Version is the per-record source version identifier where the source
	// provides one, for the run manifest. Empty where it does not.
	Version string
}

// Result is one connector read. Skipped rides beside Records rather than out
// of band because a deliberate skip is not a refusal — the import proceeds and
// the plan lists the skipped names, which is exactly what the Infisical row's
// "skipped and listed by name" requires.
type Result struct {
	Records []Record
	// Skipped names source entries the connector deliberately did not import.
	Skipped []string
	// Scope is the connector-shaped source selector the mapping template
	// records. It is the CONNECTOR's to fill because only it knows the shape:
	// k8s reports {namespace, names[]} read off the manifests, sops and
	// infisical report nothing and the framework stamps the file digest.
	Scope Scope
}

// Connector is the in-process connector interface. It is deliberately narrow
// and deliberately read-only: there is no Write, no Delete and no Put to
// implement, so no connector can mutate a foreign store even by accident. It
// is NOT an extension point — the OSS-mechanics ADR fixes exactly two, and this
// adds none.
type Connector interface {
	// Name is the `--from` spelling.
	Name() string
	// Read parses one export into records, charging the budget as it decodes.
	Read(ctx context.Context, in Input, b *Budget) (Result, error)
}

// connectors is the compile-time registry: a map literal, not an init()
// side effect, so the served set is readable in one place and a connector
// cannot register itself from somewhere unexpected.
var connectors = map[string]Connector{
	k8sSource:       k8sConnector{},
	sopsSource:      sopsConnector{},
	infisicalSource: infisicalConnector{},
}

// Sources returns the served `--from` spellings, sorted, for usage text.
func Sources() []string {
	out := make([]string, 0, len(connectors))
	for name := range connectors {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// ReadFile reads an import input under the shared per-file bound. Export files
// and reviewed artifacts take exactly this path so neither can bypass the
// regular-file or allocation checks.
//
// Stat runs before Open so a fifo is refused instead of blocking in Open. The
// open descriptor is then checked again to close the ordinary replacement
// race, and LimitReader handles a regular file that grows after either stat.
func ReadFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, failure("import", CodeMalformed, path,
			"file mode %s is not regular", info.Mode())
	}
	if info.Size() > MaxFileBytes {
		return nil, failure("import", CodeBound, path,
			"file size %d exceeds the %d-byte per-file cap", info.Size(), MaxFileBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, failure("import", CodeMalformed, path,
			"file mode %s is not regular", opened.Mode())
	}
	if opened.Size() > MaxFileBytes {
		return nil, failure("import", CodeBound, path,
			"file size %d exceeds the %d-byte per-file cap", opened.Size(), MaxFileBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, failure("import", CodeBound, path,
			"the file exceeds the %d-byte per-file cap", MaxFileBytes)
	}
	return data, nil
}

// ReadExport wraps the shared bounded reader in the connector input type.
func ReadExport(path string) (Input, error) {
	data, err := ReadFile(path)
	if err != nil {
		return Input{}, err
	}
	return Input{Path: path, Data: data}, nil
}

// Run reads one export through the named connector under every uniform bound.
// The bounds live here, once, rather than in three connectors that would have
// to agree.
func Run(ctx context.Context, name string, in Input) (Result, error) {
	c, ok := connectors[name]
	if !ok {
		return Result{}, failure("import", CodeMalformed, "",
			"%q is not a served source; served sources are %v", name, Sources())
	}
	if len(in.Data) > MaxFileBytes {
		return Result{}, failure(name, CodeBound, in.Path,
			"file size %d exceeds the %d-byte per-file cap", len(in.Data), MaxFileBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, RunDeadline)
	defer cancel()

	b := &Budget{source: name, maxBytes: MaxDecodedBytes, maxCount: MaxRecords}
	result, err := c.Read(ctx, in, b)
	if err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{}, failure(name, CodeBound, in.Path,
			"the run exceeded the %s whole-run deadline", RunDeadline)
	}
	// The per-value bound and the UTF-8/NUL rule are uniform source rules
	// (import-paths ADR § Per-source structural mapping). "Refusal is per-key,
	// not per-import" means the refusal NAMES EVERY OFFENDING KEY — a refusal
	// that stops at the first one turns a hundred-key migration into a hundred
	// runs, which is per-import behaviour wearing a per-key message.
	var oversized, binary []string
	for _, r := range result.Records {
		if len(r.Value) > MaxValueBytes {
			oversized = append(oversized, recordPath(r))
			continue
		}
		if checkUTF8(r.Value) != nil {
			binary = append(binary, recordPath(r))
		}
	}
	if len(oversized) > 0 {
		return Result{}, failure(name, CodeBound, "",
			"%d value(s) exceed the %d-byte per-value cap: %s",
			len(oversized), MaxValueBytes, strings.Join(oversized, ", "))
	}
	if len(binary) > 0 {
		return Result{}, failure(name, CodeBinaryValue, "",
			"%d value(s) are not UTF-8 text (invalid encoding or a NUL byte); Hikyo values are UTF-8 text: %s",
			len(binary), strings.Join(binary, ", "))
	}
	return result, nil
}

// nonNil renders a nil slice as an empty one before serialization. `[]` says
// "nothing here"; a JSON null would read as "unknown" for a fact the artifact
// knows exactly. One helper, because the same normalization spelled three ways
// is three places to forget a field.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
