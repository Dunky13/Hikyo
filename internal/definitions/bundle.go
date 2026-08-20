// Package definitions is the canonical definitions-bundle vocabulary and the
// pure diffing engine behind `definitions export | check | plan | apply`
// (source-of-truth ADR, as amended by the flat-model ADR). Like internal/schema
// it is a pure library: a bundle in, a canonical serialization or a diff out —
// no store, no authorization, no clock. The service layer (#70) feeds it a
// snapshot of current state and turns its diff into a plan; the importer (#68)
// emits an additive bundle through it. Nothing here reads a repository, and
// nothing here decides policy.
//
// The bundle carries a project's *shape* and nothing value-derived: keys,
// declarations, presence rules, key groups, and the environment list. Values,
// snapshots, and manifests are structurally out of scope (ADR § safety
// boundary), so this package cannot import them.
package definitions

import (
	"fmt"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// FormatVersion is the bundle format version. It advances only when the
// serialization changes incompatibly; unknown fields already reject loudly, so
// a newer server's export never applies silently truncated to an older one.
const FormatVersion = 1

// Bounds. A bundle is attacker-supplied request material (ops-spec row 15), so
// every ceiling is a named constant refused with a loud ErrLimitExceeded-class
// refusal — the raw-byte cap before the parse where possible, the entry cap
// after decode.
const (
	// MaxBundleBytes bounds the raw request body before it is parsed.
	MaxBundleBytes = 1 << 20 // 1 MiB
	// MaxBundleEntries bounds keys + environments + groups combined.
	MaxBundleEntries = 10_000
)

// Presence is a bundle's per-environment presence rule. It mirrors
// schema.Presence but names environments by their portable **name**, never by
// server-owned id, and always serializes its list (determinism beats brevity),
// so it is a distinct type resolved to ids only after environment matching.
type Presence struct {
	Mode         string   `json:"mode"`
	Environments []string `json:"environments"`
}

// Environment is one environment-topology entry: a portable name and an
// optional server-owned id (present on export, stripped by --portable).
type Environment struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// KeyGroup is one project-scoped key group by name, with an optional id.
type KeyGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// Key is one declaration entry. Every non-id field is always emitted — a bundle
// is desired state read as a diff, and an omitted field is indistinguishable
// from an intentional clear. `group` references a KeyGroup by name and is empty
// when the key belongs to no group.
type Key struct {
	ID              string             `json:"id,omitempty"`
	Name            string             `json:"name"`
	FolderPath      string             `json:"folder_path"`
	Classification  string             `json:"classification"`
	Description     string             `json:"description"`
	Deprecated      bool               `json:"deprecated"`
	DeprecationNote string             `json:"deprecation_note"`
	Group           string             `json:"group"`
	Declaration     schema.Declaration `json:"declaration"`
	RequiredIn      Presence           `json:"required_in"`
	ForbiddenIn     Presence           `json:"forbidden_in"`
}

// Bundle is the canonical definitions bundle. BaseRevision is a pointer so its
// absence — which makes the bundle *additive* (ADR § Additive bundles) — is
// distinguishable from a zero base revision.
type Bundle struct {
	FormatVersion int           `json:"format_version"`
	BaseRevision  *int64        `json:"base_revision,omitempty"`
	Environments  []Environment `json:"environments"`
	KeyGroups     []KeyGroup    `json:"key_groups"`
	Keys          []Key         `json:"keys"`
}

// Additive reports whether the bundle carries no base revision, in which case
// omission derives no deletion and modifying an existing entry is refused
// (ADR § Additive bundles).
func (b Bundle) Additive() bool { return b.BaseRevision == nil }

// invalidDetail wraps domain.ErrInvalid with caller-safe detail text. A bundle
// is entirely caller-supplied, so its parse refusals name the offending field
// verbatim and that text is safe to return on the wire — the server's uniform
// writer surfaces it via the SafeDetail interface.
type detailErr struct {
	detail string
	err    error
}

func (e *detailErr) Error() string      { return e.err.Error() }
func (e *detailErr) Unwrap() error      { return e.err }
func (e *detailErr) SafeDetail() string { return e.detail }

func invalidDetail(format string, args ...any) error {
	return detail(domain.ErrInvalid, format, args...)
}

func conflictDetail(format string, args ...any) error {
	return detail(domain.ErrConflict, format, args...)
}

func limitDetail(format string, args ...any) error {
	return detail(domain.ErrLimitExceeded, format, args...)
}

func detail(sentinel error, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	return &detailErr{detail: msg, err: fmt.Errorf("%w: %s", sentinel, msg)}
}

// AdditiveModificationError is the refusal to modify an existing entry with an
// additive bundle. It names the key so the service can attach the
// definitions.additive_modification_refused audit event, and carries caller-safe
// detail like every other bundle refusal.
type AdditiveModificationError struct {
	Key    string
	detail string
}

func (e *AdditiveModificationError) Error() string      { return e.detail }
func (e *AdditiveModificationError) SafeDetail() string { return e.detail }
func (e *AdditiveModificationError) Unwrap() error      { return domain.ErrInvalid }
