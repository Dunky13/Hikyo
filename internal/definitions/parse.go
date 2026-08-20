package definitions

import (
	"errors"
	"sort"

	"github.com/Hikyo-Org/hikyo/internal/schema"
)

// Parse reads a bundle strictly and returns it normalized: the closed schema
// rejects unknown fields (naming the field and the version mismatch), duplicate
// members, trailing content, an ids-without-base template, and the deleted
// `base` field; the size bounds refuse an oversized or overpopulated bundle
// before it can drive any work. A parsed bundle is normalized (entries sorted by
// name, declarations in schema-canonical form, presence lists sorted), so it is
// the sole producer of the canonical form Encode assumes.
func Parse(raw []byte) (Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return Bundle{}, limitDetail("bundle is %d bytes, over the %d byte limit", len(raw), MaxBundleBytes)
	}

	var b Bundle
	if err := DecodeStrict(raw, &b); err != nil {
		return Bundle{}, mapDecodeError(err)
	}

	if b.FormatVersion != FormatVersion {
		return Bundle{}, invalidDetail(
			"bundle format_version %d is not this build's %d: version mismatch", b.FormatVersion, FormatVersion)
	}

	entries := len(b.Keys) + len(b.Environments) + len(b.KeyGroups)
	if entries > MaxBundleEntries {
		return Bundle{}, limitDetail("bundle holds %d entries, over the %d entry limit", entries, MaxBundleEntries)
	}

	if b.Additive() && hasIDs(b) {
		return Bundle{}, invalidDetail("malformed template: ids without base revision")
	}

	return normalize(b)
}

// mapDecodeError translates the neutral strict-decode errors into caller-safe
// domain refusals. The `base` field gets its own message because its removal is
// a specific amendment a bundle author must be told about, not a generic
// unknown field.
func mapDecodeError(err error) error {
	var unknown *UnknownFieldError
	if errors.As(err, &unknown) {
		if foldJSONMember(unknown.Field) == foldJSONMember("base") {
			return invalidDetail("base is not a bundle field since the flat-model amendment")
		}
		return invalidDetail(
			"bundle carries field %q this build (format version %d) does not know: version mismatch",
			unknown.Field, FormatVersion)
	}
	var dup *DuplicateMemberError
	if errors.As(err, &dup) {
		return invalidDetail("bundle object member %q appears more than once", dup.Member)
	}
	if errors.Is(err, ErrTrailing) {
		return invalidDetail("trailing content after the bundle document")
	}
	return invalidDetail("bundle is not a well-formed JSON document")
}

func hasIDs(b Bundle) bool {
	for _, e := range b.Environments {
		if e.ID != "" {
			return true
		}
	}
	for _, g := range b.KeyGroups {
		if g.ID != "" {
			return true
		}
	}
	for _, k := range b.Keys {
		if k.ID != "" {
			return true
		}
	}
	return false
}

// Normalize sorts and canonicalizes a bundle. Import and tests that build a
// bundle by hand call it before Encode; Parse calls it on decode.
func Normalize(b Bundle) (Bundle, error) { return normalize(b) }

func normalize(b Bundle) (Bundle, error) {
	out := Bundle{
		FormatVersion: FormatVersion,
		BaseRevision:  b.BaseRevision,
		Environments:  append([]Environment(nil), b.Environments...),
		KeyGroups:     append([]KeyGroup(nil), b.KeyGroups...),
		Keys:          append([]Key(nil), b.Keys...),
	}
	if out.Environments == nil {
		out.Environments = []Environment{}
	}
	if out.KeyGroups == nil {
		out.KeyGroups = []KeyGroup{}
	}
	if out.Keys == nil {
		out.Keys = []Key{}
	}
	sort.SliceStable(out.Environments, func(i, j int) bool { return out.Environments[i].Name < out.Environments[j].Name })
	sort.SliceStable(out.KeyGroups, func(i, j int) bool { return out.KeyGroups[i].Name < out.KeyGroups[j].Name })
	sort.SliceStable(out.Keys, func(i, j int) bool { return out.Keys[i].Name < out.Keys[j].Name })

	for i := range out.Keys {
		k := out.Keys[i]
		if k.Classification != string(schema.Secret) && k.Classification != string(schema.Config) {
			return Bundle{}, invalidDetail(
				"key %q declares classification %q, which is neither `secret` nor `config`", k.Name, k.Classification)
		}
		canonicalDecl, err := schema.Canonical(k.Declaration)
		if err != nil {
			return Bundle{}, invalidDetail("key %q has an invalid declaration: %v", k.Name, err)
		}
		decl, err := schema.ParseDeclaration(canonicalDecl)
		if err != nil {
			return Bundle{}, invalidDetail("key %q has an invalid declaration: %v", k.Name, err)
		}
		k.Declaration = decl
		req, err := normalizePresence("required_in", k.Name, k.RequiredIn)
		if err != nil {
			return Bundle{}, err
		}
		forb, err := normalizePresence("forbidden_in", k.Name, k.ForbiddenIn)
		if err != nil {
			return Bundle{}, err
		}
		k.RequiredIn, k.ForbiddenIn = req, forb
		out.Keys[i] = k
	}
	return out, nil
}

// normalizePresence validates a bundle presence rule's mode/shape and returns
// it with a sorted, always-present environment list.
func normalizePresence(what, keyName string, p Presence) (Presence, error) {
	envs := append([]string(nil), p.Environments...)
	sort.Strings(envs)
	switch schema.PresenceMode(p.Mode) {
	case schema.PresenceNone, schema.PresenceAll:
		if len(envs) > 0 {
			return Presence{}, invalidDetail("key %q `%s` mode %q carries no environments", keyName, what, p.Mode)
		}
		return Presence{Mode: p.Mode, Environments: []string{}}, nil
	case schema.PresenceExplicit:
		if len(envs) == 0 {
			return Presence{}, invalidDetail("key %q `%s` mode `explicit` names at least one environment", keyName, what)
		}
		for i, name := range envs {
			if name == "" {
				return Presence{}, invalidDetail("key %q `%s` names an empty environment", keyName, what)
			}
			if i > 0 && envs[i-1] == name {
				return Presence{}, invalidDetail("key %q `%s` names environment %q more than once", keyName, what, name)
			}
		}
		return Presence{Mode: p.Mode, Environments: envs}, nil
	default:
		return Presence{}, invalidDetail("key %q `%s` mode %q is not one of all|none|explicit", keyName, what, p.Mode)
	}
}
