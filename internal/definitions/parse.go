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
	parsed, err := ParseCompiled(raw)
	if err != nil {
		return Bundle{}, err
	}
	return parsed.Bundle, nil
}

// CompiledBundle keeps parsed wire data separate from the classified
// declaration artifacts built from it. Apply paths consume both so a
// declaration is not compiled again after parsing.
type CompiledBundle struct {
	Bundle       Bundle
	declarations map[string]*schema.Compiled
}

// CompiledDeclaration returns the artifact for a normalized key name.
func (b CompiledBundle) CompiledDeclaration(keyName string) (*schema.Compiled, bool) {
	compiled, ok := b.declarations[keyName]
	return compiled, ok
}

// ParseCompiled parses and normalizes a wire bundle while retaining each
// declaration's classified artifact for an immediate apply.
func ParseCompiled(raw []byte) (CompiledBundle, error) {
	if len(raw) > MaxBundleBytes {
		return CompiledBundle{}, limitDetail("bundle is %d bytes, over the %d byte limit", len(raw), MaxBundleBytes)
	}

	var b Bundle
	if err := DecodeStrict(raw, &b); err != nil {
		return CompiledBundle{}, mapDecodeError(err)
	}

	if b.FormatVersion != FormatVersion {
		return CompiledBundle{}, invalidDetail(
			"bundle format_version %d is not this build's %d: version mismatch", b.FormatVersion, FormatVersion)
	}

	entries := len(b.Keys) + len(b.Environments) + len(b.KeyGroups)
	if entries > MaxBundleEntries {
		return CompiledBundle{}, limitDetail("bundle holds %d entries, over the %d entry limit", entries, MaxBundleEntries)
	}

	if b.Additive() && hasIDs(b) {
		return CompiledBundle{}, invalidDetail("malformed template: ids without base revision")
	}

	return normalizeCompiled(b)
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
func Normalize(b Bundle) (Bundle, error) {
	compiled, err := normalizeCompiled(b)
	if err != nil {
		return Bundle{}, err
	}
	return compiled.Bundle, nil
}

func normalizeCompiled(b Bundle) (CompiledBundle, error) {
	out := Bundle{
		FormatVersion: FormatVersion,
		BaseRevision:  b.BaseRevision,
		Environments:  append([]Environment(nil), b.Environments...),
		KeyGroups:     append([]KeyGroup(nil), b.KeyGroups...),
		Keys:          append([]Key(nil), b.Keys...),
	}
	declarations := make(map[string]*schema.Compiled, len(out.Keys))
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
			return CompiledBundle{}, invalidDetail(
				"key %q declares classification %q, which is neither `secret` nor `config`", k.Name, k.Classification)
		}
		compiled, err := schema.CompileClassified(schema.Classification(k.Classification), k.Declaration)
		if err != nil {
			return CompiledBundle{}, invalidDetail("key %q has an invalid declaration: %v", k.Name, err)
		}
		k.Declaration = compiled.Declaration()
		req, err := normalizePresence("required_in", k.Name, k.RequiredIn)
		if err != nil {
			return CompiledBundle{}, err
		}
		forb, err := normalizePresence("forbidden_in", k.Name, k.ForbiddenIn)
		if err != nil {
			return CompiledBundle{}, err
		}
		k.RequiredIn, k.ForbiddenIn = req, forb
		out.Keys[i] = k
		declarations[k.Name] = compiled
	}
	return CompiledBundle{Bundle: out, declarations: declarations}, nil
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
