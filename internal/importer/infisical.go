package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Dunky13/hikyo/internal/schema"
)

// The Infisical connector (import-paths ADR § Per-source structural mapping,
// Infisical row). FILE MODE ONLY in v1 — the live API is deferred, trigger:
// user demand.
//
// # The pinned export
//
// Exporter command, pinned:
//
//	infisical export --format=json --env <slug> --path <folder-path>
//
// Minimum version: **v0.43.0**. The shape below was read off Infisical/cli
// v0.43.121 (`packages/cmd/export.go` formatAsJson over
// `packages/models/cli.go` SingleEnvironmentVariable) and is fixture-pinned in
// testdata/infisical-*.json. Note that `infisical export` is NOT recursive: it
// returns the secrets at `--path`, and each entry carries its own `secretPath`,
// so a multi-folder migration is several exports or several runs.
//
// The shape, exactly — a JSON ARRAY of objects:
//
//	[{"key":"DB_URL","workspace":"…","value":"…","type":"shared",
//	  "_id":"…","secretPath":"/db","tags":[],"comment":"",
//	  "Etag":"","skipMultilineEncoding":false}]
//
// # What is refused, and why
//
//   - **Not an array.** A flat `{"KEY":"value"}` object is a dotenv export
//     wearing JSON: it carries no folder provenance and no override marking.
//     Refused by name with a pointer to the `.env` scaffold path, which already
//     handles exactly that material.
//   - **An entry without `secretPath`.** No folder provenance; the export
//     cannot be mapped onto a folder chain, and guessing "everything at the
//     root" would silently flatten a tree.
//   - **An entry without `type`.** `type` is what marks a personal override. An
//     export that has already resolved personal overrides into values has lost
//     that marker, and importing it would import one person's private
//     shadowing as if it were the team's value.
//
// # What is skipped
//
// `type: "personal"` entries are SKIPPED and LISTED BY NAME. A personal
// override is one human's private shadow of a shared secret; it is not the
// project's value and it must not become one.
//
// `--env <slug>` selects the source slice. The pinned array carries folder
// provenance per entry but no environment field, so the slug is operator-
// supplied, required, and recorded — in the mapping template's scope and in the
// run manifest's source identity — rather than inferred.

const infisicalSource = "infisical"

// InfisicalMinimumVersion is the pinned exporter floor, stated in output so a
// refused export names what to upgrade.
const InfisicalMinimumVersion = "v0.43.0"

const (
	infisicalTypeShared   = "shared"
	infisicalTypePersonal = "personal"
)

type infisicalConnector struct{}

func (infisicalConnector) Name() string { return infisicalSource }

// infisicalEntry is the pinned export entry. Fields this connector does not
// map (tags, comment, Etag, skipMultilineEncoding, workspace) are deliberately
// absent: an importer that carried a source's comment field into a Hikyo
// description would be inventing declarations from foreign free text.
type infisicalEntry struct {
	Key        string  `json:"key"`
	Value      string  `json:"value"`
	Type       *string `json:"type"`
	SecretPath *string `json:"secretPath"`
	ID         string  `json:"_id"`
}

func (infisicalConnector) Read(ctx context.Context, in Input, b *Budget) (Result, error) {
	if in.EnvSlug == "" {
		return Result{}, failure(infisicalSource, CodeProvenance, in.Path,
			"an Infisical import names its source slice: pass --env <slug>")
	}
	trimmed := bytes.TrimSpace(in.Data)
	if len(trimmed) == 0 {
		return Result{}, failure(infisicalSource, CodeMalformed, in.Path, "the export is empty")
	}
	if trimmed[0] != '[' {
		// A flat object is the dotenv-shaped export. Route it, by name, to the
		// path that already handles it.
		return Result{}, failure(infisicalSource, CodeProvenance, in.Path,
			"this is not the pinned structured export (a JSON array): a flattened export carries no folder or "+
				"override provenance — export it with `infisical export --format=json --env <slug> --path <path>` "+
				"(%s or newer), or route the flattened form through the `.env` scaffold path",
			InfisicalMinimumVersion)
	}

	// DisallowUnknownFields is deliberately NOT set: the export carries fields
	// this connector does not map, and a future Infisical release adding one
	// must not break a migration. The pin is on the fields that MUST be there,
	// checked by name below.
	var entries []infisicalEntry
	if err := json.Unmarshal(trimmed, &entries); err != nil {
		// Dropped, not wrapped: encoding/json echoes the offending value.
		return Result{}, failure(infisicalSource, CodeMalformed, in.Path,
			"the export is not the pinned JSON array of secret entries")
	}
	if len(entries) == 0 {
		return Result{}, failure(infisicalSource, CodeMalformed, in.Path, "the export holds no secrets")
	}

	var records []Record
	var skipped []string
	for i, e := range entries {
		if err := ctx.Err(); err != nil {
			return Result{}, failure(infisicalSource, CodeBound, in.Path,
				"the run exceeded the %s whole-run deadline", RunDeadline)
		}
		where := fmt.Sprintf("%s entry %d", in.Path, i)
		if e.Key == "" {
			return Result{}, failure(infisicalSource, CodeMalformed, where, "the entry carries no `key`")
		}
		named := fmt.Sprintf("%s key %s", in.Path, quoteName(e.Key))
		if e.SecretPath == nil {
			return Result{}, failure(infisicalSource, CodeProvenance, named,
				"the entry carries no `secretPath`: this export has no folder provenance and cannot be mapped")
		}
		if e.Type == nil {
			return Result{}, failure(infisicalSource, CodeProvenance, named,
				"the entry carries no `type`: personal overrides are indistinguishable from shared secrets, "+
					"so this export has already resolved them into values")
		}
		// EVERY entry is charged, BEFORE the type branch. A skipped personal
		// override still costs a decode and a record slot, so branching first
		// would make an export of a million personal overrides a free pass
		// through the record cap — the bound would count what it liked rather
		// than what it parsed.
		if err := b.Bytes(named, len(e.Value)); err != nil {
			return Result{}, err
		}
		if err := b.Record(named); err != nil {
			return Result{}, err
		}
		switch *e.Type {
		case infisicalTypePersonal:
			skipped = append(skipped, e.Key)
			continue
		case infisicalTypeShared:
		default:
			// The value is NOT echoed: `type` is a foreign enum-shaped field,
			// and an export can put anything there — a token, a terminal escape
			// sequence. Naming the field and the two admissible values says
			// everything and discloses nothing.
			return Result{}, failure(infisicalSource, CodeProvenance, named,
				"the entry's `type` is neither `shared` nor `personal`")
		}
		folder, err := infisicalFolder(named, *e.SecretPath)
		if err != nil {
			return Result{}, err
		}
		if err := b.Depth(named, len(folder)); err != nil {
			return Result{}, err
		}
		records = append(records, Record{
			Folder:     folder,
			SourceName: e.Key,
			Value:      e.Value,
			Type:       schema.TypeString,
			// Deliberately NO Version. Infisical's `_id` is the secret's
			// identity, not its version: it does not advance when the value
			// changes, so recording it as a source version would put a constant
			// in a field a reviewer reads as "this is the revision I imported".
		})
	}
	if len(records) == 0 {
		return Result{}, failure(infisicalSource, CodeMalformed, in.Path,
			"every entry in the export is a personal override; there is no shared secret to import")
	}
	slices.Sort(skipped)
	return Result{Records: records, Skipped: skipped, Scope: Scope{EnvSlug: in.EnvSlug}}, nil
}

// infisicalFolder maps `secretPath` onto a folder chain. `/` is the
// environment root and maps onto no folder at all.
func infisicalFolder(where, path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, failure(infisicalSource, CodeProvenance, where,
			"`secretPath` is not absolute; the pinned export spells folder paths from the root")
	}
	var out []string
	for _, seg := range strings.Split(strings.Trim(path, "/"), "/") {
		if seg == "" {
			continue
		}
		out = append(out, seg)
	}
	return out, nil
}
