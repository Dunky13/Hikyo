package compose

import "fmt"

// RenderProjection is the delivery projection being planned. It is explicit so
// config-only absence semantics cannot be inferred from row contents.
type RenderProjection string

const (
	RenderProjectionFull       RenderProjection = "full"
	RenderProjectionConfigOnly RenderProjection = "config-only"
)

// AbsentKeyPolicy tells the pure planner what a configured key missing from the
// source means. Live and snapshot adapters name their refusal independently;
// config-only adapters skip because projected-out secrets are absent entirely.
type AbsentKeyPolicy string

const (
	AbsentKeySkip                AbsentKeyPolicy = "skip"
	AbsentKeyRefuseNotDelivered  AbsentKeyPolicy = "refuse-not-delivered"
	AbsentKeyRefuseNotInSnapshot AbsentKeyPolicy = "refuse-not-in-snapshot"
)

// RenderTarget is one ordered target selection supplied by an adapter.
type RenderTarget struct {
	Name                     string
	KeyIDs                   []string
	AcknowledgeLoaderControl []string
}

// RenderSourceRow is one adapter-normalized delivery row. Value nil means the
// key was delivered without plaintext; UnrevealedSecret distinguishes the
// all-or-nothing secret refusal from a genuinely unset value.
type RenderSourceRow struct {
	KeyID            string
	Name             string
	Classification   string
	Value            *string
	UnrevealedSecret bool
}

// RenderInput contains every policy and datum needed to build a render plan.
// BuildRenderPlan performs no I/O and retains no reference to these slices.
type RenderInput struct {
	Projection RenderProjection
	AbsentKeys AbsentKeyPolicy
	Targets    []RenderTarget
	Rows       []RenderSourceRow
}

type RenderOmissionKind string

const (
	RenderOmissionAbsent  RenderOmissionKind = "absent"
	RenderOmissionNoValue RenderOmissionKind = "no-value"
)

// RenderOmission records a configured row intentionally omitted from output.
type RenderOmission struct {
	Target string             `json:"target"`
	KeyID  string             `json:"key_id"`
	Name   string             `json:"name,omitempty"`
	Kind   RenderOmissionKind `json:"kind"`
}

type RenderRefusalKind string

const (
	RenderRefusalKeyNotDelivered  RenderRefusalKind = "key-not-delivered"
	RenderRefusalKeyNotInSnapshot RenderRefusalKind = "key-not-in-snapshot"
	RenderRefusalSecretUnrevealed RenderRefusalKind = "secret-unrevealed"
	RenderRefusalLoaderControl    RenderRefusalKind = "loader-control"
	RenderRefusalEncoding         RenderRefusalKind = "encoding"
)

// RenderRefusal is a typed, source-stable refusal owned by the plan. CLI
// adapters add command-specific framing without re-running policy.
type RenderRefusal struct {
	Target string            `json:"target"`
	Key    string            `json:"key"`
	Kind   RenderRefusalKind `json:"kind"`
	Reason string            `json:"reason,omitempty"`
}

// RenderTargetPlan is one target's exact bytes and snapshot rows.
type RenderTargetPlan struct {
	Name         string        `json:"name"`
	Content      []byte        `json:"content"`
	SnapshotRows []SnapshotRow `json:"snapshot_rows"`
}

// RenderPlan is the complete pure decision for one render attempt.
type RenderPlan struct {
	Targets   []RenderTargetPlan `json:"targets"`
	Omissions []RenderOmission   `json:"omissions"`
	Refusals  []RenderRefusal    `json:"refusals"`
}

// BuildRenderPlan applies target selection, projection/absence policy,
// loader-control checks, raw-dotenv encoding, and snapshot-row collection.
func BuildRenderPlan(in RenderInput) (RenderPlan, error) {
	var plan RenderPlan
	if err := validateRenderInput(in); err != nil {
		return plan, err
	}

	byID := make(map[string]RenderSourceRow, len(in.Rows))
	for _, row := range in.Rows {
		if row.UnrevealedSecret && row.Value != nil {
			return RenderPlan{}, fmt.Errorf("compose: render row %q is both unrevealed and valued", row.KeyID)
		}
		byID[row.KeyID] = row
	}

	for _, target := range in.Targets {
		var rows []Row
		var snapshotRows []SnapshotRow
		var names []string
		for _, keyID := range target.KeyIDs {
			row, ok := byID[keyID]
			if !ok {
				if in.AbsentKeys == AbsentKeySkip {
					plan.Omissions = append(plan.Omissions, RenderOmission{Target: target.Name, KeyID: keyID, Kind: RenderOmissionAbsent})
				} else {
					kind := RenderRefusalKeyNotDelivered
					if in.AbsentKeys == AbsentKeyRefuseNotInSnapshot {
						kind = RenderRefusalKeyNotInSnapshot
					}
					plan.Refusals = append(plan.Refusals, RenderRefusal{Target: target.Name, Key: keyID, Kind: kind})
				}
				continue
			}
			if row.UnrevealedSecret {
				plan.Refusals = append(plan.Refusals, RenderRefusal{Target: target.Name, Key: row.Name, Kind: RenderRefusalSecretUnrevealed})
				continue
			}
			if row.Value == nil {
				plan.Omissions = append(plan.Omissions, RenderOmission{Target: target.Name, KeyID: keyID, Name: row.Name, Kind: RenderOmissionNoValue})
				continue
			}
			rows = append(rows, Row{Name: row.Name, Value: *row.Value})
			snapshotRows = append(snapshotRows, SnapshotRow{
				Name: row.Name, KeyID: row.KeyID, Classification: row.Classification, Value: *row.Value,
			})
			names = append(names, row.Name)
		}

		for _, name := range RefuseUnacknowledged(names, target.AcknowledgeLoaderControl) {
			plan.Refusals = append(plan.Refusals, RenderRefusal{Target: target.Name, Key: name, Kind: RenderRefusalLoaderControl})
		}
		content, encodingRefusals, err := EncodeRaw(rows)
		if err != nil {
			return RenderPlan{}, fmt.Errorf("compose: render target %s: %w", target.Name, err)
		}
		for _, refusal := range encodingRefusals {
			plan.Refusals = append(plan.Refusals, RenderRefusal{
				Target: target.Name, Key: refusal.Key, Kind: RenderRefusalEncoding, Reason: refusal.Reason,
			})
		}
		plan.Targets = append(plan.Targets, RenderTargetPlan{Name: target.Name, Content: content, SnapshotRows: snapshotRows})
	}
	return plan, nil
}

func validateRenderInput(in RenderInput) error {
	switch in.Projection {
	case RenderProjectionFull:
		if in.AbsentKeys == AbsentKeySkip {
			return fmt.Errorf("compose: full render projection cannot skip absent keys")
		}
	case RenderProjectionConfigOnly:
		if in.AbsentKeys != AbsentKeySkip {
			return fmt.Errorf("compose: config-only render projection must skip absent keys")
		}
	default:
		return fmt.Errorf("compose: unknown render projection %q", in.Projection)
	}
	switch in.AbsentKeys {
	case AbsentKeySkip, AbsentKeyRefuseNotDelivered, AbsentKeyRefuseNotInSnapshot:
		return nil
	default:
		return fmt.Errorf("compose: unknown absent-key policy %q", in.AbsentKeys)
	}
}
