package forgejo

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
)

type Module struct {
	API API
}

var _ adapter.Module = (*Module)(nil)

func (m *Module) ValidateConfig(cfg adapter.Config) error {
	_, err := canonicalOrigin(cfg.Origin)
	return err
}

func (m *Module) TestConnection(ctx context.Context, req adapter.ConnectionRequest) (adapter.Connection, error) {
	if m.API == nil {
		return adapter.Connection{}, errors.New("forgejo: API is not configured")
	}
	if req.Gate == nil {
		return adapter.Connection{}, adapter.ErrUnauthorized
	}
	if err := req.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	version, err := m.API.Version(ctx)
	if err != nil {
		return adapter.Connection{}, err
	}
	if !supportedVersion(version) {
		return adapter.Connection{}, fmt.Errorf("%w: this Forgejo lacks the variables API (%s)", adapter.ErrVersionFloor, version)
	}
	if err := req.Gate(ctx); err != nil {
		return adapter.Connection{}, err
	}
	id, err := m.API.ResolveDestination(ctx, req.Destination)
	if err != nil {
		return adapter.Connection{}, err
	}
	if req.Destination.NumericID != 0 && req.Destination.NumericID != id {
		return adapter.Connection{}, fmt.Errorf("%w: configured %d, resolved %d", adapter.ErrDestinationID, req.Destination.NumericID, id)
	}
	return adapter.Connection{Version: version, DestinationID: id}, nil
}

func supportedVersion(raw string) bool {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	return errMajor == nil && errMinor == nil && (major > 1 || major == 1 && minor >= 21)
}

func (m *Module) Plan(ctx context.Context, req adapter.PlanRequest) (adapter.Plan, error) {
	if err := adapter.ValidateManifest(req.Target.NamePrefix, req.Manifest); err != nil {
		return adapter.Plan{}, err
	}
	if req.Gate == nil {
		return adapter.Plan{}, adapter.ErrUnauthorized
	}
	if err := req.Gate(ctx); err != nil {
		return adapter.Plan{}, err
	}
	if err := m.verifyDestination(ctx, req.Target); err != nil {
		return adapter.Plan{}, err
	}
	if err := req.Gate(ctx); err != nil {
		return adapter.Plan{}, err
	}
	secretNames, err := m.API.ListSecretNames(ctx, req.Target.Destination)
	if err != nil {
		return adapter.Plan{}, err
	}
	providerSecrets := set(secretNames)
	ledger := ledgerMap(req.Ledger)
	desired := desiredEntries(req.Target.NamePrefix, req.Manifest, true)
	changes := make([]adapter.Change, 0, len(desired)+len(ledger))
	for _, row := range desired {
		key := ledgerKey(row.Surface, row.EffectiveName)
		state, claimed := ledger[key]
		disposition := adapter.Create
		switch {
		case claimed && (state == adapter.Owned || state == adapter.Dispatched):
			disposition = adapter.Update
		case row.Surface == adapter.Secret && providerSecrets[row.EffectiveName]:
			disposition = adapter.Conflict
		case row.Surface == adapter.Variable && !claimed:
			disposition = adapter.Unknown
		}
		changes = append(changes, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: disposition})
	}
	desiredSet := make(map[string]bool, len(desired))
	for _, row := range desired {
		desiredSet[ledgerKey(row.Surface, row.EffectiveName)] = true
	}
	for key, state := range ledger {
		if desiredSet[key] || state == adapter.Reserved {
			continue
		}
		surface, name := splitLedgerKey(key)
		changes = append(changes, adapter.Change{Surface: surface, EffectiveName: name, Disposition: adapter.Delete})
	}
	sortChanges(changes)
	return adapter.Plan{Changes: changes}, nil
}

type desired struct {
	adapter.ManifestEntry
	Surface       adapter.Surface
	EffectiveName string
}

func desiredEntries(prefix string, manifest []adapter.ManifestEntry, sentinel bool) []desired {
	rows := make([]desired, 0, len(manifest)+2)
	if sentinel {
		for _, surface := range []adapter.Surface{adapter.Secret, adapter.Variable} {
			classification := adapter.SecretClassification
			if surface == adapter.Variable {
				classification = adapter.ConfigClassification
			}
			rows = append(rows, desired{ManifestEntry: adapter.ManifestEntry{Classification: classification, Value: adapter.SentinelName}, Surface: surface, EffectiveName: prefix + adapter.SentinelName})
		}
	}
	for _, entry := range manifest {
		rows = append(rows, desired{ManifestEntry: entry, Surface: entry.Surface(), EffectiveName: prefix + entry.CanonicalName})
	}
	slices.SortStableFunc(rows, func(a, b desired) int {
		// Sentinels first. Remaining rows have deterministic surface/name order.
		aSentinel := a.KeyID == ""
		bSentinel := b.KeyID == ""
		if aSentinel != bSentinel {
			if aSentinel {
				return -1
			}
			return 1
		}
		if a.Surface != b.Surface {
			return strings.Compare(string(a.Surface), string(b.Surface))
		}
		return strings.Compare(a.EffectiveName, b.EffectiveName)
	})
	return rows
}

func (m *Module) Sync(ctx context.Context, req adapter.SyncRequest, journal adapter.Journal) (adapter.SyncResult, error) {
	if journal == nil {
		return adapter.SyncResult{}, errors.New("forgejo: durable journal is required")
	}
	if err := adapter.ValidateManifest(req.Target.NamePrefix, req.Manifest); err != nil {
		return adapter.SyncResult{}, err
	}
	inspect := adapter.Effect{Surface: adapter.Secret, EffectiveName: "*", Disposition: adapter.Update}
	if err := journal.Gate(ctx, inspect); err != nil {
		return adapter.SyncResult{}, err
	}
	if err := m.verifyDestination(ctx, req.Target); err != nil {
		return adapter.SyncResult{}, err
	}
	if err := journal.Gate(ctx, inspect); err != nil {
		return adapter.SyncResult{}, err
	}
	secretNames, err := m.API.ListSecretNames(ctx, req.Target.Destination)
	if err != nil {
		return adapter.SyncResult{}, err
	}
	providerSecrets := set(secretNames)
	ledger := ledgerMap(req.Ledger)
	desiredRows := desiredEntries(req.Target.NamePrefix, req.Manifest, !req.Teardown)
	result := adapter.SyncResult{}
	for _, row := range desiredRows {
		effect := adapter.Effect{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Create, KeyID: row.KeyID}
		key := ledgerKey(row.Surface, row.EffectiveName)
		state, claimed := ledger[key]
		if claimed && (state == adapter.Owned || state == adapter.Dispatched) {
			effect.Disposition = adapter.Update
		}
		if !claimed {
			state, err = journal.Reserve(ctx, effect)
			if err != nil {
				return result, err
			}
			ledger[key] = state
		}
		if state == adapter.Reserved && row.Surface == adapter.Secret && providerSecrets[row.EffectiveName] {
			if err := journal.Refuse(ctx, effect); err != nil {
				return result, err
			}
			conflict := adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Conflict}
			result.Conflicts = append(result.Conflicts, conflict)
			return result, fmt.Errorf("%w: secret %s", adapter.ErrConflict, row.EffectiveName)
		}
		if err := journal.Gate(ctx, effect); err != nil {
			return result, err
		}
		if err := m.verifyDestination(ctx, req.Target); err != nil {
			return result, err
		}
		if err := journal.Gate(ctx, effect); err != nil {
			return result, err
		}
		if err := journal.Prepare(ctx, effect, state); err != nil {
			return result, err
		}
		if gateErr := journal.Gate(ctx, effect); gateErr != nil {
			if finishErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: "failure", State: state}); finishErr != nil {
				return result, finishErr
			}
			return result, gateErr
		}
		err := m.write(ctx, req.Target.Destination, row, state)
		absenceProven := row.Surface == adapter.Variable && (state == adapter.Owned || state == adapter.Dispatched) && IsNotFound(err)
		if err != nil {
			if row.Surface == adapter.Variable && (state == adapter.Reserved || !claimed) && IsConflict(err) {
				if finishErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: "failure", Conflict: true}); finishErr != nil {
					return result, finishErr
				}
				conflict := adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Conflict}
				result.Conflicts = append(result.Conflicts, conflict)
				return result, fmt.Errorf("%w: variable %s", adapter.ErrConflict, row.EffectiveName)
			}
			outcome := "unknown"
			var response *ResponseError
			if errors.As(err, &response) && response.Status >= 400 && response.Status < 500 {
				outcome = "failure"
			}
			finalState := adapter.Dispatched
			if outcome == "failure" {
				if state == adapter.Reserved || absenceProven {
					finalState = ""
				} else {
					finalState = state
				}
			}
			if completeErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: outcome, State: finalState}); completeErr != nil {
				return result, completeErr
			}
			result.Failed = append(result.Failed, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: effect.Disposition})
			if outcome == "unknown" {
				return result, fmt.Errorf("%w: %s %s", adapter.ErrIndeterminate, row.Surface, row.EffectiveName)
			}
			return result, err
		}
		if err := journal.Finish(ctx, effect, adapter.Completion{Outcome: "success", State: adapter.Owned}); err != nil {
			return result, err
		}
		ledger[key] = adapter.Owned
		result.Changes = append(result.Changes, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: effect.Disposition})
	}

	desiredSet := make(map[string]bool, len(desiredRows))
	for _, row := range desiredRows {
		desiredSet[ledgerKey(row.Surface, row.EffectiveName)] = true
	}
	var reservations, prunes []adapter.LedgerEntry
	for key, state := range ledger {
		if desiredSet[key] {
			continue
		}
		surface, name := splitLedgerKey(key)
		row := adapter.LedgerEntry{Surface: surface, EffectiveName: name, State: state}
		if state == adapter.Reserved {
			reservations = append(reservations, row)
			continue
		}
		prunes = append(prunes, row)
	}
	slices.SortFunc(reservations, func(a, b adapter.LedgerEntry) int {
		if a.Surface != b.Surface {
			return strings.Compare(string(a.Surface), string(b.Surface))
		}
		return strings.Compare(a.EffectiveName, b.EffectiveName)
	})
	for _, row := range reservations {
		effect := adapter.Effect{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Delete}
		if err := journal.Gate(ctx, effect); err != nil {
			return result, err
		}
		if err := journal.ReleaseReservation(ctx, effect); err != nil {
			return result, err
		}
		result.Changes = append(result.Changes, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Delete})
	}
	slices.SortFunc(prunes, func(a, b adapter.LedgerEntry) int {
		aSentinel := strings.HasSuffix(a.EffectiveName, adapter.SentinelName)
		bSentinel := strings.HasSuffix(b.EffectiveName, adapter.SentinelName)
		if aSentinel != bSentinel {
			if aSentinel {
				return 1
			}
			return -1
		}
		if a.Surface != b.Surface {
			return strings.Compare(string(a.Surface), string(b.Surface))
		}
		return strings.Compare(a.EffectiveName, b.EffectiveName)
	})
	for _, row := range prunes {
		effect := adapter.Effect{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Delete}
		if err := journal.Gate(ctx, effect); err != nil {
			return result, err
		}
		if err := m.verifyDestination(ctx, req.Target); err != nil {
			return result, err
		}
		if err := journal.Gate(ctx, effect); err != nil {
			return result, err
		}
		if err := journal.Prepare(ctx, effect, row.State); err != nil {
			return result, err
		}
		if gateErr := journal.Gate(ctx, effect); gateErr != nil {
			if finishErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: "failure", State: row.State}); finishErr != nil {
				return result, finishErr
			}
			return result, gateErr
		}
		err := m.delete(ctx, req.Target.Destination, row.Surface, row.EffectiveName)
		if err != nil && !IsNotFound(err) {
			outcome := "unknown"
			var response *ResponseError
			if errors.As(err, &response) && response.Status >= 400 && response.Status < 500 {
				outcome = "failure"
			}
			if finishErr := journal.Finish(ctx, effect, adapter.Completion{Outcome: outcome, State: row.State}); finishErr != nil {
				return result, finishErr
			}
			result.Failed = append(result.Failed, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Delete})
			return result, err
		}
		if err := journal.Finish(ctx, effect, adapter.Completion{Outcome: "success", State: adapter.Released}); err != nil {
			return result, err
		}
		result.Changes = append(result.Changes, adapter.Change{Surface: row.Surface, EffectiveName: row.EffectiveName, Disposition: adapter.Delete})
	}
	return result, nil
}

func (m *Module) verifyDestination(ctx context.Context, target adapter.Target) error {
	id, err := m.API.ResolveDestination(ctx, target.Destination)
	if err != nil {
		return err
	}
	if id != target.Destination.NumericID {
		return fmt.Errorf("%w: configured %d, resolved %d", adapter.ErrDestinationID, target.Destination.NumericID, id)
	}
	return nil
}

func (m *Module) write(ctx context.Context, destination adapter.Destination, row desired, prior adapter.LedgerState) error {
	if row.Surface == adapter.Secret {
		return m.API.PutSecret(ctx, destination, row.EffectiveName, row.Value)
	}
	if prior == adapter.Dispatched || prior == adapter.Owned {
		return m.API.UpdateVariable(ctx, destination, row.EffectiveName, row.Value)
	}
	return m.API.CreateVariable(ctx, destination, row.EffectiveName, row.Value)
}

func (m *Module) delete(ctx context.Context, destination adapter.Destination, surface adapter.Surface, name string) error {
	if surface == adapter.Secret {
		return m.API.DeleteSecret(ctx, destination, name)
	}
	return m.API.DeleteVariable(ctx, destination, name)
}

func set(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[strings.ToUpper(value)] = true
	}
	return out
}
func ledgerKey(surface adapter.Surface, name string) string {
	return string(surface) + "\x00" + strings.ToUpper(name)
}
func splitLedgerKey(key string) (adapter.Surface, string) {
	parts := strings.SplitN(key, "\x00", 2)
	return adapter.Surface(parts[0]), parts[1]
}
func ledgerMap(rows []adapter.LedgerEntry) map[string]adapter.LedgerState {
	out := make(map[string]adapter.LedgerState, len(rows))
	for _, row := range rows {
		out[ledgerKey(row.Surface, row.EffectiveName)] = row.State
	}
	return out
}
func sortChanges(changes []adapter.Change) {
	slices.SortFunc(changes, func(a, b adapter.Change) int {
		if a.Surface != b.Surface {
			return strings.Compare(string(a.Surface), string(b.Surface))
		}
		return strings.Compare(a.EffectiveName, b.EffectiveName)
	})
}
