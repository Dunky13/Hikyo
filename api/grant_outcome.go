package api

import (
	"encoding/json"
	"fmt"
)

type grantOutcomeValue uint8

const (
	grantOutcomeInvalid grantOutcomeValue = iota
	grantOutcomeCreated
	grantOutcomeOriginAdded
	grantOutcomeUnchanged
)

// GrantOutcome is the closed result of a grant mutation. Its zero value is
// invalid so forgotten initialization fails loudly. Callers can obtain valid
// values only through the constructors below, and JSON decoding rejects every
// other wire string.
type GrantOutcome struct {
	value grantOutcomeValue
}

func GrantOutcomeCreated() GrantOutcome {
	return GrantOutcome{value: grantOutcomeCreated}
}

func GrantOutcomeOriginAdded() GrantOutcome {
	return GrantOutcome{value: grantOutcomeOriginAdded}
}

func GrantOutcomeUnchanged() GrantOutcome {
	return GrantOutcome{value: grantOutcomeUnchanged}
}

func (o GrantOutcome) Valid() bool {
	switch o.value {
	case grantOutcomeCreated, grantOutcomeOriginAdded, grantOutcomeUnchanged:
		return true
	default:
		return false
	}
}

func (o GrantOutcome) String() string {
	switch o.value {
	case grantOutcomeCreated:
		return "created"
	case grantOutcomeOriginAdded:
		return "origin_added"
	case grantOutcomeUnchanged:
		return "unchanged"
	default:
		panic(fmt.Sprintf("invalid grant outcome value %d", o.value))
	}
}

func ParseGrantOutcome(value string) (GrantOutcome, error) {
	switch value {
	case "created":
		return GrantOutcomeCreated(), nil
	case "origin_added":
		return GrantOutcomeOriginAdded(), nil
	case "unchanged":
		return GrantOutcomeUnchanged(), nil
	default:
		return GrantOutcome{}, fmt.Errorf("unknown grant outcome %q", value)
	}
}

func (o GrantOutcome) MarshalJSON() ([]byte, error) {
	if !o.Valid() {
		return nil, fmt.Errorf("invalid grant outcome value %d", o.value)
	}
	return json.Marshal(o.String())
}

func (o *GrantOutcome) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode grant outcome: %w", err)
	}
	parsed, err := ParseGrantOutcome(value)
	if err != nil {
		return err
	}
	*o = parsed
	return nil
}
