package domain

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

type capabilityFixture struct {
	Capabilities []capabilityFixtureAtom     `json:"capabilities"`
	Templates    []capabilityFixtureTemplate `json:"templates"`
}

type capabilityFixtureAtom struct {
	ID      Capability `json:"id"`
	Deepest string     `json:"deepest"`
}

type capabilityFixtureTemplate struct {
	ID           Template                `json:"id"`
	Levels       []string                `json:"levels"`
	SeedsByLevel map[string][]Capability `json:"seeds_by_level"`
}

func fixtureLevel(level Level) string {
	switch level {
	case LevelNone:
		return "instance"
	case LevelOrg:
		return "org"
	case LevelProject:
		return "project"
	case LevelEnv:
		return "environment"
	default:
		panic(fmt.Sprintf("unknown capability level %d", level))
	}
}

func currentCapabilityFixture(t *testing.T) capabilityFixture {
	t.Helper()
	current := capabilityFixture{}
	for _, capability := range Capabilities() {
		level, ok := DeepestLevel(capability)
		if !ok {
			t.Fatalf("Capabilities returned %q without a deepest level", capability)
		}
		current.Capabilities = append(current.Capabilities, capabilityFixtureAtom{
			ID: capability, Deepest: fixtureLevel(level),
		})
	}
	levels := []Level{LevelNone, LevelOrg, LevelProject, LevelEnv}
	for _, template := range Templates() {
		row := capabilityFixtureTemplate{ID: template, SeedsByLevel: map[string][]Capability{}}
		for _, level := range levels {
			seeds, err := ExpandTemplate(template, level)
			if err == ErrTemplateScope {
				continue
			}
			if err != nil {
				t.Fatalf("ExpandTemplate(%q, %s): %v", template, fixtureLevel(level), err)
			}
			name := fixtureLevel(level)
			row.Levels = append(row.Levels, name)
			row.SeedsByLevel[name] = seeds
		}
		current.Templates = append(current.Templates, row)
	}
	return current
}

func TestCapabilityRegistryMatchesSharedFixture(t *testing.T) {
	wantBytes, err := os.ReadFile("testdata/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var want capabilityFixture
	if err := json.Unmarshal(wantBytes, &want); err != nil {
		t.Fatalf("parse capability fixture: %v", err)
	}
	got := currentCapabilityFixture(t)
	if reflect.DeepEqual(got, want) {
		return
	}
	current, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal current capability registry: %v", err)
	}
	t.Fatalf("internal/domain capability registry drifted; paste this JSON into testdata/capabilities.json after reviewing the contract change:\n%s", current)
}
