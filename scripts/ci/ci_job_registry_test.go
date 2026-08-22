package ci_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

type registry struct {
	Version     int                 `json:"version"`
	Workflow    string              `json:"workflow"`
	PathClasses map[string][]string `json:"path_classes"`
	Jobs        map[string]jobRule  `json:"jobs"`
}

type jobRule struct {
	RequiredGate string   `json:"required_gate"`
	PlanJobs     []string `json:"plan_jobs,omitempty"`
}

type workflow struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Needs yaml.Node `yaml:"needs"`
	If    string    `yaml:"if"`
}

var planReference = regexp.MustCompile(`fromJSON\(needs\.changes\.outputs\.plan\)(?:\['([^']+)'\]|\.([A-Za-z0-9_-]+))`)

func TestCIJobRegistryMatchesWorkflow(t *testing.T) {
	repoRoot := repositoryRoot(t)
	registryPath := filepath.Join(repoRoot, "scripts", "ci", "ci-job-registry.json")

	registryData, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}

	var gotRegistry registry
	if err := json.Unmarshal(registryData, &gotRegistry); err != nil {
		t.Fatalf("parse registry: %v", err)
	}

	workflowData, err := os.ReadFile(filepath.Join(repoRoot, gotRegistry.Workflow))
	if err != nil {
		t.Fatal(err)
	}

	if err := validateRegistry(gotRegistry, workflowData); err != nil {
		t.Fatal(err)
	}
}

func TestCIJobRegistryRejectsWorkflowDrift(t *testing.T) {
	baseRegistry := registry{
		Version:     2,
		Workflow:    ".github/workflows/ci.yml",
		PathClasses: map[string][]string{"full": {"test"}},
		Jobs: map[string]jobRule{
			"changes":     {RequiredGate: "always"},
			"test":        {RequiredGate: "planned", PlanJobs: []string{"test"}},
			"ci-required": {RequiredGate: "aggregate"},
		},
	}
	baseWorkflow := []byte(`jobs:
  changes:
    runs-on: ubuntu-latest
  test:
    needs: changes
    if: ${{ fromJSON(needs.changes.outputs.plan).test }}
    runs-on: ubuntu-latest
  ci-required:
    if: always()
    needs: [changes, test]
    runs-on: ubuntu-latest
`)
	if err := validateRegistry(baseRegistry, baseWorkflow); err != nil {
		t.Fatalf("valid base fixture was rejected: %v", err)
	}

	tests := map[string]struct {
		mutateRegistry func(registry) registry
		workflow       []byte
	}{
		"added workflow job": {
			workflow: []byte(string(baseWorkflow) + "  future-job:\n    runs-on: ubuntu-latest\n"),
		},
		"removed workflow job": {
			workflow: []byte(`jobs:
  changes:
    runs-on: ubuntu-latest
  ci-required:
    needs: [changes]
    runs-on: ubuntu-latest
`),
		},
		"renamed workflow job": {
			workflow: []byte(`jobs:
  changes:
    runs-on: ubuntu-latest
  tests:
    needs: changes
    runs-on: ubuntu-latest
  ci-required:
    needs: [changes, tests]
    runs-on: ubuntu-latest
`),
		},
		"unregistered gate job": {
			mutateRegistry: func(input registry) registry {
				delete(input.Jobs, "test")
				return input
			},
			workflow: baseWorkflow,
		},
		"aggregate without always": {
			workflow: []byte(`jobs:
  changes:
    runs-on: ubuntu-latest
  test:
    needs: changes
    if: ${{ fromJSON(needs.changes.outputs.plan).test }}
    runs-on: ubuntu-latest
  ci-required:
    needs: [changes, test]
    runs-on: ubuntu-latest
`),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gotRegistry := cloneRegistry(t, baseRegistry)
			if test.mutateRegistry != nil {
				gotRegistry = test.mutateRegistry(gotRegistry)
			}
			if err := validateRegistry(gotRegistry, test.workflow); err == nil {
				t.Fatal("workflow drift was accepted")
			}
		})
	}
}

func validateRegistry(gotRegistry registry, workflowData []byte) error {
	if gotRegistry.Version != 2 {
		return fmt.Errorf("registry version: got %d, want 2", gotRegistry.Version)
	}
	if gotRegistry.Workflow == "" || filepath.IsAbs(gotRegistry.Workflow) {
		return errors.New("registry workflow must be a repository-relative path")
	}

	var gotWorkflow workflow
	if err := yaml.Unmarshal(workflowData, &gotWorkflow); err != nil {
		return fmt.Errorf("parse workflow YAML: %w", err)
	}

	registryJobs := sortedKeys(gotRegistry.Jobs)
	workflowJobs := sortedKeys(gotWorkflow.Jobs)
	if !reflect.DeepEqual(registryJobs, workflowJobs) {
		return fmt.Errorf("registry/workflow job mismatch: registry=%v workflow=%v", registryJobs, workflowJobs)
	}

	fullJobs, ok := gotRegistry.PathClasses["full"]
	if !ok || len(fullJobs) == 0 {
		return errors.New("registry full path class is empty")
	}
	selectable := make(map[string]bool, len(fullJobs))
	for class, jobs := range gotRegistry.PathClasses {
		if len(jobs) == 0 {
			return fmt.Errorf("path class %q is empty", class)
		}
		for _, job := range jobs {
			rule, exists := gotRegistry.Jobs[job]
			if !exists {
				return fmt.Errorf("path class %q references unknown job %q", class, job)
			}
			if rule.RequiredGate != "planned" || !reflect.DeepEqual(rule.PlanJobs, []string{job}) {
				return fmt.Errorf("path class %q job %q is not directly planned", class, job)
			}
			if class == "full" {
				selectable[job] = true
			}
		}
	}

	for job, rule := range gotRegistry.Jobs {
		condition := gotWorkflow.Jobs[job].If
		switch rule.RequiredGate {
		case "always":
			if len(rule.PlanJobs) != 0 {
				return fmt.Errorf("job %q gate %q cannot name plan jobs", job, rule.RequiredGate)
			}
			if condition != "" {
				return fmt.Errorf("always job %q has condition %q", job, condition)
			}
		case "pull-request":
			if len(rule.PlanJobs) != 0 {
				return fmt.Errorf("job %q gate %q cannot name plan jobs", job, rule.RequiredGate)
			}
			if condition != "github.event_name != 'push'" {
				return fmt.Errorf("pull-request job %q has condition %q", job, condition)
			}
		case "aggregate":
			if len(rule.PlanJobs) != 0 {
				return fmt.Errorf("job %q gate %q cannot name plan jobs", job, rule.RequiredGate)
			}
			if condition != "always()" {
				return fmt.Errorf("aggregate job %q has condition %q", job, condition)
			}
		case "planned":
			if len(rule.PlanJobs) == 0 {
				return fmt.Errorf("planned job %q has no plan jobs", job)
			}
			for _, planJob := range rule.PlanJobs {
				if !selectable[planJob] {
					return fmt.Errorf("job %q references non-selectable plan job %q", job, planJob)
				}
			}
		case "indirect":
			if len(rule.PlanJobs) == 0 {
				return fmt.Errorf("indirect job %q has no plan jobs", job)
			}
			for _, planJob := range rule.PlanJobs {
				if !selectable[planJob] {
					return fmt.Errorf("job %q references non-selectable plan job %q", job, planJob)
				}
			}
		default:
			return fmt.Errorf("job %q has unknown required gate %q", job, rule.RequiredGate)
		}

		planJobs := workflowPlanJobs(condition)
		wantPlanJobs := make([]string, len(rule.PlanJobs))
		copy(wantPlanJobs, rule.PlanJobs)
		sort.Strings(wantPlanJobs)
		if !reflect.DeepEqual(planJobs, wantPlanJobs) {
			return fmt.Errorf("job %q plan condition mismatch: workflow=%v registry=%v", job, planJobs, wantPlanJobs)
		}
	}

	directNeeds, err := workflowNeeds(gotWorkflow.Jobs["ci-required"].Needs)
	if err != nil {
		return err
	}
	wantNeeds := make([]string, 0, len(gotRegistry.Jobs))
	for job, rule := range gotRegistry.Jobs {
		if rule.RequiredGate == "always" || rule.RequiredGate == "pull-request" || rule.RequiredGate == "planned" {
			wantNeeds = append(wantNeeds, job)
		}
	}
	sort.Strings(directNeeds)
	sort.Strings(wantNeeds)
	if !reflect.DeepEqual(directNeeds, wantNeeds) {
		return fmt.Errorf("ci-required needs mismatch: workflow=%v registry=%v", directNeeds, wantNeeds)
	}

	return nil
}

func workflowPlanJobs(condition string) []string {
	matches := planReference.FindAllStringSubmatch(condition, -1)
	jobs := make([]string, 0, len(matches))
	for _, match := range matches {
		job := match[1]
		if job == "" {
			job = match[2]
		}
		jobs = append(jobs, job)
	}
	sort.Strings(jobs)
	return jobs
}

func workflowNeeds(node yaml.Node) ([]string, error) {
	switch node.Kind {
	case yaml.SequenceNode:
		needs := make([]string, 0, len(node.Content))
		for _, child := range node.Content {
			needs = append(needs, child.Value)
		}
		return needs, nil
	case yaml.ScalarNode:
		if node.Value == "" {
			return nil, errors.New("ci-required has no needs")
		}
		return []string{node.Value}, nil
	default:
		return nil, fmt.Errorf("ci-required needs has unsupported YAML kind %d", node.Kind)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func cloneRegistry(t *testing.T, input registry) registry {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var cloned registry
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func sortedKeys[Value any](input map[string]Value) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
