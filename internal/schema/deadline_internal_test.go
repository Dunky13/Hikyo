package schema

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The wall-clock budget's mechanism, tested where it is deterministic.
//
// The point of runWithDeadline is that the CALLER stops waiting: the library
// call is synchronous and cannot be cancelled, so the only enforceable half of
// the budget is the wait. Driving that with a real slow schema would be a race
// against the machine; driving it with a channel the test controls is not.

func TestRunWithDeadlineAbandonsAnOverrun(t *testing.T) {
	block := make(chan struct{})
	defer close(block) // let the abandoned goroutine finish before the test ends

	start := time.Now()
	err, outcome := runWithDeadline(func() error {
		<-block
		return nil
	}, time.Millisecond)
	if outcome != evalOverran {
		t.Fatalf("an evaluation that never returned was reported as %v (err %v)", outcome, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the caller waited %s past a 1ms deadline — the wait is not bounded", elapsed)
	}
}

func TestRunWithDeadlineReturnsTheResultWhenItFits(t *testing.T) {
	want := errors.New("verdict")
	err, outcome := runWithDeadline(func() error { return want }, time.Minute)
	if outcome != evalCompleted || !errors.Is(err, want) {
		t.Fatalf("runWithDeadline = (%v, %v), want the evaluation's own error", err, outcome)
	}
}

// drainEvaluationSlots waits until every slot is free again. The bound is
// process-wide by design, so a test that saturates it must hand it back before
// the next one runs — and "hand it back" means the abandoned goroutines have
// actually exited, not merely been unblocked.
func drainEvaluationSlots(t *testing.T) {
	t.Helper()
	limit := time.Now().Add(10 * time.Second)
	held := 0
	for held < MaxConcurrentJSONSchemaEvaluations {
		select {
		case evaluationSlots <- struct{}{}:
			held++
		default:
			if time.Now().After(limit) {
				t.Fatal("evaluation slots were never released")
			}
			time.Sleep(time.Millisecond)
		}
	}
	for range held {
		<-evaluationSlots
	}
}

// saturateEvaluationSlots fills every slot with an abandoned evaluation and
// returns the func that lets them finish.
func saturateEvaluationSlots(t *testing.T) func() {
	t.Helper()
	block := make(chan struct{})
	released := false
	release := func() {
		if !released {
			released = true
			close(block)
		}
		drainEvaluationSlots(t)
	}
	for i := range MaxConcurrentJSONSchemaEvaluations {
		if _, outcome := runWithDeadline(func() error { <-block; return nil }, time.Millisecond); outcome != evalOverran {
			release()
			t.Fatalf("saturating evaluation %d ended as %v, want an overrun", i, outcome)
		}
	}
	return release
}

// The concurrency bound covers ABANDONED work. Its whole reason to exist is
// that the deadline gives up on the wait and not on the evaluation, so a slot
// must stay held until the evaluation itself finishes — otherwise overruns
// accumulate without limit and the deadline multiplies the damage it was meant
// to bound.
func TestEvaluationConcurrencyIsBounded(t *testing.T) {
	release := saturateEvaluationSlots(t)
	// Abandoned work still counts, and the refusal is IMMEDIATE. The deadline
	// handed in is a minute, so a bounded WAIT for a slot would take a minute
	// to answer; try-acquire answers now. Every slot is provably still held
	// while this runs — nothing has released `block` yet.
	start := time.Now()
	_, outcome := runWithDeadline(func() error { return nil }, time.Minute)
	waited := time.Since(start)
	if outcome != evalRefused {
		release()
		t.Fatalf("an evaluation was admitted past the bound of %d: %v",
			MaxConcurrentJSONSchemaEvaluations, outcome)
	}
	if waited > time.Second {
		release()
		t.Fatalf("admission queued for %s against a one-minute deadline — it must not wait at all", waited)
	}
	// A slot frees only when the evaluation FINISHES.
	release()
	if _, outcome := runWithDeadline(func() error { return nil }, time.Second); outcome != evalCompleted {
		t.Fatalf("slots were never released after the evaluations completed: %v", outcome)
	}
	drainEvaluationSlots(t)
}

// The production path reports a refused admission LOUD, and as its own budget
// rather than as a deadline: the two failures have different remedies.
func TestJSONSchemaEvaluationFailsLoudWhenNotAdmitted(t *testing.T) {
	release := saturateEvaluationSlots(t)
	defer release()

	c, err := compileWithoutCompatibilityCheckForTest(Config, Declaration{Rule: &Rule{Type: TypeJSON, JSONSchema: []byte(`{"type":"object"}`)}})
	if err != nil {
		t.Fatal(err)
	}
	restore := evaluationDeadline
	evaluationDeadline = time.Millisecond
	defer func() { evaluationDeadline = restore }()

	v := c.Validate(`{}`)
	if v.Valid {
		t.Fatal("an evaluation that was never admitted was reported valid")
	}
	if v.Errors[0].Keyword != "budget.concurrency" {
		t.Fatalf("a refused admission reported as %q", v.Errors[0].Keyword)
	}
}

// The production path fails LOUD on a deadline breach — never "assume valid".
// The deadline is injected rather than waited out, so the assertion is about
// the branch and not about how fast this machine is.
func TestJSONSchemaEvaluationFailsLoudOnTheDeadline(t *testing.T) {
	drainEvaluationSlots(t) // the bound is shared; start from a clean one
	restore := evaluationDeadline
	evaluationDeadline = 0 // every evaluation overruns
	defer func() { evaluationDeadline = restore }()

	c, err := compileWithoutCompatibilityCheckForTest(Config, Declaration{Rule: &Rule{
		Type:       TypeJSON,
		JSONSchema: []byte(`{"type":"object"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	v := c.Validate(`{}`)
	if v.Valid {
		t.Fatal("an evaluation past its deadline was reported valid")
	}
	if v.Errors[0].Keyword != "budget.deadline" {
		t.Fatalf("deadline breach reported as %q", v.Errors[0].Keyword)
	}
}

// The step cap is a declaration-time product, and the subschema bound is
// derived from it rather than invented beside it. Two independently chosen
// numbers is how a bound stops bounding the thing it names.
func TestSubschemaBoundIsDerivedFromTheWorkBudget(t *testing.T) {
	if MaxJSONSchemaSubschemas != MaxEvaluationWork/MaxValidatedInstanceBytes {
		t.Fatalf("the subschema bound (%d) is no longer the work budget (%d) divided by the instance bound (%d)",
			MaxJSONSchemaSubschemas, MaxEvaluationWork, MaxValidatedInstanceBytes)
	}
}

// The byte cap budgets the COMPLETE verdict document, envelope included.
// Measuring the failure list alone under-counts by the envelope's own bytes,
// so a verdict sized exactly to the cap would ship over it.
func TestEncodedSizeMeasuresTheWholeVerdict(t *testing.T) {
	failures := []Failure{{Alternative: -1, Keyword: "pattern", Message: "no"}}
	list, err := json.Marshal(failures)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := json.Marshal(Verdict{Errors: failures})
	if err != nil {
		t.Fatal(err)
	}
	if got := encodedSize(failures); got != len(whole) {
		t.Fatalf("encodedSize = %d, want the whole verdict's %d (the bare list is %d)",
			got, len(whole), len(list))
	}
}

// The step cap counts EVALUATION PATHS, not declared subschemas.
//
// `$ref` reuse expands: `allOf: [$ref X, $ref X]` evaluates X twice, and
// nesting that doubles per level. The chain below declares a handful of
// subschemas and expands to 2^12, which is exactly the shape that made the
// declared count an unsound bound — every structural limit reports it as small.
func doublingRefChain(levels int) string {
	var b strings.Builder
	b.WriteString(`{"$defs":{"l0":{"type":"string"}`)
	for i := 1; i <= levels; i++ {
		prev := "#/$defs/l" + strconv.Itoa(i-1)
		b.WriteString(`,"l` + strconv.Itoa(i) + `":{"allOf":[{"$ref":"` + prev + `"},{"$ref":"` + prev + `"}]}`)
	}
	b.WriteString(`},"$ref":"#/$defs/l` + strconv.Itoa(levels) + `"}`)
	return b.String()
}

func TestRefExpansionIsRefusedAgainstTheWorkBudget(t *testing.T) {
	doc := doublingRefChain(12)
	// The premise: structurally small. If this ever stopped being true the test
	// would be proving the ordinary subschema bound instead.
	if declared := strings.Count(doc, `"type"`) + strings.Count(doc, `"allOf"`); declared > MaxJSONSchemaSubschemas {
		t.Fatalf("the fixture is not structurally small (%d declared constructs)", declared)
	}
	_, err := compileWithoutCompatibilityCheckForTest(Config, Declaration{Rule: &Rule{Type: TypeJSON, JSONSchema: []byte(doc)}})
	if err == nil {
		t.Fatal("a $ref chain expanding to thousands of evaluation paths was accepted")
	}
	if !strings.Contains(err.Error(), "evaluation work budget") {
		t.Fatalf("the refusal does not name the work budget: %v", err)
	}
	if !strings.Contains(err.Error(), "evaluation paths") {
		t.Fatalf("the refusal does not name what expanded: %v", err)
	}
}

// Reuse that is NOT multiplicative stays legal: the same target referenced from
// sibling branches costs one evaluation per reference, which is what the count
// says and what the budget allows.
func TestLinearRefReuseStillCompiles(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"$defs":{"t":{"type":"string","minLength":1}},"type":"object","properties":{`)
	for i := range 32 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"p` + strconv.Itoa(i) + `":{"$ref":"#/$defs/t"}`)
	}
	b.WriteString(`}}`)
	c, err := compileWithoutCompatibilityCheckForTest(Config, Declaration{Rule: &Rule{Type: TypeJSON, JSONSchema: []byte(b.String())}})
	if err != nil {
		t.Fatalf("linear $ref reuse was refused: %v", err)
	}
	// And it still validates: the bound rejected nothing it should have kept.
	if v := c.Validate(`{"p0":"x"}`); !v.Valid {
		t.Fatalf("the compiled schema refuses a valid instance: %+v", v.Errors)
	}
	if v := c.Validate(`{"p0":""}`); v.Valid {
		t.Fatal("the referenced constraint was not applied")
	}
}

// expandedPaths saturates rather than computing an astronomically large number:
// the counter must not become the expensive part of the check.
func TestExpandedPathsSaturates(t *testing.T) {
	doc := doublingRefChain(60) // 2^60 if it were counted honestly
	var parsed any
	if err := strictJSON([]byte(doc), &parsed); err != nil {
		t.Fatal(err)
	}
	w := &profileWalk{nodes: map[string]bool{}, edges: map[string][]string{}}
	if err := w.schema(parsed, "", 1); err != nil {
		t.Fatal(err)
	}
	limit := MaxEvaluationWork / MaxValidatedInstanceBytes
	if got := w.expandedPaths(limit); got != limit+1 {
		t.Fatalf("expandedPaths = %d, want the saturating %d", got, limit+1)
	}
}
