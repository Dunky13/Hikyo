package cli

import (
	"fmt"
	"strings"
)

// Context resolution (api-cli-surface ADR § Context model).
//
// A disclosure verb aimed at the wrong environment is a wrong-env plaintext
// export, so WHICH instance/org/project/env a command targets is a safety
// property — and which server receives a credential is a bigger one. Hence:
// explicit-first, per-dimension, first hit wins, and NO persistent active
// context. An earlier draft's `context use` was the sticky global this model
// exists to prohibit wearing a different name; one forgotten `use` before a
// disclosure verb is the export this design prevents.

// Dimension is one resolvable target dimension.
type Dimension string

const (
	DimInstance Dimension = "instance"
	DimOrg      Dimension = "org"
	DimProject  Dimension = "project"
	DimEnv      Dimension = "env"
)

// Source names where a dimension's value came from, so the disclosure echo
// can say which precedence level supplied each one.
type Source string

const (
	SourceFlag    Source = "flag"
	SourceEnv     Source = "environment"
	SourcePinFile Source = "pin file"
	SourceContext Source = "context"
	// SourceConfig is the hikyo-compose.yaml project file, which the compose
	// verbs fold into resolution AFTER the standard chain: it fills a dimension
	// the chain left unresolved and a disagreement with a resolved one is a hard
	// error naming both.
	SourceConfig Source = "hikyo-compose.yaml"
)

// Resolved is the assembled target with provenance.
type Resolved struct {
	Values  map[Dimension]string
	Sources map[Dimension]Source
	// PinFilePath is the pin file that contributed, if any — named in the
	// echo so an operator can see what directed them.
	PinFilePath string
	// ContextName is the named context that contributed, if any.
	ContextName string
}

// Get returns a dimension's value.
func (r Resolved) Get(d Dimension) string { return r.Values[d] }

// Require returns a dimension's value or a hard error naming what was missing
// and where the CLI looked. Ambiguity is never a default: no dimension is
// ever silently assumed.
func (r Resolved) Require(d Dimension) (string, error) {
	if v := r.Values[d]; v != "" {
		return v, nil
	}
	return "", failf(ExitUsage,
		"no %s resolved. Looked at, in order: --%s, HIKYO_%s, the %s pin file, and the named context (--context / HIKYO_CONTEXT)",
		d, d, strings.ToUpper(string(d)), PinFileName)
}

// Echo renders the fully resolved target for the disclosure echo. It goes to
// stderr, before acting, so the active target is visible exactly when it
// matters without polluting parseable stdout.
func (r Resolved) Echo() string {
	// Fixed order, outermost dimension first: the echo is read by a human
	// about to run a disclosure verb, and a target that renders in a
	// different order each time is one nobody checks.
	var parts []string
	for _, d := range []Dimension{DimInstance, DimOrg, DimProject, DimEnv} {
		if v := r.Values[d]; v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s (%s)", d, v, r.Sources[d]))
		}
	}
	return strings.Join(parts, " ")
}

// Flags carries the per-dimension flag values.
type Flags struct {
	Context  string
	Instance string
	Org      string
	Project  string
	Env      string
}

// Resolve runs the per-dimension chain: flags, then environment, then the
// project-dir pin file, then the named context. First hit wins PER DIMENSION,
// which is what makes `--env staging` against a pinned project legitimate:
// the override re-resolves within the same chain rather than replacing it.
func Resolve(st *State, env Env, flags Flags, workdir string) (Resolved, error) {
	out := Resolved{
		Values:  map[Dimension]string{},
		Sources: map[Dimension]Source{},
	}

	set := func(d Dimension, v string, src Source) {
		if v == "" || out.Values[d] != "" {
			return
		}
		out.Values[d] = v
		out.Sources[d] = src
	}

	// 1. Flags.
	set(DimInstance, flags.Instance, SourceFlag)
	set(DimOrg, flags.Org, SourceFlag)
	set(DimProject, flags.Project, SourceFlag)
	set(DimEnv, flags.Env, SourceFlag)

	// 2. Environment.
	set(DimInstance, env.Getenv("HIKYO_INSTANCE"), SourceEnv)
	set(DimOrg, env.Getenv("HIKYO_ORG"), SourceEnv)
	set(DimProject, env.Getenv("HIKYO_PROJECT"), SourceEnv)
	set(DimEnv, env.Getenv("HIKYO_ENV"), SourceEnv)

	// 3. Project-dir pin file.
	pin, pinPath, err := FindPinFile(workdir)
	if err != nil {
		return Resolved{}, err
	}
	if pinPath != "" {
		out.PinFilePath = pinPath
		set(DimInstance, pin.Instance, SourcePinFile)
		set(DimOrg, pin.Org, SourcePinFile)
		set(DimProject, pin.Project, SourcePinFile)
		set(DimEnv, pin.Env, SourcePinFile)
	}

	// 4. Named context — selected per invocation only. There is no stored
	// "current" context to forget.
	name := flags.Context
	if name == "" {
		name = env.Getenv("HIKYO_CONTEXT")
	}
	if name != "" {
		all, err := st.Contexts()
		if err != nil {
			return Resolved{}, err
		}
		c, ok := all[name]
		if !ok {
			return Resolved{}, failf(ExitNotFound, "no context named %q", name)
		}
		out.ContextName = name
		set(DimInstance, c.Instance, SourceContext)
		set(DimOrg, c.Org, SourceContext)
		set(DimProject, c.Project, SourceContext)
		set(DimEnv, c.Env, SourceContext)
	}

	return out, nil
}
