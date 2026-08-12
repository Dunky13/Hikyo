package domain

import (
	"errors"
	"sort"
)

// Role templates, machine principal classes and grant origins — the three
// closed tables the permission ADR fixes around the grant triple (#55).
//
// None of them is ever consulted by authorize(): authority is the bare
// (principal, capability, scope) triple and nothing else. A template is an
// administration affordance that expands AT GRANT TIME into independent
// rows; a machine class is a refusal rule the grant API applies before the
// write; an origin is bookkeeping that decides when a row is released.

// Template names one role template from the closed v1 set.
type Template string

const (
	TemplateViewer     Template = "viewer"
	TemplateEditor     Template = "editor"
	TemplatePublisher  Template = "publisher"
	TemplateRevealer   Template = "revealer"
	TemplateHistorian  Template = "historian"
	TemplateMaintainer Template = "maintainer"
	TemplateAdmin      Template = "admin"
	TemplateOperator   Template = "operator"
)

// templateSpec is one row of the ADR's template table.
type templateSpec struct {
	// applicable is the set of scope levels the template may be applied at.
	applicable map[Level]bool
	// creates is the capability list the template expands into at every
	// applicable level.
	creates []Capability
	// orgOnly is the extra capability list applied only at org scope — the
	// `admin` template's `manage-projects` row, and nothing else.
	orgOnly []Capability
}

var tenantLevels = map[Level]bool{LevelOrg: true, LevelProject: true, LevelEnv: true}

var orgProject = map[Level]bool{LevelOrg: true, LevelProject: true}

var instanceOnly = map[Level]bool{LevelNone: true}

// templates is the permission ADR's closed template table, verbatim.
// `maintainer` is spelled as `publisher` plus three; `admin` as `maintainer`
// plus four, with `manage-projects` at org scope only. `operator` seeds the
// operator set plus manage-members and deliberately seeds NEITHER `reveal`
// nor `reveal-history` — crypto custody is not data reading.
var templates = map[Template]templateSpec{
	TemplateViewer: {applicable: tenantLevels, creates: []Capability{CapRead}},
	TemplateEditor: {applicable: tenantLevels, creates: []Capability{CapRead, CapEdit}},
	TemplatePublisher: {
		applicable: tenantLevels,
		creates:    []Capability{CapRead, CapEdit, CapPublish, CapPin},
	},
	TemplateRevealer:  {applicable: tenantLevels, creates: []Capability{CapReveal}},
	TemplateHistorian: {applicable: tenantLevels, creates: []Capability{CapRevealHistory}},
	TemplateMaintainer: {
		applicable: orgProject,
		creates: []Capability{
			CapRead, CapEdit, CapPublish, CapPin,
			CapDefinitionsEdit, CapManageIdentities, CapManageAdapters,
		},
	},
	TemplateAdmin: {
		applicable: orgProject,
		creates: []Capability{
			CapRead, CapEdit, CapPublish, CapPin,
			CapDefinitionsEdit, CapManageIdentities, CapManageAdapters,
			CapProjectSettings, CapManageMembers,
			// Seeded as separate, separately revocable rows — the ADR's
			// amendment to the revision ADR. An installation may strip either
			// from one administrator without dismantling their authority.
			CapReveal, CapRevealHistory,
		},
		orgOnly: []Capability{CapManageProjects},
	},
	TemplateOperator: {
		applicable: instanceOnly,
		creates:    append(append([]Capability{}, OperatorSet...), CapManageMembers),
	},
}

// Templates returns the closed template name set, sorted.
func Templates() []Template {
	out := make([]Template, 0, len(templates))
	for t := range templates {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ErrNoSuchTemplate names an unknown template; ErrTemplateScope names a
// template applied at a level its ADR row does not admit.
var (
	ErrNoSuchTemplate = errors.New("no such role template")
	ErrTemplateScope  = errors.New("this role template does not apply at this scope")
)

// ExpandTemplate returns the capability list a template creates at the given
// level, in a stable order. It refuses an unknown template and a level the
// template's ADR row does not admit — the expansion is the only place the
// template name exists, so a wrong level must fail here rather than silently
// seed a shorter list.
func ExpandTemplate(t Template, at Level) ([]Capability, error) {
	spec, ok := templates[t]
	if !ok {
		return nil, ErrNoSuchTemplate
	}
	if !spec.applicable[at] {
		return nil, ErrTemplateScope
	}
	out := append([]Capability{}, spec.creates...)
	if at == LevelOrg {
		out = append(out, spec.orgOnly...)
	}
	return out, nil
}

// PrincipalClass discriminates a principal for the normative machine
// allowlists. Humans are one class; machines carry the credential class the
// machine-identities ADR fixes.
type PrincipalClass string

const (
	ClassHuman PrincipalClass = "human"
	// ClassWorkload — read-only delivery credentials.
	ClassWorkload PrincipalClass = "workload"
	// ClassAutomation — CI `apply` credentials.
	ClassAutomation PrincipalClass = "automation"
	// ClassProvisioning — the SCIM provisioning connection (#73).
	ClassProvisioning PrincipalClass = "provisioning-connection"
	// ClassInstanceConn — the instance-connection principal of the
	// multi-instance directory tier (#71).
	ClassInstanceConn PrincipalClass = "instance-connection"
)

// machineAllowlists is NORMATIVE, not convention (permission ADR § Machine
// principals): the grant API refuses a capability outside its class's list.
//
// `reveal` and `reveal-history` are absent from the workload and automation
// lists on purpose. The ADR admits them ONLY under the source-of-truth ADR's
// explicit per-project operator opt-in (reveal) and only where a pin requires
// it (reveal-history). Neither mechanism exists yet, so the list is the
// fail-closed subset: a machine reveal grant is refused by name until #17/#58
// ship the opt-in. Widening the list without the opt-in would hand every
// automation credential a standing decryption capability, which is exactly
// what the ADR says must be a deliberate per-project act.
var machineAllowlists = map[PrincipalClass]map[Capability]bool{
	ClassWorkload: {CapRead: true},
	ClassAutomation: {
		CapRead: true, CapEdit: true, CapPublish: true, CapDefinitionsEdit: true,
	},
	// The scim-provisioning amendment's single row: system-created with the
	// binding, and refused through the grant API — so the allowlist admits
	// the atom while the API's human/machine gate still refuses a manual
	// grant of it (see ErrSystemCreatedOnly).
	ClassProvisioning: {CapSCIMProvision: true},
	// The multi-instance amendment's single named per-class exception to "no
	// machine principal holds any instance capability".
	ClassInstanceConn: {CapInstanceDirector: true},
}

// MachineClasses returns the closed machine class set, sorted.
func MachineClasses() []PrincipalClass {
	out := make([]PrincipalClass, 0, len(machineAllowlists))
	for c := range machineAllowlists {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsMachineClass reports whether c is one of the machine classes.
func IsMachineClass(c PrincipalClass) bool { _, ok := machineAllowlists[c]; return ok }

// MachineMayHold reports whether a principal of machine class c may hold
// capability cap. Unknown class = false, fail-closed.
func MachineMayHold(c PrincipalClass, cap Capability) bool {
	return machineAllowlists[c][cap]
}

// machineDepths is the SHALLOWEST scope level each machine class may be
// granted at. The ADR does not only bound WHICH capabilities a machine may
// hold, it bounds WHERE: a workload credential is "`read` at explicit
// (project, environment) scope", automation is "at one project's scope".
//
// A capability allowlist alone leaves the hole open — `read` at org scope is
// on the workload list and reaches every environment in the org, which is the
// opposite of "explicit (project, environment)". The depth rule closes it.
//
// The provisioning connection's `scim-provision` is an org-scope atom and the
// instance connection's `instance-directory` is instance-scope; neither is
// grantable through this API at all (system-created with its binding, #73/#71),
// so their depth entry is the level their own atom sits at and the refusal
// that matters for them happens earlier.
var machineDepths = map[PrincipalClass]Level{
	ClassWorkload:     LevelEnv,
	ClassAutomation:   LevelProject,
	ClassProvisioning: LevelOrg,
	ClassInstanceConn: LevelNone,
}

// MachineScopeDepth returns the shallowest level a machine class may be
// granted at; a grant shallower than it is refused. Unknown class = LevelEnv
// with ok=false, fail-closed.
func MachineScopeDepth(c PrincipalClass) (Level, bool) {
	l, ok := machineDepths[c]
	return l, ok
}

// OriginKind is one kind of grant origin (scim-provisioning amendment (a)):
// a grant row exists while at least one origin holds it, and is revoked —
// with the session-generation advance — when its last origin is released.
type OriginKind string

const (
	// OriginManual is the only mintable kind today: an ordinary human grant,
	// carrying the granting principal.
	OriginManual OriginKind = "manual"
	// OriginBreakGlass is the local-host recovery grant. It is NOT manual:
	// manual(granted_by) names a granting principal whose own authority was
	// evaluated, and break-glass is by the ADR's own words "the only
	// authorization path in the system not evaluated against a grant" — it
	// has no granting principal to name. See the handoff for the reading.
	OriginBreakGlass OriginKind = "break-glass"
	// OriginSCIM, OriginStructural and OriginLockoutRetention arrive with
	// #73; declared here so the closed enumeration is the ADR's, not a
	// subset that a later ticket has to widen silently.
	OriginSCIM             OriginKind = "scim"
	OriginStructural       OriginKind = "structural"
	OriginLockoutRetention OriginKind = "lockout-retention"
)

// mintableOrigins is the subset the grant surface may write today. The rest
// are refused at the writer, so a #73-shaped origin cannot be forged through
// the #55 API before #73 defines what holds it.
var mintableOrigins = map[OriginKind]bool{
	OriginManual:     true,
	OriginBreakGlass: true,
}

// OriginKinds returns the closed origin enumeration, sorted.
func OriginKinds() []OriginKind {
	out := []OriginKind{
		OriginManual, OriginBreakGlass, OriginSCIM, OriginStructural, OriginLockoutRetention,
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsMintableOrigin reports whether the grant API may write this origin kind.
func IsMintableOrigin(k OriginKind) bool { return mintableOrigins[k] }
