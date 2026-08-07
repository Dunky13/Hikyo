package lint

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Analyzer 5 (audit-model ADR CI invariant 8): the redaction guardrail
// around the sensitive types and the audit-content/ops-log boundary.
//
// Three rules:
//  1. Every pinned sensitive type implements the full redaction surface
//     (String, GoString, LogValue, MarshalText, MarshalJSON).
//  2. No formatting/marshaling/logging call takes a sensitive-typed
//     argument outside the type's owning package — the marshal interfaces
//     redact, but a third-party serializer or a deliberate field walk would
//     not, so the expression itself is banned at the boundary where it can
//     be seen.
//  3. Audit events are never mirrored to the ops log: no logging call
//     (log, log/slog) takes an audit-content-typed argument anywhere — the
//     ops log records audit-subsystem health, never event content.
//
// This is a guardrail with named evasion limits (reflection, in-package
// extraction, custom serializers), per the ADR — never a proof.

// SensitiveTypes pins the material-holding types; crypto's compile-time
// redactionSurface pin names the same set, and CheckRedactionSurfaces
// asserts this list actually carries the five methods.
var SensitiveTypes = map[string]bool{
	Module + "/internal/crypto.Keyring":        true,
	Module + "/internal/crypto.ProjectSealer":  true,
	Module + "/internal/crypto.InstanceSealer": true,
}

// sensitiveOwner may format its own types (deliberate extraction inside the
// owning package is a stated evasion limit, reviewed there).
var sensitiveOwner = Module + "/internal/crypto"

// auditContentTypes carry audit-event content. Logging one is mirroring the
// trail into a weaker store.
var auditContentTypes = map[string]bool{
	Module + "/internal/audit.Event":      true,
	Module + "/internal/audit.Payload":    true,
	Module + "/internal/audit.Row":        true,
	Module + "/internal/store.AuditEvent": true,
}

// formattingPackages are where rule-2 calls live; loggingPackages the
// stricter rule-3 set (fmt is allowed for audit content — wrapping an error
// with an event id is not mirroring the trail; log emission is).
var formattingPackages = map[string]bool{
	"fmt": true, "encoding/json": true, "log": true, "log/slog": true,
}

var loggingPackages = map[string]bool{
	"log": true, "log/slog": true,
}

var redactionSurfaceMethods = []string{
	"String", "GoString", "LogValue", "MarshalText", "MarshalJSON",
}

// CheckRedactionSurfaces asserts rule 1 against the loaded repo.
func CheckRedactionSurfaces(pkgs []*packages.Package) []string {
	var findings []string
	found := map[string]bool{}
	for _, p := range flatten(pkgs) {
		if p.Types == nil || p.Types.Path() != sensitiveOwner {
			continue
		}
		scope := p.Types.Scope()
		for name := range SensitiveTypes {
			short := strings.TrimPrefix(name, sensitiveOwner+".")
			obj := scope.Lookup(short)
			if obj == nil {
				continue
			}
			found[name] = true
			ms := types.NewMethodSet(types.NewPointer(obj.Type()))
			for _, m := range redactionSurfaceMethods {
				if ms.Lookup(nil, m) == nil {
					findings = append(findings, fmt.Sprintf(
						"redaction: sensitive type %s lacks %s() — the full formatting surface must redact (audit-model ADR CI invariant 8)",
						name, m))
				}
			}
		}
	}
	for name := range SensitiveTypes {
		if !found[name] {
			findings = append(findings, fmt.Sprintf("redaction: pinned sensitive type %s not found in %s", name, sensitiveOwner))
		}
	}
	return findings
}

// CheckSensitiveFormatting asserts rules 2 and 3 across the module, tests
// included.
func CheckSensitiveFormatting(pkgs []*packages.Package) []string {
	var findings []string
	for _, p := range flatten(pkgs) {
		if !strings.HasPrefix(p.PkgPath, Module+"/") && p.PkgPath != Module {
			continue
		}
		base := strings.TrimSuffix(p.PkgPath, ".test")
		if p.TypesInfo == nil {
			continue
		}
		exemptSensitive := base == sensitiveOwner
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				calleePkg := calleePackage(p.TypesInfo, call)
				if calleePkg == "" {
					return true
				}
				fmtCall := formattingPackages[calleePkg]
				logCall := loggingPackages[calleePkg]
				if !fmtCall && !logCall {
					return true
				}
				for _, arg := range call.Args {
					tv, ok := p.TypesInfo.Types[arg]
					if !ok || tv.Type == nil {
						continue
					}
					if !exemptSensitive {
						if name := mentionsNamed(tv.Type, SensitiveTypes, map[types.Type]bool{}); name != "" {
							findings = append(findings, fmt.Sprintf(
								"redaction: %s: %s passes sensitive type %s to %s — formatting/marshaling sensitive types outside their owning package is banned",
								p.Fset.Position(arg.Pos()), base, name, calleePkg))
						}
					}
					if logCall {
						if name := mentionsNamed(tv.Type, auditContentTypes, map[types.Type]bool{}); name != "" {
							findings = append(findings, fmt.Sprintf(
								"redaction: %s: %s logs audit content %s — audit events are never mirrored to the ops log (audit-model ADR)",
								p.Fset.Position(arg.Pos()), base, name))
						}
					}
				}
				return true
			})
		}
	}
	return findings
}

// calleePackage resolves the package path of a call's callee — a package
// function (fmt.Sprintf) or a method whose defining package matches
// (slog.Logger.Info).
func calleePackage(info *types.Info, call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if obj, ok := info.Uses[fn.Sel]; ok {
			if f, ok := obj.(*types.Func); ok && f.Pkg() != nil {
				return f.Pkg().Path()
			}
		}
	case *ast.Ident:
		if obj, ok := info.Uses[fn]; ok {
			if f, ok := obj.(*types.Func); ok && f.Pkg() != nil {
				return f.Pkg().Path()
			}
		}
	}
	return ""
}

// mentionsNamed reports the first pinned named type reachable from t
// (directly, behind pointers/slices/maps, or as a struct field of a module
// type), or "".
func mentionsNamed(t types.Type, pinned map[string]bool, seen map[types.Type]bool) string {
	if t == nil || seen[t] {
		return ""
	}
	seen[t] = true
	if u := types.Unalias(t); u != t {
		return mentionsNamed(u, pinned, seen)
	}
	switch u := t.(type) {
	case *types.Named:
		if key := namedKey(u); pinned[key] {
			return key
		}
		obj := u.Obj()
		if obj == nil || obj.Pkg() == nil || !strings.HasPrefix(obj.Pkg().Path(), Module) {
			return ""
		}
		return mentionsNamed(u.Underlying(), pinned, seen)
	case *types.Pointer:
		return mentionsNamed(u.Elem(), pinned, seen)
	case *types.Slice:
		return mentionsNamed(u.Elem(), pinned, seen)
	case *types.Array:
		return mentionsNamed(u.Elem(), pinned, seen)
	case *types.Map:
		if s := mentionsNamed(u.Key(), pinned, seen); s != "" {
			return s
		}
		return mentionsNamed(u.Elem(), pinned, seen)
	case *types.Struct:
		for i := range u.NumFields() {
			if s := mentionsNamed(u.Field(i).Type(), pinned, seen); s != "" {
				return s
			}
		}
		return ""
	}
	return ""
}
