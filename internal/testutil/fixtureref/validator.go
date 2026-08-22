// Package fixtureref validates qualified references to executable Go test
// fixtures. It is intended for test registries, not production code.
package fixtureref

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind identifies the executable shape named by a fixture reference.
type Kind string

const (
	// KindTest names a top-level TestXxx function.
	KindTest Kind = "test"
	// KindSubtest names a slash-qualified path of literal t.Run names below a test.
	KindSubtest Kind = "subtest"
	// KindHelper names a top-level, non-Test helper function in a _test.go file.
	KindHelper Kind = "helper"
)

// FixtureRef is an exact reference to an executable fixture in one Go package.
type FixtureRef struct {
	Package  string
	TestName string
	Kind     Kind
}

type packageMetadata struct {
	ImportPath string
	Dir        string
	Name       string
}

type fixtureDefinition struct {
	kind Kind
	file string
}

// Validate proves that every reference exists exactly once, with the declared
// kind, in the declared package. It parses every _test.go file in the package,
// including files excluded by current build tags.
func Validate(root string, refs []FixtureRef) error {
	var problems []error
	seen := make(map[FixtureRef]struct{}, len(refs))
	packages := make(map[string][]FixtureRef)
	for _, ref := range refs {
		if ref.Package == "" || ref.TestName == "" {
			problems = append(problems, fmt.Errorf("incomplete fixture reference: %+v", ref))
			continue
		}
		switch ref.Kind {
		case KindTest, KindSubtest, KindHelper:
		default:
			problems = append(problems, fmt.Errorf("fixture %s.%s has unsupported kind %q", ref.Package, ref.TestName, ref.Kind))
			continue
		}
		if _, duplicate := seen[ref]; duplicate {
			problems = append(problems, fmt.Errorf("duplicate fixture reference %s.%s (%s)", ref.Package, ref.TestName, ref.Kind))
			continue
		}
		seen[ref] = struct{}{}
		packages[ref.Package] = append(packages[ref.Package], ref)
	}

	packagePaths := make([]string, 0, len(packages))
	for packagePath := range packages {
		packagePaths = append(packagePaths, packagePath)
	}
	sort.Strings(packagePaths)
	for _, packagePath := range packagePaths {
		packageRefs := packages[packagePath]
		metadata, err := loadPackage(root, packagePath)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		definitions, err := indexFixtures(metadata)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		for _, ref := range packageRefs {
			matches := definitions[ref.TestName]
			var sameKind []fixtureDefinition
			for _, match := range matches {
				if match.kind == ref.Kind {
					sameKind = append(sameKind, match)
				}
			}
			switch len(sameKind) {
			case 1:
				continue
			case 0:
				if len(matches) > 0 {
					problems = append(problems, fmt.Errorf("fixture %s.%s requested as %s but exists as %s", ref.Package, ref.TestName, ref.Kind, matches[0].kind))
				} else {
					problems = append(problems, fmt.Errorf("fixture %s.%s (%s) not found", ref.Package, ref.TestName, ref.Kind))
				}
			default:
				files := make([]string, 0, len(sameKind))
				for _, match := range sameKind {
					files = append(files, match.file)
				}
				problems = append(problems, fmt.Errorf("fixture %s.%s (%s) has %d definitions in %s", ref.Package, ref.TestName, ref.Kind, len(sameKind), strings.Join(files, ", ")))
			}
		}
	}
	return errors.Join(problems...)
}

func loadPackage(root, packagePath string) (packageMetadata, error) {
	cmd := exec.Command("go", "list", "-json", packagePath)
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return packageMetadata{}, fmt.Errorf("go list %s: %w: %s", packagePath, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return packageMetadata{}, fmt.Errorf("go list %s: %w", packagePath, err)
	}
	var metadata packageMetadata
	if err := json.Unmarshal(output, &metadata); err != nil {
		return packageMetadata{}, fmt.Errorf("decode go list %s: %w", packagePath, err)
	}
	if metadata.ImportPath == "" || metadata.Dir == "" || metadata.Name == "" {
		return packageMetadata{}, fmt.Errorf("go list %s returned incomplete package metadata", packagePath)
	}
	return metadata, nil
}

func indexFixtures(metadata packageMetadata) (map[string][]fixtureDefinition, error) {
	entries, err := os.ReadDir(metadata.Dir)
	if err != nil {
		return nil, fmt.Errorf("read package %s: %w", metadata.ImportPath, err)
	}
	definitions := make(map[string][]fixtureDefinition)
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(metadata.Dir, entry.Name())
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if file.Name.Name != metadata.Name && file.Name.Name != metadata.Name+"_test" {
			return nil, fmt.Errorf("test file %s belongs to package %s, want %s or %s_test", path, file.Name.Name, metadata.Name, metadata.Name)
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			kind := KindHelper
			if isTestFunction(file, fn) {
				kind = KindTest
			}
			definitions[fn.Name.Name] = append(definitions[fn.Name.Name], fixtureDefinition{kind: kind, file: entry.Name()})
			if kind == KindTest {
				receiver, _ := testingParameter(file, fn.Type)
				indexLiteralSubtests(file, fn.Body, receiver, fn.Name.Name, entry.Name(), definitions)
			}
		}
	}
	return definitions, nil
}

func isTestFunction(file *ast.File, fn *ast.FuncDecl) bool {
	if !goTestName(fn.Name.Name) || fieldCount(fn.Type.Results) != 0 || fn.Type.TypeParams != nil {
		return false
	}
	_, ok := testingParameter(file, fn.Type)
	return ok
}

func goTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	if len(name) == len("Test") {
		return true
	}
	next, _ := utf8.DecodeRuneInString(name[len("Test"):])
	return !unicode.IsLower(next)
}

func testingParameter(file *ast.File, function *ast.FuncType) (*ast.Object, bool) {
	if fieldCount(function.Params) != 1 || len(function.Params.List) != 1 {
		return nil, false
	}
	param := function.Params.List[0]
	star, ok := param.Type.(*ast.StarExpr)
	if !ok {
		return nil, false
	}
	testingName, dotImported := testingImport(file)
	isTestingT := false
	switch testingType := star.X.(type) {
	case *ast.SelectorExpr:
		qualifier, ok := testingType.X.(*ast.Ident)
		isTestingT = ok && qualifier.Name == testingName && testingType.Sel.Name == "T"
	case *ast.Ident:
		isTestingT = dotImported && testingType.Name == "T"
	}
	if !isTestingT {
		return nil, false
	}
	if len(param.Names) == 0 {
		return nil, true
	}
	return param.Names[0].Obj, true
}

func fieldCount(fields *ast.FieldList) int {
	if fields == nil {
		return 0
	}
	count := 0
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			count++
		} else {
			count += len(field.Names)
		}
	}
	return count
}

func testingImport(file *ast.File) (name string, dotImported bool) {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		if spec.Name == nil {
			return "testing", false
		}
		if spec.Name.Name == "." {
			return "", true
		}
		return spec.Name.Name, false
	}
	return "", false
}

func indexLiteralSubtests(source *ast.File, body *ast.BlockStmt, receiver *ast.Object, parent, file string, definitions map[string][]fixtureDefinition) {
	if receiver == nil {
		return
	}
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		callee, receiverMatches := selector.X.(*ast.Ident)
		if !receiverMatches || callee.Obj != receiver || selector.Sel.Name != "Run" || len(call.Args) != 2 {
			return true
		}
		nameLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || nameLiteral.Kind != token.STRING {
			return false
		}
		name, err := strconv.Unquote(nameLiteral.Value)
		if err != nil || name == "" {
			return false
		}
		qualified := parent + "/" + name
		definitions[qualified] = append(definitions[qualified], fixtureDefinition{kind: KindSubtest, file: file})
		callback, ok := call.Args[1].(*ast.FuncLit)
		if ok {
			nestedReceiver, valid := testingParameter(source, callback.Type)
			if valid && fieldCount(callback.Type.Results) == 0 {
				indexLiteralSubtests(source, callback.Body, nestedReceiver, qualified, file, definitions)
			}
		}
		return false
	})
}
