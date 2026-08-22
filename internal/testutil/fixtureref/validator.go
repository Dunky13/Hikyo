// Package fixtureref validates acceptance-matrix references against exact
// source definitions. It is test infrastructure; production packages do not
// import it.
package fixtureref

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind declares the executable source construct a reference must identify.
type Kind string

const (
	GoTest         Kind = "go-test"
	GoBenchmark    Kind = "go-benchmark"
	GoHelper       Kind = "go-helper"
	GoSubtest      Kind = "go-subtest"
	PlaywrightTest Kind = "playwright-test"
)

// FixtureRef identifies one executable fixture. Package is a repository-root
// relative package directory. File is optional for Go and required for
// Playwright. Go subtests use TestName "TestParent/child/grandchild"; only
// literal t.Run titles on the matching testing.T receiver are supported.
// Playwright titles must be static string literals passed through a binding
// imported from @playwright/test to test(), test.only(), or test.fail().
// Skipped/fixme and dynamic-template cases are intentionally not referenceable
// because they are not executable fixtures with one stable title.
type FixtureRef struct {
	Package  string
	File     string
	TestName string
	Kind     Kind
}

// Validate proves that ref resolves to exactly one source definition of the
// declared kind beneath repoRoot.
func Validate(repoRoot string, ref FixtureRef) error {
	if ref.TestName == "" {
		return fmt.Errorf("%s fixture requires TestName", ref.Kind)
	}
	packageDir, err := resolveRelative(repoRoot, ref.Package, "Package")
	if err != nil {
		return err
	}

	switch ref.Kind {
	case GoTest, GoBenchmark, GoHelper, GoSubtest:
		files, readErr := parseGoPackage(packageDir, ref.File)
		if readErr != nil {
			return fmt.Errorf("%s %q in %s: %w", ref.Kind, ref.TestName, ref.Package, readErr)
		}
		return validateGo(ref, files)
	case PlaywrightTest:
		if ref.File == "" {
			return fmt.Errorf("%s fixture requires File", ref.Kind)
		}
		if !strings.HasSuffix(ref.File, ".spec.ts") && !strings.HasSuffix(ref.File, ".spec.tsx") {
			return fmt.Errorf("%s fixture File %q must be a Playwright .spec.ts or .spec.tsx file", ref.Kind, ref.File)
		}
		file, resolveErr := resolveRelative(packageDir, ref.File, "File")
		if resolveErr != nil {
			return resolveErr
		}
		raw, readErr := os.ReadFile(file)
		if readErr != nil {
			return fmt.Errorf("reading %s fixture file %s/%s: %w", ref.Kind, ref.Package, ref.File, readErr)
		}
		return validatePlaywright(ref, string(raw))
	default:
		return fmt.Errorf("fixture %q has unsupported kind %q", ref.TestName, ref.Kind)
	}
}

func resolveRelative(root, name, field string) (string, error) {
	if name == "" || name == "." || !fs.ValidPath(name) || filepath.IsAbs(name) || strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("fixture %s %q must be a non-empty slash-separated relative path", field, name)
	}
	return filepath.Join(root, filepath.FromSlash(name)), nil
}

type parsedGoFile struct {
	name string
	file *ast.File
}

func parseGoPackage(packageDir, fileName string) ([]parsedGoFile, error) {
	if fileName != "" && filepath.Ext(fileName) != ".go" {
		return nil, fmt.Errorf("Go fixture File %q must end in .go", fileName)
	}

	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, fmt.Errorf("reading package directory: %w", err)
	}
	allFiles := make([]parsedGoFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		path := filepath.Join(packageDir, entry.Name())
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), parseErr)
		}
		allFiles = append(allFiles, parsedGoFile{name: entry.Name(), file: file})
	}
	if len(allFiles) == 0 {
		return nil, fmt.Errorf("package contains no Go source files")
	}
	packageName, err := owningPackageName(allFiles)
	if err != nil {
		return nil, err
	}
	files := make([]parsedGoFile, 0, len(allFiles))
	for _, parsed := range allFiles {
		if parsed.file.Name.Name == packageName && (fileName == "" || parsed.name == fileName) {
			files = append(files, parsed)
		}
	}
	if fileName != "" && len(files) == 0 {
		return nil, fmt.Errorf("File %q does not exist in owning package %q", fileName, packageName)
	}
	return files, nil
}

func owningPackageName(files []parsedGoFile) (string, error) {
	names := map[string]bool{}
	for _, parsed := range files {
		if !strings.HasSuffix(parsed.name, "_test.go") {
			names[parsed.file.Name.Name] = true
		}
	}
	if len(names) == 0 {
		for _, parsed := range files {
			if !strings.HasSuffix(parsed.file.Name.Name, "_test") {
				names[parsed.file.Name.Name] = true
			}
		}
	}
	if len(names) != 1 {
		return "", fmt.Errorf("package directory has %d possible owning package names", len(names))
	}
	for name := range names {
		return name, nil
	}
	return "", fmt.Errorf("package directory has no owning package")
}

func validateGo(ref FixtureRef, files []parsedGoFile) error {
	if ref.Kind == GoSubtest {
		return validateGoSubtest(ref, files)
	}

	nameMatches := 0
	kindMatches := 0
	for _, parsed := range files {
		aliases := testingAliases(parsed.file)
		for _, declaration := range parsed.file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != ref.TestName {
				continue
			}
			nameMatches++
			if functionHasKind(fn, aliases, ref.Kind) {
				kindMatches++
			}
		}
	}
	if kindMatches == 1 {
		return nil
	}
	if kindMatches > 1 {
		return fmt.Errorf("%s fixture %q in %s is ambiguous: %d definitions match", ref.Kind, ref.TestName, ref.Package, kindMatches)
	}
	if nameMatches > 0 {
		return fmt.Errorf("%s fixture %q in %s has wrong kind", ref.Kind, ref.TestName, ref.Package)
	}
	file := ref.File
	if file == "" {
		file = "package AST"
	}
	return fmt.Errorf("%s fixture %q not found in %s/%s", ref.Kind, ref.TestName, ref.Package, file)
}

func functionHasKind(fn *ast.FuncDecl, aliases map[string]bool, kind Kind) bool {
	switch kind {
	case GoTest:
		return goEntrypoint(fn, aliases, "Test", "T")
	case GoBenchmark:
		return goEntrypoint(fn, aliases, "Benchmark", "B")
	case GoHelper:
		if goEntrypoint(fn, aliases, "Test", "T") || goEntrypoint(fn, aliases, "Benchmark", "B") {
			return false
		}
		return firstParameterIsTesting(fn.Type.Params, aliases, "T") || firstParameterIsTesting(fn.Type.Params, aliases, "B")
	default:
		return false
	}
}

func goEntrypoint(fn *ast.FuncDecl, aliases map[string]bool, prefix, testingType string) bool {
	return isGoTestName(fn.Name.Name, prefix) &&
		fieldCount(fn.Type.Params) == 1 &&
		firstParameterIsTesting(fn.Type.Params, aliases, testingType) &&
		fieldCount(fn.Type.Results) == 0 &&
		fn.Type.TypeParams == nil
}

func isGoTestName(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	next, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(next)
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

func firstParameterIsTesting(fields *ast.FieldList, aliases map[string]bool, testingType string) bool {
	if fields == nil || len(fields.List) == 0 {
		return false
	}
	pointer, ok := fields.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if ok {
		pkg, pkgOK := selector.X.(*ast.Ident)
		return pkgOK && aliases[pkg.Name] && selector.Sel.Name == testingType
	}
	identifier, ok := pointer.X.(*ast.Ident)
	return ok && aliases["."] && identifier.Name == testingType
}

func testingAliases(file *ast.File) map[string]bool {
	aliases := map[string]bool{}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil || path != "testing" {
			continue
		}
		if imported.Name == nil {
			aliases["testing"] = true
		} else {
			aliases[imported.Name.Name] = true
		}
	}
	return aliases
}

func validateGoSubtest(ref FixtureRef, files []parsedGoFile) error {
	parts := strings.Split(ref.TestName, "/")
	if len(parts) < 2 || parts[0] == "" || parts[len(parts)-1] == "" {
		return fmt.Errorf("%s fixture %q must use TestParent/child path syntax", ref.Kind, ref.TestName)
	}

	matches := 0
	parentFound := false
	for _, parsed := range files {
		aliases := testingAliases(parsed.file)
		for _, declaration := range parsed.file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != parts[0] || !functionHasKind(fn, aliases, GoTest) {
				continue
			}
			parentFound = true
			receiver := firstParameterName(fn.Type.Params)
			if receiver == "" || fn.Body == nil {
				continue
			}
			paths := map[string]int{}
			collectSubtests(fn.Body, receiver, parts[0], paths)
			matches += paths[ref.TestName]
		}
	}
	if matches == 1 {
		return nil
	}
	if matches > 1 {
		return fmt.Errorf("%s fixture %q in %s is ambiguous: %d definitions match", ref.Kind, ref.TestName, ref.Package, matches)
	}
	if !parentFound {
		return fmt.Errorf("%s parent %q not found as a Go test in %s", ref.Kind, parts[0], ref.Package)
	}
	return fmt.Errorf("%s fixture %q not found in %s", ref.Kind, ref.TestName, ref.Package)
}

func firstParameterName(fields *ast.FieldList) string {
	if fields == nil || len(fields.List) == 0 || len(fields.List[0].Names) == 0 {
		return ""
	}
	return fields.List[0].Names[0].Name
}

func collectSubtests(body *ast.BlockStmt, receiver, parent string, paths map[string]int) {
	ast.Inspect(body, func(node ast.Node) bool {
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Run" {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if !ok || ident.Name != receiver || len(call.Args) < 2 {
			return true
		}
		title, ok := goStringLiteral(call.Args[0])
		if !ok {
			return false
		}
		path := parent + "/" + title
		paths[path]++
		callback, ok := call.Args[1].(*ast.FuncLit)
		if ok {
			childReceiver := firstParameterName(callback.Type.Params)
			if childReceiver != "" {
				collectSubtests(callback.Body, childReceiver, path, paths)
			}
		}
		return false
	})
}

func goStringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func validatePlaywright(ref FixtureRef, source string) error {
	titles, err := staticPlaywrightTitles(source)
	if err != nil {
		return fmt.Errorf("parsing Playwright fixture %s/%s: %w", ref.Package, ref.File, err)
	}
	matches := titles[ref.TestName]
	if matches == 1 {
		return nil
	}
	if matches > 1 {
		return fmt.Errorf("%s fixture %q in %s/%s is ambiguous: %d definitions match", ref.Kind, ref.TestName, ref.Package, ref.File, matches)
	}
	return fmt.Errorf("%s fixture %q not found in %s/%s", ref.Kind, ref.TestName, ref.Package, ref.File)
}

type tsToken struct {
	kind  byte
	value string
}

func staticPlaywrightTitles(source string) (map[string]int, error) {
	tokens, err := scanTypeScript(source)
	if err != nil {
		return nil, err
	}
	bindings := playwrightTestBindings(tokens)
	if len(bindings.names) == 0 {
		return nil, fmt.Errorf("source does not import a test binding from @playwright/test")
	}
	if err := rejectShadowedPlaywrightBindings(tokens, bindings); err != nil {
		return nil, err
	}
	titles := map[string]int{}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind != 'i' || !bindings.names[tokens[i].value] || (i > 0 && tokens[i-1].value == ".") {
			continue
		}
		open := i + 1
		if open+2 < len(tokens) && tokens[open].value == "." && tokens[open+1].kind == 'i' {
			modifier := tokens[open+1].value
			if modifier != "only" && modifier != "fail" {
				continue
			}
			open += 2
		}
		if open+1 >= len(tokens) || tokens[open].value != "(" || tokens[open+1].kind != 's' {
			continue
		}
		titles[tokens[open+1].value]++
	}
	return titles, nil
}

type playwrightBindings struct {
	names           map[string]bool
	importedAtIndex map[int]bool
}

func playwrightTestBindings(tokens []tsToken) playwrightBindings {
	bindings := playwrightBindings{names: map[string]bool{}, importedAtIndex: map[int]bool{}}
	for start := 0; start < len(tokens); start++ {
		if tokens[start].kind != 'i' || tokens[start].value != "import" {
			continue
		}
		if start+1 < len(tokens) && tokens[start+1].value == "type" {
			continue
		}
		from := start + 1
		for from < len(tokens) && tokens[from].value != "from" && tokens[from].value != ";" {
			from++
		}
		if from+1 >= len(tokens) || tokens[from].value != "from" || tokens[from+1].kind != 's' || tokens[from+1].value != "@playwright/test" {
			continue
		}
		open := start + 1
		for open < from && tokens[open].value != "{" {
			open++
		}
		for i := open + 1; i < from && tokens[i].value != "}"; {
			if tokens[i].kind != 'i' {
				i++
				continue
			}
			typeOnly := tokens[i].value == "type"
			if typeOnly {
				i++
				if i >= from || tokens[i].kind != 'i' {
					continue
				}
			}
			imported := tokens[i].value
			local := imported
			localIndex := i
			i++
			if i+1 < from && tokens[i].value == "as" && tokens[i+1].kind == 'i' {
				local = tokens[i+1].value
				localIndex = i + 1
				i += 2
			}
			if imported == "test" && !typeOnly {
				bindings.names[local] = true
				bindings.importedAtIndex[localIndex] = true
			}
			for i < from && tokens[i].value != "," && tokens[i].value != "}" {
				i++
			}
			if i < from && tokens[i].value == "," {
				i++
			}
		}
	}
	return bindings
}

func rejectShadowedPlaywrightBindings(tokens []tsToken, bindings playwrightBindings) error {
	for i, current := range tokens {
		if current.kind != 'i' || !bindings.names[current.value] || bindings.importedAtIndex[i] {
			continue
		}
		previous := ""
		if i > 0 {
			previous = tokens[i-1].value
		}
		next := ""
		if i+1 < len(tokens) {
			next = tokens[i+1].value
		}
		if previous == "function" || previous == "class" || previous == "const" || previous == "let" || previous == "var" || next != "(" && next != "." {
			return fmt.Errorf("Playwright test binding %q is shadowed or used indirectly", current.value)
		}
	}
	return nil
}

func scanTypeScript(source string) ([]tsToken, error) {
	tokens := make([]tsToken, 0, len(source)/4)
	for i := 0; i < len(source); {
		switch {
		case isSpace(source[i]):
			i++
		case i+1 < len(source) && source[i:i+2] == "//":
			i += 2
			for i < len(source) && source[i] != '\n' {
				i++
			}
		case i+1 < len(source) && source[i:i+2] == "/*":
			end := strings.Index(source[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated block comment")
			}
			i += end + 4
		case isIdentifierStart(source[i]):
			start := i
			i++
			for i < len(source) && isIdentifierPart(source[i]) {
				i++
			}
			tokens = append(tokens, tsToken{kind: 'i', value: source[start:i]})
		case source[i] == '\'' || source[i] == '"' || source[i] == '`':
			value, static, next, err := scanTypeScriptString(source, i)
			if err != nil {
				return nil, err
			}
			kind := byte('d')
			if static {
				kind = 's'
			}
			tokens = append(tokens, tsToken{kind: kind, value: value})
			i = next
		case source[i] == '/' && canStartRegex(tokens):
			next, regexErr := scanTypeScriptRegex(source, i)
			if regexErr != nil {
				return nil, regexErr
			}
			tokens = append(tokens, tsToken{kind: 'r', value: source[i:next]})
			i = next
		default:
			tokens = append(tokens, tsToken{kind: 'p', value: source[i : i+1]})
			i++
		}
	}
	return tokens, nil
}

func canStartRegex(tokens []tsToken) bool {
	if len(tokens) == 0 {
		return true
	}
	last := tokens[len(tokens)-1]
	if last.kind == 'i' {
		switch last.value {
		case "case", "delete", "do", "else", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield", "await":
			return true
		default:
			return false
		}
	}
	switch last.value {
	case "(", "[", "{", "=", ":", ",", ";", "!", "?", "&", "|", "+", "-", "*", "%", "~":
		return true
	case ">":
		return len(tokens) >= 2 && tokens[len(tokens)-2].value == "="
	case ")":
		return closesControlStatementHeader(tokens)
	default:
		return false
	}
}

func closesControlStatementHeader(tokens []tsToken) bool {
	depth := 0
	for i := len(tokens) - 1; i >= 0; i-- {
		switch tokens[i].value {
		case ")":
			depth++
		case "(":
			depth--
			if depth != 0 {
				continue
			}
			if i == 0 {
				return false
			}
			switch tokens[i-1].value {
			case "if", "while", "for", "with", "switch", "catch":
				return true
			default:
				return false
			}
		}
	}
	return false
}

func scanTypeScriptRegex(source string, start int) (int, error) {
	inClass := false
	for i := start + 1; i < len(source); i++ {
		switch source[i] {
		case '\n', '\r':
			return 0, fmt.Errorf("unterminated regular expression literal")
		case '\\':
			i++
			if i >= len(source) {
				return 0, fmt.Errorf("unterminated regular expression escape")
			}
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '/':
			if inClass {
				continue
			}
			i++
			for i < len(source) && isIdentifierPart(source[i]) {
				i++
			}
			return i, nil
		}
	}
	return 0, fmt.Errorf("unterminated regular expression literal")
}

func scanTypeScriptString(source string, start int) (string, bool, int, error) {
	quote := source[start]
	var value strings.Builder
	static := true
	for i := start + 1; i < len(source); i++ {
		if source[i] == quote {
			return value.String(), static, i + 1, nil
		}
		if quote == '`' && i+1 < len(source) && source[i:i+2] == "${" {
			static = false
		}
		if source[i] != '\\' {
			value.WriteByte(source[i])
			continue
		}
		i++
		if i >= len(source) {
			break
		}
		switch source[i] {
		case 'n':
			value.WriteByte('\n')
		case 'r':
			value.WriteByte('\r')
		case 't':
			value.WriteByte('\t')
		default:
			value.WriteByte(source[i])
		}
	}
	return "", false, 0, fmt.Errorf("unterminated string literal")
}

func isSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func isIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isIdentifierPart(value byte) bool {
	return isIdentifierStart(value) || value >= '0' && value <= '9'
}
