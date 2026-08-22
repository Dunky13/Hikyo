package fixtureref

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Playwright references resolve only static-title executable declarations
// through a binding imported from @playwright/test. Containers, skipped tests,
// dynamic titles, shadowed bindings, and source lookalikes do not qualify.
func validatePlaywrightRef(root string, ref FixtureRef) error {
	if ref.File == "" {
		return fmt.Errorf("%s fixture requires File", ref.Kind)
	}
	if !strings.HasSuffix(ref.File, ".spec.ts") && !strings.HasSuffix(ref.File, ".spec.tsx") {
		return fmt.Errorf("%s fixture File %q must be a Playwright .spec.ts or .spec.tsx file", ref.Kind, ref.File)
	}
	packageDir, err := resolveRelative(root, ref.Package, "Package")
	if err != nil {
		return err
	}
	file, err := resolveRelative(packageDir, ref.File, "File")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading %s fixture file %s/%s: %w", ref.Kind, ref.Package, ref.File, err)
	}
	titles, err := staticPlaywrightTitles(string(raw))
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

func resolveRelative(root, name, field string) (string, error) {
	if name == "" || name == "." || !fs.ValidPath(name) || filepath.IsAbs(name) || strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("fixture %s %q must be a non-empty slash-separated relative path", field, name)
	}
	return filepath.Join(root, filepath.FromSlash(name)), nil
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
			next, err := scanTypeScriptRegex(source, i)
			if err != nil {
				return nil, err
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

func isSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
}

func isIdentifierStart(value byte) bool {
	return value == '_' || value == '$' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isIdentifierPart(value byte) bool {
	return isIdentifierStart(value) || value >= '0' && value <= '9'
}
