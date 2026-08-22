package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type packageInfo struct {
	ImportPath   string
	Dir          string
	TestGoFiles  []string
	XTestGoFiles []string
	Module       *struct {
		Dir string
	}
	relativePath string
}

type fuzzTarget struct {
	packagePath string
	name        string
	relativeDir string
}

type options struct {
	root       string
	shard      int
	shardCount int
}

var preferredShards = map[string]map[string]int{
	"race": {
		"internal/app":           0,
		"internal/service":       0,
		"internal/lint":          1,
		"internal/store/migrate": 1,
		"internal/conformance":   2,
		"internal/store":         2,
		"internal/store/tx":      2,
	},
	"fuzz": {
		"internal/importer":      0,
		"internal/crypto":        1,
		"internal/crypto/backup": 1,
		"internal/compose":       2,
		"internal/samlsp":        2,
		"internal/scimproto":     2,
	},
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "analysis shards: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 || (args[0] != "race" && args[0] != "fuzz") {
		return errors.New("usage: analysis-shards race|fuzz --root DIR --shard N --shards N")
	}
	kind := args[0]
	flags := flag.NewFlagSet(kind, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var opts options
	flags.StringVar(&opts.root, "root", ".", "repository root")
	flags.IntVar(&opts.shard, "shard", -1, "zero-based shard index")
	flags.IntVar(&opts.shardCount, "shards", 0, "total shard count")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if opts.shardCount < 1 {
		return errors.New("shards must be positive")
	}
	if opts.shard < 0 || opts.shard >= opts.shardCount {
		return fmt.Errorf("shard %d is outside [0,%d)", opts.shard, opts.shardCount)
	}

	packages, err := listPackages(opts.root)
	if err != nil {
		return err
	}
	switch kind {
	case "race":
		return writeRaceShard(output, packages, opts)
	case "fuzz":
		return writeFuzzShard(output, packages, opts)
	default:
		panic("unreachable analysis kind")
	}
}

func listPackages(root string) ([]packageInfo, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	goBinary := os.Getenv("GO_BIN")
	if goBinary == "" {
		goBinary = "go"
	}
	command := exec.Command(goBinary, "list", "-json", "./...")
	command.Dir = absoluteRoot
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("go list failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	decoder := json.NewDecoder(&stdout)
	packages := make([]packageInfo, 0)
	for {
		var pkg packageInfo
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if pkg.Module == nil || pkg.Module.Dir == "" {
			return nil, fmt.Errorf("package %s has no module root", pkg.ImportPath)
		}
		relativePath, err := filepath.Rel(pkg.Module.Dir, pkg.Dir)
		if err != nil {
			return nil, fmt.Errorf("resolve package %s path: %w", pkg.ImportPath, err)
		}
		if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("package %s escapes its module", pkg.ImportPath)
		}
		pkg.relativePath = filepath.ToSlash(relativePath)
		packages = append(packages, pkg)
	}
	if len(packages) == 0 {
		return nil, errors.New("go list returned no packages")
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].ImportPath < packages[j].ImportPath
	})
	return packages, nil
}

func writeRaceShard(output io.Writer, packages []packageInfo, opts options) error {
	for _, pkg := range packages {
		if pkg.relativePath == "internal/isolation" {
			continue
		}
		if shardFor("race", pkg.relativePath, opts.shardCount) != opts.shard {
			continue
		}
		if _, err := fmt.Fprintln(output, pkg.ImportPath); err != nil {
			return fmt.Errorf("write race shard: %w", err)
		}
	}
	return nil
}

func writeFuzzShard(output io.Writer, packages []packageInfo, opts options) error {
	targets, err := discoverFuzzTargets(packages)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no Fuzz* target discovered")
	}
	for _, target := range targets {
		if shardFor("fuzz", target.relativeDir, opts.shardCount) != opts.shard {
			continue
		}
		if _, err := fmt.Fprintf(output, "%s\t%s\n", target.packagePath, target.name); err != nil {
			return fmt.Errorf("write fuzz shard: %w", err)
		}
	}
	return nil
}

func discoverFuzzTargets(packages []packageInfo) ([]fuzzTarget, error) {
	targets := make([]fuzzTarget, 0)
	seen := make(map[string]string)
	for _, pkg := range packages {
		files := append(append([]string(nil), pkg.TestGoFiles...), pkg.XTestGoFiles...)
		sort.Strings(files)
		for _, name := range files {
			path := filepath.Join(pkg.Dir, name)
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv != nil || !isFuzzName(function.Name.Name) {
					continue
				}
				key := pkg.ImportPath + "\x00" + function.Name.Name
				if previous, exists := seen[key]; exists {
					return nil, fmt.Errorf("duplicate fuzz target %s in %s and %s", function.Name.Name, previous, path)
				}
				seen[key] = path
				targets = append(targets, fuzzTarget{
					packagePath: pkg.ImportPath,
					name:        function.Name.Name,
					relativeDir: pkg.relativePath,
				})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].packagePath == targets[j].packagePath {
			return targets[i].name < targets[j].name
		}
		return targets[i].packagePath < targets[j].packagePath
	})
	return targets, nil
}

func isFuzzName(name string) bool {
	if !strings.HasPrefix(name, "Fuzz") || len(name) == len("Fuzz") {
		return false
	}
	first, _ := utf8.DecodeRuneInString(name[len("Fuzz"):])
	return !unicode.IsLower(first)
}

func shardFor(kind, relativePath string, shardCount int) int {
	if preferred, ok := preferredShards[kind][relativePath]; ok {
		return preferred % shardCount
	}
	hash := fnv.New32a()
	_, _ = io.WriteString(hash, relativePath)
	return int(hash.Sum32() % uint32(shardCount))
}
