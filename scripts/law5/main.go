// law5 — the domain-vocabulary law for the agnostic layer (LAW 5 in
// scripts/dependency-law.sh).
//
// LAW 1 proves libs/ links no domain module (go list -deps), but vocabulary
// coupling sails through an import check: a `CourtDID` field, a "JN submit
// HTTP %d" error, a "judicial.*" wire ID keep the agnostic layer judicial in
// everything but imports (CLI_CONSOLIDATION_REVIEW.md §3). LAW 5 closes that
// class: NO domain lexeme in libs/ EXPORTED IDENTIFIERS or STRING LITERALS
// (user- or wire-visible bytes). Comments are deliberately out of scope — they
// don't reach users or the wire.
//
// AST, not grep: only the parser can tell an identifier or string literal from
// a comment, so comments never false-positive and indirection can't hide a hit.
//
// The allowlist below is EMPTY — the §3B burn-down completed (the clitools
// court-typed config/types moved to judicial-network tools/common; the
// judicial.* monitor IDs re-namespaced to platform.*; prereq's CaseContext →
// EvalContext). The mechanism stays so any future, justified debt is carried
// explicitly (path prefix → justification), counted, and reported — but the
// steady state is zero entries: NEW vocabulary anywhere fails CI immediately.
//
// Usage: go run . <libs-root>   (exit 1 on any non-allowlisted hit)
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The domain lexemes (review §3C): judicial | court | judge | case_ | JN.
//   - identifiers: case-insensitive word-ish match for judicial/court/judge, a
//     CamelCase `Case` component (CaseRecord), and the uppercase JN token.
//   - strings: same, with \bJN\b word-bounded so "majority" / "JSON" never hit.
var (
	identRe  = regexp.MustCompile(`(?i:judicial|court|judge)|case_|Case[A-Z_]|JN`)
	stringRe = regexp.MustCompile(`(?i:judicial|court|judge)|case_|\bJN\b`)
)

// allowlist maps a path prefix (relative to the libs root, slash-separated) to
// the justification for carrying it. Kept EMPTY — add an entry only for
// migration debt that cannot land atomically, and delete it when the move
// lands; the law then enforces it forever.
var allowlist = map[string]string{}

type hit struct {
	pos  token.Position
	kind string // "exported identifier" | "string literal"
	text string
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: law5 <libs-root>")
		os.Exit(2)
	}
	root := os.Args[1]

	var violations []hit
	allowed := map[string]int{} // prefix -> count
	files := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		files++

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		hits, perr := scanFile(path)
		if perr != nil {
			return fmt.Errorf("%s: %w", path, perr)
		}
		if len(hits) == 0 {
			return nil
		}
		if prefix := allowlistedPrefix(rel); prefix != "" {
			allowed[prefix] += len(hits)
			return nil
		}
		violations = append(violations, hits...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "law5: %v\n", err)
		os.Exit(2)
	}
	if files == 0 {
		fmt.Fprintf(os.Stderr, "law5: no Go files under %s — wrong root?\n", root)
		os.Exit(2)
	}

	for _, v := range violations {
		fmt.Printf("%s: %s %q — domain vocabulary in the agnostic layer (rename to network-neutral terms; see CLI_CONSOLIDATION_REVIEW.md §3)\n",
			v.pos, v.kind, v.text)
	}
	if len(violations) > 0 {
		os.Exit(1)
	}

	// Success summary, allowlisted debt visible.
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	debt := make([]string, 0, len(keys))
	for _, k := range keys {
		debt = append(debt, fmt.Sprintf("%s %d hits (%s)", k, allowed[k], allowlist[k]))
	}
	if len(debt) == 0 {
		fmt.Printf("libs vocabulary clean: %d files, zero domain lexemes\n", files)
	} else {
		fmt.Printf("libs vocabulary clean outside allowlist: %d files; allowlisted debt: %s\n",
			files, strings.Join(debt, "; "))
	}
}

func allowlistedPrefix(rel string) string {
	for prefix := range allowlist {
		if strings.HasPrefix(rel, prefix) {
			return prefix
		}
	}
	return ""
}

// scanFile parses one file and returns every exported declared identifier and
// every string literal matching the domain lexemes. Comments are never
// visited; import paths are excluded (module paths are not user-visible text).
func scanFile(path string) ([]hit, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var hits []hit
	flagIdent := func(id *ast.Ident) {
		if id == nil || !ast.IsExported(id.Name) || !identRe.MatchString(id.Name) {
			return
		}
		hits = append(hits, hit{fset.Position(id.Pos()), "exported identifier", id.Name})
	}

	// Declared names: walk top-level decls precisely (func/method names, type
	// names, struct fields, interface methods, consts/vars) — NOT ast.Inspect,
	// which would also visit function parameters and local variables that are
	// not API surface.
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			flagIdent(d.Name)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					flagIdent(s.Name)
					switch t := s.Type.(type) {
					case *ast.StructType:
						for _, fld := range t.Fields.List {
							for _, n := range fld.Names {
								flagIdent(n)
							}
						}
					case *ast.InterfaceType:
						for _, m := range t.Methods.List {
							for _, n := range m.Names {
								flagIdent(n)
							}
						}
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						flagIdent(n)
					}
				}
			}
		}
	}

	// String literals: every token.STRING except import paths. Struct tags ARE
	// included — JSON/env tag names are wire-visible bytes.
	importPaths := map[*ast.BasicLit]bool{}
	for _, imp := range f.Imports {
		importPaths[imp.Path] = true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || importPaths[lit] {
			return true
		}
		if stringRe.MatchString(lit.Value) {
			text := lit.Value
			if len(text) > 60 {
				text = text[:57] + "..."
			}
			hits = append(hits, hit{fset.Position(lit.Pos()), "string literal", text})
		}
		return true
	})
	return hits, nil
}
