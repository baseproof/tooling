/*
libs/cli/pre1_stdout_guard_test.go — the PRE-1 machine guard: the output
contract holds by AST, not by review discipline. stdout is written ONLY in
output.go (the JSON encoder + tablef/tableln); everywhere else, a bare
fmt.Print* or an os.Stdout reference fails this test — so the 47th
contract-bypassing print cannot land.
*/
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestPRE1_NoStdoutWritesOutsideThePrinter(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		n := fi.Name()
		return strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	for _, pkg := range pkgs {
		for fname, f := range pkg.Files {
			if filepath.Base(fname) == "output.go" {
				continue // the one licensed home
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch {
				case ident.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print"):
					// fmt.Print/Println/Printf write stdout — forbidden.
					t.Errorf("%s: %s.%s writes stdout outside the printer — use tablef/tableln (output.go)",
						fset.Position(n.Pos()), ident.Name, sel.Sel.Name)
				case ident.Name == "os" && sel.Sel.Name == "Stdout":
					t.Errorf("%s: direct os.Stdout reference outside the printer",
						fset.Position(n.Pos()))
				}
				return true
			})
		}
	}
}

// TestPRE1_EnvelopeKindsArePinned is the verb-vocabulary census: every
// emitOutput kind in the package source appears in this closed list, so a
// new verb's machine output is a DELIBERATE vocabulary change, reviewed
// here — not an unversioned string drifting into pipelines.
func TestPRE1_EnvelopeKindsArePinned(t *testing.T) {
	want := map[string]bool{
		"cosign-draft":           true,
		"cosign-show":            true,
		"cosign-sign":            true,
		"cosign-submit":          true,
		"info":                   true,
		"network-bundle":         true,
		"network-bundle-publish": true,
		"network-bundle-verify":  true,
		"network-list":           true,
		"network-show":           true,
		"rotation-draft":         true,
		"rotation-finalize":      true,
		"rotation-submit":        true,
		"verify":                 true,
		"witnesses":              true,
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		n := fi.Name()
		return strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "emitOutput" {
					return true
				}
				if len(call.Args) < 2 {
					return true
				}
				lit, ok := call.Args[1].(*ast.BasicLit)
				if !ok {
					return true // dynamic kind: flagged by review, not this pin
				}
				kind := strings.Trim(lit.Value, `"`)
				if !want[kind] {
					t.Errorf("%s: emitOutput kind %q is not in the pinned vocabulary — add it HERE deliberately",
						fset.Position(n.Pos()), kind)
				}
				return true
			})
		}
	}
}
