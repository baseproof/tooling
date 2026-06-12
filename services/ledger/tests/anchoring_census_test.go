/*
FILE PATH: tests/anchoring_census_test.go

PR-4's census, as a drift guard (the dockerfile-roster discipline): the
convergence facts below were proven by hand once — this test keeps them true
without relying on review memory.

 1. DELETED THINGS STAY DELETED: the hand-curated anchor-chain file
    (LEDGER_NETWORK_ANCHORS_FILE / loadNetworkAnchors / NetworkAnchorsFile)
    reappearing anywhere in production code is the env-as-authority pattern
    PR-4b deleted — named drift, build failure.
 2. ENV-AS-SOURCE AT ZERO: the parent env knobs (LEDGER_PARENT_LOG_DID /
    LEDGER_PARENT_ADMISSION_URL) are CANARIES, consumed only in their two
    legal homes — config loading and the boot wiring (which cross-checks
    them against declarations and refuses boot on disagreement). A new
    consumer reading them anywhere else is a regression to env-as-source.
 3. THE PRODUCER ROSTER: BP-ENTRY-ANCHOR-TARGET-V1 has a producer
    (cmd/declare-anchor-target) — #94's root cause was a kind with no
    producer; its return would be silent.
 4. THE IMMUTABILITY LAW: anchor_confirmations sits in the H4 append-only
    guard list — verified_at's first-seen immutability is structural, not
    reviewed.
*/
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ledgerRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd) // tests/ → services/ledger
}

// walkProductionGo yields every non-test .go file under the ledger module,
// skipping third_party + vendor.
func walkProductionGo(t *testing.T, fn func(path, body string)) {
	t.Helper()
	root := ledgerRoot(t)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "third_party", "vendor", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		fn(rel, string(raw))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// stripComments blanks // and /* */ comments (the H4 guard's approach) so
// documentation that EXPLAINS a deleted/demoted name never trips the guard —
// only functional code does.
func stripComments(src string) string {
	out := []byte(src)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == '/' && out[i+1] == '/' {
			for j := i; j < len(out) && out[j] != '\n'; j++ {
				out[j] = ' '
			}
		} else if out[i] == '/' && out[i+1] == '*' {
			j := i + 2
			for j < len(out)-1 && !(out[j] == '*' && out[j+1] == '/') {
				j++
			}
			end := j + 2
			if end > len(out) {
				end = len(out)
			}
			for k := i; k < end; k++ {
				if out[k] != '\n' {
					out[k] = ' '
				}
			}
		}
	}
	return string(out)
}

func TestAnchoringCensus_DeletedChainFileStaysDeleted(t *testing.T) {
	// Functional forms only: an env read, a call, or a field/identifier use.
	// Comment mentions (history, rationale) are legal — code is not.
	banned := []string{`os.Getenv("LEDGER_NETWORK_ANCHORS_FILE")`, "loadNetworkAnchors(", "NetworkAnchorsFile"}
	walkProductionGo(t, func(path, body string) {
		code := stripComments(body)
		for _, tok := range banned {
			if strings.Contains(code, tok) {
				t.Errorf("%s reintroduces %q — the hand-curated anchor chain was deleted in PR-4b; the chain derives from anchor_confirmations", path, tok)
			}
		}
	})
}

func TestAnchoringCensus_ParentEnvIsCanaryOnly(t *testing.T) {
	// The two legal homes: config loading (reads the env) and the boot wiring
	// package (cross-checks + posture-logs it). Everything else must consume
	// DERIVED state (cfg fields via the derivation chain), never the env.
	allowed := map[string]bool{
		"cmd/ledger/config.go": true,
	}
	allowedDirs := []string{"cmd/ledger/boot/wire/"}
	walkProductionGo(t, func(path, body string) {
		code := stripComments(body)
		if !strings.Contains(code, `os.Getenv("LEDGER_PARENT_LOG_DID")`) && !strings.Contains(code, `os.Getenv("LEDGER_PARENT_ADMISSION_URL")`) {
			return
		}
		if allowed[path] {
			return
		}
		for _, d := range allowedDirs {
			if strings.HasPrefix(path, d) {
				return
			}
		}
		t.Errorf("%s calls os.Getenv on the parent knobs — they are pre-first-declaration canaries read only by config/wire; consume the derivation chain instead", path)
	})
}

func TestAnchoringCensus_DeclarationProducerExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join(ledgerRoot(t), "cmd", "declare-anchor-target", "main.go")); err != nil {
		t.Fatalf("BP-ENTRY-ANCHOR-TARGET-V1 has no producer (cmd/declare-anchor-target missing) — #94's root cause returned: %v", err)
	}
}

func TestAnchoringCensus_ConfirmationsInAppendOnlyLaw(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(ledgerRoot(t), "store", "append_only_guard_test.go"))
	if err != nil {
		t.Fatalf("read H4 guard: %v", err)
	}
	if !strings.Contains(string(raw), `"anchor_confirmations",`) {
		t.Fatal("anchor_confirmations left the H4 append-only list — verified_at's first-seen immutability is no longer structural")
	}
}
