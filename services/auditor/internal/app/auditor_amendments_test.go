/*
FILE PATH: services/auditor/internal/app/auditor_amendments_test.go

Ladder 2 D5 backfill (#21) — LoadAuditorAmendmentsFromFile coverage.

# PATHS PINNED

  - Happy path: well-formed manifest → SDK-typed slice, sorted ascending
    by EffectivePos regardless of operator file ordering.
  - Empty path: path=="" returns (nil, nil) — equivalent to v1.32.0
    registration-only behavior; the reconciler treats nil amendments
    as "no amendments published yet".
  - Missing-file path: surface the os.ReadFile error.
  - Malformed JSON: surface the json.Unmarshal error.
  - Per-row SDK validate failure: surface with row-index + AuditorDID
    in the wrapped error so the operator's deployment-manifest line is
    identifiable.
  - Sort discipline: operator-authored unsorted manifest is sorted on
    load (the SDK's ResolveAuditorAt contract requires sorted input;
    Ladder 1 B1 applied this same discipline to BuildAuditorRegistryFromConfig).
*/
package app

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
)

const validAmendmentManifest = `[
  {
    "effective_seq": 200,
    "auditor_did":   "did:web:auditor-a.example.org",
    "new_scope":     6,
    "reason":        "expand scope post-IR"
  },
  {
    "effective_seq": 100,
    "auditor_did":   "did:web:auditor-b.example.org",
    "new_scope":     2,
    "reason":        ""
  },
  {
    "effective_seq": 50,
    "auditor_did":   "did:web:auditor-c.example.org",
    "new_scope":     4
  }
]`

func writeManifest(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "amendments.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLoadAuditorAmendmentsFromFile_EmptyPath pins the disabled-path
// semantic: empty path returns (nil, nil) regardless of file system
// state. Matches LoadAuditorRegistryFromFile.
func TestLoadAuditorAmendmentsFromFile_EmptyPath(t *testing.T) {
	got, err := LoadAuditorAmendmentsFromFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("empty path must return nil slice; got len=%d", len(got))
	}
}

// TestLoadAuditorAmendmentsFromFile_MissingFile pins the os.ReadFile
// error surface — operator typo'd path produces an actionable error,
// not a silent (nil, nil) return.
func TestLoadAuditorAmendmentsFromFile_MissingFile(t *testing.T) {
	_, err := LoadAuditorAmendmentsFromFile("/tmp/this-file-must-not-exist-for-test")
	if err == nil {
		t.Fatal("missing file must error")
	}
	if !strings.Contains(err.Error(), "read amendment file") {
		t.Errorf("error wrap missing path: %v", err)
	}
}

// TestLoadAuditorAmendmentsFromFile_MalformedJSON pins the json
// surface.
func TestLoadAuditorAmendmentsFromFile_MalformedJSON(t *testing.T) {
	path := writeManifest(t, `{"not": "an array"}`)
	_, err := LoadAuditorAmendmentsFromFile(path)
	if err == nil {
		t.Fatal("malformed JSON must error")
	}
	if !strings.Contains(err.Error(), "parse amendment file") {
		t.Errorf("error wrap missing parse-failure context: %v", err)
	}
}

// TestLoadAuditorAmendmentsFromFile_HappyPath pins the round-trip + the
// load-order-independent sort discipline.
//
// The fixture lists EffectiveSeq in descending order (200, 100, 50) —
// the returned slice MUST be sorted ascending so the SDK's
// ResolveAuditorAt contract is satisfied at the boundary regardless
// of operator file ordering.
func TestLoadAuditorAmendmentsFromFile_HappyPath(t *testing.T) {
	path := writeManifest(t, validAmendmentManifest)
	got, err := LoadAuditorAmendmentsFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 amendments; got %d", len(got))
	}
	if !sort.IsSorted(got) {
		var seqs []uint64
		for _, r := range got {
			seqs = append(seqs, r.EffectivePos.Sequence)
		}
		t.Errorf("amendments not sorted ascending; got sequences %v", seqs)
	}
	// Lowest EffectiveSeq must be at index 0.
	if got[0].EffectivePos.Sequence != 50 {
		t.Errorf("got[0].EffectivePos.Sequence = %d, want 50",
			got[0].EffectivePos.Sequence)
	}
	if got[0].Payload.AuditorDID != "did:web:auditor-c.example.org" {
		t.Errorf("got[0].Payload.AuditorDID = %q, want %q",
			got[0].Payload.AuditorDID, "did:web:auditor-c.example.org")
	}
	// Fixture's new_scope=4 → ScopeSMTReplay (1<<2). Pinning the bit
	// here surfaces a regression that re-interpreted JSON ints as a
	// different scope encoding.
	if got[0].Payload.NewScope != network.ScopeSMTReplay {
		t.Errorf("got[0].Payload.NewScope = %d, want ScopeSMTReplay (%d)",
			got[0].Payload.NewScope, network.ScopeSMTReplay)
	}
}

// TestLoadAuditorAmendmentsFromFile_PerRowValidateFailure pins the
// error-message shape: the wrap MUST name the row index AND the
// AuditorDID so the operator can identify the manifest line.
func TestLoadAuditorAmendmentsFromFile_PerRowValidateFailure(t *testing.T) {
	// new_scope = 0 violates the SDK's "scope must be non-zero" rule.
	bad := `[
	  {
	    "effective_seq": 100,
	    "auditor_did":   "did:web:auditor-zero-scope.example.org",
	    "new_scope":     0
	  }
	]`
	path := writeManifest(t, bad)
	_, err := LoadAuditorAmendmentsFromFile(path)
	if err == nil {
		t.Fatal("zero-scope amendment must fail validate")
	}
	if !strings.Contains(err.Error(), "amendments[0]") {
		t.Errorf("error must name the row index 'amendments[0]'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "did:web:auditor-zero-scope.example.org") {
		t.Errorf("error must name the AuditorDID; got: %v", err)
	}
}

// TestLoadAuditorAmendmentsFromFile_EmptyArray pins the empty-array
// path: a valid manifest with no rows returns a non-nil empty slice
// (so the reconciler engages the amendment stream as "Gap 2 source
// wired but empty" rather than the nil "no source wired" path).
func TestLoadAuditorAmendmentsFromFile_EmptyArray(t *testing.T) {
	path := writeManifest(t, `[]`)
	got, err := LoadAuditorAmendmentsFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Error("empty-array manifest must return non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────
// Ladder 5 P8 (#21) — resource-cap tests (symmetric to the
// registry-loader caps; see auditor_registry_test.go)
// ─────────────────────────────────────────────────────────────────

// TestLoadAuditorAmendmentsFromFile_OversizeFile_Rejected pins the
// bytes-cap refusal for the amendment loader. Symmetric to the
// registry test of the same shape.
func TestLoadAuditorAmendmentsFromFile_OversizeFile_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversize-amendments.json")
	blob := make([]byte, MaxRegistryFileBytes+1)
	for i := range blob {
		blob[i] = 'A'
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadAuditorAmendmentsFromFile(path)
	if err == nil {
		t.Fatal("oversize file must be rejected; got nil error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error must name the file path %q; got: %v", path, err)
	}
	if !strings.Contains(err.Error(), "MaxRegistryFileBytes") {
		t.Errorf("error must name MaxRegistryFileBytes; got: %v", err)
	}
}

// TestLoadAuditorAmendmentsFromFile_TooManyRecords_Rejected pins the
// records-cap refusal for the amendment loader. The fixture builds
// MaxRegistryRecords+1 valid-shape amendment entries (smaller than
// the registry shape, so well inside the bytes cap).
func TestLoadAuditorAmendmentsFromFile_TooManyRecords_Rejected(t *testing.T) {
	entry := `{"effective_seq":0,"auditor_did":"did:web:x","new_scope":2}`
	body := "["
	for i := 0; i < MaxRegistryRecords+1; i++ {
		if i > 0 {
			body += ","
		}
		body += entry
	}
	body += "]"
	if int64(len(body)) > MaxRegistryFileBytes {
		t.Fatalf("test fixture exceeds bytes cap (%d > %d); would test the wrong cap",
			len(body), MaxRegistryFileBytes)
	}
	path := writeManifest(t, body)
	_, err := LoadAuditorAmendmentsFromFile(path)
	if err == nil {
		t.Fatal("too-many-records file must be rejected; got nil error")
	}
	if !strings.Contains(err.Error(), "MaxRegistryRecords") {
		t.Errorf("error must name MaxRegistryRecords; got: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error must name the file path %q; got: %v", path, err)
	}
}
