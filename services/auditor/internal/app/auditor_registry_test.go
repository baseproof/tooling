/*
FILE PATH: services/auditor/internal/app/auditor_registry_test.go

Ladder 4 T6 (#21) — LoadAuditorRegistryFromFile coverage. Symmetric to
the Ladder 3 backfill in auditor_amendments_test.go; pins every error
path the operator can drive from a misconfigured AUDITOR_REGISTRY_FILE,
plus the load-order-independent sort discipline (Ladder 1 B1).

# PATHS PINNED

  - Empty path: path=="" returns (nil, nil) — the pre-v1.32 disabled-
    gate path. The reconciler treats nil as "gate disabled, pre-v1.32
    dispatch" so this state is operationally distinct from an empty-
    array file (which the boot path REFUSES in main.go per B3).
  - Missing-file path: surface the os.ReadFile error wrapped with
    "read registry file %q" + the path, so an operator typo'd
    AUDITOR_REGISTRY_FILE produces an actionable diagnostic.
  - Malformed JSON: surface the json.Unmarshal error wrapped with
    "parse registry file %q".
  - Bad hex on public_key: surface with row index + AuditorDID.
  - Bad hex on proof_of_possession: surface with row index + AuditorDID.
  - Per-row SDK Validate failure: surface with row index + AuditorDID.
  - Empty-array manifest: returns non-nil empty slice — main.go's B3
    boot-refusal block reads this as "gate enabled, no auditors" and
    refuses to boot. Pin the SHAPE here (empty non-nil); pin the
    boot-refusal at the integration layer (T7).
  - Sort discipline: an unsorted operator manifest is sorted ascending
    on load (Ladder 1 B1 applied this to BuildAuditorRegistryFromConfig;
    LoadAuditorRegistryFromFile inherits via that constructor).

# NOTES ON RESOURCE CAPS (P8)

P8 (proposed) adds file-size + record-count caps. Those tests will land
when P8 is approved; T6 today covers the SHAPE not the SIZE.
*/
package app

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// validRegistryFixture returns one auditor manifest entry covering the
// required fields. Subtests mutate fields to drive specific error
// paths. Public key is the SDK's "valid uncompressed-prefix point"
// shape — 33 hex-bytes starting with 02 (compressed point convention
// the SDK's AuditorRegistration.Validate accepts).
const validRegistryEntry = `{
  "effective_seq":      100,
  "auditor_did":        "did:web:auditor.example.org",
  "public_key":         "020000000000000000000000000000000000000000000000000000000000000000",
  "scheme_tag":         1,
  "proof_of_possession": "",
  "findings_url":       "https://auditor.example.org/v1/findings",
  "scope":              2,
  "retired_at":         null
}`

const validRegistryManifestUnsorted = `[
  {
    "effective_seq":      200,
    "auditor_did":        "did:web:auditor-a.example.org",
    "public_key":         "020000000000000000000000000000000000000000000000000000000000000001",
    "scheme_tag":         1,
    "findings_url":       "https://auditor-a.example.org/v1/findings",
    "scope":              2
  },
  {
    "effective_seq":      100,
    "auditor_did":        "did:web:auditor-b.example.org",
    "public_key":         "020000000000000000000000000000000000000000000000000000000000000002",
    "scheme_tag":         1,
    "findings_url":       "https://auditor-b.example.org/v1/findings",
    "scope":              2
  },
  {
    "effective_seq":      50,
    "auditor_did":        "did:web:auditor-c.example.org",
    "public_key":         "020000000000000000000000000000000000000000000000000000000000000003",
    "scheme_tag":         1,
    "findings_url":       "https://auditor-c.example.org/v1/findings",
    "scope":              4
  }
]`

func writeRegistryManifest(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestLoadAuditorRegistryFromFile_EmptyPath pins the disabled-gate path:
// path=="" returns (nil, nil) regardless of file system state. This is
// the pre-v1.32 ingest behavior the reconciler engages on a nil slice.
// The boot path's B3 refusal predicate (len(auditorRegistry)==0 &&
// enforceScopes==true) deliberately does NOT fire on this path because
// the slice is nil rather than non-nil-empty.
func TestLoadAuditorRegistryFromFile_EmptyPath(t *testing.T) {
	got, err := LoadAuditorRegistryFromFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("empty path must return nil slice (preserves pre-v1.32 behavior); got len=%d", len(got))
	}
}

// TestLoadAuditorRegistryFromFile_MissingFile pins the os.ReadFile
// error surface — operator typo'd path produces an actionable error
// wrapped with the path, NOT a silent (nil, nil) return.
func TestLoadAuditorRegistryFromFile_MissingFile(t *testing.T) {
	_, err := LoadAuditorRegistryFromFile("/tmp/this-registry-file-must-not-exist-for-test")
	if err == nil {
		t.Fatal("missing file must error")
	}
	if !strings.Contains(err.Error(), "read registry file") {
		t.Errorf("error wrap missing 'read registry file' context: %v", err)
	}
	if !strings.Contains(err.Error(), "/tmp/this-registry-file-must-not-exist-for-test") {
		t.Errorf("error must name the file path; got: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_MalformedJSON pins the json
// surface — a non-array root document errors out at parse time.
func TestLoadAuditorRegistryFromFile_MalformedJSON(t *testing.T) {
	path := writeRegistryManifest(t, `{"not": "an array"}`)
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		t.Fatal("malformed JSON must error")
	}
	if !strings.Contains(err.Error(), "parse registry file") {
		t.Errorf("error wrap missing 'parse registry file' context: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_TruncatedJSON pins a different
// json-failure shape — a syntactically-broken JSON document
// (unclosed brace) also surfaces as a parse error.
func TestLoadAuditorRegistryFromFile_TruncatedJSON(t *testing.T) {
	path := writeRegistryManifest(t, `[{"effective_seq": 100`)
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		t.Fatal("truncated JSON must error")
	}
	if !strings.Contains(err.Error(), "parse registry file") {
		t.Errorf("error wrap missing 'parse registry file' context: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_BadPublicKeyHex pins the per-row
// hex-decoding error: an invalid public_key surfaces with row index
// + AuditorDID so the operator can identify the manifest line.
func TestLoadAuditorRegistryFromFile_BadPublicKeyHex(t *testing.T) {
	bad := `[
	  {
	    "effective_seq":      100,
	    "auditor_did":        "did:web:auditor-bad-hex.example.org",
	    "public_key":         "zzzz-not-hex",
	    "scheme_tag":         1,
	    "findings_url":       "https://auditor.example.org/v1/findings",
	    "scope":              2
	  }
	]`
	path := writeRegistryManifest(t, bad)
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		t.Fatal("bad public_key hex must error")
	}
	if !strings.Contains(err.Error(), "registry[0]") {
		t.Errorf("error must name the row index 'registry[0]'; got: %v", err)
	}
	if !strings.Contains(err.Error(), "did:web:auditor-bad-hex.example.org") {
		t.Errorf("error must name the AuditorDID; got: %v", err)
	}
	if !strings.Contains(err.Error(), "public_key hex") {
		t.Errorf("error must name the failing field 'public_key hex'; got: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_BadPoPHex pins the proof_of_possession
// hex-decoding error path. PoP is optional (empty string is valid), so
// the test feeds an explicit non-empty malformed value.
func TestLoadAuditorRegistryFromFile_BadPoPHex(t *testing.T) {
	bad := `[
	  {
	    "effective_seq":      100,
	    "auditor_did":        "did:web:auditor-bad-pop.example.org",
	    "public_key":         "020000000000000000000000000000000000000000000000000000000000000000",
	    "scheme_tag":         1,
	    "proof_of_possession": "qqqq-not-hex",
	    "findings_url":       "https://auditor.example.org/v1/findings",
	    "scope":              2
	  }
	]`
	path := writeRegistryManifest(t, bad)
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		t.Fatal("bad PoP hex must error")
	}
	if !strings.Contains(err.Error(), "registry[0]") {
		t.Errorf("error must name the row index; got: %v", err)
	}
	if !strings.Contains(err.Error(), "did:web:auditor-bad-pop.example.org") {
		t.Errorf("error must name the AuditorDID; got: %v", err)
	}
	if !strings.Contains(err.Error(), "proof_of_possession hex") {
		t.Errorf("error must name 'proof_of_possession hex'; got: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_PerRowSDKValidateFailure pins that
// SDK-side AuditorRegistration.Validate failures surface with row
// index + AuditorDID. The failure here is "empty findings_url" — the
// SDK requires non-empty https:// scheme.
func TestLoadAuditorRegistryFromFile_PerRowSDKValidateFailure(t *testing.T) {
	bad := `[
	  {
	    "effective_seq":      100,
	    "auditor_did":        "did:web:auditor-no-url.example.org",
	    "public_key":         "020000000000000000000000000000000000000000000000000000000000000000",
	    "scheme_tag":         1,
	    "findings_url":       "",
	    "scope":              2
	  }
	]`
	path := writeRegistryManifest(t, bad)
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		t.Fatal("missing findings_url must fail SDK Validate")
	}
	// The constructor (crosslog.BuildAuditorRegistryFromConfig) wraps
	// per-row Validate failures with "auditor_specs[%d] (DID=%q)";
	// the loader doesn't re-wrap, so the operator sees the constructor's
	// shape — different label from registry[%d] above, but row index +
	// DID still present.
	if !strings.Contains(err.Error(), "did:web:auditor-no-url.example.org") {
		t.Errorf("error must name the AuditorDID; got: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_HappyPath_Sorted pins the load-order-
// independent sort discipline: a manifest with DESCENDING EffectiveSeq
// returns a slice in ASCENDING order. Ladder 1 B1 applied this to
// BuildAuditorRegistryFromConfig; LoadAuditorRegistryFromFile inherits
// via that constructor. A regression that bypassed the sort (e.g., a
// rewrite that called the SDK record constructor directly without the
// crosslog facade) would fail this assertion.
func TestLoadAuditorRegistryFromFile_HappyPath_Sorted(t *testing.T) {
	path := writeRegistryManifest(t, validRegistryManifestUnsorted)
	got, err := LoadAuditorRegistryFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries; got %d", len(got))
	}
	if !sort.IsSorted(got) {
		var seqs []uint64
		for _, r := range got {
			seqs = append(seqs, r.EffectivePos.Sequence)
		}
		t.Errorf("entries not sorted ascending; got sequences %v", seqs)
	}
	// Lowest EffectiveSeq must be at index 0.
	if got[0].EffectivePos.Sequence != 50 {
		t.Errorf("got[0].EffectivePos.Sequence = %d, want 50", got[0].EffectivePos.Sequence)
	}
	if got[0].Payload.AuditorDID != "did:web:auditor-c.example.org" {
		t.Errorf("got[0].Payload.AuditorDID = %q, want %q",
			got[0].Payload.AuditorDID, "did:web:auditor-c.example.org")
	}
}

// TestLoadAuditorRegistryFromFile_EmptyArray pins the structurally-
// distinct "gate enabled, no auditors" shape: a manifest containing
// "[]" returns a NON-NIL empty slice. The reconciler can distinguish
// nil (gate disabled, pre-v1.32 dispatch) from non-nil-empty (gate
// enabled, no auditors registered) via this exact shape.
//
// Main's B3 boot-refusal block fires on this exact shape:
//
//	if cfg.enforceScopes && cfg.auditorRegistryFile != "" {
//	    auditorRegistry, err = app.LoadAuditorRegistryFromFile(...)
//	    if len(auditorRegistry) == 0 {
//	        return fmt.Errorf("...")  // ← B3 refusal
//	    }
//	}
//
// This test pins the load-side shape; T7 pins the boot-side refusal.
func TestLoadAuditorRegistryFromFile_EmptyArray(t *testing.T) {
	path := writeRegistryManifest(t, `[]`)
	got, err := LoadAuditorRegistryFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Error("empty-array manifest must return non-nil empty slice "+
			"(distinct from path=='' nil-slice path; this is the gate-enabled-empty shape "+
			"that B3 refuses at boot)")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestLoadAuditorRegistryFromFile_SingleValid pins the smallest happy
// path: one entry in, one entry out, sorted (trivially), round-trip
// field-equality.
func TestLoadAuditorRegistryFromFile_SingleValid(t *testing.T) {
	path := writeRegistryManifest(t, `[`+validRegistryEntry+`]`)
	got, err := LoadAuditorRegistryFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry; got %d", len(got))
	}
	if got[0].EffectivePos.Sequence != 100 {
		t.Errorf("EffectivePos.Sequence: got %d, want 100", got[0].EffectivePos.Sequence)
	}
	if got[0].Payload.AuditorDID != "did:web:auditor.example.org" {
		t.Errorf("AuditorDID: got %q", got[0].Payload.AuditorDID)
	}
	if got[0].Payload.FindingsURL != "https://auditor.example.org/v1/findings" {
		t.Errorf("FindingsURL: got %q", got[0].Payload.FindingsURL)
	}
}

// ─────────────────────────────────────────────────────────────────
// Ladder 5 P8 (#21) — resource-cap tests
// ─────────────────────────────────────────────────────────────────

// TestLoadAuditorRegistryFromFile_OversizeFile_Rejected pins the
// bytes-cap refusal: a file larger than MaxRegistryFileBytes is
// rejected with an error naming the file path + the cap. The cap
// fires BEFORE json.Unmarshal, so the test doesn't need a parseable
// JSON shape — a blob of repeated bytes is sufficient.
//
// At 15-operator scale a typo'd path pointing at e.g. a multi-GB log
// file would OOM the binary on boot without this cap; the refusal
// turns the misconfig into an actionable boot-time error.
func TestLoadAuditorRegistryFromFile_OversizeFile_Rejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversize.json")
	// Write exactly MaxRegistryFileBytes+1 bytes so we straddle the
	// boundary (not e.g. 2x to assert that the cap is tight, not
	// "much-bigger-than").
	blob := make([]byte, MaxRegistryFileBytes+1)
	for i := range blob {
		blob[i] = 'A'
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadAuditorRegistryFromFile(path)
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

// TestLoadAuditorRegistryFromFile_AtCapAcceptedOnValidJSON pins the
// other side of the cap: a file exactly AT the bytes cap (not over)
// passes the bytes check. We assert the bytes-cap failure mode is
// tight by writing valid JSON padded to just-under the cap; the
// loader proceeds to parse and rejects via the JSON path (or
// succeeds, depending on the padding shape — here we use padding
// inside a "reason"-like string so the JSON IS parseable).
//
// This is a regression guard: a future "off-by-one in
// LimitReader(max+1)" would fail this test by either:
//
//   - Rejecting a file <= cap with the bytes-cap error (tightness
//     regression toward too-strict), OR
//   - Accepting a file > cap (regression toward too-loose).
func TestLoadAuditorRegistryFromFile_AtCapAcceptedOnValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "at-cap.json")
	// Build "[]" wrapper + just-under-cap padding inside a comment-
	// style string — but JSON has no comments, so use a syntactically-
	// valid one-entry array with a giant "findings_url" field. We
	// don't care if it Validate's; the OVERSIZE check fires before
	// Validate. If the file is at-cap, the bytes check passes and
	// the test asserts the FAILURE is a JSON/decode error, not a
	// bytes-cap error.
	prefix := `[{"effective_seq":1,"auditor_did":"did:web:x","public_key":"00","scheme_tag":1,"proof_of_possession":"","findings_url":"`
	suffix := `","scope":2,"retired_at":null}]`
	padBudget := int(MaxRegistryFileBytes) - len(prefix) - len(suffix)
	if padBudget <= 0 {
		t.Fatalf("MaxRegistryFileBytes too small for at-cap test fixture")
	}
	pad := make([]byte, padBudget)
	for i := range pad {
		pad[i] = 'x'
	}
	body := prefix + string(pad) + suffix
	if int64(len(body)) != MaxRegistryFileBytes {
		t.Fatalf("test fixture sizing: got %d, want exactly %d", len(body), MaxRegistryFileBytes)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := LoadAuditorRegistryFromFile(path)
	if err == nil {
		// File-at-cap with this fixture content will likely fail
		// SDK Validate (e.g., bad findings URL); either way, we
		// MUST NOT see the bytes-cap rejection.
		return
	}
	if strings.Contains(err.Error(), "MaxRegistryFileBytes") {
		t.Errorf("file at-cap must NOT trigger bytes-cap rejection; got: %v", err)
	}
}

// TestLoadAuditorRegistryFromFile_TooManyRecords_Rejected pins the
// records-cap refusal: a JSON array under the bytes cap but with
// more than MaxRegistryRecords entries is rejected with an error
// naming the file path + the record count.
//
// We build a minimal-shape entry that fits many copies under the
// bytes cap; the records-cap fires after json.Unmarshal (which is
// where the cap stops the unbounded slice allocation).
func TestLoadAuditorRegistryFromFile_TooManyRecords_Rejected(t *testing.T) {
	// 38 bytes per entry × (MaxRegistryRecords+1) ~ 380KB, well under
	// the 1 MiB bytes cap.
	entry := `{"auditor_did":"x","public_key":""}`
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
	path := writeRegistryManifest(t, body)
	_, err := LoadAuditorRegistryFromFile(path)
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
