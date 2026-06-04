package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/artifact"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
)

// TestContentTypeCompliance_DetectsFalseClaim is the core integrity check: a
// committed artifact whose bytes do NOT match its signed MIME claim fires a
// Critical alert; an honest one is silent. The auditor runs the SAME
// crypto/artifact mechanism the producer FINISH gate runs — no on-log policy.
func TestContentTypeCompliance_DetectsFalseClaim(t *testing.T) {
	ctx := context.Background()
	store := storage.NewInMemoryContentStore()

	goodPDF := []byte("%PDF-1.7\nhonest pdf")
	badPDF := []byte("this is not a pdf at all")
	goodCID := storage.Compute(goodPDF)
	badCID := storage.Compute(badPDF)
	if err := store.Push(ctx, goodCID, goodPDF); err != nil {
		t.Fatal(err)
	}
	if err := store.Push(ctx, badCID, badPDF); err != nil {
		t.Fatal(err)
	}

	cfg := ContentTypeCheckConfig{
		Claims: []ArtifactClaim{
			{ContentCID: goodCID, DeclaredMIME: "application/pdf"},
			{ContentCID: badCID, DeclaredMIME: "application/pdf"}, // a false claim
		},
		Validator: artifact.BuildRegistry([]string{"application/pdf"}, false),
		Backend:   "test",
	}

	res, err := CheckContentTypeCompliance(ctx, cfg, store, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("CheckContentTypeCompliance: %v", err)
	}
	if res.Checked != 2 {
		t.Fatalf("Checked = %d, want 2", res.Checked)
	}
	if res.Mismatches != 1 {
		t.Fatalf("Mismatches = %d, want 1 (the false PDF claim)", res.Mismatches)
	}
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != sdkmonitoring.Critical ||
		res.Alerts[0].Monitor != MonitorContentTypeCompliance {
		t.Fatalf("want exactly one Critical content_type_compliance alert, got %+v", res.Alerts)
	}
}

// TestContentTypeCompliance_NilValidatorIsClaimPresenceOnly: with no validator,
// the monitor fetches but does not byte-validate — no mismatch is ever raised.
func TestContentTypeCompliance_NilValidatorIsClaimPresenceOnly(t *testing.T) {
	ctx := context.Background()
	store := storage.NewInMemoryContentStore()
	bad := []byte("not a pdf")
	cid := storage.Compute(bad)
	_ = store.Push(ctx, cid, bad)

	res, err := CheckContentTypeCompliance(ctx, ContentTypeCheckConfig{
		Claims:    []ArtifactClaim{{ContentCID: cid, DeclaredMIME: "application/pdf"}},
		Validator: nil,
	}, store, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Mismatches != 0 || len(res.Alerts) != 0 {
		t.Fatalf("nil validator must not raise mismatches; got %+v", res)
	}
}

// TestContentTypeCompliance_MissingBytesIsWarning: a claim whose bytes can't be
// fetched is a Warning (presence is blob_availability's job), not a type mismatch.
func TestContentTypeCompliance_MissingBytesIsWarning(t *testing.T) {
	ctx := context.Background()
	store := storage.NewInMemoryContentStore()
	cid := storage.Compute([]byte("never pushed"))

	res, err := CheckContentTypeCompliance(ctx, ContentTypeCheckConfig{
		Claims:    []ArtifactClaim{{ContentCID: cid, DeclaredMIME: "application/pdf"}},
		Validator: artifact.BuildRegistry([]string{"application/pdf"}, false),
	}, store, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Mismatches != 0 {
		t.Fatalf("missing bytes must not be a mismatch, got %d", res.Mismatches)
	}
	if len(res.Alerts) != 1 || res.Alerts[0].Severity != sdkmonitoring.Warning {
		t.Fatalf("missing bytes should be one Warning, got %+v", res.Alerts)
	}
}

// TestContentTypeCompliance_EmptyMIMESkipped: an opaque artifact (no MIME claim)
// is not checked.
func TestContentTypeCompliance_EmptyMIMESkipped(t *testing.T) {
	res, err := CheckContentTypeCompliance(context.Background(), ContentTypeCheckConfig{
		Claims: []ArtifactClaim{{ContentCID: storage.Compute([]byte("x")), DeclaredMIME: ""}},
	}, storage.NewInMemoryContentStore(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 0 {
		t.Fatalf("empty MIME claim must be skipped, Checked = %d", res.Checked)
	}
}
