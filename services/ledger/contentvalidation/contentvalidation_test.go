package contentvalidation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/crypto/artifact"
)

// reset clears the package-global custom registry between tests (internal access).
func reset() {
	mu.Lock()
	custom = map[string]artifact.ContentValidator{}
	mu.Unlock()
}

func TestBuildValidator_NilWhenNothingToEnforce(t *testing.T) {
	reset()
	if v := BuildValidator(nil, false); v != nil {
		t.Fatalf("no accepted types, no customs, not deny-unknown => want nil validator, got %T", v)
	}
}

func TestBuildValidator_AcceptedReferenceType(t *testing.T) {
	reset()
	v := BuildValidator([]string{"application/pdf"}, true)
	if v == nil {
		t.Fatal("accepted pdf should produce a validator")
	}
	ctx := context.Background()
	if err := v.Validate(ctx, "application/pdf", []byte("%PDF-1.7")); err != nil {
		t.Fatalf("valid pdf: %v", err)
	}
	if err := v.Validate(ctx, "application/pdf", []byte("not a pdf")); !errors.Is(err, artifact.ErrContentTypeMismatch) {
		t.Fatalf("bad pdf: want mismatch, got %v", err)
	}
	// deny-unknown: a type with no validator is rejected.
	if err := v.Validate(ctx, "application/zip", []byte("PK")); !errors.Is(err, artifact.ErrContentTypeMismatch) {
		t.Fatalf("unlisted type under deny-unknown: want mismatch, got %v", err)
	}
}

// TestRegister_CustomValidator is the load-bearing extensibility test (the
// network requirement): a network registers a validator for a CUSTOM MIME type
// and it is enforced at the gate exactly like a reference type — no fork, no SDK
// change. This is the JN-supports-custom-artifact-types path.
func TestRegister_CustomValidator(t *testing.T) {
	reset()
	// A custom validator for a network-specific artifact type.
	Register("application/x-jn-evidence", artifact.ValidatorFunc(
		func(_ context.Context, _ string, b []byte) error {
			if !bytes.HasPrefix(b, []byte("JNX")) {
				return fmt.Errorf("%w: missing JNX magic", artifact.ErrContentTypeMismatch)
			}
			return nil
		}))
	if Registered() != 1 {
		t.Fatalf("Registered() = %d, want 1", Registered())
	}

	// No accepted reference types, but the custom validator + deny-unknown means
	// the custom type is enforced and everything else is denied.
	v := BuildValidator(nil, true)
	if v == nil {
		t.Fatal("a registered custom validator must produce a validator")
	}
	ctx := context.Background()
	if err := v.Validate(ctx, "application/x-jn-evidence", []byte("JNX-payload")); err != nil {
		t.Fatalf("valid custom artifact rejected: %v", err)
	}
	if err := v.Validate(ctx, "application/x-jn-evidence", []byte("forged")); !errors.Is(err, artifact.ErrContentTypeMismatch) {
		t.Fatalf("forged custom artifact: want mismatch, got %v", err)
	}
	if err := v.Validate(ctx, "application/zip", []byte("PK")); !errors.Is(err, artifact.ErrContentTypeMismatch) {
		t.Fatalf("unregistered type under deny-unknown: want mismatch, got %v", err)
	}
}

func TestRegister_NilAndEmptyIgnored(t *testing.T) {
	reset()
	Register("", artifact.PDFValidator{}) // empty mime ignored
	Register("x/y", nil)                  // nil validator ignored
	if Registered() != 0 {
		t.Fatalf("Registered() = %d, want 0 (nil + empty ignored)", Registered())
	}
}
