package monitoring

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/gossip/findings"
)

type stubApplier struct {
	called bool
	err    error
}

func (s *stubApplier) Apply(_ context.Context, _ *findings.EquivocationFinding) error {
	s.called = true
	return s.err
}

func TestEquivocationResponder_DrivesSlasher(t *testing.T) {
	ap := &stubApplier{}
	r, err := NewEquivocationResponder(ap, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Respond(context.Background(), &findings.EquivocationFinding{LedgerEndpoint: "https://led"}); err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if !ap.called {
		t.Fatal("slasher.Apply not called")
	}
}

func TestEquivocationResponder_PropagatesSlasherError(t *testing.T) {
	ap := &stubApplier{err: errors.New("boom")}
	r, _ := NewEquivocationResponder(ap, nil)
	err := r.Respond(context.Background(), &findings.EquivocationFinding{LedgerEndpoint: "x"})
	if !errors.Is(err, ErrEquivocationResponse) {
		t.Fatalf("err = %v, want ErrEquivocationResponse", err)
	}
}

func TestEquivocationResponder_NilFinding(t *testing.T) {
	r, _ := NewEquivocationResponder(&stubApplier{}, nil)
	if err := r.Respond(context.Background(), nil); err == nil {
		t.Fatal("nil finding must error")
	}
}

func TestNewEquivocationResponder_NilSlasher(t *testing.T) {
	if _, err := NewEquivocationResponder(nil, nil); err == nil {
		t.Fatal("nil slasher must error")
	}
}
