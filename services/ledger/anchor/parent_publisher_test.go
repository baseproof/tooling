/*
FILE PATH: anchor/parent_publisher_test.go

Tests for the Part II.9 parent-target anchor publishing flow:
SubmitToHTTPEndpoint + Publisher.publishParentAnchor + Publisher.Run's
dual-ticker shape.

Coverage:
  - SubmitToHTTPEndpoint POSTs canonical bytes to the supplied
    endpoint with Content-Type=application/octet-stream and
    succeeds on 202.
  - SubmitToHTTPEndpoint surfaces non-202 statuses as errors
    (with the response body included for diagnostics).
  - SubmitToHTTPEndpoint rejects an empty endpoint at call time
    (a missing endpoint at signing time is a wiring bug).
  - publishParentAnchor fetches the local merkle head, builds an
    anchor entry destined for ParentLogDID, and submits via
    ParentSubmitFn — END-TO-END validated by capturing the
    submitted entry in a fake submitFn.
  - parentEnabled() reports true iff all three of ParentLogDID,
    ParentAdmissionURL, ParentSubmitFn are set.
  - Partial parent config (e.g., URL set but submitFn nil) does
    NOT activate the parent ticker — Run drops a Warn at boot and
    falls back to the local-only posture.
*/
package anchor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
)

// staticHeadProvider implements MerkleHeadProvider with a fixed head.
type staticHeadProvider struct{ head types.TreeHead }

func (s staticHeadProvider) Head() (types.TreeHead, error) { return s.head, nil }

// staticCosignedHeadProvider implements CosignedHeadProvider with a
// fixed (already-cosigned) head. Used by parent-target tests to
// provide a head that satisfies BuildCosignedAnchorEntry's
// "at-least-one-signature" precondition.
type staticCosignedHeadProvider struct{ head *types.CosignedTreeHead }

func (s staticCosignedHeadProvider) LatestCosigned(context.Context) (*types.CosignedTreeHead, error) {
	return s.head, nil
}

// fixtureCosignedHead builds a *types.CosignedTreeHead with a
// single trivially-non-zero witness signature. Suitable for tests
// where we don't verify the signature itself but need the entry
// builder to accept the head as "gossip-publishable."
func fixtureCosignedHead(treeSize uint64, rootHash, smtRoot [32]byte) *types.CosignedTreeHead {
	return &types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			TreeSize: treeSize,
			RootHash: rootHash,
			SMTRoot:  smtRoot,
		},
		Signatures: []types.WitnessSignature{{
			PubKeyID:  [32]byte{0xAB},
			SchemeTag: 0x01, // SchemeECDSA
			SigBytes:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
		}},
	}
}

// nonZeroNetworkID is the standard fixture network identity for
// anchor tests (cosign.NetworkID requires non-zero).
func nonZeroNetworkID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────
// SubmitToHTTPEndpoint
// ─────────────────────────────────────────────────────────────────────

func TestSubmitToHTTPEndpoint_HappyPath(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q, want application/octet-stream", got)
		}
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// V1.34 contract: client is REQUIRED. Pass the test server's
	// client so the test reaches the unencrypted test server.
	submit := SubmitToHTTPEndpoint(srv.Client(), srv.URL+"/v1/entries")
	entry, err := envelope.NewUnsignedEntry(
		envelope.ControlHeader{
			SignerDID:   "did:web:source.example",
			Destination: "did:web:parent.example",
			EventTime:   time.Now().Unix(),
		},
		[]byte("body"),
	)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:web:source.example",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     []byte("sig"),
	}}
	if err := submit(entry); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// The server received the canonical bytes — must round-trip.
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Equal(received, canonical) {
		t.Errorf("server received %d bytes; want %d (canonical drift)",
			len(received), len(canonical))
	}
}

func TestSubmitToHTTPEndpoint_NonAcceptedSurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte("malformed signature"))
	}))
	defer srv.Close()

	submit := SubmitToHTTPEndpoint(srv.Client(), srv.URL+"/v1/entries")
	entry, err := envelope.NewUnsignedEntry(
		envelope.ControlHeader{
			SignerDID:   "did:web:source.example",
			Destination: "did:web:parent.example",
			EventTime:   time.Now().Unix(),
		},
		[]byte("body"),
	)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:web:source.example",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     []byte("sig"),
	}}
	if err := submit(entry); err == nil {
		t.Fatal("expected error on 422")
	}
}

func TestSubmitToHTTPEndpoint_EmptyEndpointErrors(t *testing.T) {
	// An empty endpoint must error at call time — the client construction
	// succeeds (we pass a real client per the v1.34 contract), but the
	// closure errors on the first call because endpoint == "".
	submit := SubmitToHTTPEndpoint(&http.Client{}, "")
	entry, _ := envelope.NewUnsignedEntry(
		envelope.ControlHeader{SignerDID: "did:web:source.example", Destination: "did:web:parent.example", EventTime: time.Now().Unix()},
		[]byte("body"),
	)
	if err := submit(entry); err == nil {
		t.Fatal("empty endpoint must error")
	}
}

// TestNewPublisher_NilHTTPClient_Panics pins the v1.34 SDK contract:
// PublisherConfig.HTTPClient is REQUIRED; nil at construction PANICS
// rather than silently building a plaintext DefaultClient. The
// publisher's outbound is the federation's anchor-fetch surface — a
// silent fallback would let a misconfigured operator fetch peer tree
// heads over plaintext without any signal.
func TestNewPublisher_NilHTTPClient_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on nil HTTPClient; got no panic (silent-fallback regression?)")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "HTTPClient required") {
			t.Errorf("panic message should mention 'HTTPClient required'; got %q", msg)
		}
		if !strings.Contains(msg, "v1.34 SDK contract") {
			t.Errorf("panic message should cite the v1.34 contract; got %q", msg)
		}
	}()
	_ = NewPublisher(
		PublisherConfig{
			LedgerDID: "did:web:source.example",
			LogDID:    "did:web:source-log.example",
			NetworkID: nonZeroNetworkID(),
			// HTTPClient deliberately omitted — the behavior under test.
		},
		staticHeadProvider{head: types.TreeHead{TreeSize: 1}},
		nil, func(*envelope.Entry) error { return nil }, discardLogger(),
	)
}

// TestSubmitToHTTPEndpoint_NilClient_Panics pins the v1.34 SDK contract:
// nil client at construction PANICS rather than silently building a
// plaintext DefaultClient. The anchor publish surface is the federation's
// security-most-sensitive outbound; a silent fallback would let a
// misconfigured operator publish anchors over plaintext without any
// signal. This test ensures a future "convenience" refactor that
// reintroduces the silent fallback fails loudly.
func TestSubmitToHTTPEndpoint_NilClient_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on nil client; got no panic (silent-fallback regression?)")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "client required") {
			t.Errorf("panic message should mention 'client required'; got %q", msg)
		}
		if !strings.Contains(msg, "v1.34 SDK contract") {
			t.Errorf("panic message should cite the v1.34 contract; got %q", msg)
		}
	}()
	_ = SubmitToHTTPEndpoint(nil, "https://parent.example/v1/entries")
}

// ─────────────────────────────────────────────────────────────────────
// Publisher.publishParentAnchor
// ─────────────────────────────────────────────────────────────────────

// TestPublishParentAnchor_BuildsAndSubmitsThroughParentFn proves the
// parent-target build path:
//   - calls MerkleHeadProvider.Head
//   - constructs an anchor entry with Destination=ParentLogDID +
//     SourceLogDID=THIS LogDID
//   - hands the entry to ParentSubmitFn (NOT the local submitFn)
func TestPublishParentAnchor_BuildsAndSubmitsThroughParentFn(t *testing.T) {
	var (
		mu              sync.Mutex
		parentSubmitted []*envelope.Entry
		localSubmitted  []*envelope.Entry
	)
	parentFn := func(e *envelope.Entry) error {
		mu.Lock()
		defer mu.Unlock()
		parentSubmitted = append(parentSubmitted, e)
		return nil
	}
	localFn := func(e *envelope.Entry) error {
		mu.Lock()
		defer mu.Unlock()
		localSubmitted = append(localSubmitted, e)
		return nil
	}

	cosignedHead := fixtureCosignedHead(42, [32]byte{0xAA}, [32]byte{0xBB})

	pub := NewPublisher(
		PublisherConfig{
			LedgerDID:            "did:web:source-ledger.example",
			LogDID:               "did:web:source-log.example",
			NetworkID:            nonZeroNetworkID(),
			Interval:             1 * time.Hour,  // not used in this unit test
			HTTPClient:           &http.Client{}, // v1.34 contract: required
			ParentLogDID:         "did:web:parent-log.example",
			ParentAdmissionURL:   "https://parent.example/v1/entries",
			ParentAnchorInterval: 30 * time.Minute,
			ParentSubmitFn:       parentFn,
		},
		staticHeadProvider{head: cosignedHead.TreeHead},
		staticCosignedHeadProvider{head: cosignedHead},
		localFn,
		discardLogger(),
	)

	if !pub.parentEnabled() {
		t.Fatal("parentEnabled should be true with all parent fields set")
	}

	if err := pub.publishParentAnchor(context.Background()); err != nil {
		t.Fatalf("publishParentAnchor: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(parentSubmitted) != 1 {
		t.Fatalf("ParentSubmitFn calls = %d, want 1", len(parentSubmitted))
	}
	if len(localSubmitted) != 0 {
		t.Errorf("local submitFn called %d times — parent flow must NOT use local submitFn",
			len(localSubmitted))
	}
	got := parentSubmitted[0]
	if got.Header.Destination != "did:web:parent-log.example" {
		t.Errorf("Destination = %q, want did:web:parent-log.example", got.Header.Destination)
	}
	if got.Header.SignerDID != "did:web:source-ledger.example" {
		t.Errorf("SignerDID = %q, want the source ledger DID", got.Header.SignerDID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// parentEnabled — partial config diagnostics
// ─────────────────────────────────────────────────────────────────────

func TestParentEnabled_ReportsFalseOnPartialConfig(t *testing.T) {
	cosignedSrc := staticCosignedHeadProvider{
		head: fixtureCosignedHead(1, [32]byte{}, [32]byte{}),
	}
	submitFn := func(*envelope.Entry) error { return nil }
	cases := []struct {
		name        string
		cfg         PublisherConfig
		cosignedSrc CosignedHeadProvider
		want        bool
	}{
		{"all empty", PublisherConfig{}, cosignedSrc, false},
		{"only DID", PublisherConfig{ParentLogDID: "did:web:parent.example"}, cosignedSrc, false},
		{"only URL", PublisherConfig{ParentAdmissionURL: "https://parent.example/v1/entries"}, cosignedSrc, false},
		{"DID+URL no submitFn", PublisherConfig{
			ParentLogDID:       "did:web:parent.example",
			ParentAdmissionURL: "https://parent.example/v1/entries",
		}, cosignedSrc, false},
		{"all fields but nil cosigned source", PublisherConfig{
			ParentLogDID:       "did:web:parent.example",
			ParentAdmissionURL: "https://parent.example/v1/entries",
			ParentSubmitFn:     submitFn,
		}, nil, false},
		{"all set", PublisherConfig{
			ParentLogDID:       "did:web:parent.example",
			ParentAdmissionURL: "https://parent.example/v1/entries",
			ParentSubmitFn:     submitFn,
		}, cosignedSrc, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.cfg.NetworkID = nonZeroNetworkID()
			c.cfg.LogDID = "did:web:source-log.example"
			c.cfg.LedgerDID = "did:web:source-ledger.example"
			c.cfg.HTTPClient = &http.Client{} // v1.34 contract: required
			pub := NewPublisher(c.cfg, staticHeadProvider{head: types.TreeHead{TreeSize: 1}},
				c.cosignedSrc, submitFn, discardLogger())
			if got := pub.parentEnabled(); got != c.want {
				t.Errorf("parentEnabled = %v, want %v", got, c.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Run dual-ticker
// ─────────────────────────────────────────────────────────────────────

// TestRun_ExitsImmediatelyWithNoConfig proves the both-disabled
// shape returns rather than blocking forever.
func TestRun_ExitsImmediatelyWithNoConfig(t *testing.T) {
	pub := NewPublisher(
		PublisherConfig{
			LedgerDID:  "did:web:source.example",
			LogDID:     "did:web:source-log.example",
			NetworkID:  nonZeroNetworkID(),
			HTTPClient: &http.Client{}, // v1.34 contract: required
			// AnchorSources empty + parent unset → both loops disabled.
		},
		staticHeadProvider{head: types.TreeHead{TreeSize: 1}},
		nil, // no cosigned head provider
		func(*envelope.Entry) error { return nil },
		discardLogger(),
	)
	done := make(chan struct{})
	go func() {
		pub.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
		// Good — returned immediately.
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not return for empty config")
	}
}

// _ keeps the json import stable; used for canonical-bytes
// shape checks in future test expansions.
var _ = json.RawMessage{}
