package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
)

// entriesResponse renders the ledger's index-query success envelope for the given
// sequences ({entries:[{sequence_number}], count}).
func entriesResponse(seqs ...uint64) string {
	rows := make([]string, len(seqs))
	for i, s := range seqs {
		rows[i] = fmt.Sprintf(`{"sequence_number":%d,"canonical_hash":"ab","log_time":"2026-01-01T00:00:00Z"}`, s)
	}
	return fmt.Sprintf(`{"entries":[%s],"count":%d}`, strings.Join(rows, ","), len(seqs))
}

// DiscoverBySchemaRef hits /v1/query/schema_ref/{did:seq} and returns the matching
// sequences in order; the request path carries the did:seq position verbatim.
func TestDiscoverBySchemaRef_Hit(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(entriesResponse(3, 7, 11)))
	}))
	defer srv.Close()

	d, err := NewIndexDiscoverer(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewIndexDiscoverer: %v", err)
	}
	got, err := d.DiscoverBySchemaRef(context.Background(),
		types.LogPosition{LogDID: "did:web:net.example", Sequence: 5})
	if err != nil {
		t.Fatalf("DiscoverBySchemaRef: %v", err)
	}
	if len(got) != 3 || got[0].Sequence != 3 || got[2].Sequence != 11 {
		t.Fatalf("sequences = %+v, want [3 7 11]", got)
	}
	if gotPath != "/v1/query/schema_ref/did:web:net.example:5" {
		t.Errorf("path = %q, want schema_ref with did:seq", gotPath)
	}
}

// DiscoverBySignerDID hits /v1/query/signer_did/{did}.
func TestDiscoverBySignerDID_Hit(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(entriesResponse(42)))
	}))
	defer srv.Close()

	d, _ := NewIndexDiscoverer(srv.URL, srv.Client())
	got, err := d.DiscoverBySignerDID(context.Background(), "did:key:zQ3shABC")
	if err != nil {
		t.Fatalf("DiscoverBySignerDID: %v", err)
	}
	if len(got) != 1 || got[0].Sequence != 42 {
		t.Fatalf("sequences = %+v, want [42]", got)
	}
	if gotPath != "/v1/query/signer_did/did:key:zQ3shABC" {
		t.Errorf("path = %q, want signer_did", gotPath)
	}
}

// THE scaling contract: a missing/unsupported index (non-200) is a hard error
// (ErrIndexUnavailable) — the discoverer must NEVER fall back to /v1/query/scan.
func TestDiscover_FailLoudNeverScans(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		http.Error(w, "no such index", http.StatusNotFound)
	}))
	defer srv.Close()

	d, _ := NewIndexDiscoverer(srv.URL, srv.Client())
	_, err := d.DiscoverBySchemaRef(context.Background(),
		types.LogPosition{LogDID: "did:web:net.example", Sequence: 1})
	if !errors.Is(err, ErrIndexUnavailable) {
		t.Fatalf("want ErrIndexUnavailable on a missing index, got %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected exactly one request (the index query), got %d: %v", len(paths), paths)
	}
	for _, p := range paths {
		if strings.Contains(p, "/scan") {
			t.Fatalf("discoverer fell back to a SCAN (%q) — O(N), forbidden", p)
		}
	}
}

// A truncated response (count disagrees with the row count) fails closed.
func TestDiscover_CountMismatchRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"entries":[{"sequence_number":1}],"count":9}`))
	}))
	defer srv.Close()
	d, _ := NewIndexDiscoverer(srv.URL, srv.Client())
	if _, err := d.DiscoverBySignerDID(context.Background(), "did:key:z"); err == nil {
		t.Fatal("count/len mismatch must fail closed")
	}
}

// fakeElementSource serves canonical bytes + a stub inclusion proof by sequence.
type fakeElementSource struct {
	entries     map[uint64][]byte
	gotTreeSize uint64
}

func (f *fakeElementSource) FetchEntry(_ context.Context, seq uint64) ([]byte, time.Time, error) {
	b, ok := f.entries[seq]
	if !ok {
		return nil, time.Time{}, fmt.Errorf("no entry %d", seq)
	}
	return b, time.Unix(0, 0).UTC(), nil
}

func (f *fakeElementSource) FetchInclusionProof(_ context.Context, seq, treeSize uint64) (types.MerkleProof, error) {
	f.gotTreeSize = treeSize
	return types.MerkleProof{LeafPosition: seq, TreeSize: treeSize, Siblings: [][32]byte{{0x01}}}, nil
}

// AssembleEvolutionChain anchors every element on the SHARED checkpoint head
// (inclusion at checkpoint.TreeSize; no SMT) and encodes the wire section.
func TestAssembleEvolutionChain(t *testing.T) {
	src := &fakeElementSource{entries: map[uint64][]byte{
		3: []byte("amendment-at-3"),
		7: []byte("amendment-at-7"),
	}}
	checkpoint := types.CosignedTreeHead{TreeHead: types.TreeHead{
		RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xBB}, TreeSize: 100,
	}}
	raw, err := AssembleEvolutionChain(context.Background(), src,
		[]DiscoveredEntry{{Sequence: 3}, {Sequence: 7}}, checkpoint)
	if err != nil {
		t.Fatalf("AssembleEvolutionChain: %v", err)
	}
	if src.gotTreeSize != 100 {
		t.Errorf("inclusion fetched at tree_size %d, want the checkpoint's 100", src.gotTreeSize)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("encoded chain is not a JSON array: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("encoded %d elements, want 2", len(arr))
	}
}

// An empty discovery set yields a null section (a network with no such chain).
func TestAssembleEvolutionChain_Empty(t *testing.T) {
	raw, err := AssembleEvolutionChain(context.Background(), &fakeElementSource{}, nil, types.CosignedTreeHead{})
	if err != nil {
		t.Fatalf("AssembleEvolutionChain(empty): %v", err)
	}
	if raw != nil {
		t.Errorf("empty chain must be a null section, got %s", raw)
	}
}
