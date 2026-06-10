package loadgen

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
)

// LeafRecord is one root's FINAL expected state — the validation oracle's unit.
// The engine hands exactly one to the sink per root, at the moment the root's
// state can no longer change (window eviction or end-of-run flush).
type LeafRecord struct {
	RootIndex       uint64
	Key             [32]byte // SMT key = smt.DeriveKey(creation position)
	SignerDID       string
	OriginTipSeq    uint64
	AuthorityTipSeq uint64
}

// Sink consumes the streamed oracle. Implementations MUST treat each record as
// final and MUST NOT retain it beyond the call — the engine emits and forgets, so
// a conforming sink keeps the whole run O(1) in leaves.
type Sink interface {
	Leaf(LeafRecord) error
}

// DiscardSink drops every record. The in-process e2e driver that only needs to
// PRODUCE load (not validate an oracle) wires this, so a 20M run allocates
// nothing for the oracle at all.
type DiscardSink struct{}

func (DiscardSink) Leaf(LeafRecord) error { return nil }

// OracleFormat tags the JSONL header line so a reader can reject an unknown
// vintage instead of silently mis-parsing.
const OracleFormat = "baseproof-loadgen-oracle-jsonl/v1"

// OracleHeader is the first JSONL line: the run parameters known at start. Final
// counts are intentionally absent — a reader derives roots from the line count,
// which keeps the WRITER append-only (no rewrite-the-header-at-the-end seek).
type OracleHeader struct {
	Format     string  `json:"format"`
	LogDID     string  `json:"log_did"`
	Seed       int64   `json:"seed"`
	N          int     `json:"n"`
	AmendRatio float64 `json:"amend_ratio"`
}

// jsonlLeaf is the wire shape of one oracle leaf line. The first four fields
// match the legacy single-object manifest's `manifestLeaf` names so the audit
// reader's key/state extraction is a line-by-line port, not a rewrite.
type jsonlLeaf struct {
	Key             string `json:"key"` // 64-hex SMT key
	SignerDID       string `json:"signer_did"`
	OriginTipSeq    uint64 `json:"origin_tip_seq"`
	AuthorityTipSeq uint64 `json:"authority_tip_seq"`
	RootIndex       uint64 `json:"root_index"`
}

// OracleWriter streams the expected-state oracle as JSON Lines: a header line,
// then one leaf object per line, each encoded straight through a buffered writer.
// Memory is O(1) in the number of leaves — there is NO terminal json.MarshalIndent
// of the whole oracle, the allocation spike that tipped the legacy backfill over
// its cgroup limit at ~98%.
type OracleWriter struct {
	mu  sync.Mutex
	bw  *bufio.Writer
	enc *json.Encoder
	wc  io.WriteCloser
	n   int
}

// NewOracleWriter writes the header line immediately and returns a streaming sink.
// The caller owns wc and must Close the returned writer (which flushes + closes).
func NewOracleWriter(wc io.WriteCloser, h OracleHeader) (*OracleWriter, error) {
	bw := bufio.NewWriterSize(wc, 1<<16)
	enc := json.NewEncoder(bw)
	h.Format = OracleFormat
	if err := enc.Encode(h); err != nil { // json.Encoder.Encode appends '\n' ⇒ JSONL
		return nil, err
	}
	return &OracleWriter{bw: bw, enc: enc, wc: wc}, nil
}

func (o *OracleWriter) Leaf(r LeafRecord) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n++
	return o.enc.Encode(jsonlLeaf{
		Key:             hex.EncodeToString(r.Key[:]),
		SignerDID:       r.SignerDID,
		OriginTipSeq:    r.OriginTipSeq,
		AuthorityTipSeq: r.AuthorityTipSeq,
		RootIndex:       r.RootIndex,
	})
}

// Count returns the number of leaves written so far.
func (o *OracleWriter) Count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n
}

// Close flushes the buffer and closes the underlying writer.
func (o *OracleWriter) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.bw.Flush(); err != nil {
		_ = o.wc.Close()
		return err
	}
	return o.wc.Close()
}
