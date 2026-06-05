/*
FILE PATH: wal/meta_test.go

PR-N3 pinning tests for the Meta V1/V2 wire-format codec.

The Meta encoding is the durable boundary between admission
(which captures Web3VerificationReceipts) and the sequencer
(which rehydrates them onto types.EntryWithMetadata). A bug
here silently corrupts the receipt-to-projection plumbing
because the corruption surfaces only when the builder rebuilds
the ReceiptRoot — by which point the WAL has already been
fsync'd, the sequencer has advanced state, and the receipts are
lost.

What this file pins:
  - V1 records (29 bytes, no receipts) round-trip byte-identically.
  - V2 records with one receipt round-trip identically.
  - V2 records with three receipts (mixed zero + populated) round-trip.
  - V2 records honour the receipt order (swapping receipts[i] and
    receipts[j] changes the wire bytes — defends against an
    accidental sort during persistence).
  - Decoding a truncated V2 trailer fails with ErrMetaCorrupt
    (the trailer must be self-describing or rejected).
  - Encoding a Meta with empty receipts emits 29 bytes (V1
    fast path; byte-identical to pre-PR-N3 producers).
*/
package wal

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
)

func TestMeta_V1_Roundtrip_NoReceipts(t *testing.T) {
	in := Meta{
		State:         StatePending,
		LogTimeMicros: 1_000_000,
	}
	buf := encodeMeta(in)
	if got := len(buf); got != metaV1Size {
		t.Fatalf("empty-receipt encode produced %d bytes, want V1 fast-path %d", got, metaV1Size)
	}
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode V1: %v", err)
	}
	if out.State != in.State || out.LogTimeMicros != in.LogTimeMicros {
		t.Fatalf("V1 round-trip mismatch: in=%+v out=%+v", in, out)
	}
	if len(out.Web3Receipts) != 0 {
		t.Fatalf("V1 round-trip surfaced %d receipts (want none)", len(out.Web3Receipts))
	}
}

func TestMeta_V2_Roundtrip_SingleZeroReceipt(t *testing.T) {
	in := Meta{
		State:         StatePending,
		LogTimeMicros: 2_000_000,
		Web3Receipts:  []types.Web3VerificationReceipt{types.ZeroWeb3VerificationReceipt()},
	}
	buf := encodeMeta(in)
	if len(buf) <= metaV1Size {
		t.Fatalf("V2 encode produced %d bytes; expected > V1 size %d", len(buf), metaV1Size)
	}
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode V2: %v", err)
	}
	if len(out.Web3Receipts) != 1 {
		t.Fatalf("decoded %d receipts, want 1", len(out.Web3Receipts))
	}
	if !out.Web3Receipts[0].IsZero() {
		t.Fatalf("decoded receipt is not zero: %+v", out.Web3Receipts[0])
	}
}

func TestMeta_V2_Roundtrip_MultipleZeroReceipts(t *testing.T) {
	// Index-aligned with a 3-signer entry. Every slot Zero (the
	// adapter from PR-N1 produces only Zero receipts) but the
	// LENGTH must be preserved across the codec — the builder uses
	// len(receipts) == len(signatures) as an invariant.
	in := Meta{
		State:         StatePending,
		Sequence:      99,
		LogTimeMicros: 3_000_000,
		Web3Receipts: []types.Web3VerificationReceipt{
			types.ZeroWeb3VerificationReceipt(),
			types.ZeroWeb3VerificationReceipt(),
			types.ZeroWeb3VerificationReceipt(),
		},
	}
	buf := encodeMeta(in)
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode V2 (n=3): %v", err)
	}
	if len(out.Web3Receipts) != 3 {
		t.Fatalf("decoded %d receipts, want 3 — LENGTH PRESERVATION IS THE INVARIANT THE BUILDER RELIES ON",
			len(out.Web3Receipts))
	}
	for i, r := range out.Web3Receipts {
		if !r.IsZero() {
			t.Errorf("receipts[%d] is not zero: %+v", i, r)
		}
	}
}

func TestMeta_V2_Encoding_PreservesOrder(t *testing.T) {
	// Two distinct populated receipts. Swapping their order MUST
	// produce different wire bytes (the SDK's EntryReceiptHash
	// combiner is order-sensitive — see baseproof v1.7.0 commit
	// 9b7ba23 fix #1). The WAL codec must not silently sort or
	// canonicalize the slice.
	r0 := types.Web3VerificationReceipt{
		ChainID:     1,
		BlockNumber: 100,
	}
	r1 := types.Web3VerificationReceipt{
		ChainID:     1,
		BlockNumber: 200,
	}
	in01 := Meta{State: StatePending, LogTimeMicros: 1, Web3Receipts: []types.Web3VerificationReceipt{r0, r1}}
	in10 := Meta{State: StatePending, LogTimeMicros: 1, Web3Receipts: []types.Web3VerificationReceipt{r1, r0}}

	b01 := encodeMeta(in01)
	b10 := encodeMeta(in10)
	if reflect.DeepEqual(b01, b10) {
		t.Fatal("encodeMeta produced identical bytes for [r0,r1] and [r1,r0] — order MUST be wire-significant")
	}

	out, err := decodeMeta(b01)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Web3Receipts[0].BlockNumber != 100 || out.Web3Receipts[1].BlockNumber != 200 {
		t.Fatalf("decoded order wrong: got block %d,%d want 100,200",
			out.Web3Receipts[0].BlockNumber, out.Web3Receipts[1].BlockNumber)
	}
}

func TestMeta_V2_Decode_TruncatedTrailer_Rejected(t *testing.T) {
	in := Meta{
		State:         StatePending,
		LogTimeMicros: 4_000_000,
		Web3Receipts:  []types.Web3VerificationReceipt{types.ZeroWeb3VerificationReceipt()},
	}
	full := encodeMeta(in)
	// Lop off the last byte — the receipt payload is now truncated.
	cut := full[:len(full)-1]
	_, err := decodeMeta(cut)
	if err == nil {
		t.Fatal("decodeMeta accepted truncated V2 record; want ErrMetaCorrupt")
	}
	if !errors.Is(err, ErrMetaCorrupt) {
		t.Fatalf("got %v, want errors.Is(err, ErrMetaCorrupt)", err)
	}
}

const sampleTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestMeta_V3_Roundtrip_TraceOnly(t *testing.T) {
	in := Meta{
		State:         StateSequenced,
		Sequence:      42,
		LogTimeMicros: 7_000_000,
		TraceContext:  sampleTraceparent,
	}
	buf := encodeMeta(in)
	if len(buf) <= metaV1Size || buf[metaV1Size] != metaTrailerVersionV3 {
		t.Fatalf("expected a V3 trailer (0x03); got len=%d trailer=0x%02x", len(buf), buf[metaV1Size])
	}
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode V3: %v", err)
	}
	if out.TraceContext != sampleTraceparent {
		t.Fatalf("traceparent lost: got %q want %q", out.TraceContext, sampleTraceparent)
	}
	if out.State != in.State || out.Sequence != in.Sequence || out.LogTimeMicros != in.LogTimeMicros {
		t.Fatalf("V3 round-trip clobbered V1 prefix: in=%+v out=%+v", in, out)
	}
	if len(out.Web3Receipts) != 0 {
		t.Fatalf("V3 trace-only surfaced %d receipts (want none)", len(out.Web3Receipts))
	}
}

func TestMeta_V3_Roundtrip_TraceAndReceipts(t *testing.T) {
	in := Meta{
		State:         StatePending,
		LogTimeMicros: 8_000_000,
		TraceContext:  sampleTraceparent,
		Web3Receipts: []types.Web3VerificationReceipt{
			{ChainID: 1, BlockNumber: 100},
			types.ZeroWeb3VerificationReceipt(),
			{ChainID: 1, BlockNumber: 300},
		},
	}
	buf := encodeMeta(in)
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode V3+receipts: %v", err)
	}
	if out.TraceContext != sampleTraceparent {
		t.Fatalf("traceparent lost: got %q", out.TraceContext)
	}
	if len(out.Web3Receipts) != 3 {
		t.Fatalf("decoded %d receipts, want 3", len(out.Web3Receipts))
	}
	if out.Web3Receipts[0].BlockNumber != 100 || out.Web3Receipts[2].BlockNumber != 300 {
		t.Fatalf("receipt order/content lost across V3: got %d,_,%d",
			out.Web3Receipts[0].BlockNumber, out.Web3Receipts[2].BlockNumber)
	}
}

// The headline backward-compat guarantee: WITHOUT a trace context the encoding
// is byte-identical to the legacy V1/V2 producer — a V3 trailer is emitted ONLY
// when TraceContext != "".
func TestMeta_NoTrace_StaysV1V2_ByteIdentical(t *testing.T) {
	v1 := Meta{State: StatePending, LogTimeMicros: 1_000_000}
	if got := encodeMeta(v1); len(got) != metaV1Size {
		t.Fatalf("no-trace no-receipt encode = %d bytes, want V1 %d", len(got), metaV1Size)
	}
	v2 := Meta{State: StatePending, LogTimeMicros: 1, Web3Receipts: []types.Web3VerificationReceipt{{ChainID: 1, BlockNumber: 5}}}
	b := encodeMeta(v2)
	if b[metaV1Size] != metaTrailerVersionV2 {
		t.Fatalf("no-trace receipts encode used trailer 0x%02x, want V2 0x02 (byte-compat)", b[metaV1Size])
	}
}

func TestMeta_V3_Decode_TruncatedTraceparent_Rejected(t *testing.T) {
	full := encodeMeta(Meta{State: StatePending, LogTimeMicros: 1, TraceContext: sampleTraceparent})
	// Cut into the traceparent payload (after V1 prefix + version + 2-byte len).
	cut := full[:metaV1Size+1+2+3]
	_, err := decodeMeta(cut)
	if err == nil || !errors.Is(err, ErrMetaCorrupt) {
		t.Fatalf("truncated V3 traceparent accepted (err=%v); want ErrMetaCorrupt", err)
	}
}

func TestMeta_V2_LastErrTs_Preserved(t *testing.T) {
	// Defensive: the V2 trailer must NOT shadow any V1 prefix
	// field. LastErrTs in particular is at the awkward 13:21 byte
	// range; a buggy V2 encoder that overwrites it would surface
	// here.
	ts := time.Unix(0, 1_234_567_890_000).UTC()
	in := Meta{
		State:         StatePending,
		Attempts:      7,
		LastErrTs:     ts,
		LogTimeMicros: 5_000_000,
		Web3Receipts:  []types.Web3VerificationReceipt{types.ZeroWeb3VerificationReceipt()},
	}
	buf := encodeMeta(in)
	out, err := decodeMeta(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.LastErrTs.Equal(ts) {
		t.Fatalf("LastErrTs lost across V2 round-trip: got %v want %v", out.LastErrTs, ts)
	}
	if out.Attempts != 7 {
		t.Fatalf("Attempts lost: got %d want 7", out.Attempts)
	}
}
