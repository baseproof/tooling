/*
FILE PATH: wal/meta.go

Meta record encoding for entry state.

Wire format (binary) — two variants for forward-compat:

V1 (29 bytes, original):

	[1 byte state] [8 bytes seq BE] [4 bytes attempts] [8 bytes lastErrTs unix-nano] [8 bytes logTimeMicros BE]

V2 (29 + 3 + R bytes, when len(Web3Receipts) > 0):

	[V1 29-byte prefix EXACTLY]
	[1 byte trailer version = 0x02]
	[2 bytes uint16 receipt count BE]
	[R bytes payload — concatenated per-receipt records:]
	  [4 bytes uint32 per-receipt length BE]
	  [N bytes envelope.SerializeWeb3VerificationReceipt(receipt) output]

V3 (29 + 1 + 2 + T + 2 + R bytes, when TraceContext != ""):

	[V1 29-byte prefix EXACTLY]
	[1 byte trailer version = 0x03]
	[2 bytes uint16 traceparent length BE][T bytes W3C traceparent]
	[2 bytes uint16 receipt count BE][R bytes framed receipts — as V2]

Detection: len(buf) > 29 ⇒ trailer present. The 30th byte's version
discriminator (0x02 receipts-only; 0x03 traceparent + receipts) is a
hook for trailer schema evolution without breaking the V1 fast path.
A V3 record is emitted ONLY when TraceContext != "", so V1/V2 records
stay byte-identical.

Backwards compat:
  - Existing on-disk records (29 bytes) decode unchanged.
  - Encoding a Meta with no receipts (Web3Receipts == nil or
    len == 0) emits exactly 29 bytes — byte-identical to V1
    producers. A running ledger that upgrades and replaces a
    Pending entry without receipts produces a byte-identical
    re-encoding (idempotent overwrite property preserved).

LogTimeMicros: the unix-microsecond log_time assigned at first
Submit. Persisted so a byte-identical resubmission can re-issue
the SAME SCT bytes (deterministic idempotency) instead of
returning 409 Conflict.

Web3Receipts: per-signature K-of-N Web3 verification receipts
captured at admission (baseproof v1.7.0+ — see
api/submission.go::receiptClientBounds for the producer side).
The slice is index-aligned with the entry's Signatures slice;
Zero receipts populate non-EIP-1271 slots. Persisted so the
sequencer can rehydrate them onto types.EntryWithMetadata
.Web3Receipts for the builder's per-batch ReceiptRoot
computation (PR-N4..N5).
*/
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/types"
)

// EntryState is the state-machine value stored in meta:<hash>.
type EntryState uint8

const (
	// StateUnknown is the zero value; never written to disk. Reading
	// state==StateUnknown indicates a decode bug or a corrupt record.
	StateUnknown EntryState = 0

	// StatePending: WAL has the bytes durably; tessera.Add not yet
	// confirmed. Inflight breadcrumb is set in this state.
	StatePending EntryState = 1

	// StateSequenced: tessera.Add returned a sequence; the entry is
	// committed to the log's order. Bytes still live in the WAL until
	// the Shipper migrates them.
	StateSequenced EntryState = 2

	// StateShipped: bytestore upload succeeded. The Shipper transitions
	// here AND advances HWM (when contiguous).
	StateShipped EntryState = 3

	// StateManual: Shipper has retried N times and given up; bytes
	// stay in the WAL pending ledger intervention. Reads still
	// succeed via the WAL (no DLQ — the ledger's manual-intervention
	// queue is metric-only).
	StateManual EntryState = 4
)

// String renders the state for logging.
func (s EntryState) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateSequenced:
		return "sequenced"
	case StateShipped:
		return "shipped"
	case StateManual:
		return "manual"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// Meta is the in-memory representation of meta:<hash>. The disk
// encoding is variable-width binary; see file docstring for the
// V1 / V2 layout.
type Meta struct {
	State         EntryState
	Sequence      uint64    // valid iff State >= StateSequenced
	Attempts      uint32    // shipper retry counter
	LastErrTs     time.Time // wall-clock of last error; zero on success
	LogTimeMicros int64     // unix-micros log_time assigned at first Submit

	// Web3Receipts is the per-signature Web3VerificationReceipt
	// slice captured at admission. Nil or empty when the entry's
	// admission path collected no receipts (legacy single-sig
	// path; pre-v1.7.0 records). Index-aligned with the entry's
	// Signatures when populated.
	Web3Receipts []types.Web3VerificationReceipt

	// TraceContext is the W3C `traceparent` of the admission span,
	// captured at first Submit (empty when the admission trace was
	// not sampled, or tracing is off). Persisted so the asynchronous
	// downstream stages (sequencer, shipper) can RESUME the same trace
	// across the WAL boundary — turning admission→ship into one trace
	// per entry. Read-modify-write transitions (Sequence/MarkShipped/…)
	// preserve it automatically.
	TraceContext string
}

// metaV1Size is the on-disk size of the fixed-width V1 prefix.
// Every V2 record begins with these same 29 bytes.
const metaV1Size = 1 + 8 + 4 + 8 + 8

// metaTrailerVersionV2 is the discriminator byte at offset 29 of a
// V2-encoded record. Bumping this lets future encoders extend the
// trailer schema without breaking the V1 fast path.
const metaTrailerVersionV2 byte = 0x02

// metaTrailerVersionV3 is the discriminator for a record that also
// carries a TraceContext. Layout: V1 prefix, 0x03, [2-byte traceparent
// length BE][traceparent bytes], then the same [2-byte receipt count]
// [framed receipts] block as V2. A V3 record is emitted ONLY when
// TraceContext != "" — so V1/V2 records remain byte-identical and the
// idempotent-overwrite property is preserved per record.
const metaTrailerVersionV3 byte = 0x03

// ErrMetaCorrupt is returned by decodeMeta when the byte slice is
// truncated or malformed.
var ErrMetaCorrupt = errors.New("wal/meta: corrupt record")

// encodeMeta serializes Meta to V1 or V2 wire format depending on
// whether receipts are present. V1 is byte-identical to the legacy
// 29-byte producer so on-disk records survive a ledger upgrade.
func encodeMeta(m Meta) []byte {
	// V1 prefix — always present.
	v1 := make([]byte, metaV1Size)
	v1[0] = byte(m.State)
	binary.BigEndian.PutUint64(v1[1:9], m.Sequence)
	binary.BigEndian.PutUint32(v1[9:13], m.Attempts)
	if m.LastErrTs.IsZero() {
		// Zero time → store as 0 nanos (vs. UnixNano() which would
		// be a large negative pre-1970 value for some clock states).
		binary.BigEndian.PutUint64(v1[13:21], 0)
	} else {
		binary.BigEndian.PutUint64(v1[13:21], uint64(m.LastErrTs.UnixNano()))
	}
	// LogTimeMicros: int64 stored as uint64 bit-pattern; preserves
	// negative values (clock skew during early-1970 testing) without
	// a sentinel collision against the 0-means-unset semantics —
	// 0 is a valid log_time (the unix epoch instant) but in practice
	// the ledger's logTime = time.Now().UTC().UnixMicro() is always
	// strictly positive at runtime.
	binary.BigEndian.PutUint64(v1[21:29], uint64(m.LogTimeMicros))

	if len(m.Web3Receipts) == 0 && m.TraceContext == "" {
		// V1 fast path — byte-identical to the legacy producer.
		return v1
	}

	// Per the receipt-schema invariant in the v1.7.0 SDK commit message:
	// "K ≤ len(Clients) ≤ N" — every receipt's internal
	// ExecutorQuorum.Clients slice is variable-length, but
	// SerializeWeb3VerificationReceipt produces a self-describing wire-form
	// per receipt. We length-prefix each receipt at this layer so the decoder
	// can iterate without round-tripping through SDK structure validation per
	// element.
	if len(m.Web3Receipts) > 0xFFFF {
		// Defensive — envelope.MaxSignaturesPerEntry is 64, so a receipts slice
		// can never legitimately exceed that. The uint16 count field caps at
		// 65535; if a future SDK lifts the cap above that the format needs a
		// version bump.
		panic(fmt.Sprintf("wal/meta: encodeMeta receipts count %d exceeds uint16 max", len(m.Web3Receipts)))
	}

	if m.TraceContext == "" {
		// V2 trailer — receipts only; byte-identical to the legacy producer.
		out := make([]byte, 0, metaV1Size+3+128*len(m.Web3Receipts))
		out = append(out, v1...)
		out = append(out, metaTrailerVersionV2)
		return appendReceiptBlock(out, m.Web3Receipts)
	}

	// V3 trailer — traceparent (+ optional receipts). A W3C traceparent is a
	// short fixed-shape ASCII string (~55 bytes); uint16 length is ample.
	tp := []byte(m.TraceContext)
	if len(tp) > 0xFFFF {
		panic(fmt.Sprintf("wal/meta: encodeMeta traceparent length %d exceeds uint16 max", len(tp)))
	}
	out := make([]byte, 0, metaV1Size+1+2+len(tp)+3+128*len(m.Web3Receipts))
	out = append(out, v1...)
	out = append(out, metaTrailerVersionV3)
	var tpLen [2]byte
	binary.BigEndian.PutUint16(tpLen[:], uint16(len(tp)))
	out = append(out, tpLen[:]...)
	out = append(out, tp...)
	return appendReceiptBlock(out, m.Web3Receipts)
}

// appendReceiptBlock appends the shared V2/V3 receipt block to out:
// [2-byte count BE] followed by, per receipt, [4-byte length BE][body].
func appendReceiptBlock(out []byte, receipts []types.Web3VerificationReceipt) []byte {
	var countBuf [2]byte
	binary.BigEndian.PutUint16(countBuf[:], uint16(len(receipts)))
	out = append(out, countBuf[:]...)
	for i := range receipts {
		body, err := envelope.SerializeWeb3VerificationReceipt(receipts[i])
		if err != nil {
			panic(fmt.Sprintf("wal/meta: SerializeWeb3VerificationReceipt receipts[%d]: %v", i, err))
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
		out = append(out, lenBuf[:]...)
		out = append(out, body...)
	}
	return out
}

// decodeReceiptBlock parses the shared V2/V3 receipt block beginning at off,
// returning the receipts and the offset just past them.
func decodeReceiptBlock(buf []byte, off int) ([]types.Web3VerificationReceipt, int, error) {
	if off+2 > len(buf) {
		return nil, 0, fmt.Errorf("%w: receipt count truncated at off=%d", ErrMetaCorrupt, off)
	}
	count := binary.BigEndian.Uint16(buf[off : off+2])
	off += 2
	receipts := make([]types.Web3VerificationReceipt, count)
	for i := uint16(0); i < count; i++ {
		if off+4 > len(buf) {
			return nil, 0, fmt.Errorf("%w: receipt[%d] length-prefix truncated at off=%d",
				ErrMetaCorrupt, i, off)
		}
		recLen := binary.BigEndian.Uint32(buf[off : off+4])
		off += 4
		if uint64(off)+uint64(recLen) > uint64(len(buf)) {
			return nil, 0, fmt.Errorf("%w: receipt[%d] payload (len=%d) extends past buffer (off=%d, total=%d)",
				ErrMetaCorrupt, i, recLen, off, len(buf))
		}
		rec, _, err := envelope.DeserializeWeb3VerificationReceipt(buf[off : off+int(recLen)])
		if err != nil {
			return nil, 0, fmt.Errorf("%w: receipt[%d] deserialize: %v", ErrMetaCorrupt, i, err)
		}
		receipts[i] = rec
		off += int(recLen)
	}
	return receipts, off, nil
}

// decodeMeta parses a V1 or V2 meta record.
func decodeMeta(buf []byte) (Meta, error) {
	if len(buf) < metaV1Size {
		return Meta{}, fmt.Errorf("%w: short read %d < V1 size %d",
			ErrMetaCorrupt, len(buf), metaV1Size)
	}
	m := Meta{
		State:    EntryState(buf[0]),
		Sequence: binary.BigEndian.Uint64(buf[1:9]),
		Attempts: binary.BigEndian.Uint32(buf[9:13]),
	}
	if ns := int64(binary.BigEndian.Uint64(buf[13:21])); ns != 0 {
		m.LastErrTs = time.Unix(0, ns).UTC()
	}
	m.LogTimeMicros = int64(binary.BigEndian.Uint64(buf[21:29]))
	if len(buf) == metaV1Size {
		// V1 record (or V2/V3 with empty trailer payload — all encode the
		// same 29 bytes by design).
		return m, nil
	}
	// Trailer present — dispatch on the version discriminator at offset 29.
	if len(buf) < metaV1Size+1 {
		return Meta{}, fmt.Errorf("%w: trailer header short read %d", ErrMetaCorrupt, len(buf))
	}
	off := metaV1Size + 1
	switch v := buf[metaV1Size]; v {
	case metaTrailerVersionV2:
		// V2 — receipts only.
		receipts, end, err := decodeReceiptBlock(buf, off)
		if err != nil {
			return Meta{}, err
		}
		m.Web3Receipts = receipts
		off = end
	case metaTrailerVersionV3:
		// V3 — traceparent then receipts.
		if off+2 > len(buf) {
			return Meta{}, fmt.Errorf("%w: traceparent length truncated at off=%d", ErrMetaCorrupt, off)
		}
		tpLen := int(binary.BigEndian.Uint16(buf[off : off+2]))
		off += 2
		if off+tpLen > len(buf) {
			return Meta{}, fmt.Errorf("%w: traceparent (len=%d) extends past buffer (off=%d, total=%d)",
				ErrMetaCorrupt, tpLen, off, len(buf))
		}
		m.TraceContext = string(buf[off : off+tpLen])
		off += tpLen
		receipts, end, err := decodeReceiptBlock(buf, off)
		if err != nil {
			return Meta{}, err
		}
		m.Web3Receipts = receipts
		off = end
	default:
		return Meta{}, fmt.Errorf("%w: unknown trailer version 0x%02x", ErrMetaCorrupt, v)
	}
	if off != len(buf) {
		return Meta{}, fmt.Errorf("%w: trailing %d bytes after trailer", ErrMetaCorrupt, len(buf)-off)
	}
	return m, nil
}
