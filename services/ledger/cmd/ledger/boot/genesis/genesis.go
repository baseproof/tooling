/*
FILE PATH: cmd/ledger/boot/genesis/genesis.go

#76 — the seq-0 constitution producer.

The network's constitution is sequenced as the log's FIRST entry
(BP-ENTRY-NETWORK-GENESIS-V1 at sequence 0), so the witness-set projection
roots in the LOG itself (decode entry 0 → verify the ceremony → walk
rotations) rather than in an off-log seed. EnsureRecord is the producer half;
verifier.GenesisSetFromRecord (consumed by the witness-baseline re-root) is the
re-root half.

This package owns ONLY the producer rule — build, submit, await, assert. It
takes narrow interfaces (Submitter / SeqIndex / ByteFetcher), so it is driven
identically by the boot adapter (over *wal.Committer + *store.EntryStore) and by
the integration harness (over the same real components). It deliberately depends
on the SDK alone — no store, no deps — so the rule has one home and one set of
collaborators.

CLASSIFICATION. The record rides a plain ledger-signed envelope with no
Target_Root and no Authority_Path, so builder.ClassifyEntry returns Commentary:
it advances tree_size by one Merkle leaf WITHOUT mutating the SMT root (still
EmptyHash at sequence 0). The checkpoint loop's genesis-disambiguation
(IntegratedSize 0 vs 1 over a byte-identical smt_root_state) depends on exactly
this shape.

ORDERING. EnsureRecord runs after the sequencer is consuming the WAL and BEFORE
the HTTP listener serves: the record is sequenced through the SAME WAL the
admission path uses, so the sequencer assigns its leaf, but no external write
can interleave because /v1/entries is not yet serving. A constitution sequenced
anywhere but position 0 is a corrupt log — boot fails.

FAIL-CLOSED. The mounted document was already ceremony-verified at config load
(#75 Phase B); EncodeNetworkGenesisRecord re-checks before producing the record
(an unendorsed require constitution cannot reach the log). On restart, sequence
0 is decoded under the mounted NetworkID pin and must be THIS network's
constitution — a seq-0 that is not is the wrong log or a tampered root, and boot
fails.
*/
package genesis

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// Submitter is the WAL entry point the genesis record is submitted through —
// the SAME seam the admission handler and the rotation appender use. Satisfied
// by *wal.Committer.
type Submitter interface {
	Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64, receipts []types.Web3VerificationReceipt) error
}

// SeqIndex reads the entry_index the sequencer writes: presence of sequence 0
// (FetchHashBySeq) and the sequence a hash was assigned (FetchPrimarySeqByHash).
// Satisfied by *store.EntryStore.
type SeqIndex interface {
	FetchHashBySeq(ctx context.Context, seq uint64) ([32]byte, time.Time, bool, bool, error)
	FetchPrimarySeqByHash(ctx context.Context, hash [32]byte) (uint64, bool, error)
}

// ByteFetcher reads an entry's canonical bytes by position, for the
// restart-verification decode of sequence 0. Satisfied by
// *store.PostgresEntryFetcher over the composite byte reader.
type ByteFetcher interface {
	Fetch(ctx context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// Config is the producer inputs, decoupled from the full wire.Config + AppDeps
// so the producer is driven against real store components (tier T2+) or narrow
// fakes by exactly the same call.
type Config struct {
	Doc       network.BootstrapDocument // the verified constitution (config load, #75 Phase B)
	LogDID    string
	SignerDID string            // the ledger's own did:key (entry author)
	Priv      *ecdsa.PrivateKey // the ledger signer
	Pin       [32]byte          // doc's NetworkID (restart decode pin)
	Poll      time.Duration
	Timeout   time.Duration
	Logger    *slog.Logger
}

// EnsureRecord guarantees the constitution sits at sequence 0 before the write
// surface opens, and returns the on-log genesis RECORD bytes (the envelope's
// domain payload) so the caller can re-root the witness-set baseline from the
// log without re-fetching. Idempotent: on a log that already has sequence 0 it
// verifies that entry is this network's constitution and appends nothing,
// returning the verified record.
func EnsureRecord(
	ctx context.Context,
	submitter Submitter,
	seqs SeqIndex,
	fetcher ByteFetcher,
	cfg Config,
) ([]byte, error) {
	if _, _, _, present, err := seqs.FetchHashBySeq(ctx, 0); err != nil {
		return nil, fmt.Errorf("genesis: probe sequence 0: %w", err)
	} else if present {
		return verifyAtZero(ctx, fetcher, cfg)
	}
	return appendAtZero(ctx, submitter, seqs, cfg)
}

// verifyAtZero is the restart path: decode sequence 0 under the mounted pin and
// confirm it is THIS network's constitution. Fail-closed. Returns the verified
// record bytes.
func verifyAtZero(ctx context.Context, fetcher ByteFetcher, cfg Config) ([]byte, error) {
	meta, err := fetcher.Fetch(ctx, types.LogPosition{LogDID: cfg.LogDID, Sequence: 0})
	if err != nil {
		return nil, fmt.Errorf("genesis: read sequence 0 for restart verification: %w", err)
	}
	if meta == nil {
		return nil, fmt.Errorf("genesis: sequence 0 present in index but its bytes are unreadable")
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("genesis: deserialize sequence 0: %w", err)
	}
	if _, err := network.DecodeNetworkGenesisRecord(entry.DomainPayload, cfg.Pin); err != nil {
		return nil, fmt.Errorf("genesis: sequence 0 is not this network's verified constitution "+
			"(wrong log or tampered genesis record): %w", err)
	}
	cfg.Logger.InfoContext(ctx, "genesis record verified at sequence 0 (restart)")
	return entry.DomainPayload, nil
}

// appendAtZero is the fresh-log path: encode → ledger-sign → submit → await
// sequencing → assert sequence 0. Returns the record bytes it produced.
func appendAtZero(ctx context.Context, submitter Submitter, seqs SeqIndex, cfg Config) ([]byte, error) {
	record, err := network.EncodeNetworkGenesisRecord(cfg.Doc)
	if err != nil {
		// Refuses an unendorsed require constitution — an unceremonied
		// constitution cannot reach the log (the encoder owns that rule).
		return nil, fmt.Errorf("genesis: encode network genesis record: %w", err)
	}

	canonical, identity, err := buildEntry(record, cfg)
	if err != nil {
		return nil, err
	}

	if err := submitter.Submit(ctx, identity, canonical, time.Now().UTC().UnixMicro(), nil); err != nil {
		return nil, fmt.Errorf("genesis: submit record to WAL: %w", err)
	}

	seq, err := awaitSequence(ctx, seqs, identity, cfg)
	if err != nil {
		return nil, err
	}
	if seq != 0 {
		return nil, fmt.Errorf("genesis: constitution sequenced at %d, not 0 — the log was not empty "+
			"when the genesis producer ran (corrupt boot order or pre-existing entries)", seq)
	}
	cfg.Logger.InfoContext(ctx, "genesis record sequenced at 0 (fresh log)",
		"network_id", fmt.Sprintf("%x", cfg.Pin[:8]))
	return record, nil
}

// buildEntry wraps the record in a ledger-signed commentary envelope — the same
// recipe ProductionRotationAppender.buildSignedEntry uses for the ledger's other
// self-authored on-log entries.
func buildEntry(record []byte, cfg Config) ([]byte, [32]byte, error) {
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   cfg.SignerDID,
		Destination: cfg.LogDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}, record)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("genesis: build entry: %w", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(signingHash, cfg.Priv)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("genesis: sign entry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: cfg.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("genesis: serialize entry: %w", err)
	}
	identity, err := envelope.EntryIdentity(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("genesis: entry identity: %w", err)
	}
	return canonical, identity, nil
}

// BuildEntry exposes the commentary-envelope construction for the
// classification pin (the genesis entry must classify as Commentary). It is the
// exact entry appendAtZero submits.
func BuildEntry(cfg Config) (*envelope.Entry, error) {
	record, err := network.EncodeNetworkGenesisRecord(cfg.Doc)
	if err != nil {
		return nil, fmt.Errorf("genesis: encode network genesis record: %w", err)
	}
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   cfg.SignerDID,
		Destination: cfg.LogDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}, record)
	if err != nil {
		return nil, fmt.Errorf("genesis: build entry: %w", err)
	}
	return entry, nil
}

// awaitSequence polls entry_index until the sequencer has assigned the genesis
// entry a leaf (the production sequencing path, not a synchronous re-derivation
// of it).
func awaitSequence(ctx context.Context, seqs SeqIndex, identity [32]byte, cfg Config) (uint64, error) {
	deadline := time.Now().Add(cfg.Timeout)
	for {
		seq, ok, err := seqs.FetchPrimarySeqByHash(ctx, identity)
		if err != nil {
			return 0, fmt.Errorf("genesis: sequence lookup: %w", err)
		}
		if ok {
			return seq, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("genesis: timed out after %s waiting for the constitution to be sequenced", cfg.Timeout)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(cfg.Poll):
		}
	}
}
