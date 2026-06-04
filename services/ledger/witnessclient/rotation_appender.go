/*
FILE PATH: witnessclient/rotation_appender.go

ProductionRotationAppender — the real RotationLogAppender (closes the
dormant on-log-rotation seam that, until now, only fakeRotationAppender
filled in tests).

It commits a witness-rotation payload as a SEQUENCED, WITNESS-COSIGNED
on-log entry and returns the entry's canonical bytes, its INTRINSIC leaf
position, and an RFC 6962 inclusion proof binding that leaf to a cosigned
head — exactly the (entryCanonical, pos, proof) triple ProcessRotation
(rotation_handler.go) persists as the PROVEN EffectivePos and ships inside
the self-contained WitnessRotationFinding.

# THE PIPELINE (all real components; no fakes)

 1. Build a ledger-authored envelope.Entry around the rotation payload
    and sign it with the ledger's key (the anchor/commitment-publisher
    recipe: sha256(SigningPayload) → signatures.SignEntry → attach).
 2. Submit the canonical bytes into the sequencing pipeline (the WAL).
    The sequencer assigns the leaf via tessera.AppendLeaf(identity) —
    so the entry_index sequence IS the Tessera leaf index
    (sequencer/loop.go) — and the builder cosigns heads as witness
    rounds complete.
 3. Poll for the assigned intrinsic sequence by the entry identity
    (store.EntryStore.FetchPrimarySeqByHash).
 4. Poll for a witness-cosigned head whose TreeSize covers that leaf
    (store.TreeHeadStore.LatestCosigned at the active quorum K).
 5. Build the RFC 6962 inclusion proof (tessera TypedInclusionProof)
    and bind its leaf to envelope.OnLogEntryLeafHash(canonical) =
    H(0x00 || SHA-256(canonical)) — the leaf an Baseproof ledger commits
    (it feeds Tessera the 32-byte EntryIdentity as leaf data).
 6. SELF-VERIFY: the proof MUST reconstruct to the cosigned RootHash
    (smt.VerifyMerkleInclusion) before the appender returns it —
    AppendRotationEntry never hands back an unprovable position.

Steps 3–4 block across a witness round (per the RotationLogAppender
contract); the poll interval + timeout are configurable.
*/
package witnessclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
)

// rotationEntrySubmitter durably enqueues a ledger-authored entry into the
// sequencing pipeline. Satisfied by *wal.Committer (Submit).
type rotationEntrySubmitter interface {
	Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64,
		receipts []types.Web3VerificationReceipt) error
}

// rotationSeqLookup resolves a just-submitted entry's assigned intrinsic
// sequence by its identity hash. Satisfied by *store.EntryStore
// (FetchPrimarySeqByHash). The returned bool reports whether the entry has
// been sequenced yet.
type rotationSeqLookup interface {
	FetchPrimarySeqByHash(ctx context.Context, hash [32]byte) (uint64, bool, error)
}

// rotationCosignedHeads returns the latest witness-cosigned tree head with
// at least minSigs distinct witness signatures, or (nil, nil) when none
// exists yet. Satisfied by *store.TreeHeadStore (LatestCosigned).
type rotationCosignedHeads interface {
	LatestCosigned(ctx context.Context, minSigs int) (*store.CosignedTreeHead, error)
}

// rotationProofBuilder builds an RFC 6962 inclusion proof (LeafHash left
// zeroed — the appender binds it). Satisfied by *tessera.TesseraAdapter
// (TypedInclusionProof).
type rotationProofBuilder interface {
	TypedInclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
}

// Default polling cadence for the sequence + cosigned-head waits. A witness
// round can take a while, so the timeout is generous; callers that need a
// tighter bound supply their own ctx deadline (which always wins).
const (
	defaultRotationPollInterval = 250 * time.Millisecond
	defaultRotationPollTimeout  = 2 * time.Minute
)

// ProductionRotationAppender implements RotationLogAppender against the live
// ledger: WAL submit → sequencer → Tessera → witness cosign → inclusion
// proof. Construct via NewProductionRotationAppender and wire it onto the
// RotationHandler with WithAppender.
type ProductionRotationAppender struct {
	priv      *ecdsa.PrivateKey
	signerDID string // ledger signer DID (ControlHeader.SignerDID)
	logDID    string // log DID (ControlHeader.Destination + LogPosition.LogDID)

	keys      *quorum.Manager        // active set → quorum K for the cosigned-head wait
	submitter rotationEntrySubmitter // WAL
	seqs      rotationSeqLookup      // entry_index seq-by-identity
	heads     rotationCosignedHeads  // cosigned tree_heads
	proofs    rotationProofBuilder   // Tessera inclusion proofs
	logger    *slog.Logger

	pollInterval time.Duration
	pollTimeout  time.Duration
}

// NewProductionRotationAppender wires the live components. priv/signerDID are
// the ledger's signing identity; logDID is the ledger's log DID (stamped on
// the returned LogPosition). keys supplies the active quorum K for deciding
// when a head is "cosigned enough" to cover the rotation leaf.
func NewProductionRotationAppender(
	priv *ecdsa.PrivateKey,
	signerDID string,
	logDID string,
	keys *quorum.Manager,
	submitter rotationEntrySubmitter,
	seqs rotationSeqLookup,
	heads rotationCosignedHeads,
	proofs rotationProofBuilder,
	logger *slog.Logger,
) *ProductionRotationAppender {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProductionRotationAppender{
		priv:         priv,
		signerDID:    signerDID,
		logDID:       logDID,
		keys:         keys,
		submitter:    submitter,
		seqs:         seqs,
		heads:        heads,
		proofs:       proofs,
		logger:       logger,
		pollInterval: defaultRotationPollInterval,
		pollTimeout:  defaultRotationPollTimeout,
	}
}

// WithPolling overrides the default poll interval + timeout (tests use a
// short cadence). Returns the receiver for chaining.
func (a *ProductionRotationAppender) WithPolling(interval, timeout time.Duration) *ProductionRotationAppender {
	if interval > 0 {
		a.pollInterval = interval
	}
	if timeout > 0 {
		a.pollTimeout = timeout
	}
	return a
}

// Compile-time assertion: this is a RotationLogAppender.
var _ RotationLogAppender = (*ProductionRotationAppender)(nil)

// AppendRotationEntry implements RotationLogAppender. See the file docstring
// for the pipeline. Blocks until the entry is sequenced AND covered by a
// witness-cosigned head (or ctx / pollTimeout elapses).
func (a *ProductionRotationAppender) AppendRotationEntry(
	ctx context.Context,
	rotationPayload []byte,
) ([]byte, types.LogPosition, *types.MerkleProof, error) {
	// 1. Build + sign the ledger-authored entry around the rotation payload.
	canonical, identity, err := a.buildSignedEntry(rotationPayload)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}

	// 2. Submit into the sequencing pipeline (the WAL). Same entry point the
	// admission handler uses; the sequencer picks it up and assigns the leaf.
	nowMicros := time.Now().UTC().UnixMicro()
	if err = a.submitter.Submit(ctx, identity, canonical, nowMicros, nil); err != nil {
		return nil, types.LogPosition{}, nil, fmt.Errorf(
			"rotation-appender: submit rotation entry: %w", err)
	}

	// 3. Wait for the intrinsic leaf sequence (entry_index == Tessera index).
	seq, err := a.waitForSequence(ctx, identity)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}

	// 4. Wait for a witness-cosigned head that covers the leaf.
	head, err := a.waitForCoveringHead(ctx, seq)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}

	// 5. Build the inclusion proof and bind the on-log-entry leaf.
	proof, err := a.proofs.TypedInclusionProof(seq, head.TreeSize)
	if err != nil {
		return nil, types.LogPosition{}, nil, fmt.Errorf(
			"rotation-appender: inclusion proof (seq=%d treeSize=%d): %w", seq, head.TreeSize, err)
	}
	proof.LeafHash = envelope.OnLogEntryLeafHash(canonical)

	// 6. Self-verify: the proof MUST reconstruct to the cosigned root.
	if err := smt.VerifyMerkleInclusion(proof, head.RootHash); err != nil {
		return nil, types.LogPosition{}, nil, fmt.Errorf(
			"rotation-appender: built proof does not reconstruct to cosigned root "+
				"(seq=%d treeSize=%d): %w", seq, head.TreeSize, err)
	}

	a.logger.InfoContext(ctx, "witness rotation committed on-log",
		"seq", seq, "tree_size", head.TreeSize)

	return canonical, types.LogPosition{LogDID: a.logDID, Sequence: seq}, proof, nil
}

// buildSignedEntry wraps the rotation payload in a ledger-signed
// envelope.Entry and returns its canonical bytes + 32-byte identity
// (= SHA-256(canonical), the leaf data the sequencer feeds Tessera and the
// canonical_hash entry_index keys on). Mirrors anchor.SignAndSubmit's
// production signing recipe.
func (a *ProductionRotationAppender) buildSignedEntry(payload []byte) ([]byte, [32]byte, error) {
	hdr := envelope.ControlHeader{
		SignerDID:   a.signerDID,
		Destination: a.logDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("rotation-appender: build entry: %w", err)
	}

	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(signingHash, a.priv)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("rotation-appender: sign entry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: a.signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}

	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("rotation-appender: serialize entry: %w", err)
	}
	identity, err := envelope.EntryIdentity(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("rotation-appender: entry identity: %w", err)
	}
	return canonical, identity, nil
}

// waitForSequence polls until the entry has been sequenced, returning its
// intrinsic leaf position.
func (a *ProductionRotationAppender) waitForSequence(ctx context.Context, identity [32]byte) (uint64, error) {
	deadline := time.Now().Add(a.pollTimeout)
	for {
		seq, ok, err := a.seqs.FetchPrimarySeqByHash(ctx, identity)
		if err != nil {
			return 0, fmt.Errorf("rotation-appender: seq lookup: %w", err)
		}
		if ok {
			return seq, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("rotation-appender: timed out after %s waiting for "+
				"rotation entry to be sequenced", a.pollTimeout)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(a.pollInterval):
		}
	}
}

// waitForCoveringHead polls until a witness-cosigned head (at the active
// quorum K) covers the leaf at seq (TreeSize > seq).
func (a *ProductionRotationAppender) waitForCoveringHead(ctx context.Context, seq uint64) (*store.CosignedTreeHead, error) {
	minSigs := 1
	if cur := a.keys.Current(); cur != nil {
		minSigs = cur.Quorum()
	}
	deadline := time.Now().Add(a.pollTimeout)
	for {
		head, err := a.heads.LatestCosigned(ctx, minSigs)
		if err != nil {
			return nil, fmt.Errorf("rotation-appender: cosigned head: %w", err)
		}
		// TreeSize > seq ⟺ the tree of that size includes leaf index seq.
		if head != nil && head.TreeSize > seq {
			return head, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("rotation-appender: timed out after %s waiting for a "+
				"witness-cosigned head (quorum=%d) covering leaf %d", a.pollTimeout, minSigs, seq)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(a.pollInterval):
		}
	}
}
