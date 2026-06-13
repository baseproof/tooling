/*
FILE PATH: witnessclient/burn_appender.go

ProductionBurnAppender implements BurnLogAppender against the live ledger:
WAL submit → sequencer → entry_index sequence. It is the burn analogue of
ProductionRotationAppender, and a STRICT SUBSET of it: a burn needs NO
inclusion proof and NO covering cosigned head, because a burn's authority is
its OWN K-of-N quorum cosignatures (verified by network.VerifyBurn at every
walk) — not a Merkle binding. The appender's only job is to author the burn
entry through the burn door's single writer and return its intrinsic
sequence; the declared-burn projection then walks ResolveBurnAt by sequence.

It reuses the package's entry-submit (Submit) and seq-by-identity
(FetchPrimarySeqByHash) contracts — the same *store components the rotation
appender binds — so there is one WAL entry point, not two.
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
	"github.com/baseproof/baseproof/crypto/signatures"
)

// ProductionBurnAppender authors burn entries on the live log. Construct via
// NewProductionBurnAppender and wire it onto the BurnProcessor.
type ProductionBurnAppender struct {
	priv      *ecdsa.PrivateKey
	signerDID string
	logDID    string
	submitter rotationEntrySubmitter // shared WAL submit contract
	seqs      rotationSeqLookup      // shared entry_index seq-by-identity contract
	logger    *slog.Logger

	pollInterval time.Duration
	pollTimeout  time.Duration
}

// NewProductionBurnAppender wires the appender from the ledger's signer +
// the shared WAL submit / seq-lookup components (satisfied by the same
// *store.EntryStore the rotation appender uses).
func NewProductionBurnAppender(
	priv *ecdsa.PrivateKey,
	signerDID string,
	logDID string,
	submitter rotationEntrySubmitter,
	seqs rotationSeqLookup,
	logger *slog.Logger,
) *ProductionBurnAppender {
	if logger == nil {
		logger = slog.Default()
	}
	return &ProductionBurnAppender{
		priv:         priv,
		signerDID:    signerDID,
		logDID:       logDID,
		submitter:    submitter,
		seqs:         seqs,
		logger:       logger,
		pollInterval: defaultRotationPollInterval,
		pollTimeout:  defaultRotationPollTimeout,
	}
}

// WithPolling overrides the default poll cadence (tests use a short one).
func (a *ProductionBurnAppender) WithPolling(interval, timeout time.Duration) *ProductionBurnAppender {
	if interval > 0 {
		a.pollInterval = interval
	}
	if timeout > 0 {
		a.pollTimeout = timeout
	}
	return a
}

// AppendBurnEntry builds the ledger-authored entry around the burn payload,
// submits it into the WAL (the SAME entry point the admission handler uses,
// which is why the admission firewall refuses externally-submitted burns —
// this appender is the only legitimate author), and returns the intrinsic
// sequence once the sequencer assigns the leaf. No proof step: a burn is
// self-authorizing by its quorum cosignatures.
func (a *ProductionBurnAppender) AppendBurnEntry(ctx context.Context, burnPayload []byte) (uint64, error) {
	canonical, identity, err := a.buildSignedEntry(burnPayload)
	if err != nil {
		return 0, err
	}
	nowMicros := time.Now().UTC().UnixMicro()
	if err = a.submitter.Submit(ctx, identity, canonical, nowMicros, nil); err != nil {
		return 0, fmt.Errorf("burn-appender: submit burn entry: %w", err)
	}
	seq, err := a.waitForSequence(ctx, identity)
	if err != nil {
		return 0, err
	}
	return seq, nil
}

// buildSignedEntry mirrors ProductionRotationAppender.buildSignedEntry: the
// ledger authors and signs the entry that carries the burn payload. (Kept
// local rather than shared to leave the rotation appender untouched; a future
// dedup can extract the common author-sign-serialize seam.)
func (a *ProductionBurnAppender) buildSignedEntry(payload []byte) ([]byte, [32]byte, error) {
	hdr := envelope.ControlHeader{
		SignerDID:   a.signerDID,
		Destination: a.logDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("burn-appender: build entry: %w", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(signingHash, a.priv)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("burn-appender: sign entry: %w", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: a.signerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("burn-appender: serialize entry: %w", err)
	}
	identity, err := envelope.EntryIdentity(entry)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("burn-appender: entry identity: %w", err)
	}
	return canonical, identity, nil
}

// waitForSequence mirrors the rotation appender's seq wait: poll
// FetchPrimarySeqByHash until the leaf is sequenced or the deadline elapses.
func (a *ProductionBurnAppender) waitForSequence(ctx context.Context, identity [32]byte) (uint64, error) {
	deadline := time.Now().Add(a.pollTimeout)
	for {
		seq, ok, err := a.seqs.FetchPrimarySeqByHash(ctx, identity)
		if err != nil {
			return 0, fmt.Errorf("burn-appender: seq lookup: %w", err)
		}
		if ok {
			return seq, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("burn-appender: timed out after %s waiting for burn entry to be sequenced", a.pollTimeout)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(a.pollInterval):
		}
	}
}
