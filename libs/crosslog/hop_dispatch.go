/*
FILE PATH: libs/crosslog/hop_dispatch.go

DESCRIPTION:

	HopDispatcher is the per-hop key-at-position dispatch for a CROSS-LOG
	evidence chain — the foreign-hop verifier from the Item-3 dispatch table.
	For each hop it resolves the signer's active key at the hop's intrinsic
	log position and checks the hop entry's signature under it, dispatched by
	DID method:

	  on-log domain (GovernsOnLog) : RotationHistorySource → resolve the active
	      key at the position (VerifyKeyAtPosition) → forward-verify the hop's
	      secp256k1 signature (signatures.VerifyEntry). On-log domain DIDs
	      (vendor/role DIDs JN governs) have a position-bound key history that
	      the registry's current-key resolution cannot answer.
	  did:pkh / did:web / did:key : the SDK SignatureVerifier registry, which
	      dispatches per method — EIP-1271 block-pin, DID document, or the
	      key embedded in the DID.

	VerifyHop matches verifier.EvidenceHopVisitor, so it plugs straight into a
	foreign verifier.VerifyEvidenceChain walk.
*/
package crosslog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// RotationResolver materializes a signer DID's authority-verified rotation
// history. verification.RotationHistorySource satisfies it.
type RotationResolver interface {
	Build(ctx context.Context, signerDID string, initialKey []byte) ([]verifier.RotationRecord, error)
}

var (
	// ErrNilHop is returned for a nil hop or an unfetched hop entry.
	ErrNilHop = errors.New("crosslog: nil hop or entry")
	// ErrHopUnsigned is returned when an on-log hop entry has no secp256k1 signature.
	ErrHopUnsigned = errors.New("crosslog: hop entry carries no SigAlgoECDSA signature")
	// ErrHopMisconfigured is returned when a needed dependency is nil.
	ErrHopMisconfigured = errors.New("crosslog: HopDispatcher missing dependency")
	// ErrHopSignatureInvalid is returned when a hop's signature does not verify.
	ErrHopSignatureInvalid = errors.New("crosslog: hop signature invalid")
)

// HopDispatcher verifies cross-log evidence-chain hops by method-dispatched
// key-at-position resolution. Construct once; safe for concurrent VerifyHop.
type HopDispatcher struct {
	// Registry verifies did:pkh/web/key hop signatures. Required.
	Registry attestation.SignatureVerifier

	// Rotations resolves on-log domain signers' rotation history. Required
	// when GovernsOnLog can return true.
	Rotations RotationResolver

	// InitialKey returns a signer DID's pre-rotation (root-entity) public
	// key, rooting its rotation chain. Required for on-log domain signers.
	InitialKey func(ctx context.Context, signerDID string) ([]byte, error)

	// GovernsOnLog reports whether a signer DID's key history is materialized
	// on-log (so the rotation path applies) vs resolved off-log via the
	// registry. nil ⇒ every hop goes through the registry.
	GovernsOnLog func(signerDID string) bool
}

// VerifyHop verifies one evidence-chain hop. It satisfies
// verifier.EvidenceHopVisitor, so the walker records a returned error on the
// hop. A nil return means the hop's signature is valid under the key active
// for its signer at its position.
func (d *HopDispatcher) VerifyHop(ctx context.Context, hop *verifier.EvidenceHop) error {
	if hop == nil || hop.Entry == nil {
		return ErrNilHop
	}
	signer := hop.Entry.Header.SignerDID

	if d.GovernsOnLog != nil && d.GovernsOnLog(signer) {
		return d.verifyOnLogHop(ctx, signer, hop)
	}

	if d.Registry == nil {
		return fmt.Errorf("%w: nil Registry", ErrHopMisconfigured)
	}
	report, err := attestation.VerifyEntrySignatures(ctx, hop.Entry, d.Registry)
	if err != nil {
		return fmt.Errorf("crosslog: hop %q registry verify: %w", signer, err)
	}
	if report.Total == 0 || report.ValidCount != report.Total || report.FirstError != nil {
		return fmt.Errorf("%w: %q (registry: %d/%d valid)", ErrHopSignatureInvalid, signer, report.ValidCount, report.Total)
	}
	return nil
}

func (d *HopDispatcher) verifyOnLogHop(ctx context.Context, signer string, hop *verifier.EvidenceHop) error {
	if d.Rotations == nil || d.InitialKey == nil {
		return fmt.Errorf("%w: on-log hop needs Rotations + InitialKey", ErrHopMisconfigured)
	}
	if len(hop.Entry.Signatures) == 0 || hop.Entry.Signatures[0].AlgoID != envelope.SigAlgoECDSA {
		return fmt.Errorf("%w: %q", ErrHopUnsigned, signer)
	}
	initial, err := d.InitialKey(ctx, signer)
	if err != nil {
		return fmt.Errorf("crosslog: hop %q initial key: %w", signer, err)
	}
	recs, err := d.Rotations.Build(ctx, signer, initial)
	if err != nil {
		return fmt.Errorf("crosslog: hop %q rotation history: %w", signer, err)
	}
	active, err := resolveActiveKey(ctx, signer, hop.Position, initial, recs)
	if err != nil {
		return fmt.Errorf("crosslog: hop %q active key: %w", signer, err)
	}
	pub, err := signatures.ParsePubKey(active)
	if err != nil {
		return fmt.Errorf("crosslog: hop %q parse active key: %w", signer, err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(hop.Entry))
	if err := signatures.VerifyEntry(digest, hop.Entry.Signatures[0].Bytes, pub); err != nil {
		return fmt.Errorf("%w: %q (forward-verify: %v)", ErrHopSignatureInvalid, signer, err)
	}
	return nil
}

// resolveActiveKey returns the key active for signer at pos via the SDK's
// positional walk. VerifyKeyAtPosition populates ActiveKey regardless of the
// candidate, so a sentinel (never-matched) candidate yields the resolved key.
func resolveActiveKey(ctx context.Context, signer string, pos types.LogPosition, initial []byte, recs []verifier.RotationRecord) ([]byte, error) {
	res, err := verifier.VerifyKeyAtPosition(ctx, verifier.KeyAtPositionQuery{
		SignerDID:    signer,
		CandidateKey: []byte{0x00}, // sentinel: we read ActiveKey, not Active
		QueryPos:     pos,
		InitialKey:   initial,
	}, recs)
	if err != nil {
		return nil, err
	}
	return res.ActiveKey, nil
}
