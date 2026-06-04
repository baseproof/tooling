// FILE PATH: services/auditor/internal/gossipfeed/signer.go
//
// DESCRIPTION:
//
//	The emit-side gossip identity for judicial-network. When the JN
//	acts as an active auditor (equivocation scanner, anchor publisher)
//	it stops being a passive receiver and becomes an ORIGINATOR on the
//	gossip plane: every event it broadcasts must be cosign-signed under
//	a stable DID and carry a strictly-increasing per-originator Lamport
//	clock plus a hash chain (prev = EventIDOf(last)).
//
//	EventSigner owns that originator state. It wraps the SDK's
//	gossip.Sign with a mutex-guarded (lamport, prev) tuple so concurrent
//	emitters can never interleave a regressing Lamport — the primary
//	transport-level replay defence (gossip.ErrLamportRegression).
//
//	Restart safety (D3): the Lamport clock is seeded from
//	time.Now().UnixNano() at construction. A restarted JN therefore
//	always resumes ABOVE any sequence it emitted before, so peers never
//	reject its post-restart events as stale. Gaps are irrelevant — only
//	monotonicity matters. Persisting the exact (lamport, prev) tuple
//	into the durable store is the planned fast-follow; until then the
//	prev chain restarts from zero on reboot (acceptable: peers catch up
//	by Lamport, not by prev-continuity).
//
// KEY DEPENDENCIES:
//   - baseproof/gossip: Sign, EventIDOf, Event, SignedEvent
//   - baseproof/crypto/cosign: WitnessSigner, NetworkID
//   - baseproof/crypto/signatures: PrivKeyFromBytes (secp256k1 scalar)
package gossipfeed

import (
	"context"
	"crypto/ecdsa"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/gossip"
)

// signingKeyPEMType is the PEM block type for the JN's secp256k1
// gossip signing key. Identical to the witness key envelope so a
// single key-gen tool produces keys for either role; distinct from
// the stdlib "EC PRIVATE KEY" (SEC1) so a P-256 key fails loudly
// rather than cosigning on the wrong curve.
const signingKeyPEMType = "BASEPROOF SECP256K1 PRIVATE KEY"

// LoadSigningKeyPEM reads the JN's secp256k1 gossip signing key from a
// PEM file (block type signingKeyPEMType, payload = 32-byte big-endian
// scalar). Fail-closed on a missing file, missing/foreign block type,
// or an off-curve scalar.
func LoadSigningKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gossipfeed: read signing key %q: %w", path, err)
	}
	return decodeSigningKeyPEM(data)
}

func decodeSigningKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block in signing key file", ErrInvalidConfig)
	}
	if block.Type != signingKeyPEMType {
		return nil, fmt.Errorf("%w: signing key PEM type %q, want %q (secp256k1, not P-256)",
			ErrInvalidConfig, block.Type, signingKeyPEMType)
	}
	key, err := signatures.PrivKeyFromBytes(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: secp256k1 scalar: %v", ErrInvalidConfig, err)
	}
	return key, nil
}

// DIDKeyForSigningKey derives the self-certifying did:key (did:key:zQ3s…)
// for a secp256k1 signing key. This is the JN's gossip originator
// identity: self-certifying means peers verify a finding's signature
// against the key embedded IN the DID — no web resolution, no external
// trust root. Operational config carries the key PEM path, never a DID
// string (the no-DID-in-config invariant), so the originator identity is
// derived here rather than configured.
func DIDKeyForSigningKey(key *ecdsa.PrivateKey) (string, error) {
	uncompressed := signatures.PubKeyBytes(&key.PublicKey)
	compressed, err := signatures.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", fmt.Errorf("gossipfeed: compress pubkey: %w", err)
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}

// EventSigner is the stateful gossip originator identity. One per
// process; its Sign method is safe for concurrent use and is the value
// passed as equivocation.ScannerConfig.Signer.
type EventSigner struct {
	signer     cosign.WitnessSigner
	networkID  cosign.NetworkID
	originator string

	mu      sync.Mutex
	lamport uint64
	prev    [32]byte
}

// NewEventSigner validates the originator identity and seeds the
// Lamport clock from wall-clock nanoseconds (see file docstring, D3).
func NewEventSigner(signer cosign.WitnessSigner, networkID cosign.NetworkID, originator string) (*EventSigner, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: nil WitnessSigner", ErrInvalidConfig)
	}
	if networkID.IsZero() {
		return nil, fmt.Errorf("%w: zero NetworkID", ErrInvalidConfig)
	}
	if originator == "" {
		return nil, fmt.Errorf("%w: empty originator DID", ErrInvalidConfig)
	}
	return &EventSigner{
		signer:     signer,
		networkID:  networkID,
		originator: originator,
		lamport:    uint64(time.Now().UnixNano()),
	}, nil
}

// Sign advances the Lamport clock, cosign-signs ev under the
// originator identity, and links it to the previous event via prev.
// On any signing failure the clock is NOT advanced, so a transient
// error never burns a Lamport tick or breaks the chain.
func (s *EventSigner) Sign(ctx context.Context, ev gossip.Event) (gossip.SignedEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.lamport + 1
	signed, err := gossip.Sign(ctx, ev, s.signer, s.networkID, s.originator, s.prev, next)
	if err != nil {
		return gossip.SignedEvent{}, err
	}
	id, err := gossip.EventIDOf(signed)
	if err != nil {
		return gossip.SignedEvent{}, fmt.Errorf("gossipfeed: event id: %w", err)
	}
	s.lamport = next
	s.prev = id
	return signed, nil
}
