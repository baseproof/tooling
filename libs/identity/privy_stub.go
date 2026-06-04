/*
FILE PATH: libs/identity/privy_stub.go

DESCRIPTION:

	Deterministic in-memory IdentityProvider implementation for tests
	and local development. Satisfies the full IdentityProvider
	interface without any network I/O.

	A real PrivyProvider lives in a later phase (privy.go) and talks
	to Privy's REST API for token verification (JWKS) and wallet
	signing (walletApi.rawSign). The interface is shared; only the
	implementation is different. Test code constructs a StubProvider;
	production code constructs a PrivyProvider.

	The stub:
	  - Maps token strings to Claims (BindToken).
	  - Maps DIDs to secp256k1 private keys (BindKey).
	  - Signs digests with the bound key via secp256k1.SignCompact
	    (the same wire format Privy returns: 65-byte recoverable).
	  - Optionally injects ErrSignRejected per DID (RejectSigning).
	  - Optionally injects ErrSignTimeout per DID (TimeoutSigning).

	Invariant: the stub never holds plaintext that a real Privy
	provider wouldn't see. The only state is (DID → privKey) bindings
	that the test wired up, plus the (token → Claims) registrations.

KEY DEPENDENCIES:
  - api/exchange/identity/identity.go (IdentityProvider, Claims).
  - api/exchange/identity/identity_signing.go (SignRequest/Response).
  - github.com/decred/dcrd/dcrec/secp256k1/v4 (curve operations).
*/
package identity

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// StubProvider is an in-memory IdentityProvider for tests and dev.
// Safe for concurrent use.
type StubProvider struct {
	mu sync.RWMutex

	// tokens maps an opaque token string to the Claims VerifyToken
	// returns. Tests register tokens with BindToken.
	tokens map[string]*Claims

	// keys maps a did:key to the secp256k1 private key. Tests
	// register with BindKey.
	keys map[string]*secp256k1.PrivateKey

	// rejectDIDs short-circuits SignDigest to ErrSignRejected.
	// Tests opt-in via RejectSigning.
	rejectDIDs map[string]bool

	// timeoutDIDs short-circuits SignDigest to ErrSignTimeout.
	timeoutDIDs map[string]bool

	// nowFn lets tests pin "now" for token-expiration assertions.
	nowFn func() time.Time

	// healthErr lets tests force Health to fail.
	healthErr error
}

// NewStubProvider returns an empty stub. Bind keys and tokens before
// using it.
func NewStubProvider() *StubProvider {
	return &StubProvider{
		tokens:      make(map[string]*Claims),
		keys:        make(map[string]*secp256k1.PrivateKey),
		rejectDIDs:  make(map[string]bool),
		timeoutDIDs: make(map[string]bool),
		nowFn:       time.Now,
	}
}

// SetNowFn replaces the clock — useful for testing token expiration.
func (s *StubProvider) SetNowFn(fn func() time.Time) {
	s.mu.Lock()
	s.nowFn = fn
	s.mu.Unlock()
}

// SetHealthErr controls what Health returns. nil = healthy.
func (s *StubProvider) SetHealthErr(err error) {
	s.mu.Lock()
	s.healthErr = err
	s.mu.Unlock()
}

// BindToken registers a (token → claims) mapping. VerifyToken looks
// here. Tests call this with a representative Claims to drive
// downstream auth behaviors.
func (s *StubProvider) BindToken(token string, claims *Claims) {
	s.mu.Lock()
	s.tokens[token] = claims
	s.mu.Unlock()
}

// BindKey registers a (DID → secp256k1 private key) mapping. The
// stub holds the private key in memory (test-only); a real provider
// holds nothing.
func (s *StubProvider) BindKey(did string, priv *secp256k1.PrivateKey) {
	s.mu.Lock()
	s.keys[did] = priv
	s.mu.Unlock()
}

// RejectSigning forces SignDigest to return ErrSignRejected for
// signerDID. Used to test the "user declines in wallet" path.
func (s *StubProvider) RejectSigning(did string, reject bool) {
	s.mu.Lock()
	if reject {
		s.rejectDIDs[did] = true
	} else {
		delete(s.rejectDIDs, did)
	}
	s.mu.Unlock()
}

// TimeoutSigning forces SignDigest to return ErrSignTimeout for
// signerDID. Used to test the "user did not respond" path.
func (s *StubProvider) TimeoutSigning(did string, timeout bool) {
	s.mu.Lock()
	if timeout {
		s.timeoutDIDs[did] = true
	} else {
		delete(s.timeoutDIDs, did)
	}
	s.mu.Unlock()
}

// VerifyToken returns the Claims previously bound to token. Returns
// ErrTokenInvalid when unknown; the bound Claims are run through
// Validate so an expired binding surfaces ErrTokenExpired etc.
func (s *StubProvider) VerifyToken(ctx context.Context, token string) (*Claims, error) {
	s.mu.RLock()
	c, ok := s.tokens[token]
	now := s.nowFn()
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("stub: unknown token: %w", ErrTokenInvalid)
	}
	if err := c.Validate(now); err != nil {
		return nil, err
	}
	return c, nil
}

// SignDigest validates the request, then signs the 32-byte digest
// with the bound key. Returns 65-byte SignCompact output (V||R||S
// per dcrd's convention; callers re-serialize as needed).
func (s *StubProvider) SignDigest(ctx context.Context, req SignRequest) (*SignResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	priv, hasKey := s.keys[req.SignerDID]
	rejected := s.rejectDIDs[req.SignerDID]
	timedOut := s.timeoutDIDs[req.SignerDID]
	now := s.nowFn()
	s.mu.RUnlock()

	if !hasKey {
		return nil, fmt.Errorf("stub: %s: %w", req.SignerDID, ErrSignerNotFound)
	}
	if rejected {
		return nil, fmt.Errorf("stub: user declined: %w", ErrSignRejected)
	}
	if timedOut {
		return nil, fmt.Errorf("stub: user did not respond: %w", ErrSignTimeout)
	}

	sig := ecdsa.SignCompact(priv, req.Digest[:], false)
	pub := priv.PubKey().SerializeUncompressed()

	return &SignResponse{
		Signature:           sig,
		PublicKey:           pub,
		Algorithm:           "secp256k1",
		SignedAtUnixSeconds: now.Unix(),
	}, nil
}

// PublicKey returns the bound key's uncompressed (65-byte) public
// key. Returns ErrSignerNotFound when unknown.
func (s *StubProvider) PublicKey(ctx context.Context, signerDID string) ([]byte, error) {
	s.mu.RLock()
	priv, ok := s.keys[signerDID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("stub: %s: %w", signerDID, ErrSignerNotFound)
	}
	return priv.PubKey().SerializeUncompressed(), nil
}

// Health returns the configured error (nil by default).
func (s *StubProvider) Health(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.healthErr
}

// Static check that StubProvider satisfies the interface.
var _ IdentityProvider = (*StubProvider)(nil)
