/*
FILE PATH: libs/identity/identity.go

DESCRIPTION:

	The IdentityProvider interface — the single seam between JN and
	whichever Web2→Web3 IdP the deployment uses (in our case, Privy).

	Two responsibilities:

	  1. Token verification. The user signs into the dApp via the
	     IdP; the IdP issues a JWT that travels with subsequent HTTP
	     requests. JN verifies the JWT against the IdP's keys and
	     extracts Claims (subject did:key, expiration, email).

	  2. Wallet signing. When JN needs to publish an on-log entry on
	     a user's behalf — a delegation, a revocation, a filing —
	     it computes the entry's typed-data digest and asks the IdP
	     to have the user's wallet sign it. The IdP shows a UX
	     confirmation; the user approves or rejects. JN never holds
	     the private key.

	Why this is a JN-side seam (not a direct Privy SDK import):

	  - Privy's API surface evolves; pinning JN to a single SDK
	    version creates upgrade risk.
	  - Test deployments need a deterministic stub that doesn't talk
	    to a real IdP. The interface lets us swap a stub in.
	  - A second deployment may want a different IdP (an enterprise
	    SSO+wallet bridge, an on-prem custody provider). The
	    interface is stable; only the implementation changes.

	Sign-time digest framing:
	  Inputs to SignDigest are 32-byte digests. The SDK's signing
	  contract (and EIP-712 typed-data convention) means JN computes
	  keccak256(domain_separator || keccak256(typed_struct)) and
	  passes the result. The provider does NOT hash again; it signs
	  the bytes given. This keeps the wallet UX accurate (the wallet
	  displays the typed structure to the user) and the protocol
	  framing (the domain separator binds the signature to a specific
	  court + schema version, preventing cross-court replay).

KEY DEPENDENCIES:
  - api/exchange/identity/identity_signing.go (SignRequest,
    SignResponse, TypedDataDisplay).
*/
package identity

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// IdentityProvider is the seam between JN and the Web2→Web3 IdP.
// Implementations: PrivyProvider (production), StubProvider (tests).
type IdentityProvider interface {
	// VerifyToken validates a token presented by an HTTP caller and
	// returns Claims on success. For Privy this is a JWT signed by
	// Privy's keys.
	//
	// On invalid signature, expired token, missing required claims:
	// returns an error wrapping ErrTokenInvalid.
	VerifyToken(ctx context.Context, token string) (*Claims, error)

	// SignDigest asks the provider to sign a 32-byte typed-data
	// digest using the wallet bound to req.SignerDID. The provider
	// shows a UX confirmation to the user (with req.Display fields
	// rendered as typed data); on approval, returns the signature.
	//
	// On user rejection: returns an error wrapping ErrSignRejected.
	// On approval timeout: returns an error wrapping ErrSignTimeout.
	// On wallet not bound to SignerDID: returns ErrSignerNotFound.
	SignDigest(ctx context.Context, req SignRequest) (*SignResponse, error)

	// PublicKey returns the secp256k1 public key (uncompressed, 65
	// bytes with 0x04 prefix) for the given DID. Used by the SDK to
	// recover an entry's signer for verification. Cheap; safe to call
	// frequently. Returns ErrSignerNotFound when unknown.
	PublicKey(ctx context.Context, signerDID string) ([]byte, error)

	// Health reports whether the provider is reachable and healthy.
	// Called by deployment readiness probes. Cheap; should not
	// trigger any user-visible work.
	Health(ctx context.Context) error
}

// Claims is the verified-token payload. Populated by VerifyToken
// from the JWT's standard + custom claims.
type Claims struct {
	// Subject is the user's protocol DID (did:key derived from the
	// secp256k1 public key of their Privy embedded wallet). Required.
	Subject string

	// Issuer identifies the IdP. For Privy: a known Privy issuer URL.
	// JN's middleware checks this against the configured allowlist.
	Issuer string

	// IssuedAt / NotBefore / ExpiresAt are populated from the JWT's
	// iat/nbf/exp standard claims. ExpiresAt is required and must be
	// in the future at verify time.
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time

	// Email is the verified email address linked to the wallet.
	// Optional; empty when the user did not link an email.
	Email string

	// EmailVerified is true iff the IdP attests the email is
	// confirmed (e.g., the user clicked a verification link). JN
	// does not trust unverified emails for any authority decision.
	EmailVerified bool

	// Custom is the JWT's custom-claims object (Privy-specific
	// fields like privy_user_id, linked_accounts). JN treats this
	// as opaque metadata; only the Subject DID drives authority.
	Custom map[string]any
}

// Validate runs structural sanity on a Claims instance. Returns nil
// iff the required fields are populated and the timestamps are in a
// consistent state. Does NOT check the signature — that's
// VerifyToken's job; this is a post-parse sanity gate.
func (c *Claims) Validate(now time.Time) error {
	if c == nil {
		return fmt.Errorf("identity: nil claims")
	}
	if c.Subject == "" {
		return fmt.Errorf("identity: claims subject (did:key) required")
	}
	if c.Issuer == "" {
		return fmt.Errorf("identity: claims issuer required")
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("identity: claims expires_at required")
	}
	if !c.ExpiresAt.After(now) {
		return fmt.Errorf("identity: claims expired at %s (now %s): %w",
			c.ExpiresAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), ErrTokenExpired)
	}
	if !c.NotBefore.IsZero() && c.NotBefore.After(now) {
		return fmt.Errorf("identity: claims not yet valid (nbf=%s, now=%s): %w",
			c.NotBefore.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339), ErrTokenNotYetValid)
	}
	if !c.IssuedAt.IsZero() && !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("identity: claims expires_at must be after issued_at")
	}
	return nil
}

// IsEmailTrusted returns true iff the claims carry a verified email.
// JN audit trails record (Subject, Email) only when this is true.
func (c *Claims) IsEmailTrusted() bool {
	return c != nil && c.Email != "" && c.EmailVerified
}

// ─── Sentinel errors ────────────────────────────────────────────────

var (
	// ErrTokenInvalid is wrapped for any structural or cryptographic
	// failure during VerifyToken. Callers errors.Is() this rather
	// than parsing strings.
	ErrTokenInvalid = errors.New("identity: token invalid")

	// ErrTokenExpired is wrapped when the JWT's exp claim is in the
	// past. A subset of ErrTokenInvalid.
	ErrTokenExpired = errors.New("identity: token expired")

	// ErrTokenNotYetValid is wrapped when the JWT's nbf claim is in
	// the future. A subset of ErrTokenInvalid.
	ErrTokenNotYetValid = errors.New("identity: token not yet valid")

	// ErrSignerNotFound is returned when SignDigest or PublicKey is
	// called with a DID the provider does not own a wallet for.
	ErrSignerNotFound = errors.New("identity: signer not found")

	// ErrSignRejected is wrapped when the user explicitly declines
	// the wallet UX confirmation.
	ErrSignRejected = errors.New("identity: sign rejected by user")

	// ErrSignTimeout is wrapped when the user neither approves nor
	// declines within the configured window. Implementations decide
	// the window; typical: 60s.
	ErrSignTimeout = errors.New("identity: sign approval timeout")

	// ErrProviderUnavailable is wrapped when the IdP is unreachable
	// or returning persistent infrastructure errors.
	ErrProviderUnavailable = errors.New("identity: provider unavailable")
)
