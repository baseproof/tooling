package artifactstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"
)

// CustodyResolver resolves the custody state of an artifact CID at a log
// position by walking the on-log chain. Implemented by *custody.Resolver
// (structurally — the signatures match, so neither package imports the other).
type CustodyResolver interface {
	ResolveCustodyAt(ctx context.Context, cid storage.CID, asOf types.LogPosition) (owner, custodian string, destroyed, found bool, err error)
}

var (
	// ErrCustodyNotFound — no custody root (ArtifactGenesis) for the artifact.
	ErrCustodyNotFound = errors.New("artifactstore: no custody record for artifact")
	// ErrCustodyDestroyed — a destruction record is in effect at asOf.
	ErrCustodyDestroyed = errors.New("artifactstore: artifact destroyed")
	// ErrNotCustodyAuthorized — the requester is neither the current owner nor custodian.
	ErrNotCustodyAuthorized = errors.New("artifactstore: requester is not the current owner/custodian")
	// ErrCustodyUnauthenticated — no client identity (mTLS URI SAN) to check.
	ErrCustodyUnauthenticated = errors.New("artifactstore: no client identity for custody check")
)

// CustodyHook is a custody-aware AuthorizationHook for the RESTRICTED posture.
// It resolves the (owner, custodian) authoritative at the REQUEST'S as-of
// position by walking the on-log custody chain, and admits ONLY the resolved
// owner or custodian. A destroyed artifact is denied; any resolution error fails
// closed.
//
//   - asOf yields the log position the request resolves against. Default
//     (DefaultAsOf): the latest tree size — "who owns it now". A handler may
//     supply a pinned ?asOf= for a historical custody check.
//   - requesterDID extracts the caller identity. Default: the verified mTLS
//     client cert's first URI SAN (the ledger/JN convention).
type CustodyHook struct {
	resolver     CustodyResolver
	asOf         func(ctx context.Context, r *http.Request) (types.LogPosition, error)
	requesterDID func(r *http.Request) (string, error)
}

// NewCustodyHook builds the hook. asOf is required (it binds the resolution to a
// log position — there is no "latest" in the custody model). requesterDID nil
// defaults to RequesterDIDFromMTLS.
func NewCustodyHook(
	resolver CustodyResolver,
	asOf func(ctx context.Context, r *http.Request) (types.LogPosition, error),
	requesterDID func(r *http.Request) (string, error),
) *CustodyHook {
	if requesterDID == nil {
		requesterDID = RequesterDIDFromMTLS
	}
	return &CustodyHook{resolver: resolver, asOf: asOf, requesterDID: requesterDID}
}

// Authorize implements AuthorizationHook.
func (h *CustodyHook) Authorize(ctx context.Context, r *http.Request, cid storage.CID) error {
	asOf, err := h.asOf(ctx, r)
	if err != nil {
		return fmt.Errorf("artifactstore: custody asOf: %w", err)
	}
	owner, custodian, destroyed, found, err := h.resolver.ResolveCustodyAt(ctx, cid, asOf)
	if err != nil {
		return err // fail closed (already wrapped by the resolver)
	}
	if !found {
		return ErrCustodyNotFound
	}
	if destroyed {
		return ErrCustodyDestroyed
	}
	did, err := h.requesterDID(r)
	if err != nil || did == "" {
		return ErrCustodyUnauthenticated
	}
	if did == owner || did == custodian {
		return nil
	}
	return fmt.Errorf("%w: requester=%q owner=%q custodian=%q", ErrNotCustodyAuthorized, did, owner, custodian)
}

// RequesterDIDFromMTLS extracts the caller DID from the verified mTLS client
// cert's first URI SAN — the same identity convention the JN and ledger use
// (client certs carry the caller DID in a URI SAN). No client cert / no URI SAN
// => unauthenticated.
func RequesterDIDFromMTLS(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrCustodyUnauthenticated
	}
	uris := r.TLS.PeerCertificates[0].URIs
	if len(uris) == 0 {
		return "", ErrCustodyUnauthenticated
	}
	return uris[0].String(), nil
}

// compile-time guard: CustodyHook is an AuthorizationHook.
var _ AuthorizationHook = (*CustodyHook)(nil)
