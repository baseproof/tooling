package artifactstore_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

type fakeCustodyResolver struct {
	owner, custodian string
	destroyed, found bool
	err              error
}

func (f fakeCustodyResolver) ResolveCustodyAt(context.Context, storage.CID, types.LogPosition) (string, string, bool, bool, error) {
	return f.owner, f.custodian, f.destroyed, f.found, f.err
}

// reqWithDID builds a request carrying did in a verified mTLS client-cert URI SAN.
func reqWithDID(did string) *http.Request {
	u, _ := url.Parse(did) // "did:court:a" round-trips through url.URL.String()
	cert := &x509.Certificate{URIs: []*url.URL{u}}
	return &http.Request{TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
}

func fixedAsOf(context.Context, *http.Request) (types.LogPosition, error) {
	return types.LogPosition{LogDID: "did:web:ledger", Sequence: 7}, nil
}

func TestCustodyHook_Authorize(t *testing.T) {
	cid := storage.Compute([]byte("artifact"))
	cases := []struct {
		name    string
		res     fakeCustodyResolver
		did     string
		mtls    bool
		wantErr error // nil = authorized
	}{
		{"owner_allowed", fakeCustodyResolver{owner: "did:court:a", custodian: "did:cust:a", found: true}, "did:court:a", true, nil},
		{"custodian_allowed", fakeCustodyResolver{owner: "did:court:a", custodian: "did:cust:a", found: true}, "did:cust:a", true, nil},
		{"stranger_denied", fakeCustodyResolver{owner: "did:court:a", custodian: "did:cust:a", found: true}, "did:court:z", true, artifactstore.ErrNotCustodyAuthorized},
		{"destroyed_denied", fakeCustodyResolver{owner: "did:court:a", found: true, destroyed: true}, "did:court:a", true, artifactstore.ErrCustodyDestroyed},
		{"not_found_denied", fakeCustodyResolver{found: false}, "did:court:a", true, artifactstore.ErrCustodyNotFound},
		{"no_mtls_denied", fakeCustodyResolver{owner: "did:court:a", found: true}, "", false, artifactstore.ErrCustodyUnauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := artifactstore.NewCustodyHook(tc.res, fixedAsOf, nil) // default mTLS DID extractor
			var r *http.Request
			if tc.mtls {
				r = reqWithDID(tc.did)
			} else {
				r = &http.Request{} // no TLS
			}
			err := h.Authorize(context.Background(), r, cid)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want authorized, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCustodyHook_FailsClosedOnResolverError(t *testing.T) {
	h := artifactstore.NewCustodyHook(
		fakeCustodyResolver{err: errors.New("source down")}, fixedAsOf, nil)
	if err := h.Authorize(context.Background(), reqWithDID("did:court:a"), storage.Compute([]byte("x"))); err == nil {
		t.Fatal("resolver error must fail closed (deny)")
	}
}

func TestRequesterDIDFromMTLS(t *testing.T) {
	did, err := artifactstore.RequesterDIDFromMTLS(reqWithDID("did:court:a"))
	if err != nil || did != "did:court:a" {
		t.Fatalf("got (%q,%v), want did:court:a", did, err)
	}
	if _, err := artifactstore.RequesterDIDFromMTLS(&http.Request{}); !errors.Is(err, artifactstore.ErrCustodyUnauthenticated) {
		t.Fatalf("no TLS → ErrCustodyUnauthenticated, got %v", err)
	}
}
