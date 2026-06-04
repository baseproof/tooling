package custody_test

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/custody"
)

type fakeSource struct {
	ch  custody.Chain
	err error
}

func (f fakeSource) Chain(context.Context, storage.CID) (custody.Chain, error) { return f.ch, f.err }

func cpos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:ledger", Sequence: seq}
}

func TestResolver_WalksChainAtAsOf(t *testing.T) {
	cd := storage.Compute([]byte("the plaintext"))
	genesis := storage.ArtifactCustodyRecord{ContentDigest: cd, Owner: "did:court:a", Custodian: "did:court:a", EffectivePos: cpos(1)}
	transfers := []storage.ArtifactCustodyTransfer{
		// intentionally unsorted; the resolver sorts before the walk.
		{ContentDigest: cd, FromOwner: "did:court:b", ToOwner: "did:court:c", ToCustodian: "did:cust:c", EffectivePos: cpos(10)},
		{ContentDigest: cd, FromOwner: "did:court:a", ToOwner: "did:court:b", ToCustodian: "did:cust:b", EffectivePos: cpos(5)},
	}
	r := custody.NewResolver(fakeSource{ch: custody.Chain{Genesis: genesis, Transfers: transfers, Found: true}})

	for _, tc := range []struct {
		asOf             uint64
		owner, custodian string
	}{
		{3, "did:court:a", "did:court:a"},
		{5, "did:court:b", "did:cust:b"},
		{7, "did:court:b", "did:cust:b"},
		{10, "did:court:c", "did:cust:c"},
		{100, "did:court:c", "did:cust:c"},
	} {
		o, c, destroyed, found, err := r.ResolveCustodyAt(context.Background(), cd, cpos(tc.asOf))
		if err != nil || !found || destroyed {
			t.Fatalf("asOf=%d: found=%v destroyed=%v err=%v", tc.asOf, found, destroyed, err)
		}
		if o != tc.owner || c != tc.custodian {
			t.Errorf("asOf=%d: got (%s,%s) want (%s,%s)", tc.asOf, o, c, tc.owner, tc.custodian)
		}
	}
}

func TestResolver_DestroyedAtAsOf(t *testing.T) {
	cd := storage.Compute([]byte("x"))
	genesis := storage.ArtifactCustodyRecord{ContentDigest: cd, Owner: "did:court:a", Custodian: "did:court:a", EffectivePos: cpos(1)}
	d := &storage.ArtifactDestruction{ContentDigest: cd, AuthorizingPrincipal: "did:court:a", EffectivePos: cpos(10)}
	r := custody.NewResolver(fakeSource{ch: custody.Chain{Genesis: genesis, Destruction: d, Found: true}})

	if _, _, destroyed, _, _ := r.ResolveCustodyAt(context.Background(), cd, cpos(9)); destroyed {
		t.Fatal("must NOT be destroyed before the destruction position")
	}
	if _, _, destroyed, _, _ := r.ResolveCustodyAt(context.Background(), cd, cpos(10)); !destroyed {
		t.Fatal("must be destroyed at/after the destruction position (inclusive)")
	}
}

func TestResolver_NotFound(t *testing.T) {
	r := custody.NewResolver(fakeSource{ch: custody.Chain{Found: false}})
	_, _, _, found, err := r.ResolveCustodyAt(context.Background(), storage.Compute([]byte("x")), cpos(1))
	if err != nil || found {
		t.Fatalf("no genesis → found=false, no error; got found=%v err=%v", found, err)
	}
}

func TestResolver_ForgedChainFailsClosed(t *testing.T) {
	cd := storage.Compute([]byte("x"))
	genesis := storage.ArtifactCustodyRecord{ContentDigest: cd, Owner: "did:court:a", Custodian: "did:court:a", EffectivePos: cpos(1)}
	forged := []storage.ArtifactCustodyTransfer{
		{ContentDigest: cd, FromOwner: "did:forged", ToOwner: "did:court:z", EffectivePos: cpos(5)},
	}
	r := custody.NewResolver(fakeSource{ch: custody.Chain{Genesis: genesis, Transfers: forged, Found: true}})
	if _, _, _, _, err := r.ResolveCustodyAt(context.Background(), cd, cpos(5)); err == nil {
		t.Fatal("a forged FromOwner must fail the walk closed (error, not silent)")
	}
}

func TestResolver_SourceErrorFailsClosed(t *testing.T) {
	r := custody.NewResolver(fakeSource{err: errors.New("db down")})
	if _, _, _, _, err := r.ResolveCustodyAt(context.Background(), storage.Compute([]byte("x")), cpos(1)); !errors.Is(err, custody.ErrSourceFailed) {
		t.Fatalf("want ErrSourceFailed, got %v", err)
	}
}
