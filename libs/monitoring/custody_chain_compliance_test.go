package monitoring

import (
	"context"
	"testing"
	"time"

	sdkmon "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

func ccd(s string) storage.CID { return storage.Compute([]byte(s)) }
func ccpos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:web:ledger", Sequence: seq}
}
func ccGenesis(cd storage.CID) storage.ArtifactCustodyRecord {
	return storage.ArtifactCustodyRecord{ContentDigest: cd, Owner: "did:org:a", Custodian: "did:org:a", EffectivePos: ccpos(1)}
}

func runCustody(chains map[string]*crosslog.CustodyChain, asOf types.LogPosition) []sdkmon.Alert {
	a, _ := CheckCustodyChainCompliance(context.Background(),
		CustodyChainComplianceConfig{Custody: crosslog.MaterializedCustody{Chains: chains}, AsOf: asOf}, time.Unix(1000, 0))
	return a
}

func TestCustody_CleanChain_NoAlert(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis: ccGenesis(cd),
		Transfers: []storage.ArtifactCustodyTransfer{
			{ContentDigest: cd, FromOwner: "did:org:a", ToOwner: "did:org:b", ToCustodian: "did:cust:b", EffectivePos: ccpos(5)},
			{ContentDigest: cd, FromOwner: "did:org:b", ToOwner: "did:org:c", ToCustodian: "did:cust:c", EffectivePos: ccpos(9)},
		},
	}}
	if a := runCustody(chains, ccpos(100)); len(a) != 0 {
		t.Fatalf("a clean chain must raise no alerts, got %+v", a)
	}
}

func TestCustody_GenesisOnly_NoAlert(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {Genesis: ccGenesis(cd)}}
	if a := runCustody(chains, ccpos(100)); len(a) != 0 {
		t.Fatalf("a genesis-only chain must raise no alerts, got %+v", a)
	}
}

func TestCustody_DestroyedChain_NoAlert(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis:     ccGenesis(cd),
		Destruction: &storage.ArtifactDestruction{ContentDigest: cd, AuthorizingPrincipal: "did:org:a", EffectivePos: ccpos(10)},
	}}
	// Destruction is legitimate; the chain still walks cleanly.
	if a := runCustody(chains, ccpos(100)); len(a) != 0 {
		t.Fatalf("a destroyed-but-clean chain must raise no alerts, got %+v", a)
	}
}

// The headline finding: a transfer whose FromOwner is not the current owner.
func TestCustody_ForgedFromOwner_Critical(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis: ccGenesis(cd), // owner is did:org:a
		Transfers: []storage.ArtifactCustodyTransfer{
			{ContentDigest: cd, FromOwner: "did:forged", ToOwner: "did:org:z", ToCustodian: "did:cust:z", EffectivePos: ccpos(5)},
		},
	}}
	a := runCustody(chains, ccpos(100))
	if countSeverity(a, sdkmon.Critical) != 1 {
		t.Fatalf("a forged FromOwner must raise one Critical, got %+v", a)
	}
}

func TestCustody_CrossContentSplice_Critical(t *testing.T) {
	cd, other := ccd("A"), ccd("B")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis: ccGenesis(cd),
		Transfers: []storage.ArtifactCustodyTransfer{
			// References a DIFFERENT artifact's ContentDigest.
			{ContentDigest: other, FromOwner: "did:org:a", ToOwner: "did:org:b", ToCustodian: "did:cust:b", EffectivePos: ccpos(5)},
		},
	}}
	if countSeverity(runCustody(chains, ccpos(100)), sdkmon.Critical) != 1 {
		t.Fatal("a cross-content splice must raise one Critical")
	}
}

// Transfers with no genesis in range → Warning (likely a scan-window gap).
func TestCustody_OrphanTransfersNoGenesis_Warning(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		// No Genesis set (zero record).
		Transfers: []storage.ArtifactCustodyTransfer{
			{ContentDigest: cd, FromOwner: "did:org:a", ToOwner: "did:org:b", EffectivePos: ccpos(5)},
		},
	}}
	a := runCustody(chains, ccpos(100))
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("orphan transfers (no genesis) must Warn, got %+v", a)
	}
}

// A null EffectivePos (projection anomaly) → Warning, not a fraud Critical.
func TestCustody_NullEffectivePos_Warning(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis: ccGenesis(cd),
		Transfers: []storage.ArtifactCustodyTransfer{
			{ContentDigest: cd, FromOwner: "did:org:a", ToOwner: "did:org:b", EffectivePos: types.LogPosition{}},
		},
	}}
	a := runCustody(chains, ccpos(100))
	if countSeverity(a, sdkmon.Warning) != 1 || countSeverity(a, sdkmon.Critical) != 0 {
		t.Fatalf("a null EffectivePos must Warn, got %+v", a)
	}
}

// The monitor sorts before walking, so position-correct but unsorted transfers
// still walk cleanly (no false ErrCustodyTransfersNotSorted).
func TestCustody_UnsortedButValid_SortedThenClean(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {
		Genesis: ccGenesis(cd),
		Transfers: []storage.ArtifactCustodyTransfer{
			{ContentDigest: cd, FromOwner: "did:org:b", ToOwner: "did:org:c", ToCustodian: "did:cust:c", EffectivePos: ccpos(9)},
			{ContentDigest: cd, FromOwner: "did:org:a", ToOwner: "did:org:b", ToCustodian: "did:cust:b", EffectivePos: ccpos(5)},
		},
	}}
	if a := runCustody(chains, ccpos(100)); len(a) != 0 {
		t.Fatalf("the monitor must sort before walking — no alert expected, got %+v", a)
	}
}

func TestCustody_EmptyProjection_NoOp(t *testing.T) {
	if a := runCustody(map[string]*crosslog.CustodyChain{}, ccpos(1)); a != nil {
		t.Fatalf("empty projection (unwired) must no-op, got %+v", a)
	}
}

func TestCustody_NullAsOf_Warning(t *testing.T) {
	cd := ccd("A")
	chains := map[string]*crosslog.CustodyChain{cd.String(): {Genesis: ccGenesis(cd)}}
	if countSeverity(runCustody(chains, types.LogPosition{}), sdkmon.Warning) != 1 {
		t.Fatal("a null as-of must Warn once (cannot walk)")
	}
}
