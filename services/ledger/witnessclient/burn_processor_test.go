package witnessclient

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/api"
)

type fakeAppender struct {
	calls int
	err   error
}

func (f *fakeAppender) AppendBurnEntry(context.Context, []byte) (uint64, error) {
	f.calls++
	return 99, f.err
}

type staticKeys struct{ set *cosign.WitnessKeySet }

func (s staticKeys) Current() *cosign.WitnessKeySet { return s.set }

func mintBurn(t *testing.T, ws *witnesstest.Set, netID cosign.NetworkID, n int) network.NetworkBurn {
	t.Helper()
	b := network.NetworkBurn{NetworkID: [32]byte(netID), ReasonClass: "witness_quorum_compromise"}
	payload := cosign.NewBurnPayloadSHA256(network.BurnContentDigest(b))
	for i := 0; i < n; i++ {
		sig, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			t.Fatal(err)
		}
		b.Signatures = append(b.Signatures, types.WitnessSignature{PubKeyID: ws.Keys[i].ID, SchemeTag: ws.Keys[i].SchemeTag, SigBytes: sig})
	}
	return b
}

func TestBurnProcessor_FullPath(t *testing.T) {
	var netID cosign.NetworkID
	for i := range netID {
		netID[i] = byte(i + 1)
	}
	ws := witnesstest.NewSet(t, netID, 3, 2)
	app := &fakeAppender{}
	p := NewBurnProcessor(staticKeys{ws.KeySet}, app)

	// Pre-burn: declared leg honest false.
	if burned, _ := p.DeclaredBurn(context.Background()); burned {
		t.Fatal("must not be burned before any burn")
	}

	// Rogue burn: refused, nothing appended, nothing flipped.
	rogue := witnesstest.NewSet(t, netID, 3, 2)
	if _, err := p.ProcessBurn(context.Background(), mintBurn(t, rogue, netID, 2)); !errors.Is(err, network.ErrNetworkBurnUnauthorized) {
		t.Fatalf("rogue-signed burn must refuse: %v", err)
	}
	if app.calls != 0 {
		t.Fatal("a refused burn must never reach the appender (verify BEFORE append)")
	}
	if burned, _ := p.DeclaredBurn(context.Background()); burned {
		t.Fatal("nothing half-applied: refused burn must not flip state")
	}

	// Append failure: state must NOT flip.
	app.err = errors.New("wal down")
	if _, err := p.ProcessBurn(context.Background(), mintBurn(t, ws, netID, 2)); err == nil {
		t.Fatal("append failure must surface")
	}
	if burned, _ := p.DeclaredBurn(context.Background()); burned {
		t.Fatal("append failure must not flip declared state")
	}

	// The real burn: accepted, appended, declared flips.
	app.err = nil
	seq, err := p.ProcessBurn(context.Background(), mintBurn(t, ws, netID, 2))
	if err != nil || seq != 99 {
		t.Fatalf("quorum-signed burn must commit: seq=%d err=%v", seq, err)
	}
	if burned, _ := p.DeclaredBurn(context.Background()); !burned {
		t.Fatal("declared leg must flip after the on-log append")
	}

	// Terminal: a second burn is 409-class.
	if _, err := p.ProcessBurn(context.Background(), mintBurn(t, ws, netID, 2)); !errors.Is(err, api.ErrAlreadyBurned) {
		t.Fatalf("burn is terminal: %v", err)
	}
}

// TestBurnProcessor_RebuildFromLog is the projection-is-a-cache proof
// (Category A, in process): the declared-burn state is REBUILDABLE by walking
// the log's burn records, never hand-seeded. An empty/clean log → not burned;
// an authorized burn record → declared seeded; a poisoned (rogue-signed)
// record → the walk refuses and boot is told to fail closed.
func TestBurnProcessor_RebuildFromLog(t *testing.T) {
	var netID cosign.NetworkID
	for i := range netID {
		netID[i] = byte(i + 1)
	}
	ws := witnesstest.NewSet(t, netID, 3, 2)
	p := NewBurnProcessor(staticKeys{ws.KeySet}, &fakeAppender{})
	ctx := context.Background()
	asOf := types.LogPosition{LogDID: "did:web:me", Sequence: ^uint64(0)}

	// Empty log: not burned, no error (normal life).
	if err := p.RebuildFromLog(ctx, nil, ws.KeySet, asOf); err != nil {
		t.Fatalf("empty log rebuild must be clean: %v", err)
	}
	if burned, _ := p.DeclaredBurn(ctx); burned {
		t.Fatal("empty log must not seed a burn")
	}

	// An AUTHORIZED burn record on the log → declared seeded by the walk.
	b := mintBurn(t, ws, netID, 2)
	recs := []network.NetworkBurnRecord{{EffectivePos: types.LogPosition{LogDID: "did:web:me", Sequence: 100}, Payload: b}}
	if err := p.RebuildFromLog(ctx, recs, ws.KeySet, asOf); err != nil {
		t.Fatalf("authorized burn must rebuild: %v", err)
	}
	if burned, _ := p.DeclaredBurn(ctx); !burned {
		t.Fatal("an authorized on-log burn must seed declared at boot")
	}

	// A poisoned record (rogue-signed) → the walk refuses; boot fails closed.
	fresh := NewBurnProcessor(staticKeys{ws.KeySet}, &fakeAppender{})
	rogue := witnesstest.NewSet(t, netID, 3, 2)
	poisoned := []network.NetworkBurnRecord{{EffectivePos: types.LogPosition{LogDID: "did:web:me", Sequence: 100}, Payload: mintBurn(t, rogue, netID, 2)}}
	if err := fresh.RebuildFromLog(ctx, poisoned, ws.KeySet, asOf); err == nil {
		t.Fatal("a poisoned burn stream at boot must refuse (fail closed), not seed not-burned")
	}
	if burned, _ := fresh.DeclaredBurn(ctx); burned {
		t.Fatal("a refused rebuild must not flip declared state")
	}
}
