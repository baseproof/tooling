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
