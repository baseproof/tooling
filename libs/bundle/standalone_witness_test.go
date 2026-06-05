package bundle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// witnessKit builds n real did:key witnesses + their cosign signers.
func witnessKit(t *testing.T, n int) (dids []string, signers []cosign.WitnessSigner) {
	t.Helper()
	for i := 0; i < n; i++ {
		kp, err := did.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		dids = append(dids, kp.DID)
		signers = append(signers, cosign.NewECDSAWitnessSigner(kp.PrivateKey))
	}
	return dids, signers
}

// headCosignedBy builds a checkpoint cosigned by the given signers under nid.
func headCosignedBy(t *testing.T, signers []cosign.WitnessSigner, nid cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		RootHash: [32]byte{0x11}, SMTRoot: [32]byte{0x22}, ReceiptRoot: [32]byte{0x33}, TreeSize: 10,
	}}
	payload := cosign.NewTreeHeadPayload(head.TreeHead)
	for _, s := range signers {
		sig, err := s.Sign(context.Background(), payload, nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("cosign: %v", err)
		}
		head.Signatures = append(head.Signatures, sig)
	}
	return head
}

func witnessTestBootstrap(genesisDIDs []string) *network.BootstrapDocument {
	return &network.BootstrapDocument{
		ProtocolVersion: "1", ExchangeDID: "did:web:exchange.example", NetworkName: "wr-test-net",
		GenesisWitnessSet:           genesisDIDs,
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy:      network.SignaturePolicy{AllowedEntrySigSchemes: []uint16{0x0001}, AllowedCosignSchemeTags: []uint8{0x01}, MinSignaturesPerEntry: 1},
	}
}

func witnessGather(t *testing.T, srv *httptest.Server, bdoc *network.BootstrapDocument, k int, horizon types.CosignedTreeHead) *StandaloneLedgerGather {
	t.Helper()
	client, err := clitools.NewLedgerClient(srv.URL, "did:web:gather.test")
	if err != nil {
		t.Fatalf("NewLedgerClient: %v", err)
	}
	g, err := NewStandaloneLedgerGather(client, srv.URL, srv.Client(), bdoc, k, 7, [32]byte{0x9})
	if err != nil {
		t.Fatalf("NewStandaloneLedgerGather: %v", err)
	}
	g.horizon = &horizon // pre-cache the checkpoint so getHorizon makes no HTTP call
	return g
}

// COMMON CASE: the genesis set still cosigns the checkpoint ⇒ the network never
// rotated ⇒ an EMPTY witness chain, with NO log scan (zero HTTP).
func TestGather_WitnessRotation_GenesisShortCircuit(t *testing.T) {
	const n, k = 3, 2
	dids, signers := witnessKit(t, n)
	bdoc := witnessTestBootstrap(dids)
	ids, err := bdoc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	head := headCosignedBy(t, signers, cosign.NetworkID(ids.NetworkID))

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "no HTTP expected on the genesis short-circuit", http.StatusInternalServerError)
	}))
	defer srv.Close()

	g := witnessGather(t, srv, bdoc, k, head)
	got, err := g.FetchWitnessRotationChain(context.Background(), 10)
	if err != nil {
		t.Fatalf("FetchWitnessRotationChain: %v", err)
	}
	if got != nil {
		t.Errorf("a never-rotated network must yield an empty witness_rotation_chain, got %d elements", len(got))
	}
	if hits != 0 {
		t.Errorf("the genesis short-circuit must make zero HTTP calls (no scan), made %d", hits)
	}
}

// ROTATED DISPATCH: when the genesis set does NOT cosign the checkpoint (the set
// rotated), the gather takes the Rebuilder path — it fetches the ledger's current
// witness set first. (Here the ledger doesn't serve it ⇒ a clear error, proving the
// dispatch reached the rotated path rather than silently returning empty.)
func TestGather_WitnessRotation_RotatedDispatch(t *testing.T) {
	const n, k = 3, 2
	genesisDIDs, _ := witnessKit(t, n)        // genesis set S0
	_, otherSigners := witnessKit(t, n)       // a DIFFERENT set cosigns the checkpoint
	bdoc := witnessTestBootstrap(genesisDIDs) // bootstrap pins S0
	ids, err := bdoc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	head := headCosignedBy(t, otherSigners, cosign.NetworkID(ids.NetworkID)) // NOT cosigned by S0

	srv := httptest.NewServer(http.NotFoundHandler()) // current-witness-set endpoint absent
	defer srv.Close()

	g := witnessGather(t, srv, bdoc, k, head)
	_, err = g.FetchWitnessRotationChain(context.Background(), 10)
	if err == nil {
		t.Fatal("a rotated network with no current-witness-set endpoint must error (dispatch reached the Rebuilder path)")
	}
	if !strings.Contains(err.Error(), "current witness set") {
		t.Errorf("error should name the current-witness-set fetch, got: %v", err)
	}
}
