package main

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// signingKeyPEMType mirrors the (unexported) block type gossipfeed.LoadSigningKeyPEM
// expects. Kept in lock-step with services/auditor/internal/gossipfeed/signer.go.
const eqSigningKeyPEMType = "BASEPROOF SECP256K1 PRIVATE KEY"

func eqTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

// eqWriteSigningKey generates a secp256k1 gossip signing key and writes it as the
// PEM gossipfeed.LoadSigningKeyPEM reads (32-byte big-endian scalar).
func eqWriteSigningKey(t *testing.T) string {
	t.Helper()
	k, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var scalar [32]byte
	k.D.FillBytes(scalar[:])
	path := filepath.Join(t.TempDir(), "gossip-key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: eqSigningKeyPEMType, Bytes: scalar[:]})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// eqTestWitnessSet builds a real 1-of-1 ECDSA witness key set (no PoP needed for
// ECDSA), the genesis-derived shape the scanner verifies fetched heads against.
func eqTestWitnessSet(t *testing.T, nid cosign.NetworkID) *cosign.WitnessKeySet {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	keys := []types.WitnessPublicKey{{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}}
	set, err := cosign.NewECDSAWitnessKeySet(keys, nid, 1)
	if err != nil {
		t.Fatalf("NewECDSAWitnessKeySet: %v", err)
	}
	return set
}

// eqStubResolver satisfies witness.EndpointResolver. It points at an unroutable
// host so the scanner's first sweep fails fast (and logs, never crashes).
type eqStubResolver struct{}

func (eqStubResolver) LedgerEndpoint(_ context.Context, _ string) (string, error) {
	return "https://peer.invalid", nil
}
func (eqStubResolver) WitnessEndpoints(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func eqBaseDeps(t *testing.T) equivScannerDeps {
	return equivScannerDeps{
		networkID:  cosign.NetworkID{1},
		resolver:   eqStubResolver{},
		httpClient: &http.Client{Timeout: time.Second},
		logger:     eqTestLogger(),
	}
}

func eqAssertDisabled(t *testing.T, done <-chan struct{}, cleanup func(context.Context) error, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("disabled path returned error: %v", err)
	}
	if done != nil || cleanup != nil {
		t.Fatalf("want disabled (nil done + cleanup), got done=%v cleanup!=nil=%v", done != nil, cleanup != nil)
	}
}

// A zero/unset scan interval is the default — the scanner must stay dark even
// when a signing key is present.
func TestStartEquivocationScanner_DisabledWhenIntervalZero(t *testing.T) {
	d := eqBaseDeps(t)
	d.scanInterval = 0
	d.signingKeyFile = eqWriteSigningKey(t)
	done, cleanup, err := startEquivocationScanner(context.Background(), d)
	eqAssertDisabled(t, done, cleanup, err)
}

// Emit needs a gossip identity: an interval without a signing key disables the
// scanner (and must NOT fail boot — it's an additive leg).
func TestStartEquivocationScanner_DisabledWhenNoSigningKey(t *testing.T) {
	d := eqBaseDeps(t)
	d.scanInterval = time.Second
	d.signingKeyFile = ""
	d.peers = []resolvedPeer{{baseURL: "https://p", originatorDID: "did:key:z1"}}
	d.witnessSets = map[string]*cosign.WitnessKeySet{"did:key:z1": eqTestWitnessSet(t, d.networkID)}
	done, cleanup, err := startEquivocationScanner(context.Background(), d)
	eqAssertDisabled(t, done, cleanup, err)
}

// No resolved peers ⇒ nothing to scan or push to; disabled before the key is even
// read (so a bogus path here is fine — it proves the early return).
func TestStartEquivocationScanner_DisabledWhenNoPeers(t *testing.T) {
	d := eqBaseDeps(t)
	d.scanInterval = time.Second
	d.signingKeyFile = "/nonexistent/key.pem"
	d.peers = nil
	done, cleanup, err := startEquivocationScanner(context.Background(), d)
	eqAssertDisabled(t, done, cleanup, err)
}

// Full config: a valid key + one peer with a matching witness set constructs the
// signer + push publisher + head client + per-peer scanner and launches it. The
// leg must unwind cleanly on ctx cancel and the publisher must drain.
func TestStartEquivocationScanner_EnabledPath(t *testing.T) {
	d := eqBaseDeps(t)
	d.scanInterval = time.Second
	d.signingKeyFile = eqWriteSigningKey(t)
	const logDID = "did:key:zPeerOriginator"
	d.peers = []resolvedPeer{{baseURL: "https://peer.invalid", originatorDID: logDID}}
	d.witnessSets = map[string]*cosign.WitnessKeySet{logDID: eqTestWitnessSet(t, d.networkID)}

	ctx, cancel := context.WithCancel(context.Background())
	done, cleanup, err := startEquivocationScanner(ctx, d)
	if err != nil {
		cancel()
		t.Fatalf("enabled path returned error: %v", err)
	}
	if done == nil || cleanup == nil {
		cancel()
		t.Fatalf("want enabled (non-nil done + cleanup)")
	}

	cancel() // unblock every per-peer scanner's Run loop
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner leg did not unwind within 5s of ctx cancel")
	}
	if err := cleanup(context.Background()); err != nil {
		t.Errorf("cleanup (publisher drain): %v", err)
	}
}
