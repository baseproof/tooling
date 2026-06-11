// Package fixture is an in-process, real-crypto stand-in for the ledger fleet: a
// TLS "ledger" serving the FULL read surface (network introspection + the v2 proof
// gather endpoints) for ONE pre-committed entry, plus a TLS "auditor" (/healthz +
// /v1/log-info, reporting in-sync with the ledger horizon).
//
// It exists so the e2e RUNNER's read/verify/info stages — the unified-CLI paths —
// are proven end to end with real cryptography over real HTTPS, in ANY environment
// (no docker, no Postgres). `e2e selftest` drives the runner against this fixture;
// `e2e up`+`run` drive the runner against the real docker fleet. Same runner, same
// libs commands — the fixture closes the read side, the fleet closes the write side.
package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// Fixture is a started in-process fleet: the TLS ledger + auditor, the run CA
// file (the ledger's server cert, to pass as --ca-cert), and the facts the runner
// needs to drive the read stages (network id, log DID, target sequence + SMT key).
type Fixture struct {
	Ledger    *httptest.Server
	Auditor   *httptest.Server
	CAPath    string
	NetworkID string
	LogDID    string
	Seq       uint64
	SMTKeyHex string
	dir       string
}

// Close shuts the servers down and removes the scratch dir.
func (f *Fixture) Close() {
	if f.Ledger != nil {
		f.Ledger.Close()
	}
	if f.Auditor != nil {
		f.Auditor.Close()
	}
	if f.dir != "" {
		_ = os.RemoveAll(f.dir)
	}
}

// Start builds the real-crypto fixture (n witnesses, quorum k) and serves it over
// TLS. The returned CAPath is the ledger's server cert PEM (server-verify anchor).
func Start(n, k int) (*Fixture, error) {
	fx, err := buildCrypto(n, k)
	if err != nil {
		return nil, err
	}

	// Auditor: in-sync with the ledger horizon (tree_size matches), healthy.
	amux := http.NewServeMux()
	amux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	amux.HandleFunc("/v1/log-info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"tree_size": fx.head.TreeSize, "log_did": fx.networkDID})
	})
	// The auditor's OWN listener is plain HTTP (matches the real fleet: only the
	// ledger terminates TLS; the auditor is probed over plain http on its own port).
	auditor := httptest.NewServer(amux)

	mux := http.NewServeMux()
	// — network introspection (authoring + info) —
	mux.HandleFunc("GET /v1/network/bootstrap", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fx.canonical)
	})
	mux.HandleFunc("GET /v1/network/identity", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"network_id": fx.nidHex, "network_did": fx.networkDID,
			"network_uuid": "00000000-0000-0000-0000-000000000000", "bootstrap_hash": fx.nidHex,
		})
	})
	mux.HandleFunc("GET /v1/log-info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"log_did": fx.networkDID, "network_id": fx.nidHex, "tree_size": fx.head.TreeSize})
	})
	mux.HandleFunc("GET /v1/network/peers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{})
	})
	mux.HandleFunc("GET /v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
		keys := make([]map[string]any, len(fx.witnessKeyIDs))
		for i, id := range fx.witnessKeyIDs {
			keys[i] = map[string]any{"id": id, "public_key": "04", "scheme_tag": 1}
		}
		writeJSON(w, map[string]any{"set_hash": strings.Repeat("7f", 32), "scheme_tag": 1, "effective_seq": 0, "keys": keys})
	})
	mux.HandleFunc("GET /v1/network/auditors", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"auditors": []map[string]any{
			{"auditor_did": "did:key:zAuditor", "findings_url": auditor.URL + "/v1/gossip"},
		}})
	})
	mux.HandleFunc("GET /v1/network/mirrors", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"mirrors": []any{}})
	})
	mux.HandleFunc("GET /v1/admission/difficulty", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"difficulty": 8})
	})

	// — v2 proof gather + horizon —
	mux.HandleFunc("GET /v1/tree/horizon", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, types.FromCosignedTreeHead(fx.head))
	})
	mux.HandleFunc("GET /v1/entries/{seq}/raw", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Sequence", r.PathValue("seq"))
		w.Header().Set("X-Log-Time", fx.logTime.Format(time.RFC3339Nano))
		_, _ = w.Write(fx.entryBytes)
	})
	mux.HandleFunc("GET /v1/tree/inclusion/{seq}", func(w http.ResponseWriter, _ *http.Request) {
		hashes := make([]string, len(fx.inc.Siblings))
		for i, s := range fx.inc.Siblings {
			hashes[i] = hex.EncodeToString(s[:])
		}
		writeJSON(w, map[string]any{"leaf_index": fx.inc.LeafPosition, "tree_size": fx.inc.TreeSize, "hashes": hashes})
	})
	mux.HandleFunc("GET /v1/smt/proof/{key}", func(w http.ResponseWriter, r *http.Request) {
		raw, err := hex.DecodeString(r.PathValue("key"))
		if err != nil || len(raw) != 32 {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		var key [32]byte
		copy(key[:], raw)
		typ := "membership"
		p, perr := fx.smtTree.GenerateMembershipProof(r.Context(), key)
		if perr != nil {
			http.Error(w, perr.Error(), 500)
			return
		}
		if p == nil {
			typ = "non_membership"
			if p, perr = fx.smtTree.GenerateNonMembershipProof(r.Context(), key); perr != nil {
				http.Error(w, perr.Error(), 500)
				return
			}
		}
		writeJSON(w, map[string]any{"type": typ, "proof": p})
	})
	mux.HandleFunc("GET /v1/receipt/proof/{seq}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"receipt_proof": nil})
	})
	mux.HandleFunc("GET /v1/burn", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"is_burned": false})
	})

	ledger := httptest.NewTLSServer(mux)

	dir, err := os.MkdirTemp("", "e2e-fixture-")
	if err != nil {
		ledger.Close()
		auditor.Close()
		return nil, err
	}
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, ledgerCertPEM(ledger), 0o644); err != nil {
		ledger.Close()
		auditor.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}

	return &Fixture{
		Ledger: ledger, Auditor: auditor, CAPath: caPath,
		NetworkID: fx.nidHex, LogDID: fx.networkDID,
		Seq: fx.seq, SMTKeyHex: hex.EncodeToString(fx.smtKey[:]), dir: dir,
	}, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ledgerCertPEM PEM-encodes an httptest TLS server's own cert — the server-verify
// anchor a client pins via --ca-cert (the cert is self-signed, so it is its own CA).
func ledgerCertPEM(s *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
}

// crypto bundles the real-crypto artifacts (mirrors libs/cli's buildRealFixture,
// in a non-test package so the runner + cmd can use it).
type crypto struct {
	canonical     []byte
	nidHex        string
	nid           cosign.NetworkID
	networkDID    string
	witnessKeyIDs []string
	entryBytes    []byte
	seq           uint64
	smtKey        [32]byte
	smtTree       *smt.Tree
	head          types.CosignedTreeHead
	inc           *types.MerkleProof
	logTime       time.Time
}

func buildCrypto(n, k int) (*crypto, error) {
	ctx := context.Background()
	dids := make([]string, n)
	signers := make([]cosign.WitnessSigner, n)
	keyIDs := make([]string, n)
	for i := 0; i < n; i++ {
		kp, err := sdkdid.GenerateDIDKeySecp256k1()
		if err != nil {
			return nil, fmt.Errorf("witness keygen: %w", err)
		}
		dids[i] = kp.DID
		signers[i] = cosign.NewECDSAWitnessSigner(kp.PrivateKey)
		// Display id for /v1/network/witnesses/current (info renders it; the
		// VERIFY path derives the trusted set from the bootstrap, not this).
		idsum := sha256.Sum256([]byte(kp.DID))
		keyIDs[i] = hex.EncodeToString(idsum[:])
	}

	bdoc := &network.BootstrapDocument{
		ProtocolVersion: "1", ExchangeDID: "did:web:exchange.example", NetworkName: "e2e-fixture-net",
		GenesisWitnessSet:           dids,
		GenesisQuorumK:              len(dids)/2 + 1, // REQUIRED since rc4 (NetworkID-bound); majority satisfies 2K>N
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes: []uint16{0x0001}, AllowedCosignSchemeTags: []uint8{0x01}, MinSignaturesPerEntry: 1,
		},
	}
	ids, err := bdoc.IDs()
	if err != nil {
		return nil, fmt.Errorf("bootstrap ids: %w", err)
	}
	canonical, err := bdoc.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}

	authorKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		return nil, err
	}
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID: authorKP.DID, Destination: "did:web:exchange.example", EventTime: 1700000000,
	}, []byte("e2e fixture target payload"))
	if err != nil {
		return nil, err
	}
	signHash := sha256.Sum256(envelope.SigningPayload(unsigned))
	authorSig, err := signatures.SignEntry(signHash, authorKP.PrivateKey)
	if err != nil {
		return nil, err
	}
	unsigned.Signatures = []envelope.Signature{{SignerDID: authorKP.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: authorSig}}
	if err := unsigned.Validate(); err != nil {
		return nil, err
	}
	entryBytes, err := envelope.Serialize(unsigned)
	if err != nil {
		return nil, err
	}
	entryID := sha256.Sum256(entryBytes)

	tree := smt.NewStubMerkleTree()
	pos, err := tree.AppendLeaf(entryID[:])
	if err != nil {
		return nil, err
	}
	if _, err := tree.AppendLeaf([]byte("padding-leaf")); err != nil {
		return nil, err
	}
	chronHead, err := tree.Head()
	if err != nil {
		return nil, err
	}
	merkleProof, err := tree.InclusionProof(ctx, pos, chronHead.TreeSize)
	if err != nil {
		return nil, err
	}

	smtTree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	leafKey := sha256.Sum256([]byte("e2e-fixture-entry-key"))
	if err := smtTree.SetLeaf(ctx, leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: types.LogPosition{LogDID: ids.DID, Sequence: pos}, AuthorityTip: types.LogPosition{LogDID: ids.DID, Sequence: pos},
	}); err != nil {
		return nil, err
	}
	otherKey := sha256.Sum256([]byte("e2e-fixture-other-key"))
	if err := smtTree.SetLeaf(ctx, otherKey, types.SMTLeaf{
		Key: otherKey, OriginTip: types.LogPosition{LogDID: ids.DID, Sequence: 1}, AuthorityTip: types.LogPosition{LogDID: ids.DID, Sequence: 1},
	}); err != nil {
		return nil, err
	}
	smtRoot, err := smtTree.Root(ctx)
	if err != nil {
		return nil, err
	}

	head := types.CosignedTreeHead{TreeHead: types.TreeHead{RootHash: chronHead.RootHash, SMTRoot: smtRoot, TreeSize: chronHead.TreeSize}}
	payload := cosign.NewTreeHeadPayload(head.TreeHead)
	for _, s := range signers {
		wsig, err := s.Sign(ctx, payload, ids.NetworkID, cosign.HashAlgoSHA256)
		if err != nil {
			return nil, fmt.Errorf("witness sign: %w", err)
		}
		head.Signatures = append(head.Signatures, wsig)
	}

	return &crypto{
		canonical: canonical, nidHex: hex.EncodeToString(ids.NetworkID[:]), nid: ids.NetworkID,
		networkDID: ids.DID, witnessKeyIDs: keyIDs, entryBytes: entryBytes, seq: pos,
		smtKey: leafKey, smtTree: smtTree, head: head, inc: merkleProof,
		logTime: time.Unix(1700000000, 0).UTC(),
	}, nil
}
