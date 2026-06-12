/*
FILE PATH: libs/cli/rotation_cmd_test.go

DESCRIPTION:

	PRE-6 B1 — the rotation driver's verbs, each against an httptest ledger
	(the standing reminder for why verbs need their own tests: the shim
	--quorum runtime break shipped through exactly this gap):

	  draft     populates the draft from the LIVE keys + the bundle's
	            constitutional K; a served set_hash that does not match the
	            hash derived from the served keys is a named (poisoned-
	            projection) refusal; a bundle without K refuses; an
	            unsatisfiable proposal (2K<=N) refuses at the coordinator,
	            BEFORE any file exists to relay.
	  finalize  ONE shuffled consent list → exactly the verifier-accepted
	            rotation (round-trip through VerifyRotation — assembly
	            shares the verifier) with C1's derived tags and C2's
	            membership bucketing.
	  submit    fail-closed before the POST: an era drift (the set rotated
	            since the draft was cut) is a NAMED refusal and the door is
	            never hit; a tampered finalized file (a flipped signature
	            bit that survives structural decode) is refused by the
	            LOCAL VerifyRotation, door never hit; a door rejection
	            surfaces verbatim; the happy path delivers the exact
	            finalized bytes to POST /v1/network/rotation.
*/
package cli

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"
)

// rotWitness is one ceremony participant with its private key in hand.
type rotWitness struct {
	priv *ecdsa.PrivateKey
	did  string
	key  types.WitnessPublicKey
}

func genRotWitness(t *testing.T) rotWitness {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil {
		t.Fatal(err)
	}
	return rotWitness{priv: kp.PrivateKey, did: kp.DID, key: keys[0]}
}

// serveWitnessCurrent renders /v1/network/witnesses/current CONSISTENTLY:
// the served set_hash is derived from the served keys (the production
// projection's invariant).
func serveWitnessCurrent(keys ...types.WitnessPublicKey) http.HandlerFunc {
	h := witness.ComputeSetHash(keys)
	view := wireWitnessSetFull{SetHash: hex.EncodeToString(h[:]), SchemeTag: 1, EffectiveSeq: 1}
	for _, k := range keys {
		view.Keys = append(view.Keys, wireWitnessKeyFull{
			ID: hex.EncodeToString(k.ID[:]), PublicKey: hex.EncodeToString(k.PublicKey), SchemeTag: k.SchemeTag,
		})
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
	}
}

func TestRotationDraftVerb(t *testing.T) {
	ctx := context.Background()
	cur := genRotWitness(t)
	next := genRotWitness(t)
	nid := strings.Repeat("ab", 32)

	t.Run("populates from the live keys and the constitutional K", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 1})
		out := filepath.Join(t.TempDir(), "draft.json")

		if err := RunNetwork(ctx, []string{"rotation", "draft", "--bundle", bp, "--new-set", next.did, "--out", out, "--output", "json"}); err != nil {
			t.Fatalf("draft: %v", err)
		}
		d, err := rotationdraft.LoadDraft(out)
		if err != nil {
			t.Fatal(err)
		}
		if d.QuorumK != 1 || d.NetworkIDHex != nid {
			t.Fatalf("draft bindings: %+v", d)
		}
		if len(d.CurrentSet) != 1 || !strings.EqualFold(d.CurrentSet[0].IDHex, hex.EncodeToString(cur.key.ID[:])) {
			t.Fatalf("the draft's current set must be the LIVE keys: %+v", d.CurrentSet)
		}
		if len(d.NewSet) != 1 || !strings.EqualFold(d.NewSet[0].IDHex, hex.EncodeToString(next.key.ID[:])) {
			t.Fatalf("the draft's new set must come from --new-set: %+v", d.NewSet)
		}
	})

	t.Run("a poisoned projection is a named refusal", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/network/witnesses/current", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wireWitnessSetFull{
				SetHash: strings.Repeat("ee", 32), SchemeTag: 1, // does NOT match the keys
				Keys: []wireWitnessKeyFull{{ID: hex.EncodeToString(cur.key.ID[:]), PublicKey: hex.EncodeToString(cur.key.PublicKey), SchemeTag: 1}},
			})
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 1})
		err := RunNetwork(ctx, []string{"rotation", "draft", "--bundle", bp, "--new-set", next.did, "--out", filepath.Join(t.TempDir(), "d.json")})
		if err == nil || !strings.Contains(err.Error(), "inconsistent") {
			t.Fatalf("served set_hash != derived must refuse by name: %v", err)
		}
	})

	t.Run("a bundle without the constitutional K refuses", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x"}) // QuorumK absent
		err := RunNetwork(ctx, []string{"rotation", "draft", "--bundle", bp, "--new-set", next.did, "--out", filepath.Join(t.TempDir(), "d.json")})
		if err == nil || !strings.Contains(err.Error(), "quorum_k") {
			t.Fatalf("a missing constitutional K must refuse, never guess: %v", err)
		}
	})

	t.Run("an unsatisfiable proposal refuses BEFORE the file exists", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 1})
		// Three new witnesses at K=1: 2K <= N — VerifyRotation's quorum-
		// intersection gate would reject at finalize, so the coordinator
		// refuses to even cut the draft.
		w2, w3 := genRotWitness(t), genRotWitness(t)
		out := filepath.Join(t.TempDir(), "d.json")
		err := RunNetwork(ctx, []string{"rotation", "draft", "--bundle", bp,
			"--new-set", next.did + "," + w2.did + "," + w3.did, "--out", out})
		if err == nil || !strings.Contains(err.Error(), "next set size") {
			t.Fatalf("2K<=N must refuse at the coordinator: %v", err)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatal("a refused draft must never be written")
		}
	})
}

// ceremonyFixture drives the PRODUCTION path end to end: the draft verb cuts
// the draft against the live set, both members consent through the production
// signer, and the finalize verb mints the rotation file. Returns the
// finalized payload path and the current set for verification.
func ceremonyFixture(t *testing.T, ctx context.Context, cur, next rotWitness, nid string, srvURL string) (finPath string, curSet *cosign.WitnessKeySet) {
	t.Helper()
	dir := t.TempDir()
	bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srvURL, LogDID: "did:web:x", QuorumK: 1})

	draftPath := filepath.Join(dir, "draft.json")
	if err := RunNetwork(ctx, []string{"rotation", "draft", "--bundle", bp, "--new-set", next.did, "--out", draftPath}); err != nil {
		t.Fatalf("draft verb: %v", err)
	}
	d, err := rotationdraft.LoadDraft(draftPath)
	if err != nil {
		t.Fatal(err)
	}
	cA, err := d.SignConsent(cur.priv)
	if err != nil {
		t.Fatalf("current consent: %v", err)
	}
	cB, err := d.SignConsent(next.priv)
	if err != nil {
		t.Fatalf("new consent: %v", err)
	}
	aPath, bPath := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := rotationdraft.Save(aPath, cA); err != nil {
		t.Fatal(err)
	}
	if err := rotationdraft.Save(bPath, cB); err != nil {
		t.Fatal(err)
	}

	finPath = filepath.Join(dir, "rotation.json")
	// Deliberately "mis-sorted": the new witness's consent first. There are
	// no buckets at the operator surface — membership routing decides.
	if err := RunNetwork(ctx, []string{"rotation", "finalize", "--draft", draftPath, "--consents", bPath + "," + aPath, "--out", finPath}); err != nil {
		t.Fatalf("finalize verb: %v", err)
	}

	var nidBytes [32]byte
	raw, err := hex.DecodeString(nid)
	if err != nil {
		t.Fatal(err)
	}
	copy(nidBytes[:], raw)
	curSet, err = cosign.NewECDSAWitnessKeySet([]types.WitnessPublicKey{cur.key}, cosign.NetworkID(nidBytes), 1)
	if err != nil {
		t.Fatal(err)
	}
	return finPath, curSet
}

func TestRotationFinalizeVerb_MintsExactlyTheVerifierAcceptedRotation(t *testing.T) {
	ctx := context.Background()
	cur, next := genRotWitness(t), genRotWitness(t)
	nid := strings.Repeat("ab", 32)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	finPath, curSet := ceremonyFixture(t, ctx, cur, next, nid, srv.URL)
	payload, err := os.ReadFile(finPath)
	if err != nil {
		t.Fatal(err)
	}
	r, err := witness.DecodeWitnessRotationPayload(payload)
	if err != nil {
		t.Fatalf("the finalize verb must write the SDK wire format: %v", err)
	}
	// C1: tags DERIVED from the key material — never a hardcode.
	if r.SchemeTagOld != cur.key.SchemeTag || r.SchemeTagNew != next.key.SchemeTag {
		t.Fatalf("derived tags: old=0x%02x new=0x%02x", r.SchemeTagOld, r.SchemeTagNew)
	}
	// C2: membership bucketing routed the shuffled consents to their sides.
	if len(r.CurrentSignatures) != 1 || len(r.NewSignatures) != 1 {
		t.Fatalf("bucketing: current=%d new=%d", len(r.CurrentSignatures), len(r.NewSignatures))
	}
	// Assembly shares the verifier: the SDK's full recipe accepts the bytes.
	if _, err := witness.VerifyRotation(r, curSet); err != nil {
		t.Fatalf("the minted rotation must round-trip VerifyRotation: %v", err)
	}
}

func TestRotationSubmitVerb_FailClosedThenDoor(t *testing.T) {
	ctx := context.Background()
	cur, next := genRotWitness(t), genRotWitness(t)
	nid := strings.Repeat("ab", 32)

	doorHits := 0
	var doorBody []byte
	doorVerdict := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
	doorCode, doorResp := http.StatusAccepted, `{"applied":true,"new_witness_count":1}`

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
	mux.HandleFunc("POST /v1/network/rotation", func(w http.ResponseWriter, r *http.Request) {
		doorHits++
		doorBody, _ = io.ReadAll(r.Body)
		doorVerdict(w, doorCode, doorResp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	finPath, _ := ceremonyFixture(t, ctx, cur, next, nid, srv.URL)
	bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 1})

	t.Run("happy path delivers the exact finalized bytes to the door", func(t *testing.T) {
		if err := RunNetwork(ctx, []string{"rotation", "submit", "--bundle", bp, "--output", "json", finPath}); err != nil {
			t.Fatalf("submit: %v", err)
		}
		if doorHits != 1 {
			t.Fatalf("door hits = %d, want 1", doorHits)
		}
		want, _ := os.ReadFile(finPath)
		if string(doorBody) != string(want) {
			t.Fatal("the door must receive the finalized file's exact bytes")
		}
	})

	t.Run("a tampered finalized file is refused LOCALLY, door never hit", func(t *testing.T) {
		payload, _ := os.ReadFile(finPath)
		r, err := witness.DecodeWitnessRotationPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		r.CurrentSignatures[0].SigBytes[7] ^= 1 // survives structural decode
		tampered, err := witness.EncodeWitnessRotationPayload(r)
		if err != nil {
			t.Fatal(err)
		}
		tPath := filepath.Join(t.TempDir(), "tampered.json")
		if err := os.WriteFile(tPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		before := doorHits
		err = RunNetwork(ctx, []string{"rotation", "submit", "--bundle", bp, tPath})
		if err == nil || !strings.Contains(err.Error(), "refused locally") {
			t.Fatalf("a tampered file must be refused locally: %v", err)
		}
		if doorHits != before {
			t.Fatal("a locally-refused rotation must never be posted")
		}
	})

	t.Run("a door rejection surfaces verbatim", func(t *testing.T) {
		doorCode, doorResp = http.StatusUnprocessableEntity, `{"error":"rotation rejected: the consents did not satisfy the current set"}`
		t.Cleanup(func() { doorCode, doorResp = http.StatusAccepted, `{"applied":true,"new_witness_count":1}` })
		err := RunNetwork(ctx, []string{"rotation", "submit", "--bundle", bp, finPath})
		if err == nil || !strings.Contains(err.Error(), "HTTP 422") || !strings.Contains(err.Error(), "did not satisfy") {
			t.Fatalf("the door's verdict must surface verbatim: %v", err)
		}
	})
}

func TestRotationSubmitVerb_EraDriftIsANamedRefusal(t *testing.T) {
	ctx := context.Background()
	cur, next := genRotWitness(t), genRotWitness(t)
	nid := strings.Repeat("ab", 32)

	// The ceremony runs against the ORIGINAL set...
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(cur.key))
	srv := httptest.NewServer(mux)
	finPath, _ := ceremonyFixture(t, ctx, cur, next, nid, srv.URL)
	srv.Close()

	// ...but by submit time the network has ROTATED (a different live set).
	rotated := genRotWitness(t)
	doorHits := 0
	mux2 := http.NewServeMux()
	mux2.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(rotated.key))
	mux2.HandleFunc("POST /v1/network/rotation", func(http.ResponseWriter, *http.Request) { doorHits++ })
	srv2 := httptest.NewServer(mux2)
	t.Cleanup(srv2.Close)
	bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv2.URL, LogDID: "did:web:x", QuorumK: 1})

	err := RunNetwork(ctx, []string{"rotation", "submit", "--bundle", bp, finPath})
	if err == nil || !strings.Contains(err.Error(), "re-draft against the live set") {
		t.Fatalf("era drift must be a named refusal: %v", err)
	}
	if doorHits != 0 {
		t.Fatal("a stale rotation must never reach the door")
	}
}
