/*
FILE PATH: cmd/audit/main.go

audit — a STATELESS LIGHT-CLIENT AUDITOR. One trust root, one verb.

PRINCIPLE (minimal trust, CT-style)

	The ONLY thing trusted is the K-of-N witness-cosigned checkpoint. Everything
	else is a proof that either verifies against the witnessed roots or does not.
	No Postgres is trusted, no tiles are trusted, no re-derivation is trusted —
	only the witness signatures (from the bootstrap's genesis_witness_set) and
	SHA-256. This is the CT auditor model (RFC 6962), extended to the SMT via the
	smt_root that witnesses cosign atomically with the CT root.

WHAT IT DOES

 1. Build the trust root from the bootstrap: genesis_witness_set DIDs +
    quorum K → a cosign.WitnessKeySet (SDK).

 2. Verify the checkpoint: GET /v1/tree/horizon (the proof anchor), verify >= K valid witness
    cosignatures over (RootHash, SMTRoot, ReceiptRoot, TreeSize). ← the only
    trust step. On success, head.SMTRoot is a TRUSTED root.

 3. Verify SMT proofs against that trusted smt_root:
    - membership: real keys (from the backfill manifest) →
    smt.VerifyMembershipProof MUST pass.
    - non-membership: random absent keys →
    smt.VerifyNonMembershipProof MUST pass.

    A tile-served proof that verifies against the witnessed smt_root is correct
    by soundness of the hash — that single check IS the de-pollution cutover
    evidence (no pg-vs-tiles byte compare, which would mean trusting pg). Point
    the ledger's proof source at tiles (LEDGER_SMT_PROOF_SOURCE=tiles) to certify
    the de-polluted path specifically.

SCALE

	O(samples · log n), stateless. Auditing 10B entries is identical to auditing
	10 — the checkpoint is O(1), proofs are O(log n), you just sample more keys.

USAGE

	audit -url http://ledger:8080 -bootstrap /run/clarity/network-bootstrap.json \
	      -quorum 2 -manifest /out/backfill-manifest.json -samples 32 -random 16
*/
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdklog "github.com/baseproof/baseproof/log"
	sdknetwork "github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/internal/clienttls"
	"github.com/baseproof/tooling/services/ledger/internal/retryhttp"
)

// hc is the outbound HTTP client used for every call to the ledger
// (the /v1/tree/horizon trust step + each /v1/smt/proof/{key} fetch).
// Initialized in main() after flag.Parse — ALWAYS retryhttp-backed for
// startup-race resilience, with TLS material composed in when the mTLS
// flags are set. There is no "retryhttp OR mTLS" split: one single
// client, one single retry posture, regardless of TLS configuration.
var hc *http.Client

// mtlsFlags exposes -client-cert / -client-key / -ca-cert.
var mtlsFlags clienttls.Flags

func init() { mtlsFlags.Bind(flag.CommandLine) }

func main() {
	var (
		ledgerURL = flag.String("url", "http://localhost:8080", "ledger base URL")
		bootstrap = flag.String("bootstrap", "", "path to network-bootstrap.json (trust root) — REQUIRED")
		quorum    = flag.Int("quorum", 0, "K-of-N witness quorum to require — REQUIRED")
		manifest  = flag.String("manifest", "", "backfill manifest JSON (source of real membership keys)")
		samples   = flag.Int("samples", 32, "membership keys to sample from the manifest")
		random    = flag.Int("random", 16, "random absent keys to check non-membership")
		seed      = flag.Int64("seed", 1, "RNG seed for sampling")
	)
	flag.Parse()
	tlsCfg, err := mtlsFlags.TLSConfig()
	if err != nil {
		log.Fatalf("audit: mTLS config: %v", err)
	}
	hc = retryhttp.Client(15*time.Second, tlsCfg)
	if *bootstrap == "" || *quorum < 1 {
		log.Fatal("audit: -bootstrap and -quorum (>=1) are required")
	}

	// ── 1. Trust root: bootstrap genesis_witness_set → WitnessKeySet ──────────
	set, n := mustWitnessKeySet(*bootstrap, *quorum)
	fmt.Printf("audit: trust root — %d genesis witnesses, quorum K=%d\n", n, *quorum)

	// SDK v1.22.0 light-client primitives replace this tool's former hand-rolled
	// HTTP+JSON: the checkpoint client (horizon) + the SMT proof reader. hc gives
	// the checkpoint fetch startup-resilience; proofs are read after it succeeds.
	ctx := context.Background()
	cp, err := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{BaseURL: *ledgerURL, Client: hc})
	if err != nil {
		log.Fatalf("audit: checkpoint client: %v", err)
	}
	pr, err := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{BaseURL: *ledgerURL, Client: hc})
	if err != nil {
		log.Fatalf("audit: proof reader: %v", err)
	}

	// ── 2. Verify the cosigned checkpoint (the ONLY trust step) ───────────────
	// FetchVerifiedHorizon returns the published horizon ONLY if >= K valid witness
	// cosignatures verify over (RootHash, SMTRoot, ReceiptRoot, TreeSize). Fetched
	// ONCE — every sampled proof below verifies against this head.SMTRoot, keeping
	// the auditor's O(1)-checkpoint / O(samples·log n)-proof scale. (The per-key
	// log.VerifyMembershipAsOfHorizon helper re-fetches the checkpoint on each call:
	// the right tool for one-off consumer lookups, the wrong shape for a bulk
	// sampler that audits many keys against ONE checkpoint.)
	head, err := cp.FetchVerifiedHorizon(ctx, set)
	if err != nil {
		log.Fatalf("audit: horizon checkpoint NOT TRUSTED — %v. Refusing to proceed; "+
			"nothing downstream is trustworthy without the witnessed root.", err)
	}
	smtRoot := head.SMTRoot
	fmt.Printf("audit: checkpoint VERIFIED — tree_size=%d root_hash=%s smt_root=%s (>= K=%d witness cosignatures)\n",
		head.TreeSize, hex.EncodeToString(head.RootHash[:])[:16]+"…",
		hex.EncodeToString(smtRoot[:])[:16]+"…", *quorum)

	rng := rand.New(rand.NewSource(*seed))
	failures := 0

	// ── 3a. Membership proofs verify against the witnessed smt_root ───────────
	if *manifest != "" {
		keys := mustManifestKeys(*manifest)
		sample := keys
		if len(sample) > *samples {
			rng.Shuffle(len(sample), func(i, j int) { sample[i], sample[j] = sample[j], sample[i] })
			sample = sample[:*samples]
		}
		bad := 0
		for _, key := range sample {
			kh := hex.EncodeToString(key[:])
			res, err := pr.Proof(ctx, key)
			if err != nil {
				fmt.Printf("  membership FAIL key=%s proof fetch: %v\n", kh[:12], err)
				bad++
				continue
			}
			if !res.Membership {
				fmt.Printf("  membership FAIL key=%s served non-membership (want membership)\n", kh[:12])
				bad++
				continue
			}
			if err := smt.VerifyMembershipProof(res.Proof, smtRoot); err != nil {
				fmt.Printf("  membership FAIL key=%s does NOT verify against witnessed smt_root: %v\n", kh[:12], err)
				bad++
			}
		}
		if bad == 0 {
			fmt.Printf("audit: membership — %d/%d proofs verify against the witnessed smt_root\n", len(sample), len(sample))
		} else {
			fmt.Printf("audit: membership — %d/%d FAILED to verify against the witnessed smt_root\n", bad, len(sample))
		}
		failures += bad
	} else {
		fmt.Println("audit: membership — skipped (no -manifest; pass the backfill manifest for real member keys)")
	}

	// ── 3b. Non-membership proofs verify against the witnessed smt_root ───────
	badNM := 0
	for i := 0; i < *random; i++ {
		var key [32]byte
		rng.Read(key[:])
		kh := hex.EncodeToString(key[:])
		res, err := pr.Proof(ctx, key)
		if err != nil {
			fmt.Printf("  non-membership FAIL key=%s proof fetch: %v\n", kh[:12], err)
			badNM++
			continue
		}
		if res.Membership {
			fmt.Printf("  non-membership FAIL key=%s served membership (want absence)\n", kh[:12])
			badNM++
			continue
		}
		if err := smt.VerifyNonMembershipProof(res.Proof, smtRoot); err != nil {
			fmt.Printf("  non-membership FAIL key=%s does NOT verify against witnessed smt_root: %v\n", kh[:12], err)
			badNM++
		}
	}
	if badNM == 0 {
		fmt.Printf("audit: non-membership — %d/%d proofs verify against the witnessed smt_root\n", *random, *random)
	} else {
		fmt.Printf("audit: non-membership — %d/%d FAILED\n", badNM, *random)
	}
	failures += badNM

	if failures > 0 {
		log.Fatalf("audit: FAILED — %d proof(s) did not verify against the witnessed root", failures)
	}
	fmt.Println("audit: PASS — every sampled proof verifies against the K-of-N witness-cosigned root")
}

// mustWitnessKeySet builds the trust root from the bootstrap, exactly as the
// auditor service does: genesis_witness_set DIDs → ECDSA keys → WitnessKeySet
// bound to the bootstrap-derived NetworkID.
func mustWitnessKeySet(path string, quorum int) (*cosign.WitnessKeySet, int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("audit: read bootstrap %q: %v", path, err)
	}
	var doc sdknetwork.BootstrapDocument
	if err = json.Unmarshal(raw, &doc); err != nil {
		log.Fatalf("audit: parse bootstrap: %v", err)
	}
	if doc.ExchangeDID == "" || len(doc.GenesisWitnessSet) == 0 {
		log.Fatal("audit: bootstrap missing exchange_did / genesis_witness_set")
	}
	if quorum > len(doc.GenesisWitnessSet) {
		log.Fatalf("audit: -quorum %d > N=%d witnesses", quorum, len(doc.GenesisWitnessSet))
	}
	ids, err := doc.IDs()
	if err != nil {
		log.Fatalf("audit: derive network identity: %v", err)
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		log.Fatalf("audit: resolve witness keys from DIDs: %v", err)
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, ids.NetworkID, quorum)
	if err != nil {
		log.Fatalf("audit: build witness key set: %v", err)
	}
	return set, len(doc.GenesisWitnessSet)
}

// mustManifestKeys reads the backfill manifest and returns its leaf keys as
// 32-byte SMT keys (the proof reader takes [32]byte; the manifest stores 64-hex).
func mustManifestKeys(path string) [][32]byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("audit: read manifest %q: %v", path, err)
	}
	var m struct {
		Leaves []struct {
			Key string `json:"key"`
		} `json:"leaves"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		log.Fatalf("audit: parse manifest: %v", err)
	}
	keys := make([][32]byte, 0, len(m.Leaves))
	for _, l := range m.Leaves {
		kb, err := hex.DecodeString(l.Key)
		if err != nil || len(kb) != 32 {
			continue
		}
		var k [32]byte
		copy(k[:], kb)
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		log.Fatal("audit: manifest has no valid 32-byte leaf keys")
	}
	return keys
}
