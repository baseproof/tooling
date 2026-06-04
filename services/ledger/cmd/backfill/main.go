/*
FILE PATH: cmd/backfill/main.go

backfill — generates VALID, INTERCONNECTED entries that actually populate the
SMT, so the de-pollution / membership-parity validation has real data to work
against. Unlike submit-stamp (which emits COMMENTARY entries — no AuthorityPath,
no SMT leaf), backfill builds the authority lanes the SMT indexes.

WHY THIS EXISTS

	submit-stamp produces commentary: it advances the CT log but creates no SMT
	leaf (SDK builder/algorithm.go: TargetRoot==nil && AuthorityPath==nil →
	Commentary). Membership proofs, tiles, and shadow parity all live in the SMT,
	so a submit-stamp-only load leaves nothing to validate. backfill emits the
	entry classes the SMT actually tracks.

WHAT IT GUARANTEES

  - VALID: every entry is built with the SDK's typed builders (builder.Build*),
    signed end-to-end (secp256k1), and admitted via Mode B PoW — never a
    hand-rolled header.
  - INTERCONNECTED: a stateful in-memory model tracks each entity (its creation
    LogPosition + owner key + current tips). New entries only ever reference
    positions the model already discovered, and amendments are signed by the
    SAME key that created the root (Path A's same-signer rule). So references
    always resolve and signers are always authorized — by construction.
  - REPRODUCIBLE + SELF-CHECKING: one seeded RNG drives the run, and the model
    is an ORACLE — it writes a manifest of expected per-leaf state
    (key, origin_tip, authority_tip). The validator asserts the ledger's
    /v1/smt/leaf/{key} matches, i.e. authority tracking is correct over time,
    not merely that a proof verifies.

SLICE COVERAGE (this file)

	Slice 1: NewLeaf (BuildRootEntity) + Path A (BuildAmendment, same signer).
	This alone populates the SMT and unblocks de-pollution validation.

USAGE

	backfill -url http://ledger:8080 -log-did did:web:... -n 1000 \
	         -amend-ratio 0.5 -seed 1 -manifest /out/backfill-manifest.json
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/internal/clienttls"
	"github.com/baseproof/tooling/services/ledger/internal/retryhttp"
)

// hc is the package-level HTTP client every outbound POST routes
// through. Initialized at main()'s flag.Parse boundary — ALWAYS
// retryhttp-backed (DNS / connection-refused / EOF retries during pod
// startup) with TLS material composed in when the mTLS flags are set:
//
//   - With `-client-cert / -client-key` set, hc carries a TLS 1.3 client
//     cert matching the ledger's server posture (api/server.go's
//     buildServerTLSConfig: RequireAndVerifyClientCert + TLS 1.3) AND
//     keeps the retryhttp retry posture — both, not either-or.
//   - Without those flags, tlsCfg is nil → stdlib server-verify-only
//     transport, same retryhttp retries. The retry posture is invariant
//     under TLS configuration.
var hc *http.Client

// mtlsFlags exposes -client-cert / -client-key / -ca-cert. Bound at
// init time so they show up in `backfill -h` and parse normally; the
// loaded *http.Client materializes inside main() once flag.Parse runs.
var mtlsFlags clienttls.Flags

func init() { mtlsFlags.Bind(flag.CommandLine) }

// entity is one SMT leaf the model tracks. pos is the CREATION position — the
// SMT key derives from it (smt.DeriveKey) and amendments reference it as
// TargetRoot. originTip advances on each Path-A amendment; authorityTip stays
// at creation (Path A is the origin lane).
type entity struct {
	pos          types.LogPosition
	did          string
	priv         *ecdsa.PrivateKey
	originTip    types.LogPosition
	authorityTip types.LogPosition
}

type manifestLeaf struct {
	Key             string `json:"key"` // hex of smt.DeriveKey(creation pos)
	SignerDID       string `json:"signer_did"`
	OriginTipSeq    uint64 `json:"origin_tip_seq"`    // expected leaf.OriginTip.Sequence
	AuthorityTipSeq uint64 `json:"authority_tip_seq"` // expected leaf.AuthorityTip.Sequence
}

type manifest struct {
	LogDID     string         `json:"log_did"`
	Entries    int            `json:"entries"` // total entries submitted (roots + amendments)
	Roots      int            `json:"roots"`   // = len(leaves)
	Amendments int            `json:"amendments"`
	Leaves     []manifestLeaf `json:"leaves"`
}

// workItem is a built-but-not-yet-stamped entry. The seeded RNG builds these in
// order (preserving the reproducible reference stream); the CPU-bound PoW in
// signAndSubmit (or the per-batch sign in signAndPostBatch) then runs across
// the worker pool. Within an epoch no entry references another (amendments only
// target prior-epoch, already-discovered roots), so concurrent submission is
// order-independent and safe. Package-scoped so the batch helpers can name it.
type workItem struct {
	entry *envelope.Entry
	priv  *ecdsa.PrivateKey
	did   string
	root  *entity // non-nil for a new root
	amend *entity // non-nil for an amendment
}

// pendingItem tracks entries submitted in the current epoch whose sequence is
// not yet known. Discovered en masse at epoch end so the next epoch can
// reference freshly-created roots.
type pendingItem struct {
	hash  string  // SCT.canonical_hash
	root  *entity // non-nil for a new-root submission (pos filled in on discovery)
	amend *entity // non-nil for an amendment (originTip advanced on discovery)
}

func main() {
	var (
		ledgerURL   = flag.String("url", "http://localhost:8080", "ledger base URL")
		logDID      = flag.String("log-did", "", "destination log DID (Header.Destination) — REQUIRED")
		n           = flag.Int("n", 100, "total entries to submit (roots + amendments)")
		amendRatio  = flag.Float64("amend-ratio", 0.5, "fraction of entries that amend an existing root (Path A); rest create new roots")
		epochSize   = flag.Int("epoch", 64, "entries per epoch (submitted, then sequence-discovered, before the next epoch)")
		seed        = flag.Int64("seed", 1, "RNG seed — same seed reproduces the exact entry stream")
		difficulty  = flag.Int("difficulty", 0, "Mode B PoW difficulty; 0 → query /v1/admission/difficulty")
		epochSec    = flag.Int("epoch-window", 3600, "Mode B epoch window seconds (must match LEDGER_EPOCH_WINDOW_SECONDS)")
		manifestP   = flag.String("manifest", "", "path to write the expected-state manifest JSON (the validation oracle)")
		seqTimeout  = flag.Duration("seq-timeout", 120*time.Second, "how long to wait for a submitted entry to be sequenced")
		progressPct = flag.Float64("progress-every-pct", 1.0, "emit a progress line (count, %, rate, ETA) each time this %% of -n completes; 0 = every epoch. For large -n keep this >0 so 10M doesn't spew one line per 64-entry epoch.")
		workers     = flag.Int("workers", runtime.GOMAXPROCS(0), "concurrent PoW/submit workers (the bounded in-flight bound). The CPU-bound Mode B stamp parallelizes across these; <1 → 1. Defaults to GOMAXPROCS.")
		token       = flag.String("token", "", "Mode A Bearer token; when set, submit with a write credit (no PoW) — admission deducts one credit per entry against the seeded session. Empty → Mode B PoW.")
		batchSize   = flag.Int("batch-size", 1, "POST /v1/entries/batch when >1; group N entries per HTTP request. Each batch = ONE credit deduction + ONE WAL append, which is the difference between scaling Mode A admission and not. Mode A only (requires -token); Mode B does not batch (per-entry PoW is the bottleneck). Capped server-side at MaxBatchSize=256.")
	)
	flag.Parse()
	tlsCfg, err := mtlsFlags.TLSConfig()
	if err != nil {
		log.Fatalf("backfill: mTLS config: %v", err)
	}
	hc = retryhttp.Client(30*time.Second, tlsCfg)
	if *logDID == "" {
		log.Fatal("backfill: -log-did is required")
	}
	if *n < 1 {
		log.Fatal("backfill: -n must be >= 1")
	}
	if *batchSize < 1 {
		log.Fatal("backfill: -batch-size must be >= 1")
	}
	if *batchSize > 1 && *token == "" {
		log.Fatal("backfill: -batch-size > 1 requires -token (Mode A); Mode B PoW does not batch")
	}
	if *batchSize > 256 {
		log.Fatalf("backfill: -batch-size=%d exceeds server MaxBatchSize=256", *batchSize)
	}

	diff := uint32(*difficulty)
	if *token == "" && diff == 0 {
		d, err := queryDifficulty(*ledgerURL)
		if err != nil {
			log.Fatalf("backfill: query difficulty: %v", err)
		}
		diff = d
	}
	if *workers < 1 {
		*workers = 1
	}
	mode := "B(PoW)"
	if *token != "" {
		mode = "A(credit)"
	}
	fmt.Printf("backfill: url=%s log-did=%s n=%d amend-ratio=%.2f admission=mode-%s difficulty=%d seed=%d workers=%d batch-size=%d\n",
		*ledgerURL, *logDID, *n, *amendRatio, mode, diff, *seed, *workers, *batchSize)

	rng := rand.New(rand.NewSource(*seed))
	entities := make([]*entity, 0, *n)
	submitted, amendments := 0, 0
	t0 := time.Now()
	nextPct := *progressPct // next % threshold at which to emit progress

	for submitted < *n {
		batch := *epochSize
		if remaining := *n - submitted; remaining < batch {
			batch = remaining
		}

		// Phase 1 — BUILD sequentially so the seeded RNG drives a reproducible
		// stream (amend-vs-root choice + which root to amend). No PoW here.
		items := make([]workItem, 0, batch)
		for j := 0; j < batch; j++ {
			if len(entities) > 0 && rng.Float64() < *amendRatio {
				// Path A amendment of an already-discovered entity, signed by its owner.
				e := entities[rng.Intn(len(entities))]
				payload := []byte(fmt.Sprintf("amend-%d-of-%d", submitted+j, e.pos.Sequence))
				entry, err := builder.BuildAmendment(builder.AmendmentParams{
					Destination: *logDID,
					SignerDID:   e.did,
					TargetRoot:  e.pos,
					Payload:     payload,
					EventTime:   time.Now().UTC().UnixMicro(),
				})
				if err != nil {
					log.Fatalf("backfill: BuildAmendment: %v", err)
				}
				items = append(items, workItem{entry: entry, priv: e.priv, did: e.did, amend: e})
				amendments++
			} else {
				// New root entity → a fresh SMT leaf.
				kp, err := sdkdid.GenerateDIDKeySecp256k1()
				if err != nil {
					log.Fatalf("backfill: generate key: %v", err)
				}
				payload := []byte(fmt.Sprintf("root-%d", submitted+j))
				entry, err := builder.BuildRootEntity(builder.RootEntityParams{
					Destination: *logDID,
					SignerDID:   kp.DID,
					Payload:     payload,
					EventTime:   time.Now().UTC().UnixMicro(),
				})
				if err != nil {
					log.Fatalf("backfill: BuildRootEntity: %v", err)
				}
				items = append(items, workItem{entry: entry, priv: kp.PrivateKey, did: kp.DID, root: &entity{did: kp.DID, priv: kp.PrivateKey}})
			}
		}

		// Phase 2 — STAMP + sign + POST across the worker pool. Bounded in-flight =
		// at most *workers concurrent PoW computations (or *workers concurrent batch
		// POSTs when -batch-size > 1). Order-preserving: hashes[i] is the SCT
		// canonical_hash for items[i].
		var hashes []string
		if *batchSize <= 1 {
			hashes = submitConcurrent(*workers, items, func(it workItem) string {
				return signAndSubmit(*ledgerURL, *logDID, it.entry, it.priv, it.did, diff, uint64(*epochSec), *token)
			})
		} else {
			// Batch path: group items into chunks of -batch-size and POST each chunk
			// to /v1/entries/batch. Each chunk is ONE credit deduction + ONE WAL
			// append server-side — the whole point of the flag.
			chunks := chunkItems(items, *batchSize)
			chunkResults := make([][]string, len(chunks))
			chunkIdx := make(chan int)
			var bwg sync.WaitGroup
			for w := 0; w < *workers; w++ {
				bwg.Add(1)
				go func() {
					defer bwg.Done()
					for i := range chunkIdx {
						chunkResults[i] = signAndPostBatch(*ledgerURL, *logDID, chunks[i], *token)
					}
				}()
			}
			for i := range chunks {
				chunkIdx <- i
			}
			close(chunkIdx)
			bwg.Wait()
			hashes = make([]string, 0, len(items))
			for _, cr := range chunkResults {
				hashes = append(hashes, cr...)
			}
		}
		pending := make([]pendingItem, len(items))
		for i, it := range items {
			pending[i] = pendingItem{hash: hashes[i], root: it.root, amend: it.amend}
		}
		submitted += batch

		// Phase 3 — DISCOVER sequences for this epoch's submissions before the next
		// epoch (so new roots become referenceable).
		for _, p := range pending {
			seq, err := waitForSequence(*ledgerURL, p.hash, *seqTimeout)
			if err != nil {
				log.Fatalf("backfill: sequence discovery for %s: %v", p.hash[:16], err)
			}
			pos := types.LogPosition{LogDID: *logDID, Sequence: seq}
			switch {
			case p.root != nil:
				p.root.pos = pos
				p.root.originTip = pos
				p.root.authorityTip = pos
				entities = append(entities, p.root)
			case p.amend != nil:
				// Path A advances OriginTip to the amendment's position. Concurrent
				// submission means arrival order (hence assigned sequence) need not
				// match build order, and an entity may be amended more than once in an
				// epoch — so take the MAX sequence, which is the state the ledger's
				// in-order apply converges to (submission-order-independent).
				if pos.Sequence > p.amend.originTip.Sequence {
					p.amend.originTip = pos
				}
			}
		}
		// Progress: every epoch when progress-every-pct<=0, else each time we
		// cross the next %-of-n threshold (so 10M reports ~100 lines, not 156K),
		// with rate + ETA for the remaining entries.
		pct := 100 * float64(submitted) / float64(*n)
		if *progressPct <= 0 || pct >= nextPct || submitted >= *n {
			elapsed := time.Since(t0).Seconds()
			rate := float64(submitted) / elapsed
			eta := time.Duration(0)
			if rate > 0 {
				eta = time.Duration(float64(*n-submitted)/rate) * time.Second
			}
			fmt.Printf("backfill: progress — %d/%d (%.1f%%) roots=%d amendments=%d %.1f/s eta=%s\n",
				submitted, *n, pct, len(entities), amendments, rate, eta.Round(time.Second))
			for *progressPct > 0 && nextPct <= pct {
				nextPct += *progressPct
			}
		}
	}

	fmt.Printf("backfill: complete — %d entries (%d roots, %d amendments) in %.1fs\n",
		submitted, len(entities), amendments, time.Since(t0).Seconds())

	if *manifestP != "" {
		writeManifest(*manifestP, *logDID, submitted, amendments, entities)
	}
}

// writeManifest emits the expected per-leaf state — the validation oracle.
func writeManifest(path, logDID string, submitted, amendments int, entities []*entity) {
	m := manifest{
		LogDID:     logDID,
		Entries:    submitted,
		Roots:      len(entities),
		Amendments: amendments,
		Leaves:     make([]manifestLeaf, 0, len(entities)),
	}
	for _, e := range entities {
		key := smt.DeriveKey(e.pos)
		m.Leaves = append(m.Leaves, manifestLeaf{
			Key:             hex.EncodeToString(key[:]),
			SignerDID:       e.did,
			OriginTipSeq:    e.originTip.Sequence,
			AuthorityTipSeq: e.authorityTip.Sequence,
		})
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatalf("backfill: marshal manifest: %v", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		log.Fatalf("backfill: write manifest %q: %v", path, err)
	}
	fmt.Printf("backfill: manifest = %s (%d leaves)\n", path, len(m.Leaves))
}

// submitConcurrent runs submit(items[i]) across up to `workers` goroutines and
// returns results in INPUT ORDER (results[i] ↔ items[i]). This is the backfill's
// bounded-in-flight worker pool: at most `workers` Mode B PoW computations (the
// CPU bottleneck) run at once, so a 10M-entry backfill saturates all cores
// without an unbounded goroutine fan-out. workers<1 is treated as 1.
//
// Order preservation matters because the caller pairs results[i] with the
// pre-built items[i] (its root/amend entity) during sequence discovery. Each
// index is handled by exactly one worker, so writing results[i] needs no lock.
func submitConcurrent[T any](workers int, items []T, submit func(T) string) []string {
	if workers < 1 {
		workers = 1
	}
	results := make([]string, len(items))
	if len(items) == 0 {
		return results
	}
	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				results[i] = submit(items[i])
			}
		}()
	}
	for i := range items {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return results
}

// signAndSubmit admits the (already-built) entry and returns the SCT
// canonical_hash. Two admission modes (mutually exclusive on the wire):
//
//   - Mode A (token != ""): leave AdmissionProof nil, sign once, POST with an
//     Authorization: Bearer header. The ledger deducts one write credit from the
//     token's session balance. No PoW — submission is bound only by HTTP +
//     sequencer throughput.
//   - Mode B (token == ""): brute-force a PoW stamp. Mirrors submit-stamp's Mode
//     B loop (the stamp target is the canonical hash, which includes the
//     signature, so each nonce re-signs).
func signAndSubmit(ledgerURL, logDID string, entry *envelope.Entry, priv *ecdsa.PrivateKey, signerDID string, difficulty uint32, epochWindowSec uint64, token string) string {
	if token != "" {
		// Mode A — credit/Bearer. AdmissionProof stays nil; sign once and POST.
		entry.Header.AdmissionProof = nil
		u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
		if err != nil {
			log.Fatalf("backfill: NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(u))
		sig, err := sdksigs.SignEntry(signingHash, priv)
		if err != nil {
			log.Fatalf("backfill: SignEntry: %v", err)
		}
		u.Signatures = []envelope.Signature{{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
		canonical, err := envelope.Serialize(u)
		if err != nil {
			log.Fatalf("backfill: serialize: %v", err)
		}
		return postEntry(ledgerURL, canonical, token)
	}
	entry.Header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: uint8(difficulty),
		HashFunc:   sdkadmission.WireByteHashSHA256,
		Epoch:      sdkadmission.CurrentEpoch(epochWindowSec),
	}
	const maxIter uint64 = 1 << 30
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		entry.Header.AdmissionProof.Nonce = nonce
		// Re-derive an unsigned entry from the (mutated) header so the canonical
		// signing payload reflects this nonce, then sign.
		u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
		if err != nil {
			log.Fatalf("backfill: NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(u))
		sig, err := sdksigs.SignEntry(signingHash, priv)
		if err != nil {
			log.Fatalf("backfill: SignEntry: %v", err)
		}
		u.Signatures = []envelope.Signature{{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
		canonical, err := envelope.Serialize(u)
		if err != nil {
			log.Fatalf("backfill: serialize: %v", err)
		}
		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(entry.Header.AdmissionProof, logDID)
		if err := sdkadmission.VerifyStamp(apiProof, entryHash, logDID, difficulty,
			sdkadmission.HashSHA256, nil, sdkadmission.CurrentEpoch(epochWindowSec), 1); err == nil {
			return postEntry(ledgerURL, canonical, token)
		}
	}
	log.Fatalf("backfill: PoW nonce exhausted (difficulty=%d too high?)", difficulty)
	return ""
}

// postEntry POSTs canonical wire bytes, requires 202, and returns the SCT's
// canonical_hash (used to discover the assigned sequence). A non-empty token is
// sent as an Authorization: Bearer header (Mode A credit deduction).
func postEntry(ledgerURL string, wire []byte, token string) string {
	req, err := http.NewRequest(http.MethodPost, ledgerURL+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		log.Fatalf("backfill: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatalf("backfill: POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		log.Fatalf("backfill: submit HTTP %d: %s", resp.StatusCode, body)
	}
	var sct struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if err := json.Unmarshal(body, &sct); err != nil || sct.CanonicalHash == "" {
		log.Fatalf("backfill: parse SCT canonical_hash: %v (body=%s)", err, body)
	}
	return sct.CanonicalHash
}

// chunkItems splits items into slices of at most `size` elements, preserving
// order. size<=0 → one chunk per item. Used by the -batch-size > 1 path to
// group entries for /v1/entries/batch POSTs.
func chunkItems[T any](items []T, size int) [][]T {
	if size <= 0 {
		size = 1
	}
	chunks := make([][]T, 0, (len(items)+size-1)/size)
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

// signAndPostBatch signs each item in chunk (Mode A — no PoW, no
// AdmissionProof), bundles them into a /v1/entries/batch request, and returns
// the per-item canonical_hashes in order. The whole batch is ONE credit
// deduction + ONE WAL append server-side. Mode A only; the caller validates
// token != "" before invoking.
func signAndPostBatch(ledgerURL, logDID string, chunk []workItem, token string) []string {
	type batchEntry struct {
		WireBytesHex string `json:"wire_bytes_hex"`
	}
	type batchReq struct {
		Entries []batchEntry `json:"entries"`
	}
	req := batchReq{Entries: make([]batchEntry, len(chunk))}
	for i, it := range chunk {
		it.entry.Header.AdmissionProof = nil
		u, err := envelope.NewUnsignedEntry(it.entry.Header, it.entry.DomainPayload)
		if err != nil {
			log.Fatalf("backfill: NewUnsignedEntry: %v", err)
		}
		signingHash := sha256.Sum256(envelope.SigningPayload(u))
		sig, err := sdksigs.SignEntry(signingHash, it.priv)
		if err != nil {
			log.Fatalf("backfill: SignEntry: %v", err)
		}
		u.Signatures = []envelope.Signature{{SignerDID: it.did, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
		canonical, err := envelope.Serialize(u)
		if err != nil {
			log.Fatalf("backfill: serialize: %v", err)
		}
		req.Entries[i] = batchEntry{WireBytesHex: hex.EncodeToString(canonical)}
	}
	return postBatch(ledgerURL, req, token, len(chunk))
}

// postBatch POSTs the batch envelope to /v1/entries/batch and returns the
// per-entry canonical_hash slice (in submitted order). The server response is:
//
//   - 202 Accepted        — all entries accepted; every result has an SCT.
//   - 207 Multi-Status    — accepted prefix + rejected tail; rejected entries
//     carry an error+class (no SCT). The backfill fails
//     fast on any rejection (no per-entry retry here);
//     the caller resubmits the rejected tail manually.
//   - 402 / 503 / 500     — systemic failure with nothing accepted; bare
//     typed error in the body.
func postBatch(ledgerURL string, body any, token string, expectedResults int) []string {
	js, err := json.Marshal(body)
	if err != nil {
		log.Fatalf("backfill: marshal batch: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ledgerURL+"/v1/entries/batch", bytes.NewReader(js))
	if err != nil {
		log.Fatalf("backfill: new batch request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatalf("backfill: POST /v1/entries/batch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // matches server cap
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusMultiStatus {
		log.Fatalf("backfill: batch HTTP %d: %s", resp.StatusCode, respBody)
	}
	var parsed struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
		Results  []struct {
			Index  int    `json:"index"`
			Status string `json:"status"`
			SCT    *struct {
				CanonicalHash string `json:"canonical_hash"`
			} `json:"sct,omitempty"`
			Error string `json:"error,omitempty"`
			Class string `json:"class,omitempty"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		log.Fatalf("backfill: parse batch response: %v (body=%s)", err, respBody)
	}
	if len(parsed.Results) != expectedResults {
		log.Fatalf("backfill: batch returned %d results, expected %d", len(parsed.Results), expectedResults)
	}
	if parsed.Rejected > 0 {
		// Find the first rejected entry for a clear error — the rejected
		// tail all carries the same systemic class+error by design.
		for _, r := range parsed.Results {
			if r.Status != "accepted" {
				log.Fatalf("backfill: batch %d/%d rejected (first at index %d): class=%s error=%s",
					parsed.Rejected, expectedResults, r.Index, r.Class, r.Error)
			}
		}
	}
	hashes := make([]string, len(parsed.Results))
	for i, r := range parsed.Results {
		if r.SCT == nil || r.SCT.CanonicalHash == "" {
			log.Fatalf("backfill: batch result %d (status=%q): missing SCT canonical_hash", i, r.Status)
		}
		hashes[i] = r.SCT.CanonicalHash
	}
	return hashes
}

// waitForSequence polls GET /v1/entries-hash/{hash} until the entry is sequenced
// and returns its assigned sequence number.
func waitForSequence(ledgerURL, canonicalHash string, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	url := ledgerURL + "/v1/entries-hash/" + canonicalHash
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// The 200 family is POLYMORPHIC (api/queries.go NewHashLookupHandler):
				// a SEQUENCED entry carries sequence_number; a WAL-resident entry that
				// is admitted but not yet sequenced carries {"state":"pending"|"manual"}
				// and NO sequence_number. Decode sequence_number as a POINTER so an
				// absent field is nil (keep polling) rather than the zero value 0 — the
				// latter mis-records every still-pending entry as seq 0, which under
				// high-throughput admission collapses EVERY manifest leaf key to
				// DeriveKey(seq 0) and makes the membership audit fail wholesale.
				var er struct {
					SequenceNumber *uint64 `json:"sequence_number"`
					State          string  `json:"state"`
				}
				if jErr := json.Unmarshal(body, &er); jErr == nil && er.SequenceNumber != nil {
					return *er.SequenceNumber, nil
				}
				// pending/manual (sequence_number absent) — not sequenced yet; keep
				// polling until the sequencer assigns a sequence.
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, fmt.Errorf("not sequenced within %s", timeout)
}

// queryDifficulty reads the live Mode B difficulty from the ledger.
func queryDifficulty(ledgerURL string) (uint32, error) {
	resp, err := hc.Get(ledgerURL + "/v1/admission/difficulty")
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Difficulty uint32 `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode: %w", err)
	}
	return body.Difficulty, nil
}
