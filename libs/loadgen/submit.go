package loadgen

// submit.go is the admission/transport layer: build → stamp/sign → POST →
// discover-sequence. It is a faithful port of the legacy cmd/backfill helpers
// with two deliberate changes for library use:
//
//   - it RETURNS errors instead of log.Fatalf (a library must never kill the
//     process), and
//   - the *http.Client is INJECTED (the caller supplies its mTLS + retry posture;
//     the engine stays transport-agnostic), rather than a package global.
//
// The two admission modes are unchanged on the wire: Mode B brute-forces a PoW
// stamp (each nonce re-signs because the stamp target is the canonical hash);
// Mode A (token) submits with a Bearer credit and no PoW, and may batch.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// engine carries the per-run transport + admission parameters shared by every
// submit call, so the hot-path helpers don't thread a dozen arguments.
type engine struct {
	client         *http.Client
	ledgerURL      string
	logDID         string
	token          string // "" ⇒ Mode B PoW; non-empty ⇒ Mode A credit
	difficulty     uint32
	epochWindowSec uint64
	seqTimeout     time.Duration
	batchSize      int
	workers        int
}

// workItem is a built-but-not-yet-admitted entry plus the model bookkeeping the
// discovery phase needs. Exactly one of root/amend/delegFor is non-nil.
type workItem struct {
	entry    *envelope.Entry
	priv     *ecdsa.PrivateKey
	did      string
	root     *root // non-nil ⇒ a new root entity
	amend    *root // non-nil ⇒ an amendment (same-signer or delegated) of this windowed root
	delegFor *root // non-nil ⇒ a delegation (owner→delegate) that makes this entity delegation-capable
}

// submitConcurrent runs submit(items[i]) across up to `workers` goroutines and
// returns the SCT canonical_hashes in INPUT ORDER (results[i] ↔ items[i]). The
// first error cancels the context so in-flight PoW/HTTP unwinds promptly, and
// that error is returned. Bounded in-flight = at most `workers` concurrent PoW
// computations — a 20M run saturates the cores without an unbounded fan-out.
func submitConcurrent(ctx context.Context, workers int, items []workItem,
	submit func(context.Context, workItem) (string, error)) ([]string, error) {

	if workers < 1 {
		workers = 1
	}
	results := make([]string, len(items))
	if len(items) == 0 {
		return results, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	idx := make(chan int)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				if ctx.Err() != nil {
					return
				}
				h, err := submit(ctx, items[i])
				if err != nil {
					select {
					case errCh <- fmt.Errorf("item %d: %w", i, err):
						cancel()
					default:
					}
					return
				}
				results[i] = h
			}
		}()
	}
	for i := range items {
		select {
		case idx <- i:
		case <-ctx.Done():
		}
	}
	close(idx)
	wg.Wait()
	select {
	case err := <-errCh:
		return results, err
	default:
		return results, nil
	}
}

// signCanonical signs the (mutated-header) unsigned entry and returns its
// canonical wire bytes.
func signCanonical(u *envelope.Entry, priv *ecdsa.PrivateKey, signerDID string) ([]byte, error) {
	signingHash := sha256.Sum256(envelope.SigningPayload(u))
	sig, err := sdksigs.SignEntry(signingHash, priv)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	u.Signatures = []envelope.Signature{{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	canonical, err := envelope.Serialize(u)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}
	return canonical, nil
}

// signAndSubmit admits the (already-built) entry and returns the SCT
// canonical_hash. Mode A leaves AdmissionProof nil and signs once; Mode B
// brute-forces the PoW nonce (re-signing each iteration), checking the context
// periodically so a cancelled run unwinds.
func (e *engine) signAndSubmit(ctx context.Context, entry *envelope.Entry, priv *ecdsa.PrivateKey, signerDID string) (string, error) {
	if e.token != "" {
		entry.Header.AdmissionProof = nil
		u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
		if err != nil {
			return "", fmt.Errorf("new unsigned entry: %w", err)
		}
		canonical, err := signCanonical(u, priv, signerDID)
		if err != nil {
			return "", err
		}
		return e.postEntry(ctx, canonical)
	}

	entry.Header.AdmissionProof = &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		Difficulty: uint8(e.difficulty),
		HashFunc:   sdkadmission.WireByteHashSHA256,
		Epoch:      sdkadmission.CurrentEpoch(e.epochWindowSec),
	}
	const maxIter uint64 = 1 << 30
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		if nonce&0x3ff == 0 && ctx.Err() != nil {
			return "", ctx.Err()
		}
		entry.Header.AdmissionProof.Nonce = nonce
		u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
		if err != nil {
			return "", fmt.Errorf("new unsigned entry: %w", err)
		}
		canonical, err := signCanonical(u, priv, signerDID)
		if err != nil {
			return "", err
		}
		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(entry.Header.AdmissionProof, e.logDID)
		if err := sdkadmission.VerifyStamp(apiProof, entryHash, e.logDID, e.difficulty,
			sdkadmission.HashSHA256, nil, sdkadmission.CurrentEpoch(e.epochWindowSec), 1); err == nil {
			return e.postEntry(ctx, canonical)
		}
	}
	return "", fmt.Errorf("PoW nonce exhausted (difficulty=%d too high?)", e.difficulty)
}

// postEntry POSTs canonical wire bytes, requires 202, and returns the SCT's
// canonical_hash.
func (e *engine) postEntry(ctx context.Context, wire []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.ledgerURL+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST /v1/entries: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("submit HTTP %d: %s", resp.StatusCode, body)
	}
	var sct struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if err := json.Unmarshal(body, &sct); err != nil || sct.CanonicalHash == "" {
		return "", fmt.Errorf("parse SCT canonical_hash: %v (body=%s)", err, body)
	}
	return sct.CanonicalHash, nil
}

// waitForSequence polls GET /v1/entries-hash/{hash} until the entry is sequenced
// and returns its assigned sequence. The 200 family is polymorphic — a pending
// entry carries {"state":...} with NO sequence_number — so sequence_number is
// decoded as a POINTER (absent ⇒ keep polling, never the zero value 0, which
// would collapse every still-pending leaf to DeriveKey(seq 0)).
func (e *engine) waitForSequence(ctx context.Context, canonicalHash string) (uint64, error) {
	deadline := time.Now().Add(e.seqTimeout)
	url := e.ledgerURL + "/v1/entries-hash/" + canonicalHash
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, fmt.Errorf("new request: %w", err)
		}
		resp, err := e.client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var er struct {
					SequenceNumber *uint64 `json:"sequence_number"`
					State          string  `json:"state"`
				}
				if jErr := json.Unmarshal(body, &er); jErr == nil && er.SequenceNumber != nil {
					return *er.SequenceNumber, nil
				}
			}
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return 0, fmt.Errorf("not sequenced within %s", e.seqTimeout)
}

// queryDifficulty reads the live Mode B difficulty from the ledger.
func (e *engine) queryDifficulty(ctx context.Context) (uint32, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.ledgerURL+"/v1/admission/difficulty", nil)
	if err != nil {
		return 0, err
	}
	resp, err := e.client.Do(req)
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

// submitBatched groups items into chunks of batchSize and POSTs each chunk to
// /v1/entries/batch across the worker pool, returning the per-item canonical
// hashes in input order. Mode A only (the caller validates Token != "").
func (e *engine) submitBatched(ctx context.Context, items []workItem) ([]string, error) {
	chunks := chunkItems(items, e.batchSize)
	results := make([][]string, len(chunks))
	errs := make([]error, len(chunks))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	idxCh := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < e.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idxCh {
				if ctx.Err() != nil {
					return
				}
				h, err := e.signAndPostBatch(ctx, chunks[i])
				if err != nil {
					errs[i] = err
					cancel()
					return
				}
				results[i] = h
			}
		}()
	}
	for i := range chunks {
		select {
		case idxCh <- i:
		case <-ctx.Done():
		}
	}
	close(idxCh)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(items))
	for _, cr := range results {
		out = append(out, cr...)
	}
	return out, nil
}

// chunkItems splits items into slices of at most `size` elements, preserving order.
func chunkItems(items []workItem, size int) [][]workItem {
	if size <= 0 {
		size = 1
	}
	chunks := make([][]workItem, 0, (len(items)+size-1)/size)
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

// signAndPostBatch signs each item (Mode A — no PoW) and POSTs the bundle to
// /v1/entries/batch, returning the per-item canonical hashes in order.
func (e *engine) signAndPostBatch(ctx context.Context, chunk []workItem) ([]string, error) {
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
			return nil, fmt.Errorf("new unsigned entry: %w", err)
		}
		canonical, err := signCanonical(u, it.priv, it.did)
		if err != nil {
			return nil, err
		}
		req.Entries[i] = batchEntry{WireBytesHex: hex.EncodeToString(canonical)}
	}
	return e.postBatch(ctx, req, len(chunk))
}

// postBatch POSTs the batch envelope and returns the per-entry canonical_hash
// slice (submitted order). Fails fast on any rejection (the rejected tail carries
// the same systemic class by design).
func (e *engine) postBatch(ctx context.Context, body any, expectedResults int) ([]string, error) {
	js, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.ledgerURL+"/v1/entries/batch", bytes.NewReader(js))
	if err != nil {
		return nil, fmt.Errorf("new batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /v1/entries/batch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusMultiStatus {
		return nil, fmt.Errorf("batch HTTP %d: %s", resp.StatusCode, respBody)
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
		return nil, fmt.Errorf("parse batch response: %w (body=%s)", err, respBody)
	}
	if len(parsed.Results) != expectedResults {
		return nil, fmt.Errorf("batch returned %d results, expected %d", len(parsed.Results), expectedResults)
	}
	if parsed.Rejected > 0 {
		for _, r := range parsed.Results {
			if r.Status != "accepted" {
				return nil, fmt.Errorf("batch %d/%d rejected (first at index %d): class=%s error=%s",
					parsed.Rejected, expectedResults, r.Index, r.Class, r.Error)
			}
		}
	}
	hashes := make([]string, len(parsed.Results))
	for i, r := range parsed.Results {
		if r.SCT == nil || r.SCT.CanonicalHash == "" {
			return nil, fmt.Errorf("batch result %d (status=%q): missing SCT canonical_hash", i, r.Status)
		}
		hashes[i] = r.SCT.CanonicalHash
	}
	return hashes, nil
}
