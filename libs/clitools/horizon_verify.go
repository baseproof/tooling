// FILE PATH: libs/clitools/horizon_verify.go
//
// Horizon-anchored verification — the light-client durability check.
//
// As of baseproof v1.22.0 the SDK ships the canonical horizon client (the C/D
// adoption primitive), so this is a THIN convenience wrapper over it — one call
// for a tool that wants "verify this ledger's published horizon + sample its
// proofs." All decode / cosignature / proof logic lives in the SDK; there is no
// parallel decoder here (the v1.21.0 "one wire type, one decoder" principle):
//
//	log.HTTPCheckpointClient.FetchVerifiedHorizon  — fetch + decode + K-of-N trust
//	smt.HTTPProofReader.Proof                       — fetch a proof
//	smt.Verify{Membership,NonMembership}Proof       — bind it to head.SMTRoot
//
// FetchVerifiedHorizon is the SINGLE trust step: it returns the head only if
// >= set.Quorum() valid witness cosignatures verify, so head.SMTRoot is a trusted
// anchor (errors: log.ErrHorizonNotPublished pre-genesis, log.ErrHorizonNotTrusted
// sub-quorum). Each sampled proof must then resolve against that witnessed root.
//
// v1.27.1 surface (single canonical form). VerifyHorizon and VerifyAsOfHorizon
// take a REQUIRED *http.Client. The v1.25.0 SDK explicitly removed the dual
// DefaultClient / DefaultClientWithTLS pattern; the previous tooling
// shape re-introduced exactly that pattern one layer up (VerifyHorizon vs
// VerifyHorizonWithClient with a silent plaintext fallback). This file now
// matches the SDK's "caller owns the transport" contract: one function, one
// shape, no implicit-default footgun. mTLS-required deployments build the
// client from log.LoadClientTLSConfig + log.DefaultClient(t, tlsCfg); plaintext
// deployments still build a client explicitly (typically log.DefaultClient(t,
// nil)).
//
// Correctness is covered by the SDK's hermetic tests (log.VerifyMembership/
// NonMembershipAsOfHorizon, FetchVerifiedHorizon tamper/sub-quorum) + the e2e.
// Distinct from clitools.LedgerClient.TreeHead() (raw /v1/tree/head map, display
// only, unverified).
package clitools

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"
)

// ErrNilHTTPClient is returned by VerifyHorizon / VerifyAsOfHorizon when the
// caller passes nil for httpClient. The previous shape silently fell back to a
// 15-second plaintext client, which v1.27.1 explicitly removed — every caller
// must construct its client (log.DefaultClient(t, tlsCfg) or any *http.Client)
// so the transport posture (mTLS, retry, pool) is visible at the call site.
var ErrNilHTTPClient = errors.New("clitools: httpClient is required (build via log.DefaultClient or any *http.Client)")

// HorizonResult is the evidence a verification produced.
type HorizonResult struct {
	TreeSize    uint64
	RootHash    [32]byte
	SMTRoot     [32]byte
	ValidCosigs int // valid witness cosignatures observed (>= Quorum on success)
	Quorum      int // K required
	ProofsOK    int // sampled proofs that verified against SMTRoot
	ProofsTotal int
}

// VerifyHorizon fetches + cosignature-verifies baseURL's published horizon, then
// samples `samples` random keys and verifies each returned proof against the
// witnessed SMTRoot. set is the out-of-band witness key set (carries the quorum).
// httpClient is the caller-built transport (required; see ErrNilHTTPClient).
//
// A non-nil error means the durability guarantee FAILED (not published, quorum
// unmet, transport, or a proof that does not resolve to the witnessed root).
//
// Transport notes for callers building the client:
//   - For mTLS-required ledgers, build via log.DefaultClient(timeout, tlsCfg)
//     where tlsCfg comes from log.LoadClientTLSConfig.
//   - For plaintext deployments, log.DefaultClient(timeout, nil) is canonical;
//     a bare &http.Client{Timeout: t} is also accepted.
//   - The horizon endpoint's 503 means "not yet published" (persistent state),
//     so a Retry-After middleware would mask ErrHorizonNotPublished. The
//     SDK's HTTPCheckpointClient handles this and recommends a non-retrying
//     client.
func VerifyHorizon(ctx context.Context, baseURL string, set *cosign.WitnessKeySet, samples int, httpClient *http.Client) (HorizonResult, error) {
	if httpClient == nil {
		return HorizonResult{}, ErrNilHTTPClient
	}
	cp, err := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{
		BaseURL: baseURL,
		Client:  httpClient,
	})
	if err != nil {
		return HorizonResult{}, fmt.Errorf("clitools: checkpoint client: %w", err)
	}
	head, err := cp.FetchVerifiedHorizon(ctx, set) // the ONLY trust step
	if err != nil {
		return HorizonResult{}, err
	}
	res := HorizonResult{TreeSize: head.TreeSize, RootHash: head.RootHash, SMTRoot: head.SMTRoot, ProofsTotal: samples}
	if set != nil {
		res.Quorum = set.Quorum()
		res.ValidCosigs = cosign.VerifyTreeHeadCosignatures(head, set)
	}
	pr, err := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{
		BaseURL: baseURL,
		Client:  httpClient,
	})
	if err != nil {
		return res, fmt.Errorf("clitools: proof reader: %w", err)
	}
	for i := 0; i < samples; i++ {
		var key [32]byte
		if _, rErr := rand.Read(key[:]); rErr != nil {
			return res, fmt.Errorf("clitools: random key: %w", rErr)
		}
		rr, pErr := pr.Proof(ctx, key)
		if pErr != nil {
			return res, fmt.Errorf("clitools: fetch proof: %w", pErr)
		}
		var vErr error
		if rr.Membership {
			vErr = smt.VerifyMembershipProof(rr.Proof, head.SMTRoot)
		} else {
			vErr = smt.VerifyNonMembershipProof(rr.Proof, head.SMTRoot)
		}
		if vErr != nil {
			return res, fmt.Errorf("clitools: proof for %x does not verify against the witnessed smt_root: %w", key[:8], vErr)
		}
		res.ProofsOK++
	}
	return res, nil
}

// VerifyAsOfHorizon verifies a single KNOWN key against the witnessed checkpoint
// — for the court-tools CLI ("verify this key against the witnessed checkpoint").
// Fetch + K-of-N-trust the horizon, then bind the key's membership proof to the
// witnessed SMTRoot. Thin pass-through to the SDK horizon-anchored verify.
//
// httpClient is required (see ErrNilHTTPClient). Same transport guidance as
// VerifyHorizon above.
func VerifyAsOfHorizon(ctx context.Context, baseURL string, set *cosign.WitnessKeySet, key [32]byte, httpClient *http.Client) (*types.SMTProof, types.CosignedTreeHead, error) {
	if httpClient == nil {
		return nil, types.CosignedTreeHead{}, ErrNilHTTPClient
	}
	cp, err := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{
		BaseURL: baseURL,
		Client:  httpClient,
	})
	if err != nil {
		return nil, types.CosignedTreeHead{}, fmt.Errorf("clitools: checkpoint client: %w", err)
	}
	pr, err := smt.NewHTTPProofReader(smt.HTTPProofReaderConfig{
		BaseURL: baseURL,
		Client:  httpClient,
	})
	if err != nil {
		return nil, types.CosignedTreeHead{}, fmt.Errorf("clitools: proof reader: %w", err)
	}
	return sdklog.VerifyMembershipAsOfHorizon(ctx, cp, pr, set, key)
}
