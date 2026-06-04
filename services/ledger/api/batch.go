package api

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"
	sdksct "github.com/baseproof/baseproof/crypto/sct"
	"github.com/baseproof/baseproof/exchange/policy"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/wal"
)

const (
	// MaxBatchSize caps the number of entries per batch request.
	MaxBatchSize = 256

	// AbsoluteMaxBatchPayloadBytes is the hard ceiling on the
	// HTTP request body size for /v1/entries/batch. Caps heap
	// pressure under malicious payloads regardless of the per-entry
	// MaxEntrySize configuration: a 1 MB single-entry cap can still
	// admit 256 entries × ~2× hex overhead, but the total request
	// body never exceeds this absolute ceiling.
	AbsoluteMaxBatchPayloadBytes = 64 << 20 // 64 MiB

	// maxBatchPayloadBytes is the floor used when a tiny per-entry
	// MaxEntrySize would otherwise produce a request-body cap below
	// the minimum useful size. Pre-existing constant kept for
	// backwards compatibility with callers expecting a fixed floor.
	maxBatchPayloadBytes = 4 << 20 // 4 MiB
)

type BatchEntry struct {
	WireBytesHex string `json:"wire_bytes_hex"`

	// WriteAuthorizationB64 is the per-entry detached write authorization
	// (base64 authz.WriteAuthorization), required when the on-log admission
	// policy is GatingRequired. Each batch entry carries its own — without
	// this the batch endpoint would be a bypass of the single-path gate.
	// Empty/ignored when the policy does not require gating.
	WriteAuthorizationB64 string `json:"write_authorization_b64,omitempty"`
}

type BatchSubmissionRequest struct {
	Entries []BatchEntry `json:"entries"`
}

// Batch result statuses.
const (
	batchStatusAccepted = "accepted"
	batchStatusRejected = "rejected"
)

// BatchResultEntry is the disposition of ONE entry in a batch
// submission, index-aligned to the request via Index.
//
//   - status "accepted": the entry is durable and SCT is present.
//   - status "rejected": the entry was NOT committed; Error + Class
//     explain why and the entry is safe to resubmit.
//
// Phase-2 (commit) failures are systemic — credit exhaustion, WAL
// backpressure, an infra fault — not entry-specific (entry-specific
// faults are caught in the all-or-nothing phase-1 validation). They
// recur for every subsequent entry, so the commit loop stops at the
// first one: the accepted prefix keeps its SCTs and the failing entry
// plus the untried suffix are all reported rejected with the SAME
// reason. The caller resubmits exactly the rejected tail — never a
// scattered "12 of 30 failed".
type BatchResultEntry struct {
	Index  int                                `json:"index"`
	Status string                             `json:"status"`
	SCT    *sdksct.SignedCertificateTimestamp `json:"sct,omitempty"`
	Error  string                             `json:"error,omitempty"`
	Class  apitypes.ErrorClass                `json:"class,omitempty"`
}

// BatchSubmissionResponse is returned with 202 (all accepted) or 207
// Multi-Status (accepted prefix + rejected tail). Accepted + Rejected
// always sum to the request entry count; Results holds one disposition
// per entry in request order.
type BatchSubmissionResponse struct {
	Accepted int                `json:"accepted"`
	Rejected int                `json:"rejected"`
	Results  []BatchResultEntry `json:"results"`
}

// batchStop captures the first systemic failure in the phase-2 commit
// loop. nil means every entry committed.
type batchStop struct {
	class      apitypes.ErrorClass
	status     int
	msg        string
	retryAfter bool
}

type preparedEntry struct {
	entry         *envelope.Entry
	canonical     []byte
	canonicalHash [32]byte
	logTime       time.Time
	// web3Receipts are the per-signature Web3VerificationReceipts produced by
	// the shared signature gate (verifyEntrySignaturesGated) — populated on the
	// polymorphic multi-sig path (e.g. EIP-1271), nil on the legacy path. Threaded
	// into WAL.Submit so a batch-submitted entry persists the SAME receipt
	// metadata the single-entry path does.
	web3Receipts []types.Web3VerificationReceipt
}

type preflightError struct {
	status int
	msg    string
	class  apitypes.ErrorClass
}

func (e *preflightError) Error() string { return e.msg }
func preflightFail(class apitypes.ErrorClass, status int, format string, args ...any) *preflightError {
	return &preflightError{status: status, msg: fmt.Sprintf(format, args...), class: class}
}

// computeEffectiveBatchPayloadCap derives the io.LimitReader cap
// for a batch request body from the per-entry MaxEntrySize.
//
// Bounds:
//   - Floor at maxBatchPayloadBytes (4 MiB): a tiny per-entry cap
//     would otherwise produce a request-body cap below the minimum
//     useful size; raise to 4 MiB so legitimate small-entry callers
//     are not artificially capped.
//   - Ceiling at AbsoluteMaxBatchPayloadBytes (64 MiB): defends
//     against OOM via crafted batches. The naive formula
//     (MaxBatchSize × per-entry × 2 + headroom) yields ~512 MiB at
//     the default 1 MiB MaxEntrySize, far above any legitimate
//     batch payload size.
func computeEffectiveBatchPayloadCap(maxEntrySize int64) int64 {
	cap := int64(MaxBatchSize)*((maxEntrySize+512)*2+128) + 1024
	if cap < maxBatchPayloadBytes {
		cap = maxBatchPayloadBytes
	}
	if cap > AbsoluteMaxBatchPayloadBytes {
		cap = AbsoluteMaxBatchPayloadBytes
	}
	return cap
}

func NewBatchSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}
	if deps.LedgerDID == "" {
		panic("api: SubmissionDeps.LedgerDID must be non-empty for batch SCT signing")
	}
	if deps.LedgerSignerPriv == nil {
		panic("api: SubmissionDeps.LedgerSignerPriv must be non-nil for batch SCT signing")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}
	effectiveBatchPayloadCap := computeEffectiveBatchPayloadCap(deps.MaxEntrySize)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, effectiveBatchPayloadCap))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "failed to read request body")
			return
		}
		var req BatchSubmissionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedJSON,
				http.StatusBadRequest, fmt.Sprintf("invalid JSON: %s", err))
			return
		}
		if len(req.Entries) == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassEmptyBatch,
				http.StatusBadRequest, "empty batch")
			return
		}
		if len(req.Entries) > MaxBatchSize {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest,
				fmt.Sprintf("batch size %d exceeds max %d", len(req.Entries), MaxBatchSize))
			return
		}

		prepared := make([]*preparedEntry, 0, len(req.Entries))
		// Intra-batch dedup: rejecting a same-batch duplicate before
		// credit deduction prevents the caller from paying twice for
		// the same canonical hash. Historical dedup (entry_index)
		// happens immediately after — both return 409 Conflict so the
		// caller can fix the batch and retry without partial state.
		seen := make(map[[32]byte]int, len(req.Entries))
		for i, be := range req.Entries {
			rawWire, decodeErr := hex.DecodeString(be.WireBytesHex)
			if decodeErr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexEncoding,
					http.StatusBadRequest, fmt.Sprintf("entry %d: hex decode: %s", i, decodeErr))
				return
			}
			pe, perr := preflightEntry(ctx, rawWire, deps, freshness)
			if perr != nil {
				writeTypedError(ctx, w, perr.class,
					perr.status, fmt.Sprintf("entry %d: %s", i, perr.msg))
				return
			}
			// Gate 5 (write-path authorization), per entry — else the batch
			// endpoint bypasses the single-path gate. Policy-driven (on-log
			// BP-ENTRY-ADMISSION-POLICY-V1). All-or-nothing: a single rejection fails
			// the whole batch before any WAL write.
			if deps.AdmissionPolicy != nil {
				pol, polErr := deps.AdmissionPolicy.Current(ctx)
				if polErr != nil {
					writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
						http.StatusInternalServerError, "admission policy resolution failed")
					return
				}
				if pol.GatingRequired {
					if err := admission.VerifyWriteAuthorization(
						ctx, be.WriteAuthorizationB64, pe.canonicalHash, deps.LogDID, deps.AdmissionAuthorities,
					); err != nil {
						em := mapWriteAuthError(err)
						writeTypedError(ctx, w, em.Class, em.Status, fmt.Sprintf("entry %d: %s", i, em.Message))
						return
					}
				}
			}
			// In-batch dedup.
			if firstIdx, dup := seen[pe.canonicalHash]; dup {
				writeTypedError(ctx, w, apitypes.ErrorClassDuplicateEntry,
					http.StatusConflict,
					fmt.Sprintf("entry %d duplicates entry %d in same batch", i, firstIdx))
				return
			}
			// Historical dedup against entry_index. Skipped when
			// EntryStore is nil (unit-test path); production wiring
			// always provides one. Mirrors api/submission.go step 8a.
			if deps.Storage.EntryStore != nil {
				if existingSeq, found, fetchErr := deps.Storage.EntryStore.FetchByHash(ctx, pe.canonicalHash); fetchErr == nil && found {
					writeTypedError(ctx, w, apitypes.ErrorClassDuplicateEntry,
						http.StatusConflict,
						fmt.Sprintf("entry %d duplicate entry: existing sequence %d", i, existingSeq))
					return
				}
			}
			seen[pe.canonicalHash] = i
			prepared = append(prepared, pe)
		}

		// Phase 2 — pre-loop: ONE credit deduction for the WHOLE batch
		// (cost = len(prepared)). The store semantic allows the pre-deduction
		// balance > 0 caller to take the balance negative once — a 200-credit
		// exchange submitting a 256-entry batch is honored (ends at -56) and
		// rejected on the next request until BulkPurchase tops up. Hoisting
		// the deduction here (instead of N times in the loop below) collapses
		// N per-entry row-lock acquisitions into one — the difference between
		// per-batch admission scaling and not. Failure here is systemic (no
		// entry is durable), so return the typed error directly — same
		// convention as the "nothing accepted" branch below.
		if err := deductCreditModeA(ctx, deps, middleware.IsAuthenticated(ctx),
			middleware.ExchangeDID(ctx), int64(len(prepared))); err != nil {
			if errors.Is(err, apitypes.ErrInsufficientCredits) {
				writeTypedError(ctx, w, apitypes.ErrorClassInsufficientCredits,
					http.StatusPaymentRequired,
					fmt.Sprintf("insufficient write credits for batch of %d", len(prepared)))
				return
			}
			deps.Logger.Error("batch credit deduction failed", "batch_size", len(prepared), "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassCreditDeductFailed,
				http.StatusInternalServerError, "credit deduction failed")
			return
		}

		// Phase 2 — commit loop. The systemic deduction above already ran
		// for the whole batch; this loop only does the per-entry WAL.Submit
		// + SCT.Sign. A per-entry systemic failure (WAL backpressure, SCT
		// signing) still stops at the first one and reports an accepted
		// prefix + rejected tail (see batchStop).
		results := make([]BatchResultEntry, 0, len(prepared))
		accepted := 0
		var stop *batchStop
		stopAt := -1
		for i, pe := range prepared {
			// Persist with the per-signature Web3VerificationReceipts the
			// shared signature gate collected (verifyEntrySignaturesGated):
			// nil/empty on the legacy path (byte-identical V1-shaped Meta
			// record), populated on the polymorphic path (e.g. EIP-1271) so a
			// batch-submitted entry carries the SAME receipt metadata the
			// single-entry path persists.
			if err := deps.Storage.WAL.Submit(ctx, pe.canonicalHash, pe.canonical, pe.logTime.UnixMicro(), pe.web3Receipts); err != nil {
				if errors.Is(err, wal.ErrQueueFull) {
					stop = &batchStop{class: apitypes.ErrorClassWALBackpressure,
						status: http.StatusServiceUnavailable, msg: "WAL queue full (backpressure)",
						retryAfter: true}
				} else {
					deps.Logger.Error("batch wal submit failed", "index", i, "error", err)
					stop = &batchStop{class: apitypes.ErrorClassWALPersistFailed,
						status: http.StatusInternalServerError, msg: "WAL persist failed"}
				}
				stopAt = i
				break
			}

			sct, signErr := SignSCT(deps.LedgerSignerPriv, deps.LedgerDID, deps.LogDID, pe.canonicalHash, pe.logTime)
			if signErr != nil {
				// Entry is durable (WAL.Submit succeeded) but the SCT
				// couldn't be signed — a ~never, catastrophic path
				// (local ECDSA sign with an in-memory key). Stop and
				// report rejected; a resubmit of this now-durable entry
				// resolves via the dedup 409.
				deps.Logger.Error("batch SCT signing failed", "index", i, "error", signErr)
				stop = &batchStop{class: apitypes.ErrorClassSCTSigningFailed,
					status: http.StatusInternalServerError, msg: "SCT signing failed"}
				stopAt = i
				break
			}
			results = append(results, BatchResultEntry{Index: i, Status: batchStatusAccepted, SCT: sct})
			accepted++
		}

		// Nothing durable and nothing accepted → return the systemic
		// status directly (mirrors phase-1's clean all-or-nothing
		// surface). With an accepted prefix we MUST return the SCTs, so
		// fold the rejection into a 207 Multi-Status below instead.
		if stop != nil && accepted == 0 {
			if stop.retryAfter {
				w.Header().Set("Retry-After", "5")
			}
			writeTypedError(ctx, w, stop.class, stop.status, stop.msg)
			return
		}

		// Account for the failing entry + the untried suffix so every
		// index appears in Results and the caller can retry exactly the
		// rejected tail.
		if stop != nil {
			for j := stopAt; j < len(prepared); j++ {
				results = append(results, BatchResultEntry{
					Index: j, Status: batchStatusRejected, Class: stop.class, Error: stop.msg,
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if stop == nil {
			w.WriteHeader(http.StatusAccepted) // 202 — all accepted
		} else {
			if stop.retryAfter {
				w.Header().Set("Retry-After", "5")
			}
			w.WriteHeader(http.StatusMultiStatus) // 207 — accepted prefix + rejected tail
		}
		_ = json.NewEncoder(w).Encode(BatchSubmissionResponse{
			Accepted: accepted,
			Rejected: len(prepared) - accepted,
			Results:  results,
		})
	}
}

func preflightEntry(ctx context.Context, rawWire []byte, deps *SubmissionDeps, freshness time.Duration) (*preparedEntry, *preflightError) {
	if len(rawWire) < 6 {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(rawWire[0:2])
	// Protocol-version admission via the shared gate (same helper as the
	// single-entry path): on-log policy when wired, else "current version only".
	if pvErr := admitProtocolVersion(ctx, protocolVersion, deps); pvErr != nil {
		if matched, status, class := admission.MapSDKError(pvErr); matched {
			return nil, preflightFail(class, status, "%s", pvErr)
		}
		return nil, preflightFail(apitypes.ErrorClassDBQueryFailed, http.StatusInternalServerError, "protocol-version gate failed: %s", pvErr)
	}
	entry, err := envelope.Deserialize(rawWire)
	if err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "deserialize: %s", err)
	}
	canonical := rawWire
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if vErr := envelope.ValidateAlgorithmID(algoID); vErr != nil {
		return nil, preflightFail(apitypes.ErrorClassSignatureInvalid, http.StatusUnauthorized, "%s", vErr)
	}
	if vErr := entry.Validate(); vErr != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "entry validation: %s", vErr)
	}
	if vErr := admission.CheckNFC(entry); vErr != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "NFC: %s", vErr)
	}
	if entry.Header.Destination != deps.LogDID {
		return nil, preflightFail(apitypes.ErrorClassDestinationMismatch, http.StatusForbidden, "entry destination %q does not match log %q", entry.Header.Destination, deps.LogDID)
	}
	if fErr := policy.CheckFreshness(entry, time.Now().UTC(), freshness); fErr != nil {
		return nil, preflightFail(apitypes.ErrorClassFreshnessExpired, http.StatusUnprocessableEntity, "freshness: %s", fErr)
	}
	if entry.Header.SignerDID == "" {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "empty signer DID")
	}
	// Signature verification via the SHARED gate (api/signature_gate.go) — the
	// same polymorphic multi-sig + network-signature-policy pipeline the
	// single-entry path runs. Errors are SDK-sentinel-wrapped; map them with
	// admission.MapSDKError (covering ErrSignatureInvalid / ErrSignerDIDResolution
	// / ErrUnsupportedSignatureAlgo / ErrSignatureAlgoNotAllowed /
	// ErrSignaturePolicyFailed) exactly as the Mode-B PoW gate below does.
	web3Receipts, vsErr := verifyEntrySignaturesGated(ctx, entry, sigBytes, deps)
	if vsErr != nil {
		if matched, status, class := admission.MapSDKError(vsErr); matched {
			return nil, preflightFail(class, status, "%s", vsErr)
		}
		return nil, preflightFail(apitypes.ErrorClassDBQueryFailed, http.StatusInternalServerError, "signature verification path failed")
	}
	if int64(len(canonical)) > deps.MaxEntrySize {
		return nil, preflightFail(apitypes.ErrorClassBodyTooLarge, http.StatusRequestEntityTooLarge, "canonical bytes %d exceed max %d", len(canonical), deps.MaxEntrySize)
	}
	if !middleware.CheckEvidenceCap(entry) {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "Evidence_Pointers %d exceeds cap %d (non-snapshot)", len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)
	}
	canonicalHash, err := envelope.EntryIdentity(entry)
	if err != nil {
		return nil, preflightFail(apitypes.ErrorClassEnvelopeRejected, http.StatusUnprocessableEntity, "EntryIdentity: %s", err)
	}
	// Post-II #3 refactor (issue #152): the inline VerifyStamp call
	// is now admission.VerifyAdmissionStamp via the DifficultyResolver
	// seam. Mirrors the equivalent refactor in submission.go step 7
	// so the two paths share one gate function.
	if !middleware.IsAuthenticated(ctx) {
		if !deps.Gates.ModeBPoW || deps.DifficultyResolver == nil {
			return nil, preflightFail(apitypes.ErrorClassAdmissionProofInvalid,
				http.StatusForbidden,
				"Mode-B PoW disabled on this network; submission must be authenticated")
		}
		currentEpoch := sdkadmission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds))
		acceptanceWindow := uint64(deps.Admission.EpochAcceptanceWindow)
		if err := admission.VerifyAdmissionStamp(
			ctx, deps.DifficultyResolver, entry, deps.LogDID,
			currentEpoch, acceptanceWindow,
		); err != nil {
			if matched, status, class := admission.MapSDKError(err); matched {
				return nil, preflightFail(class, status, "%s", err)
			}
			return nil, preflightFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError,
				"Mode-B PoW gate failed: %s", err)
		}
	}
	logTime := time.Now().UTC()
	return &preparedEntry{
		entry:         entry,
		canonical:     canonical,
		canonicalHash: canonicalHash,
		logTime:       logTime,
		web3Receipts:  web3Receipts,
	}, nil
}
