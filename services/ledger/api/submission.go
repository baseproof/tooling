/*
FILE PATH: api/submission.go

POST /v1/entries — the unified asynchronous SCT/MMD entry point.
Fail-fast: first failure terminates with appropriate HTTP status.

CONTRACT:

	On success, returns 202 Accepted with a SignedCertificateTimestamp.
	The SCT is the ledger's binding promise to sequence the entry
	into the log within Maximum Merge Delay (LEDGER_MMD). It is
	signed by the ledger's secp256k1 ECDSA identity key and is
	offline-verifiable against the ledger's published public key.

	The handler never blocks on Tessera or Postgres. Sequence-number
	assignment, entry_index INSERT, and commitment_split_id extraction
	all happen asynchronously in the background Sequencer.

	Consumers waiting for sequencing confirmation poll
	GET /v1/entries-hash/{canonical_hash} — the same endpoint used by
	monitors, audit jobs, and the SDK's HTTP entry fetcher.

FAST-PATH SHAPE (admission steps run inline):

 1. Read & validate preamble (prepareSubmission step 1)

 2. Deserialize wire bytes (step 2)

 3. NFC normalization check (step 3a)

 4. Destination binding (step 3b)

 5. Late-replay freshness (step 3c)

 6. Signature verification (step 4)

 7. Entry size + Evidence_Pointers cap (steps 5, 6)

 8. Mode A auth probe / Mode B PoW verify (step 7)

 9. Canonical hash + early duplicate probe (steps 8, 8a)

 10. Mode A credit deduction (its own pg tx; pre-WAL)

 11. WAL.Submit (durable)                     (step 10)

 12. Sign + return SCT (step 11)

    Mode A credit deduction stays synchronous in the fast path so a
    credit-exhausted caller receives 402 before the WAL is touched —
    an SCT is never issued without payment authorization.

INVARIANTS:

  - Past step 3a-NFC: all entries have NFC-normalized DID-shaped fields.
  - Past step 3b: all entries are bound to THIS log's LogDID.
  - Past step 4: all entries have verified signatures (SDK-D5).
  - Past step 11 (WAL.Submit): bytes are durably persisted; the
    Sequencer will assign a sequence number and write entry_index
  - commitment_split_id atomically in its own pg transaction.
  - Sequence numbers are gapless (Postgres sequence; assigned by
    sequencer/loop.go, not this handler).

COMMITMENT SCHEMA DISPATCH:

	The Sequencer is the sole owner of dispatchCommitmentSchema —
	commitment_split_id population happens in the same pg transaction
	as the entry_index INSERT. Admission does not parse domain
	payloads here, in keeping with the Domain/Protocol Separation
	Principle.
*/
package api

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/attestation"
	"github.com/baseproof/baseproof/authz"
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

// ─────────────────────────────────────────────────────────────────────────────
// 1) DID Resolution Interface (signature verification)
// ─────────────────────────────────────────────────────────────────────────────

// DIDResolver resolves a signer DID to its current secp256k1 public key.
// The SDK's did package provides the concrete implementation
// (did/resolver.go).
//
// nil = wire-format-integrity-only trust model (no DID resolution).
// set = full verification (DID → pubkey → sdk VerifyEntry).
//
// Structurally compatible with admission.DIDResolver — the ledger's
// admission package defines the same single-method interface, and Go
// auto-converts at the call site to admission.VerifyEntrySignature.
type DIDResolver interface {
	ResolvePublicKey(ctx context.Context, did string) (*ecdsa.PublicKey, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 2) WAL + Tessera interfaces (minimal admission-side surfaces)
// ─────────────────────────────────────────────────────────────────────────────

// WALCommitter is the WAL surface admission needs.
// *wal.Committer satisfies it.
type WALCommitter interface {
	// Submit blocks until wire bytes are durably persisted to local
	// disk. Returns wal.ErrQueueFull when the in-memory queue is
	// saturated; admission maps this to HTTP 503 + Retry-After.
	// logTimeMicros is the ledger-assigned admission time
	// persisted in Meta for the P5 deterministic-idempotency
	// path (re-issuing the same SCT bytes on byte-identical
	// resubmission). receipts is the per-signature
	// Web3VerificationReceipt slice captured by admission
	// (baseproof v1.7.0+); nil or empty is accepted and produces
	// a V1 Meta record byte-identical to legacy producers.
	Submit(ctx context.Context, hash [32]byte, wire []byte, logTimeMicros int64, receipts []types.Web3VerificationReceipt) error

	// Sequence transitions the WAL state pending → sequenced after
	// Tessera assigned a sequence number for the entry. Used by the
	// sequencer; v1 facade reads MetaState only.
	Sequence(ctx context.Context, hash [32]byte, seq uint64) error

	// MetaState returns the current WAL state record for an entry.
	// The v1 facade polls this to wait for the background Sequencer
	// to advance Pending → Sequenced.
	MetaState(ctx context.Context, hash [32]byte) (wal.Meta, error)
}

// TesseraAppender is the Tessera surface admission needs.
// *tessera.EmbeddedAppender satisfies it. AppendLeaf is dedup-aware
// when the appender is constructed with tessera.WithDeduplication
// (wired in cmd/ledger/main.go) — re-Add of an existing identity
// returns the previously-assigned sequence rather than integrating
// again. This is the load-bearing safety property under concurrent
// admission of the same content.
type TesseraAppender interface {
	AppendLeaf(ctx context.Context, data []byte) (uint64, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// 3) Submission Dependencies — grouped by cohesion
// ─────────────────────────────────────────────────────────────────────────────

// StorageDeps groups persistence dependencies for the submission
// handler. The byte-store writer that lived here in v1 is gone:
// admission writes wire bytes to the WAL only; the Shipper migrates
// them to the byte store asynchronously.
//
// — Pure CQRS: EntryStore is the api.EntryStore interface
// (defined in ports.go); the field used to be *store.EntryStore.
// The DB field is gone — credit deduction now uses the self-tx
// CreditDeducter interface and admission's only Postgres write
// (entry_index INSERT) lives entirely in the sequencer goroutine.
type StorageDeps struct {
	EntryStore EntryStore
	WAL        WALCommitter
	Tessera    TesseraAppender
}

// AdmissionConfig groups parameters that govern admission proof verification.
type AdmissionConfig struct {
	DiffController        *middleware.DifficultyController
	EpochWindowSeconds    int
	EpochAcceptanceWindow int
}

// IdentityDeps groups credential and DID resolution dependencies.
//
// — Pure CQRS: Credits is the api.CreditDeducter interface
// (defined in ports.go); the field used to be *store.CreditStore.
// The interface's tx-less Deduct(ctx, exchangeDID) signature lets
// the api package hold zero pgx imports.
//
// v1.37.0 SDK adoption — POLYMORPHIC ADMISSION
//
// Verifier is the SDK's *did.VerifierRegistry (or any
// attestation.SignatureVerifier). When set, the multi-sig admission
// path delegates ALL algorithm/DID-method dispatch to the SDK,
// supporting every algorithm the SDK knows about (ECDSA, Ed25519,
// EIP-191/712/1271, ML-DSA-65/87, SLH-DSA-128s) and every DID
// method registered with the resolver chain (did:key, did:web,
// did:pkh). The legacy `DIDResolver` field is kept for backward
// compatibility — it bridges to the secp256k1-ECDSA-only adapter
// used by tests and pre-v1.37.0 deployments. Production wires
// Verifier; tests may still wire DIDResolver alone.
//
// When BOTH are set, Verifier wins. The ECDSA-only constraint at
// admission/multisig_verifier.go:118 is bypassed when Verifier is
// set because the dispatch happens inside the SDK registry.
type IdentityDeps struct {
	Credits     CreditDeducter
	DIDResolver DIDResolver

	// Verifier is the polymorphic admission entry point. See struct
	// doc above. May be nil; if so the legacy DIDResolver path is
	// used (ECDSA-only via sigVerifierAdapter).
	Verifier attestation.SignatureVerifier
}

// SubmissionDeps is the dependency surface for the POST /v1/entries handler.
type SubmissionDeps struct {
	Storage   StorageDeps
	Admission AdmissionConfig
	Identity  IdentityDeps

	// AuthorizedWitnesses returns the witness PubKeyID set the network
	// trusts for PRE-12 witness-endpoint enrollment authorization
	// (witness.KeysFromDIDs over the constitution's GenesisWitnessSet,
	// unioned with the on-log rotation chain). Consulted at step 4h for
	// WitnessEndpointDeclarationV1 entries. nil ⇒ empty ⇒ fail-closed
	// (every declaration refused). Production wires it at boot.
	AuthorizedWitnesses func() map[[32]byte]struct{}

	LogDID       string
	LedgerDID    string
	MaxEntrySize int64
	Logger       *slog.Logger

	// LedgerSignerPriv signs SCTs returned by asynchronous
	// submission endpoints, including POST /v1/entries/batch.
	LedgerSignerPriv *ecdsa.PrivateKey

	// FreshnessTolerance configures the late-replay rejection window
	// at admission time. Zero defaults to policy.FreshnessInteractive.
	FreshnessTolerance time.Duration

	// BLSQuorumVerifier validates K-of-N witness cosignatures on
	// any tree head EMBEDDED inside an admitted entry's payload
	// (anchor entries authored by peer ledgers, witness-attestation
	// commentary, cross-log proof entries).
	//
	// Optional: nil disables the check entirely. Existing commitment-
	// entry surfaces don't embed tree heads, so the detector returns
	// false unconditionally and the verifier is dead code today;
	// wiring it now means the moment a schema starts embedding tree
	// heads the K-of-N check fires without an additional code change.
	// Wired by cmd/ledger/main.go iff a witness key set is loaded.
	BLSQuorumVerifier *admission.BLSQuorumVerifier

	// SchemaRegistry is the v0.4.0 DI schema admission registry
	// (baseproof SDK schema.Registry). The handler calls
	// admission.VerifyEntrySchema against it to reject malformed
	// commitment payloads at the front door, BEFORE the entry
	// consumes a Tessera sequence number.
	//
	// Optional: nil disables the schema gate entirely (the
	// downstream sequencer still validates via the parse path —
	// defense in depth). Production wiring (cmd/ledger/boot/wire)
	// constructs the registry via schemareg.BuildLedgerSchemaRegistry
	// and threads it here.
	SchemaRegistry admission.SchemaRegistry

	// Gates carries the four per-gate feature flags from
	// admission/feature_flags.go (issue #75 / #76 PR-A). Each
	// gate added in PR-C through PR-F consults its own boolean
	// here. The zero value (all false) is the legacy single-sig
	// admission path — production wires
	// admission.LoadGatesFromEnv() at boot.
	Gates admission.Gates

	// AdmissionAuthorities resolves the current on-log admission-authority
	// keyset for gate 5 (write-path authorization). Production wires
	// admission.OnLogAdmissionKeyset over the QueryAPI.
	AdmissionAuthorities admission.AdmissionKeyset

	// AdmissionPolicy resolves the current on-log admission policy
	// (whether gating is required + the cost regime). Gate 5 runs iff
	// the resolved policy is GatingRequired. nil ⇒ gate 5 is skipped
	// (test/degraded path); production ALWAYS wires it, defaulting to
	// SecureDefaultPolicy (gating required) so the ledger is
	// default-require.
	AdmissionPolicy admission.AdmissionPolicyResolver

	// EvidenceChainFetcher is the types.EntryFetcher wired into
	// the PR-F evidence-chain STRUCTURAL gate
	// (admission.VerifyEvidenceChainSurgical: cycles / broken hops /
	// bounded depth). nil disables the gate even when
	// Gates.EvidenceChain=true — the flag is the *intent*, this is
	// the *capability*. Production wires *store.PostgresEntryFetcher
	// here.
	EvidenceChainFetcher types.EntryFetcher

	// SignaturePolicyResolver supplies the network's current
	// signature policy (allow-listed algoIDs + per-group thresholds)
	// to the Part II.6 gate. Production wires
	// admission.GenesisSignaturePolicyResolver in v1.3 (static, from
	// BootstrapDocument.GenesisSignaturePolicy); a future amendment-
	// aware resolver swaps in here without changing the gate code.
	// nil disables the gate even when Gates.SignaturePolicy=true —
	// the flag is the intent, this is the capability.
	SignaturePolicyResolver admission.SignaturePolicyResolver

	// AlgorithmPolicyResolver supplies the network's current algorithm policy
	// (per-algoID active/deprecated/forbidden lifecycle) to the crypto-agility
	// gate (issue #201). Production wires admission.GenesisAlgorithmPolicyResolver
	// (synthesized from the genesis allow-list) or the amendment-aware
	// OnLogAlgorithmPolicyResolver. nil disables the gate even when
	// Gates.AlgorithmPolicy=true — the flag is the intent, this is the capability.
	AlgorithmPolicyResolver admission.AlgorithmPolicyResolver

	// ProtocolVersionResolver supplies the network's current protocol-version
	// admission policy (per-version write/read/forbidden state) to the
	// crypto-agility gate (issue #201). nil → the legacy "wire version ==
	// CurrentProtocolVersion()" rule stands regardless of Gates.ProtocolVersion.
	ProtocolVersionResolver admission.ProtocolVersionResolver

	// DifficultyResolver supplies the in-force Mode-B PoW
	// difficulty + hash function to the Mode-B gate
	// (admission.VerifyAdmissionStamp). Production wires
	// admission.StaticDifficultyResolver over the existing
	// middleware.DifficultyController; a future on-log resolver
	// swaps in here without changing the gate code. nil disables
	// the Mode-B PoW gate even when Gates.ModeBPoW=true — the
	// flag is the intent, this is the capability. When Mode-B is
	// disabled by either intent or capability, the handler
	// rejects every unauthenticated submission with
	// ErrModeBProofRequired (403) rather than silently admitting.
	//
	// Post-II #3 (issue #152).
	DifficultyResolver admission.DifficultyResolver
}

// ─────────────────────────────────────────────────────────────────────────────
// 4) Submission Handler
// ─────────────────────────────────────────────────────────────────────────────

// preparedSubmission is the result of running steps 1-9 of the
// admission fast path. The handler diverges at step 10+ to deduct
// credits, persist to the WAL, and sign the SCT.
type preparedSubmission struct {
	raw           []byte
	entry         *envelope.Entry
	canonicalHash [32]byte
	logTime       time.Time
	authenticated bool
	exchangeDID   string

	// idempotentReplay is true when the canonical hash already
	// has a Meta record in the WAL (byte-identical resubmission).
	// logTime is the persisted value — re-issuing the SCT with
	// it produces byte-identical SCT bytes. The handler skips
	// wal.Submit + credit deduction in this case (P5).
	idempotentReplay bool

	// web3Receipts is the per-signature Web3VerificationReceipt
	// slice returned by attestation.VerifyEntrySignatures (baseproof
	// v1.7.0+). Index-aligned with entry.Signatures. Zero receipts
	// populate slots for did:key / EOA signers; populated K-of-N
	// receipts populate slots for did:pkh EIP-1271 signers (when
	// the verifier registry is wired with PKH executors). Nil on
	// the legacy single-sig path (deps.Gates.MultiSig=false) and
	// on the idempotent-replay short-circuit (the persisted
	// receipts from the original submission stand).
	//
	// PR-N3 will widen wal.Submit to accept this slice and persist
	// it alongside LogTimeMicros so the sequencer can rehydrate it
	// into types.EntryWithMetadata.Web3Receipts for the builder's
	// ReceiptRoot computation (PR-N5).
	web3Receipts []types.Web3VerificationReceipt
}

// submissionError carries the HTTP status + message a fast-path
// validation failure should surface to the caller. The handler
// (v1 or v2) is responsible for writing the response — keeping
// the helper free of *http.ResponseWriter so it can be unit-tested
// without httptest plumbing.
type submissionError struct {
	Status  int
	Message string
	Class   apitypes.ErrorClass
}

// submissionFail constructs a typed *submissionError. Every
// admission-side error carries an apitypes.ErrorClass so the
// HTTP handler increments the right OTel counter dimension.
func submissionFail(class apitypes.ErrorClass, status int, format string, args ...any) *submissionError {
	return &submissionError{
		Status:  status,
		Message: fmt.Sprintf(format, args...),
		Class:   class,
	}
}

// receiptClientBounds returns (min, max, populated) of
// len(receipt.ExecutorQuorum.Clients) across the receipts slice,
// filtering out zero receipts (EOA / did:key signers carry no
// on-chain attestations and would skew the min toward 0).
// populated is true when AT LEAST ONE non-zero receipt is present;
// when false, every signer was non-EIP-1271 and the receipt
// shape is uninteresting for observability.
//
// Used by the admission log line to surface the executor-quorum
// shape (per v1.7.1: K ≤ len(Clients) ≤ N is the steady-state
// shape under short-circuit-at-K; a count of 0 across the batch
// means atomic-batch-consensus failed per v1.7.1 multicall3
// semantics).
func receiptClientBounds(receipts []types.Web3VerificationReceipt) (minClients, maxClients int, populated bool) {
	for i := range receipts {
		if receipts[i].IsZero() {
			continue
		}
		n := len(receipts[i].ExecutorQuorum.Clients)
		if !populated || n < minClients {
			minClients = n
		}
		if n > maxClients {
			maxClients = n
		}
		populated = true
	}
	return minClients, maxClients, populated
}

// prepareSubmission runs admission steps 1-9: read body, validate
// preamble, deserialize, NFC, destination binding, freshness,
// signature, size, evidence cap, mode dispatch, canonical hash,
// early-dup check, log_time. Returns either a fully-populated
// preparedSubmission ready for wal.Submit, or a submissionError
// to be written to the client.
//
// Body size handling (Tier-2 BUG #3 alignment): the request is
// expected to arrive through the SizeLimit middleware (server.go),
// which wraps r.Body with http.MaxBytesReader at MaxEntrySize+1024.
// As defense-in-depth — and so direct callers (handler tests that
// bypass the middleware chain) get the same behavior — we wrap a
// second MaxBytesReader at the slightly tighter handler-local cap
// MaxEntrySize+sigOverhead. Either trigger surfaces as
// *http.MaxBytesError on Read, which we map to 413 instead of the
// legacy 400 "failed to read request body" + silent truncation.
func prepareSubmission(
	ctx context.Context,
	deps *SubmissionDeps,
	w http.ResponseWriter,
	r *http.Request,
	freshness time.Duration,
) (*preparedSubmission, *submissionError) {
	// ── Step 1: Read raw bytes + validate preamble ─────────────────
	sigOverhead := int64(512)
	r.Body = http.MaxBytesReader(w, r.Body, deps.MaxEntrySize+sigOverhead)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, submissionFail(apitypes.ErrorClassBodyTooLarge,
				http.StatusRequestEntityTooLarge,
				"entry exceeds %d bytes", maxErr.Limit)
		}
		return nil, submissionFail(apitypes.ErrorClassMalformedBody,
			http.StatusBadRequest, "failed to read request body")
	}
	if len(raw) < 6 {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "entry too short for preamble")
	}
	protocolVersion := binary.BigEndian.Uint16(raw[0:2])
	// Protocol-version admission via the shared gate (api/signature_gate.go):
	// the on-log policy when wired (Gates.ProtocolVersion), else the legacy
	// "current version only" rule. Same helper the batch path uses.
	if pvErr := admitProtocolVersion(ctx, protocolVersion, deps); pvErr != nil {
		if matched, status, class := admission.MapSDKError(pvErr); matched {
			return nil, submissionFail(class, status, "%s", pvErr)
		}
		return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
			http.StatusInternalServerError, "protocol-version gate failed: %s", pvErr)
	}

	// ── Step 2: Deserialize wire bytes, validate algo ID ───────────
	entry, err := envelope.Deserialize(raw)
	if err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "deserialize: %s", err)
	}
	algoID := entry.Signatures[0].AlgoID
	sigBytes := entry.Signatures[0].Bytes
	if err := envelope.ValidateAlgorithmID(algoID); err != nil {
		return nil, submissionFail(apitypes.ErrorClassSignatureInvalid,
			http.StatusUnauthorized, "%s", err)
	}

	// ── Step 3a: Re-apply NewEntry's write-time invariants ─────────
	if err := entry.Validate(); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "entry validation: %s", err)
	}
	// ── Step 3a-NFC ────────────────────────────────────────────────
	if err := admission.CheckNFC(entry); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "NFC: %s", err)
	}
	// ── Step 3b: Destination binding ───────────────────────────────
	if entry.Header.Destination != deps.LogDID {
		return nil, submissionFail(apitypes.ErrorClassDestinationMismatch,
			http.StatusForbidden,
			"entry destination %q does not match log %q",
			entry.Header.Destination, deps.LogDID)
	}
	// ── Step 3c: Late-replay freshness ─────────────────────────────
	if err := policy.CheckFreshness(entry, time.Now().UTC(), freshness); err != nil {
		return nil, submissionFail(apitypes.ErrorClassFreshnessExpired,
			http.StatusUnprocessableEntity, "freshness: %s", err)
	}

	// ── Step 4: Signature verification ─────────────────────────────
	if entry.Header.SignerDID == "" {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "empty signer DID")
	}
	var (
		sigErr       error
		web3Receipts []types.Web3VerificationReceipt
	)
	// Step 4 verification is shared with the batch path via
	// verifyEntrySignaturesGated (api/signature_gate.go) so the single-entry and
	// batch submission paths apply IDENTICAL signature semantics (polymorphic
	// multi-sig + network signature policy, or the legacy single-sig fallback)
	// and cannot drift apart.
	web3Receipts, sigErr = verifyEntrySignaturesGated(ctx, entry, sigBytes, deps)
	if sigErr != nil {
		if minC, maxC, populated := receiptClientBounds(web3Receipts); populated {
			deps.Logger.Error("signature verification path failed",
				"error", sigErr,
				"receipts", len(web3Receipts),
				"min_clients", minC, "max_clients", maxC)
		} else {
			deps.Logger.Error("signature verification path failed", "error", sigErr)
		}
		if matched, status, class := admission.MapSDKError(sigErr); matched {
			return nil, submissionFail(class, status, "%s", sigErr)
		}
		return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
			http.StatusInternalServerError, "signature verification failed")
	}
	if minC, maxC, populated := receiptClientBounds(web3Receipts); populated {
		deps.Logger.Info("admission receipts collected",
			"signer", entry.Header.SignerDID,
			"signatures", len(entry.Signatures),
			"receipts", len(web3Receipts),
			"min_clients", minC, "max_clients", maxC)
	}

	// ── Step 4a: CosignatureOf binding (PR-D gate 2) ──────────────
	if deps.Gates.CosigBinding {
		if err := admission.VerifyCosignatureBinding(ctx, entry, deps.LogDID, deps.Storage.EntryStore); err != nil {
			if matched, status, class := admission.MapSDKError(err); matched {
				return nil, submissionFail(class, status, "%s", err)
			}
			deps.Logger.Error("cosignature binding verification failed", "error", err)
			return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "cosignature binding verification failed")
		}
	}

	// ── Step 4b: Embedded tree head K-of-N verification ───────────
	if deps.BLSQuorumVerifier != nil {
		if err := deps.BLSQuorumVerifier.VerifyEntry(entry); err != nil {
			switch {
			case errors.Is(err, admission.ErrWitnessQuorumInsufficient),
				errors.Is(err, admission.ErrWitnessKeySetUnavailable):
				return nil, submissionFail(apitypes.ErrorClassSignatureInvalid,
					http.StatusUnauthorized, "%s", err)
			default:
				deps.Logger.Error("embedded tree head verification failed", "error", err)
				return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
					http.StatusInternalServerError, "tree head verification failed")
			}
		}
	}

	// ── Step 4e: Surgical evidence-chain walk (PR-F gate 4) ───────
	if deps.Gates.EvidenceChain && deps.EvidenceChainFetcher != nil {
		if _, err := admission.VerifyEvidenceChainSurgical(ctx, entry, deps.LogDID, deps.EvidenceChainFetcher); err != nil {
			if matched, status, class := admission.MapSDKError(err); matched {
				return nil, submissionFail(class, status, "%s", err)
			}
			deps.Logger.Error("evidence chain verification failed", "error", err)
			return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "evidence chain verification failed")
		}
	}

	// ── Step 4c: Schema validation (v0.4.0 DI registry) ────────────
	if err := admission.VerifyEntrySchema(ctx, entry, deps.SchemaRegistry); err != nil {
		if errors.Is(err, admission.ErrSchemaInvalid) {
			return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
				http.StatusUnprocessableEntity, "%s", err)
		}
		deps.Logger.Error("schema verification path failed", "error", err)
		return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
			http.StatusInternalServerError, "schema verification failed")
	}

	// ── Step 4f: On-log entry-signer rotation validation ──────────
	// Rotation entries (DomainPayload kind=BP-ENTRY-SIGNER-ROTATION-PAYLOAD-V1,
	// baseproof v1.13.0) are sequenced as first-class entries, but the
	// ledger refuses to sequence a MALFORMED one — the sequenced entry
	// is the position-authoritative rotation record, so a garbage
	// payload would poison the consumer's key-at-position walk.
	// Structure-only (verifier.RotationPayload); authority is verified
	// positionally at the consumer (JN), not here. Non-rotation
	// payloads pass through untouched.
	if err := admission.VerifyRotationEntry(entry); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "%s", err)
	}

	// ── Step 4g: v1.32.0 network-payload structural validation ────
	// Same rationale as 4f, applied to the three new on-log network
	// entry kinds the SDK v1.32.0 ships:
	//   - WitnessEndpointDeclarationV1
	//   - WitnessIdentityLabelV1
	//   - AuditorRegistrationV1
	// Each ships a Validate() method (URL scheme, public-key length,
	// scope ≠ 0, PoP-required-for-BLS, etc.). Refusing to sequence a
	// MALFORMED declaration converts a 422 at the front door into a
	// guarantee that downstream walkers (the SDK's ResolveXxxAt) never
	// see a poisoned record. Non-network payloads pass through.
	if err := admission.VerifyNetworkPayloadEntry(entry); err != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity, "%s", err)
	}

	// ── Step 4h: network-payload AUTHORIZATION (PRE-12 enrollment) ─
	// A WitnessEndpointDeclarationV1 that passed the structural gate must
	// ALSO be self-attested by an AUTHORIZED witness (VERIFY+AUTHORIZE+BIND)
	// — else the on-log dial-list is attacker-hijackable. Default-ON: a nil
	// verifier or an empty authorized set fails closed (every declaration
	// refused). Non-gated kinds pass through untouched.
	{
		var authorized map[[32]byte]struct{}
		if deps.AuthorizedWitnesses != nil {
			authorized = deps.AuthorizedWitnesses()
		}
		if err := admission.AuthorizeNetworkPayloadEntry(ctx, entry, deps.Identity.Verifier, authorized); err != nil {
			return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
				http.StatusForbidden, "%s", err)
		}
	}

	// ── Step 5: Entry size ─────────────────────────────────────────
	if int64(len(raw)) > deps.MaxEntrySize {
		return nil, submissionFail(apitypes.ErrorClassBodyTooLarge,
			http.StatusRequestEntityTooLarge,
			"canonical bytes %d exceed max %d", len(raw), deps.MaxEntrySize)
	}

	// ── Step 6: Evidence_Pointers cap ──────────────────────────────
	if !middleware.CheckEvidenceCap(entry) {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity,
			"Evidence_Pointers %d exceeds cap %d (non-snapshot)",
			len(entry.Header.EvidencePointers), middleware.MaxEvidencePointers)
	}

	// ── Step 7: Admission mode (Mode B stamp verify; auth probe) ───
	authenticated := middleware.IsAuthenticated(ctx)
	exchangeDID := middleware.ExchangeDID(ctx)
	if !authenticated {
		if !deps.Gates.ModeBPoW || deps.DifficultyResolver == nil {
			return nil, submissionFail(apitypes.ErrorClassAdmissionProofInvalid,
				http.StatusForbidden,
				"Mode-B PoW disabled on this network; submission must be authenticated")
		}
		if err := admission.VerifyAdmissionStamp(
			ctx,
			deps.DifficultyResolver,
			entry,
			deps.LogDID,
			sdkadmission.CurrentEpoch(uint64(deps.Admission.EpochWindowSeconds)),
			uint64(deps.Admission.EpochAcceptanceWindow),
		); err != nil {
			if matched, status, class := admission.MapSDKError(err); matched {
				return nil, submissionFail(class, status, "%s", err)
			}
			return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError,
				"Mode-B PoW gate failed: %s", err)
		}
	}

	// ── Step 8: Canonical hash ─────────────────────────────────────
	canonicalHash, hashErr := envelope.EntryIdentity(entry)
	if hashErr != nil {
		return nil, submissionFail(apitypes.ErrorClassEnvelopeRejected,
			http.StatusUnprocessableEntity,
			"EntryIdentity: %s", hashErr)
	}

	// ── Step 8a: Deterministic-idempotency probe ──────────────────
	if deps.Storage.WAL != nil {
		if meta, err := deps.Storage.WAL.MetaState(ctx, canonicalHash); err == nil &&
			meta.State != wal.StateUnknown && meta.LogTimeMicros > 0 {
			return &preparedSubmission{
				raw:              raw,
				entry:            entry,
				canonicalHash:    canonicalHash,
				logTime:          time.UnixMicro(meta.LogTimeMicros).UTC(),
				idempotentReplay: true,
				authenticated:    authenticated,
				exchangeDID:      exchangeDID,
			}, nil
		}
	}

	// ── Step 8b: Write-path GATING (gate 5) ────────────────────────
	if deps.AdmissionPolicy != nil {
		pol, polErr := deps.AdmissionPolicy.Current(ctx)
		if polErr != nil {
			return nil, submissionFail(apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "admission policy resolution failed")
		}
		if pol.GatingRequired {
			if err := admission.VerifyWriteAuthorization(
				ctx, r.Header.Get(admission.WriteAuthHeader),
				canonicalHash, deps.LogDID, deps.AdmissionAuthorities,
			); err != nil {
				return nil, mapWriteAuthError(err)
			}
		}
	}

	// ── Step 9: Log_Time assignment ────────────────────────────────
	logTime := time.Now().UTC()

	return &preparedSubmission{
		raw:           raw,
		entry:         entry,
		canonicalHash: canonicalHash,
		logTime:       logTime,
		authenticated: authenticated,
		exchangeDID:   exchangeDID,
		web3Receipts:  web3Receipts,
	}, nil
}

// mapWriteAuthError maps gate-5 failures to a typed submission error.
func mapWriteAuthError(err error) *submissionError {
	switch {
	case errors.Is(err, admission.ErrWriteAuthMissing),
		errors.Is(err, admission.ErrWriteAuthMalformed),
		errors.Is(err, authz.ErrUnauthorizedWriter),
		errors.Is(err, authz.ErrEmptyAuthoritySet):
		return submissionFail(apitypes.ErrorClassWriteAuthRejected,
			http.StatusForbidden, "write authorization: %s", err)
	default:
		return submissionFail(apitypes.ErrorClassDBQueryFailed,
			http.StatusInternalServerError, "write authorization check failed")
	}
}

// deductCreditModeA subtracts `cost` credits from the authenticated
// exchange DID. Called BEFORE wal.Submit so a credit-exhausted caller
// never gets an SCT or a slot in the WAL.
func deductCreditModeA(
	ctx context.Context,
	deps *SubmissionDeps,
	authenticated bool,
	exchangeDID string,
	cost int64,
) error {
	if !authenticated {
		return nil
	}
	if deps.Identity.Credits == nil {
		return nil
	}
	return deps.Identity.Credits.Deduct(ctx, exchangeDID, cost)
}

// NewSubmissionHandler creates the POST /v1/entries handler.
func NewSubmissionHandler(deps *SubmissionDeps) http.HandlerFunc {
	if deps == nil {
		panic("api: SubmissionDeps must be non-nil")
	}
	if deps.Admission.EpochWindowSeconds <= 0 {
		panic("api: SubmissionDeps.Admission.EpochWindowSeconds must be positive")
	}
	if deps.LogDID == "" {
		panic("api: SubmissionDeps.LogDID must be non-empty (destination-binding enforcement)")
	}
	if deps.LedgerDID == "" {
		panic("api: SubmissionDeps.LedgerDID must be non-empty — SCT signer identity")
	}
	if deps.LedgerSignerPriv == nil {
		panic("api: SubmissionDeps.LedgerSignerPriv must be non-nil — SCT signing")
	}

	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	return func(w http.ResponseWriter, r *http.Request) {
		sct, _, ok := admitEntry(r.Context(), deps, w, r, freshness)
		if !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(sct)
	}
}

// admitEntry runs the admission + durability + SCT pipeline shared by the generic
// entry endpoint (NewSubmissionHandler) and the artifact-reserve endpoint
// (NewArtifactReserveHandler): prepareSubmission (gates 1-9), idempotent-replay
// short-circuit, credit deduction, WAL.Submit, and SCT signing. On ANY failure it
// writes the typed error response and returns ok=false; on success it returns the
// signed SCT + the prepared submission WITHOUT writing the success body, so the
// caller owns the response shape. Keeping this domain-agnostic is exactly what
// lets /v1/entries stay free of any payload parsing — the artifact endpoint, not
// this core, is the home for understanding artifact-genesis.
func admitEntry(
	ctx context.Context,
	deps *SubmissionDeps,
	w http.ResponseWriter,
	r *http.Request,
	freshness time.Duration,
) (*sdksct.SignedCertificateTimestamp, *preparedSubmission, bool) {
	prep, errResp := prepareSubmission(ctx, deps, w, r, freshness)
	if errResp != nil {
		writeTypedError(ctx, w, errResp.Class, errResp.Status, errResp.Message)
		return nil, nil, false
	}

	if prep.idempotentReplay {
		sct, err := SignSCT(deps.LedgerSignerPriv, deps.LedgerDID, deps.LogDID, prep.canonicalHash, prep.logTime)
		if err != nil {
			deps.Logger.Error("SignSCT (idempotent replay)", "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassSCTSigningFailed,
				http.StatusInternalServerError, "SCT signing failed")
			return nil, nil, false
		}
		return sct, prep, true
	}

	if err := deductCreditModeA(ctx, deps, prep.authenticated, prep.exchangeDID, 1); err != nil {
		if errors.Is(err, apitypes.ErrInsufficientCredits) {
			writeTypedError(ctx, w, apitypes.ErrorClassInsufficientCredits,
				http.StatusPaymentRequired, "insufficient write credits")
			return nil, nil, false
		}
		deps.Logger.Error("credit deduction", "error", err)
		writeTypedError(ctx, w, apitypes.ErrorClassCreditDeductFailed,
			http.StatusInternalServerError, "credit deduction failed")
		return nil, nil, false
	}

	if err := deps.Storage.WAL.Submit(ctx, prep.canonicalHash, prep.raw, prep.logTime.UnixMicro(), prep.web3Receipts); err != nil {
		if errors.Is(err, wal.ErrQueueFull) {
			w.Header().Set("Retry-After", "5")
			writeTypedError(ctx, w, apitypes.ErrorClassWALBackpressure,
				http.StatusServiceUnavailable,
				"backpressure: WAL queue full, retry shortly")
			return nil, nil, false
		}
		deps.Logger.Error("wal submit", "error", err)
		writeTypedError(ctx, w, apitypes.ErrorClassWALPersistFailed,
			http.StatusInternalServerError, "WAL persist failed")
		return nil, nil, false
	}

	sct, err := SignSCT(deps.LedgerSignerPriv, deps.LedgerDID, deps.LogDID, prep.canonicalHash, prep.logTime)
	if err != nil {
		deps.Logger.Error("SignSCT", "error", err)
		writeTypedError(ctx, w, apitypes.ErrorClassSCTSigningFailed,
			http.StatusInternalServerError, "SCT signing failed")
		return nil, nil, false
	}
	return sct, prep, true
}

// ─────────────────────────────────────────────────────────────────────────────
// 5) Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
