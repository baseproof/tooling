/*
FILE PATH: admission/pow_gate_test.go

Tests for the Post-Part-II #3 Mode-B PoW admission gate
(admission/pow_gate.go).

Coverage:
  - VerifyAdmissionStamp:
  - nil resolver → inert no-op (caller-opt-out).
  - nil entry → programmer-error.
  - nil AdmissionProof → ErrModeBProofRequired.
  - Resolver error → ErrModeBResolverFailed (wraps underlying).
  - VerifyStamp success → nil.
  - VerifyStamp failure → ErrModeBStampInvalid (errors.Join'd
    with the SDK sentinel so callers can errors.Is on either).
  - The SDK sentinel for "hash below target" specifically is
    reachable via errors.Is on the joined error (defense for
    the error-mapping discipline).
  - StaticDifficultyResolver:
  - nil source rejected at construction.
  - Current passes through CurrentDifficulty()/HashFunction()
    verbatim with SHA-256 default for unrecognised strings.
  - Error-mapping integration:
  - ErrModeBProofRequired routes to HTTP 403 +
    ErrorClassAdmissionProofInvalid.
  - ErrModeBStampInvalid same.
  - ErrModeBResolverFailed NOT in table (must route via 500
    default, mirrors II.6's resolver-failure posture).

In-memory fixtures only — no DB, no I/O. Mode-B PoW stamps are
generated via the SDK's GenerateStamp so the cryptographic
verification path is exercised against real bytes (no mocking
of VerifyStamp itself).
*/
package admission_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

// fakeDifficultySource implements admission's unexported
// difficultySource via the same shape *middleware.DifficultyController
// exposes. Used for the StaticDifficultyResolver tests.
type fakeDifficultySource struct {
	difficulty   uint32
	hashFuncName string
}

func (f *fakeDifficultySource) CurrentDifficulty() uint32 { return f.difficulty }
func (f *fakeDifficultySource) HashFunction() string      { return f.hashFuncName }

// stubResolver implements admission.DifficultyResolver with
// stored difficulty / hashFunc / err for direct gate tests
// without an intermediate StaticDifficultyResolver.
type stubResolver struct {
	difficulty uint32
	hashFunc   sdkadmission.HashFunc
	err        error
}

func (s *stubResolver) Current(_ context.Context) (uint32, sdkadmission.HashFunc, error) {
	return s.difficulty, s.hashFunc, s.err
}

// powEntry builds an envelope.Entry with a Mode-B AdmissionProof
// whose stamp satisfies the difficulty. AdmissionProof.Nonce is
// part of the entry's canonical bytes, so EntryIdentity(entry)
// changes as the nonce changes — the stamp's EntryHash input
// therefore co-depends on the nonce we pick. The only correct
// fixture is to brute-force the nonce space: for each candidate
// nonce, serialize the entry, compute EntryIdentity, call
// VerifyStamp; accept the first nonce that passes.
//
// This is the same pattern the existing
// api/submission_helpers_test.go:signedEntryModeBWithKey uses.
// At difficulty=1 the expected iteration count is ~2 (50% of
// hashes satisfy a 1-bit target), so the cost is negligible.
func powEntry(
	t *testing.T,
	logDID string,
	difficulty uint32,
	hashFunc sdkadmission.HashFunc,
	epochWindowSeconds uint64,
) *envelope.Entry {
	t.Helper()
	epoch := sdkadmission.CurrentEpoch(epochWindowSeconds)

	hdr := envelope.ControlHeader{
		SignerDID:   "did:web:test-signer",
		Destination: logDID,
		EventTime:   1700000000,
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:       0x01, // AdmissionModeB
			Difficulty: uint8(difficulty),
			HashFunc:   uint8(hashFunc),
			Epoch:      epoch,
		},
	}

	const maxIter uint64 = 1 << 20
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		hdr.AdmissionProof.Nonce = nonce
		entry, err := envelope.NewUnsignedEntry(hdr, []byte("test-payload"))
		if err != nil {
			t.Fatalf("NewUnsignedEntry: %v", err)
		}
		entry.Signatures = []envelope.Signature{{
			SignerDID: hdr.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     []byte("test-sig-bytes"),
		}}
		canonicalHash, err := envelope.EntryIdentity(entry)
		if err != nil {
			t.Fatalf("EntryIdentity: %v", err)
		}
		apiProof := sdkadmission.ProofFromWire(entry.Header.AdmissionProof, logDID)
		if verr := sdkadmission.VerifyStamp(
			apiProof,
			canonicalHash,
			logDID,
			difficulty,
			hashFunc,
			nil,
			epoch,
			1,
		); verr == nil {
			return entry
		}
	}
	t.Fatalf("powEntry: no valid nonce in %d iterations at difficulty=%d", maxIter, difficulty)
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp — opt-out and structural guards
// ─────────────────────────────────────────────────────────────────────

func TestVerifyAdmissionStamp_NilResolverIsInert(t *testing.T) {
	// nil resolver = caller opted out (e.g., Gates.ModeBPoW=false).
	// Returns nil regardless of entry shape — the absence of a
	// resolver is "no gate enforcement", not "default-deny".
	err := admission.VerifyAdmissionStamp(
		context.Background(), nil, nil, "did:test:log", 0, 0,
	)
	if err != nil {
		t.Errorf("nil resolver should return nil; got %v", err)
	}
}

func TestVerifyAdmissionStamp_NilEntryIsProgrammerError(t *testing.T) {
	r := &stubResolver{difficulty: 1, hashFunc: sdkadmission.HashSHA256}
	err := admission.VerifyAdmissionStamp(
		context.Background(), r, nil, "did:test:log", 0, 0,
	)
	if err == nil {
		t.Fatal("nil entry must surface as programmer error")
	}
	// Specifically NOT one of the typed sentinels — programmer error.
	if errors.Is(err, admission.ErrModeBProofRequired) ||
		errors.Is(err, admission.ErrModeBStampInvalid) ||
		errors.Is(err, admission.ErrModeBResolverFailed) {
		t.Errorf("nil entry should NOT route to a typed gate sentinel; got %v", err)
	}
}

func TestVerifyAdmissionStamp_MissingProofReturnsErrModeBProofRequired(t *testing.T) {
	r := &stubResolver{difficulty: 1, hashFunc: sdkadmission.HashSHA256}
	entry, _ := envelope.NewUnsignedEntry(
		envelope.ControlHeader{
			SignerDID:   "did:web:test-signer",
			Destination: "did:test:log",
		},
		[]byte("payload"),
	)
	// entry.Header.AdmissionProof intentionally nil — unauthenticated
	// caller forgot the stamp.
	err := admission.VerifyAdmissionStamp(
		context.Background(), r, entry, "did:test:log", 0, 0,
	)
	if !errors.Is(err, admission.ErrModeBProofRequired) {
		t.Fatalf("got %v; want wraps ErrModeBProofRequired", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp — resolver error
// ─────────────────────────────────────────────────────────────────────

func TestVerifyAdmissionStamp_ResolverErrorRoutesViaResolverFailedSentinel(t *testing.T) {
	boom := errors.New("difficulty store down")
	r := &stubResolver{err: boom}
	// Entry has a proof — but the resolver fails first.
	entry := powEntry(t, "did:test:log", 1, sdkadmission.HashSHA256, 3600)
	err := admission.VerifyAdmissionStamp(
		context.Background(), r, entry, "did:test:log", 0, 0,
	)
	if !errors.Is(err, admission.ErrModeBResolverFailed) {
		t.Fatalf("got %v; want wraps ErrModeBResolverFailed", err)
	}
	// MUST NOT route as a policy reject — those are 403; resolver
	// failures are 500. The error-mapping discipline depends on
	// these staying distinct (mirrors II.6's
	// ErrSignaturePolicyResolverFailed posture).
	if errors.Is(err, admission.ErrModeBStampInvalid) {
		t.Errorf("resolver failure must NOT also satisfy ErrModeBStampInvalid; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp — happy path
// ─────────────────────────────────────────────────────────────────────

func TestVerifyAdmissionStamp_HappyPath_SHA256(t *testing.T) {
	const logDID = "did:test:log"
	const epochWindowSeconds = uint64(3600)
	r := &stubResolver{difficulty: 1, hashFunc: sdkadmission.HashSHA256}
	entry := powEntry(t, logDID, 1, sdkadmission.HashSHA256, epochWindowSeconds)

	err := admission.VerifyAdmissionStamp(
		context.Background(),
		r, entry, logDID,
		sdkadmission.CurrentEpoch(epochWindowSeconds),
		1, // ±1 epoch acceptance
	)
	if err != nil {
		t.Errorf("happy path must succeed; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAdmissionStamp — stamp failure modes
// ─────────────────────────────────────────────────────────────────────

func TestVerifyAdmissionStamp_DifficultyBelowMinReturnsErrModeBStampInvalid(t *testing.T) {
	const logDID = "did:test:log"
	const epochWindowSeconds = uint64(3600)
	// Resolver demands difficulty 8; proof was generated at
	// difficulty 1 — SDK rejects with ErrStampDifficultyBelowMin.
	r := &stubResolver{difficulty: 8, hashFunc: sdkadmission.HashSHA256}
	entry := powEntry(t, logDID, 1, sdkadmission.HashSHA256, epochWindowSeconds)

	err := admission.VerifyAdmissionStamp(
		context.Background(),
		r, entry, logDID,
		sdkadmission.CurrentEpoch(epochWindowSeconds),
		1,
	)
	if !errors.Is(err, admission.ErrModeBStampInvalid) {
		t.Fatalf("got %v; want wraps ErrModeBStampInvalid", err)
	}
	// The SDK sentinel must also be reachable via errors.Is —
	// the gate joins them so callers (e.g., diagnostic dashboards)
	// can route on the specific failure class.
	if !errors.Is(err, sdkadmission.ErrStampDifficultyBelowMin) {
		t.Errorf("expected unwrap to reach ErrStampDifficultyBelowMin; got %v", err)
	}
}

// Note on TargetLog: AdmissionProofBody on the wire does NOT
// carry TargetLog; sdkadmission.ProofFromWire stamps the caller's
// logDID into proof.TargetLog at verify time. ErrStampTargetLogMismatch
// can therefore only fire when the gate is wired with the wrong
// LogDID (a composition-root bug), not via an adversarial wire input.
// The bytes-don't-match-this-log case surfaces as
// ErrStampHashBelowTarget instead — covered by
// TestVerifyAdmissionStamp_StampForDifferentLogFailsHashCheck below.

func TestVerifyAdmissionStamp_StampForDifferentLogFailsHashCheck(t *testing.T) {
	const epochWindowSeconds = uint64(3600)
	// Difficulty=16 (not 1): the test asserts that a stamp for log-A
	// fails verification against log-B because the recomputed hash
	// over log-B's bytes no longer satisfies the leading-zero
	// target. With difficulty=1 the test is flaky-by-design — ~50%
	// of random SHA-256 outputs have ≥1 leading zero bit, so the
	// recomputed hash often coincidentally meets the target and
	// verification returns nil (correct verification behaviour;
	// fragile test expectation).
	//
	// With difficulty=16 the probability that a recomputed hash
	// coincidentally satisfies the target drops to ~1/65,536 —
	// robust against SDK canonical-layout changes that shift which
	// specific nonce produces which specific hash. (The baseproof
	// v1.31.0 → v1.32.0 bump changed buildHashInputBuffer's wire
	// layout, which surfaced the difficulty=1 weakness as a
	// deterministic test failure.)
	r := &stubResolver{difficulty: 16, hashFunc: sdkadmission.HashSHA256}
	// Stamp generated for log A; gate called with log B's DID.
	// ProofFromWire stamps TargetLog=log-B so the TargetLog check
	// passes, but the recomputed hash uses log-B's bytes — the
	// proof's nonce no longer satisfies the leading-zero target.
	entry := powEntry(t, "did:test:log-A", 16, sdkadmission.HashSHA256, epochWindowSeconds)

	err := admission.VerifyAdmissionStamp(
		context.Background(),
		r, entry, "did:test:log-B",
		sdkadmission.CurrentEpoch(epochWindowSeconds),
		1,
	)
	if !errors.Is(err, admission.ErrModeBStampInvalid) {
		t.Fatalf("got %v; want wraps ErrModeBStampInvalid", err)
	}
	if !errors.Is(err, sdkadmission.ErrStampHashBelowTarget) {
		t.Errorf("expected unwrap to reach ErrStampHashBelowTarget; got %v", err)
	}
}

func TestVerifyAdmissionStamp_TamperedNonceReturnsErrModeBStampInvalid(t *testing.T) {
	const logDID = "did:test:log"
	const epochWindowSeconds = uint64(3600)
	// Difficulty=16 (not 1): same flaky-by-design issue as
	// StampForDifferentLogFailsHashCheck above — at difficulty=1,
	// ~50% of tampered nonces coincidentally produce hashes that
	// still satisfy the 1-leading-zero target. Difficulty=16 makes
	// the test robust (~1/65,536 false-pass probability).
	r := &stubResolver{difficulty: 16, hashFunc: sdkadmission.HashSHA256}
	entry := powEntry(t, logDID, 16, sdkadmission.HashSHA256, epochWindowSeconds)
	// Tamper the nonce — verify will recompute the hash from
	// the modified nonce and reject with ErrStampHashBelowTarget
	// (the new hash overwhelmingly doesn't meet the 16-leading-
	// zero-bit target). The Hash field is wire-only; tampering
	// it would have NO effect because VerifyStamp doesn't read it.
	entry.Header.AdmissionProof.Nonce++

	err := admission.VerifyAdmissionStamp(
		context.Background(),
		r, entry, logDID,
		sdkadmission.CurrentEpoch(epochWindowSeconds),
		1,
	)
	if !errors.Is(err, admission.ErrModeBStampInvalid) {
		t.Fatalf("got %v; want wraps ErrModeBStampInvalid", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// StaticDifficultyResolver
// ─────────────────────────────────────────────────────────────────────

func TestNewStaticDifficultyResolver_RejectsNilSource(t *testing.T) {
	_, err := admission.NewStaticDifficultyResolver(nil)
	if err == nil {
		t.Fatal("nil source must be rejected at construction")
	}
}

func TestStaticDifficultyResolver_PassthroughSHA256(t *testing.T) {
	src := &fakeDifficultySource{difficulty: 12, hashFuncName: "sha256"}
	r, err := admission.NewStaticDifficultyResolver(src)
	if err != nil {
		t.Fatalf("NewStaticDifficultyResolver: %v", err)
	}
	d, hf, err := r.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if d != 12 {
		t.Errorf("difficulty = %d, want 12", d)
	}
	if hf != sdkadmission.HashSHA256 {
		t.Errorf("hashFunc = %v, want HashSHA256", hf)
	}
}

func TestStaticDifficultyResolver_PassthroughArgon2id(t *testing.T) {
	src := &fakeDifficultySource{difficulty: 8, hashFuncName: "argon2id"}
	r, _ := admission.NewStaticDifficultyResolver(src)
	_, hf, _ := r.Current(context.Background())
	if hf != sdkadmission.HashArgon2id {
		t.Errorf("hashFunc = %v, want HashArgon2id", hf)
	}
}

func TestStaticDifficultyResolver_UnknownHashFuncFallsBackToSHA256(t *testing.T) {
	// Operator typo ("shap256") must not bring Mode-B down —
	// fallback to SHA-256 mirrors the pre-refactor inline behaviour
	// in api/submission.go step 7 + api/batch.go preflight.
	src := &fakeDifficultySource{difficulty: 1, hashFuncName: "shap256"}
	r, _ := admission.NewStaticDifficultyResolver(src)
	_, hf, _ := r.Current(context.Background())
	if hf != sdkadmission.HashSHA256 {
		t.Errorf("hashFunc = %v, want HashSHA256 (typo fallback)", hf)
	}
}

func TestStaticDifficultyResolver_ReadsDifficultyOnEveryCall(t *testing.T) {
	// "Static" refers to the SOURCE, not the value — the wrapper
	// MUST re-read CurrentDifficulty on every Current call so a
	// mutated underlying controller is observed immediately.
	src := &fakeDifficultySource{difficulty: 10, hashFuncName: "sha256"}
	r, _ := admission.NewStaticDifficultyResolver(src)
	d1, _, _ := r.Current(context.Background())
	src.difficulty = 99
	d2, _, _ := r.Current(context.Background())
	if d1 != 10 || d2 != 99 {
		t.Errorf("expected re-read after source mutation; got d1=%d d2=%d", d1, d2)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error-mapping integration
// ─────────────────────────────────────────────────────────────────────

func TestErrorMapping_ModeBSentinels_RouteAs403(t *testing.T) {
	cases := []error{
		admission.ErrModeBProofRequired,
		admission.ErrModeBStampInvalid,
	}
	for _, sentinel := range cases {
		matched, status, _ := admission.MapSDKError(sentinel)
		if !matched {
			t.Errorf("MapSDKError missed sentinel %v", sentinel)
			continue
		}
		if status != 403 {
			t.Errorf("sentinel %v: got %d, want 403", sentinel, status)
		}
	}
}

// Resolver-failure sentinel MUST NOT be in the table — production
// routing falls through to the 500 default. A regression that adds
// it to the table would silently downgrade infrastructure failures
// to policy rejects. Mirror of TestErrorMapping_ResolverFailureSentinel_
// NotInTable for II.6.
func TestErrorMapping_ModeBResolverFailureSentinel_NotInTable(t *testing.T) {
	matched, _, _ := admission.MapSDKError(admission.ErrModeBResolverFailed)
	if matched {
		t.Error("ErrModeBResolverFailed is in sdkErrorTable; " +
			"infrastructure failures must route via the 500 default, NOT as a policy reject")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time / discriminator pins
// ─────────────────────────────────────────────────────────────────────

// The gate documentation references the SDK's
// crypto/admission.AdmissionModeB constant — pin it as the value
// powEntry uses (the test fixture writes it directly into
// AdmissionProofBody.Mode). A future SDK that renumbers Mode
// values without updating the fixture would surface here.
func TestPowEntry_FixtureUsesAdmissionModeB(t *testing.T) {
	entry := powEntry(t, "did:test:log", 1, sdkadmission.HashSHA256, 3600)
	if entry.Header.AdmissionProof.Mode != 1 {
		t.Errorf("AdmissionProofBody.Mode = %d, want 1 (AdmissionModeB)",
			entry.Header.AdmissionProof.Mode)
	}
}

// _ keeps imports stable for fixture growth.
var _ = sha256.Sum256
var _ = strings.TrimSpace
