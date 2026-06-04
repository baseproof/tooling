/*
FILE PATH: witnessclient/rotation_handler.go

Witness set rotation handling. Accepts rotation findings, runs
the SDK's cryptographic Verify, persists to the witness_sets
table, swaps the in-memory set, and emits a KindWitnessRotation
gossip event so tailing auditors learn about the change.

# KEY DESIGN DECISIONS

  - The handler consumes baseproof v0.7.0's findings.WitnessRotation
    Finding directly. The pre-v0.7.0 ledger-local "structural-
    only" path is gone — every rotation runs the SDK's full
    cryptographic recipe (set-hash rebind → scheme enforcement
    → OLD K-of-N quorum → optional NEW dual-sign quorum) via
    (*WitnessRotationFinding).Verify(set).

  - The handler owns the *cosign.WitnessKeySet, not a flat
    []types.WitnessPublicKey. The WitnessKeySet encapsulates
    NetworkID + Quorum + BLSVerifier alongside the keys — the
    SAME topology the EquivocationMonitor uses, so the two
    surfaces stay aligned by construction.

  - Verify runs BEFORE persist, persist runs BEFORE emit. Order
    is load-bearing: an unverified rotation must never reach the
    DB, and an emitted event implies durable local persistence
    (peers can trust that downloading from this ledger's
    by-binding endpoint will find the same event).

# WHAT'S OUT OF SCOPE (NEXT-TODO)

Inbound consumption of peer ledgers' KindWitnessRotation events
(cross-ledger witness-set consistency auditing) is a separate
surface that mirrors the upcoming KindCrossLogInclusion
consumption: both require polling peers + decoding + verifying
under our trusted set. Deferred together so the inbound
mechanism is shipped as one coherent feature.
*/
package witnessclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// RotationLogAppender commits a witness-rotation payload as a sequenced
// ON-LOG entry and returns the entry's canonical bytes, its INTRINSIC log
// position, and an RFC 6962 inclusion proof binding the entry leaf to a
// witness-cosigned head's RootHash at that position.
//
// Production implementations build + sign the envelope.Entry around the
// payload, submit it through the ledger's sequencing pipeline, and wait
// for a witness round to cosign a head covering the assigned leaf before
// building the proof — so AppendRotationEntry MAY block across a witness
// round. The returned position is the AUTHORITY for EffectivePos (the
// intrinsic leaf sequence), replacing the pre-v1.39 MAX(tree_size)
// timestamp; the proof is what makes that position verifiable offline.
//
// A nil appender on the handler means on-log rotation is not wired — the
// handler is dormant until the inbound-rotation consumer + the sequencer
// seam are wired (ProcessRotation returns a clear error rather than
// silently falling back to an unprovable position).
type RotationLogAppender interface {
	AppendRotationEntry(ctx context.Context, rotationPayload []byte) (
		entryCanonical []byte, pos types.LogPosition, proof *types.MerkleProof, err error)
}

// RotationHandler manages witness set rotations.
type RotationHandler struct {
	db             *pgxpool.Pool
	keys           *quorum.Manager
	schemeTag      byte
	ledgerEndpoint string
	logger         *slog.Logger

	// allowedCosignSchemeTags is the network's
	// GenesisSignaturePolicy.AllowedCosignSchemeTags. When non-empty,
	// ProcessRotation rejects a rotation whose NEW set introduces a witness
	// using a cosign scheme the network does not admit — the same gate
	// quorum.ValidateCosignSchemePolicy applies to the genesis set at boot.
	// Empty = no enforcement (set via WithCosignSchemePolicy).
	allowedCosignSchemeTags []uint8

	// emitter broadcasts each successful rotation as a gossip
	// event. nil = gossip-disabled deployment (the rotation still
	// applies locally; auditors will catch up via anti-entropy
	// when an emitter is wired). See rotation_emitter.go.
	emitter WitnessRotationEmitter

	// appender commits the rotation as a sequenced on-log entry and
	// returns its intrinsic position + inclusion proof. nil = on-log
	// rotation unwired (dormant); ProcessRotation fails closed rather
	// than persist an unprovable position. See RotationLogAppender.
	appender RotationLogAppender
}

// NewRotationHandler creates a rotation handler over the shared witness
// keyset Manager + the ledger's externally-visible endpoint (carried in
// the rotation finding so auditors can crawl back to this ledger for
// follow-up state).
//
// keys is the single source of truth for the active witness set, shared
// with the admission gate and the equivocation monitor. ProcessRotation
// reads keys.Current() for the topology the SDK Verify needs (NetworkID,
// Quorum, BLSVerifier) and calls keys.Update() to install the new set —
// so the rotation is observed by every reader, not just this handler.
func NewRotationHandler(
	db *pgxpool.Pool,
	keys *quorum.Manager,
	schemeTag byte,
	ledgerEndpoint string,
	logger *slog.Logger,
) *RotationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RotationHandler{
		db:             db,
		keys:           keys,
		schemeTag:      schemeTag,
		ledgerEndpoint: ledgerEndpoint,
		logger:         logger,
	}
}

// WithEmitter wires the gossip-emitter. nil is permitted
// (gossip-disabled). Returns the receiver so callers can chain.
// Mirrors the sequencer's WithGhostLeafEmitter pattern.
func (rh *RotationHandler) WithEmitter(e WitnessRotationEmitter) *RotationHandler {
	rh.emitter = e
	return rh
}

// WithCosignSchemePolicy sets the network's allowed witness cosign scheme tags
// (GenesisSignaturePolicy.AllowedCosignSchemeTags). When non-empty,
// ProcessRotation rejects a rotation whose NEW set introduces a witness using a
// cosign scheme the network does not admit — the same gate
// quorum.ValidateCosignSchemePolicy applies to the genesis set at boot. Empty /
// unset = no enforcement (matches the bootstrap default before a policy is
// configured). Returns the receiver so callers can chain. Mirrors WithEmitter.
func (rh *RotationHandler) WithCosignSchemePolicy(allowed []uint8) *RotationHandler {
	rh.allowedCosignSchemeTags = allowed
	return rh
}

// WithAppender wires the on-log appender that commits each rotation as a
// sequenced entry and returns its intrinsic position + inclusion proof.
// nil leaves on-log rotation unwired — ProcessRotation fails closed rather
// than persist an unprovable position. Returns the receiver so callers can
// chain. Mirrors WithEmitter.
func (rh *RotationHandler) WithAppender(a RotationLogAppender) *RotationHandler {
	rh.appender = a
	return rh
}

// ProcessRotation validates a rotation cryptographically, persists
// it to the witness_sets table, swaps the in-memory set, and emits
// a KindWitnessRotation gossip event. Returns the new witness set
// on success.
//
// Order of operations is load-bearing:
//
//  1. Build the SDK finding (runs Validate — bounds-checks every
//     wire-shaped field; rejects oversize NewSet, oversize keys,
//     oversize sigs, etc.).
//  2. Cryptographically verify against the CURRENT set (runs the
//     SDK's full 4-step recipe via witness.VerifyRotation).
//  3. Persist to DB.
//  4. Swap the in-memory WitnessKeySet to the NEW set, inheriting
//     NetworkID + Quorum + BLSVerifier from the current set.
//  5. Emit to gossip (best-effort; failure does NOT roll back the
//     rotation — the local audit trail is durable, and peers will
//     catch up via anti-entropy).
//
// Any failure in steps 1–4 leaves the handler in its previous
// state. The rotation has not been applied.
func (rh *RotationHandler) ProcessRotation(
	ctx context.Context,
	rotation types.WitnessRotation,
) ([]types.WitnessPublicKey, error) {
	cur := rh.keys.Current()
	if cur == nil {
		return nil, fmt.Errorf("witness/rotation: handler has no current witness set")
	}

	// Step 1: structurally validate + encode the rotation as the canonical
	// on-log entry payload. EncodeWitnessRotationPayload runs the SDK's
	// structural validation (bounds every wire-shaped field; the on-log
	// entry stays within the 65,535-byte cap, ZT-LIM-01 / ZT-SDK-06).
	payload, err := witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: encode payload: %w", err)
	}

	// Step 2: cryptographic Verify against the current set — the SDK's
	// canonical recipe (set-hash rebind, scheme enforcement, OLD K-of-N
	// quorum, optional NEW dual-sign quorum). Authenticity is checked
	// BEFORE the rotation is committed on-log (fail-closed, ZT-SDK-03).
	if _, vErr := witness.VerifyRotation(rotation, cur); vErr != nil {
		return nil, fmt.Errorf("witness/rotation: verify: %w", vErr)
	}

	// Step 2a: enforce the network's allowed cosign-scheme policy on the NEW set.
	// VerifyRotation proves the rotation is AUTHENTIC; this proves the new
	// witnesses' cosign schemes are ADMISSIBLE under
	// GenesisSignaturePolicy.AllowedCosignSchemeTags — the same gate applied to
	// the genesis set at boot (quorum.ValidateCosignSchemePolicy). Checked BEFORE
	// the on-log append so a policy-violating rotation is never committed
	// (fail-closed). No-op when no policy is wired (WithCosignSchemePolicy unset).
	if err = quorum.ValidateCosignSchemePolicy(rotation.NewSet, rh.allowedCosignSchemeTags); err != nil {
		return nil, fmt.Errorf("witness/rotation: %w", err)
	}

	// Step 2b: commit the rotation as a sequenced ON-LOG entry and obtain
	// its INTRINSIC position + an inclusion proof binding the entry leaf to
	// a witness-cosigned head (ZT-WIT-07: rotation is a verified on-log
	// event, not a config edit). A nil appender means on-log rotation is
	// unwired — fail closed rather than persist an unprovable position.
	if rh.appender == nil {
		return nil, fmt.Errorf("witness/rotation: on-log appender not wired " +
			"(on-log rotation requires a RotationLogAppender)")
	}
	entryCanonical, effectivePos, inclusionProof, err := rh.appender.AppendRotationEntry(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: append on-log entry: %w", err)
	}

	// Step 3: persist the new set. As of v1.3 (migration 0014), the
	// witness_sets row's set_hash is the content-addressable IDENTITY
	// of the new set (cosign.SetHash, plan §I.3) — NOT the OLD set's
	// hash. The new columns effective_seq / retired_seq classify the
	// row as live vs. retired, supporting the new
	// /v1/network/witnesses/{set_hash} and /at/{seq} endpoints.
	keysJSON, err := json.Marshal(rotation.NewSet)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: marshal new set: %w", err)
	}
	newScheme := rotation.SchemeTagOld
	if rotation.SchemeTagNew != 0 {
		newScheme = rotation.SchemeTagNew
	}

	// Compute the NEW set's content-addressable hash under the same
	// topology the in-memory WitnessKeySet will carry. The hash is
	// over the JCS-canonical {network_id, quorum_k, witnesses[]} and
	// matches every consumer (gossip, /v1/network/witnesses/*, bundle
	// witness_set_hint) byte-identically.
	newSet, err := cosign.NewWitnessKeySet(
		rotation.NewSet,
		cur.NetworkID(),
		cur.Quorum(),
		cur.BLSVerifier(),
	)
	if err != nil {
		// This should be unreachable: Verify already ran Validate on
		// every key, and NewWitnessKeySet only rejects shapes Validate
		// already enforced. Surface loudly — contract drift in the SDK.
		return nil, fmt.Errorf("witness/rotation: construct new set "+
			"(SDK contract drift between Verify and NewWitnessKeySet): %w", err)
	}
	newSetHash := newSet.SetHash()

	// effective_seq = the rotation entry's INTRINSIC on-log position (the
	// leaf sequence the appender assigned). Per ZT-IMM-01 / ZT-WIT-07 this
	// is the position at/after which the new set is authoritative, PROVEN
	// by inclusionProof against a cosigned head — never the pre-v1.39
	// MAX(tree_size) timestamp (an asserted, unprovable number).
	effectiveSeq := effectivePos.Sequence

	// Two writes, one tx: (a) retire the currently-active row by
	// stamping its retired_seq; (b) insert the new active row.
	// Atomicity matters — the partial unique index witness_sets_active
	// enforces "exactly one row has retired_seq IS NULL" and would
	// reject the new INSERT if the prior row isn't retired first.
	tx, err := rh.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `
		UPDATE witness_sets
		   SET retired_seq = $1
		 WHERE retired_seq IS NULL`,
		int64(effectiveSeq),
	); err != nil {
		return nil, fmt.Errorf("witness/rotation: retire prior: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO witness_sets
		    (set_hash, keys_json, scheme_tag, effective_seq, retired_seq, rotation_event_id)
		VALUES ($1, $2, $3, $4, NULL, NULL)`,
		newSetHash[:], keysJSON, int16(newScheme), int64(effectiveSeq),
	); err != nil {
		return nil, fmt.Errorf("witness/rotation: persist: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("witness/rotation: commit: %w", err)
	}

	// Step 4: swap the in-memory set (already constructed in step 3
	// for the SetHash computation). Atomic — admission + the
	// equivocation monitor observe the new set on their next read.
	rh.keys.Update(newSet)
	rh.schemeTag = newScheme

	rh.logger.InfoContext(ctx, "witness rotation applied",
		"new_keys", len(rotation.NewSet),
		"scheme_tag", newScheme,
		"dual_sign", rotation.IsDualSigned(),
	)

	// Step 5: emit the SELF-CONTAINED gossip finding. Best-effort,
	// nil-safe. The finding carries the on-log entry bytes + the inclusion
	// proof, so a late-joining / offline auditor verifies the rotation AND
	// its position with no live ledger (ZT-SCN-02 / ZT-SCN-07). Peers also
	// catch up via the log + anti-entropy if the broadcast fails.
	if rh.emitter != nil {
		finding, ferr := findings.NewWitnessRotationFinding(
			entryCanonical, effectivePos, inclusionProof, rh.ledgerEndpoint)
		if ferr != nil {
			// Unreachable in practice: the appender produced a well-formed
			// entry + proof. Surface loudly rather than silently drop the
			// emit (ZT-ENG-GO-03 — no masked errors).
			rh.logger.ErrorContext(ctx, "witness/rotation: build self-contained finding for emit",
				"error", ferr)
		} else {
			rh.emitter.Emit(ctx, finding)
		}
	}

	return rotation.NewSet, nil
}

// WitnessSetRow is the wire shape of a single witness_sets row,
// minus the heavy keys_json blob. Returned by the historical-lookup
// helpers below (LoadSetByHash, LoadSetAtSeq, LoadCurrentSetRow);
// the /v1/network/witnesses/* HTTP handlers compose the JSON
// response around it.
type WitnessSetRow struct {
	// SetHash is the content-addressable identity of this row's set
	// (cosign.SetHash, plan §I.3).
	SetHash [32]byte
	// KeysJSON is the canonical wire-form of the witness keys in
	// this row. The caller deserializes into []types.WitnessPublicKey.
	KeysJSON []byte
	// SchemeTag is the signature scheme tag (cosign.SchemeECDSA / BLS / …).
	SchemeTag byte
	// EffectiveSeq is the rotation entry's intrinsic on-log position — the
	// leaf sequence at/after which this set is authoritative (v1.39:
	// supplied by the RotationLogAppender, not the old MAX(tree_size)).
	// 0 for the genesis baseline.
	EffectiveSeq uint64
	// RetiredSeq is the intrinsic on-log position at which this set was
	// retired (the successor rotation's EffectiveSeq). nil = currently active.
	RetiredSeq *uint64
}

// LoadCurrentSetRow is LoadCurrentSet's structured variant — returns
// the FULL row (including set_hash + effective_seq) for the active
// set. Backs GET /v1/network/witnesses/current (Part II.1).
func LoadCurrentSetRow(ctx context.Context, db *pgxpool.Pool) (*WitnessSetRow, error) {
	row := &WitnessSetRow{}
	var setHash []byte
	var schemeTag int16
	err := db.QueryRow(ctx,
		`SELECT set_hash, keys_json, scheme_tag, effective_seq, retired_seq
		   FROM witness_sets
		  WHERE retired_seq IS NULL
		  LIMIT 1`,
	).Scan(&setHash, &row.KeysJSON, &schemeTag, &row.EffectiveSeq, &row.RetiredSeq)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: load current row: %w", err)
	}
	if len(setHash) != 32 {
		return nil, fmt.Errorf("witness/rotation: corrupted set_hash length %d (want 32)", len(setHash))
	}
	copy(row.SetHash[:], setHash)
	row.SchemeTag = byte(schemeTag)
	return row, nil
}

// LoadSetByHash returns the row whose set_hash matches the supplied
// 32-byte content-addressable identity, or pgx.ErrNoRows-wrapped on
// miss. Backs GET /v1/network/witnesses/{set_hash} (Part II.1) —
// immutable / content-addressable, so callers cache forever.
func LoadSetByHash(ctx context.Context, db *pgxpool.Pool, setHash [32]byte) (*WitnessSetRow, error) {
	row := &WitnessSetRow{SetHash: setHash}
	var schemeTag int16
	err := db.QueryRow(ctx,
		`SELECT keys_json, scheme_tag, effective_seq, retired_seq
		   FROM witness_sets
		  WHERE set_hash = $1`,
		setHash[:],
	).Scan(&row.KeysJSON, &schemeTag, &row.EffectiveSeq, &row.RetiredSeq)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: load by hash %x: %w", setHash, err)
	}
	row.SchemeTag = byte(schemeTag)
	return row, nil
}

// LoadSetAtSeq returns the witness set active at tree_size seq —
// i.e., the row where effective_seq <= seq AND (retired_seq IS NULL
// OR retired_seq > seq). Backs GET /v1/network/witnesses/at/{seq}
// (Part II.1). Returns pgx.ErrNoRows-wrapped if no row covers seq
// (typically: seq predates the first rotation AND no genesis row
// has been persisted — in this case the caller should fall back
// to the genesis config).
func LoadSetAtSeq(ctx context.Context, db *pgxpool.Pool, seq uint64) (*WitnessSetRow, error) {
	row := &WitnessSetRow{}
	var setHash []byte
	var schemeTag int16
	err := db.QueryRow(ctx,
		`SELECT set_hash, keys_json, scheme_tag, effective_seq, retired_seq
		   FROM witness_sets
		  WHERE effective_seq <= $1
		    AND (retired_seq IS NULL OR retired_seq > $1)
		  ORDER BY effective_seq DESC
		  LIMIT 1`,
		int64(seq),
	).Scan(&setHash, &row.KeysJSON, &schemeTag, &row.EffectiveSeq, &row.RetiredSeq)
	if err != nil {
		return nil, fmt.Errorf("witness/rotation: load at seq %d: %w", seq, err)
	}
	if len(setHash) != 32 {
		return nil, fmt.Errorf("witness/rotation: corrupted set_hash length %d (want 32)", len(setHash))
	}
	copy(row.SetHash[:], setHash)
	row.SchemeTag = byte(schemeTag)
	return row, nil
}

// CurrentSet returns the active witness key set's public keys.
// The returned slice is a copy of the keys held inside the
// *cosign.WitnessKeySet; the WitnessKeySet itself is immutable so
// concurrent callers see consistent state.
func (rh *RotationHandler) CurrentSet() []types.WitnessPublicKey {
	cur := rh.keys.Current()
	if cur == nil {
		return nil
	}
	pks := cur.Keys()
	out := make([]types.WitnessPublicKey, len(pks))
	copy(out, pks)
	return out
}

// CurrentWitnessKeySet exposes the active *cosign.WitnessKeySet
// for callers that need the full topology (NetworkID + Quorum +
// BLSVerifier in addition to keys). The returned pointer is the
// live keyset; callers MUST NOT mutate (the type is immutable by
// construction, but a future refactor that exposes a mutator
// would silently de-sync from the handler's invariants).
func (rh *RotationHandler) CurrentWitnessKeySet() *cosign.WitnessKeySet {
	return rh.keys.Current()
}

// SchemeTag returns the active signature scheme.
func (rh *RotationHandler) SchemeTag() byte {
	return rh.schemeTag
}

// LoadCurrentSet loads the active witness set from Postgres. As of
// migration 0014 (Part II.2), "active" is identified by
// retired_seq IS NULL — backed by the witness_sets_active partial
// index for O(1) lookup. There is exactly one such row at any
// moment (enforced by the unique partial index).
//
// On miss (table empty / no rotations applied yet), returns
// pgx.ErrNoRows wrapped. The caller in cmd/ledger/boot/wire/gossip.go
// catches this and falls through to the genesis-config path.
func LoadCurrentSet(ctx context.Context, db *pgxpool.Pool) ([]types.WitnessPublicKey, byte, error) {
	var keysJSON []byte
	var schemeTag int16
	err := db.QueryRow(ctx,
		`SELECT keys_json, scheme_tag
		   FROM witness_sets
		  WHERE retired_seq IS NULL
		  LIMIT 1`,
	).Scan(&keysJSON, &schemeTag)
	if err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: load current set: %w", err)
	}

	var keys []types.WitnessPublicKey
	if err := json.Unmarshal(keysJSON, &keys); err != nil {
		return nil, 0, fmt.Errorf("witness/rotation: unmarshal keys: %w", err)
	}
	return keys, byte(schemeTag), nil
}
