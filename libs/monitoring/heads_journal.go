// HeadsJournal — durable cosigned-head archive with as-of, fork-aware,
// and equivocation-aware reads. The cryptographic bedrock that
// makes year-15 verification of year-1 bundles possible.
//
// # Why this exists
//
// TrustedHeadStore (peer_consistency.go) keeps a single "highest
// verified head per source log" in memory — enough to anchor
// cross-log inclusion proofs at the current moment, but insufficient
// for:
//
//   - SCENARIO 2 (year-15 forensic):  a sealing order issued in 2026
//     and witnessed by W1 = {Alice, Bob, Carol} must remain
//     verifiable in 2041 when the live witness set has rotated to
//     W4 = {David, Eve, Frank}. The 2026 cosigned head — including
//     its witness signatures — must survive every rotation.
//
//   - SCENARIO 4 (split-brain / fork): if a log forks past sequence
//     1_345_000, BOTH heads at that sequence (with different
//     RootHashes) are physical reality. The journal records both
//     and lets the verifier bind its verdict to ONE chain by
//     RootHash, refusing to silently accept whichever side the
//     local backend happened to see.
//
//   - SCENARIO 12 (equivocation watchdog): the orthogonal
//     equivocation responder needs both conflicting heads at the
//     same sequence + a record that the contradiction was seen at
//     time T. This journal is that record.
//
// # The 5 binding design decisions (per network architect, 2026-05)
//
//  1. asOf is MANDATORY at the SDK / domain boundary. There is no
//     "latest" default. The Domain Application explicitly passes a
//     LogPosition (sequence or RootHash) into every verification
//     call. A verdict rendered today renders the same result 15
//     years from now.
//
//  2. Primary key is (LogDID, Sequence, RootHash). Three columns.
//     A collision at (LogDID, Sequence) with a different RootHash
//     INSTANTLY surfaces as RecordVerdict.Equivocation = true, and
//     the caller emits a KindEquivocationFinding into the gossip
//     network. Fork tolerance is built into the schema, not
//     bolted on later.
//
//  3. NEVER DELETE. No TTL, no PruneJob hook, no retention window.
//     At 1 head/minute × 15 years × 30 logs ≈ 250M rows; each row
//     is ~150 bytes including signatures — ~38 GB total. Modern
//     PostgreSQL handles this trivially. The journal is permanent
//     cryptographic bedrock; transient gossip-network evidence
//     lives in a different store and prunes on its own cadence.
//
//  4. Cross-network fork → FAIL-CLOSED.  Once equivocation is
//     detected for a given LogDID, the log is BURNED. Subsequent
//     HeadAt / HeadAtTime / LatestHead return ErrEquivocatedLog.
//     Verification halts globally for that log until human
//     governance re-establishes a clean trust root (out-of-band).
//
//  5. Wire-format preservation. CanonicalBytes (the exact bytes
//     that were cosigned) survive verbatim in the journal so a
//     year-15 binary reading year-1 head bytes succeeds without
//     translation shims (Goal 11 bundle wire-format freeze).
//
// # Threading model
//
// All operations are safe for concurrent use. Implementations
// serialize writes per LogDID (since equivocation detection
// requires a read-then-write race-free check at the (LogDID,
// Sequence) row); reads are unsynchronized.
package monitoring

import (
	"context"
	"errors"
	"time"

	"github.com/baseproof/baseproof/types"
)

// HeadsJournal is the durable archive of every cosigned head this
// auditor has ever verified. Three implementations are shipped:
//
//   - MemoryHeadsJournal in libs/monitoring (this package): in-memory,
//     for tests and small deployments where process lifetime equals
//     "as long as we need history"
//
//   - PostgresHeadsJournal in services/auditor/internal/store:
//     persistent, for production
//
//   - the JN's own future cache + remote-query implementation
//     (PR-C C-4 follow-up) consuming the auditor's API
//
// All three honor the same contract.
type HeadsJournal interface {
	// Record persists a verified cosigned head and returns the
	// resulting RecordVerdict. Implementations MUST:
	//
	//   - be idempotent on the composite key (LogDID, Sequence,
	//     RootHash): re-recording the exact same head returns
	//     {Persisted:false}
	//
	//   - detect equivocation: if a head already exists at
	//     (LogDID, Sequence) with a DIFFERENT RootHash, write the
	//     new row AND return {Equivocation:true}. The first call
	//     that detects the collision returns {BurnTransition:true}
	//     as well — subsequent calls (or non-equivocating
	//     records on the same now-burned log) keep
	//     Equivocation:true but BurnTransition:false
	//
	// On any persistence error the implementation MUST return a
	// non-nil error and a zero RecordVerdict.
	Record(ctx context.Context, head Head) (RecordVerdict, error)

	// HeadAt returns the head at OR BEFORE asOfSequence for the
	// given log on the BURN-FREE history. Returns:
	//
	//   - the matching Head, nil on success
	//   - zero Head, ErrEquivocatedLog if the log is burned
	//   - zero Head, ErrNoHead if no head exists at or before
	//     asOfSequence (e.g., query for sequence 5 before any
	//     head has been recorded)
	//
	// "At or before" semantics make this the correct primitive
	// for as-of authority evaluation: the verifier asks "what
	// head was authoritative when this entry was admitted at
	// sequence N?" and gets the largest head ≤ N — exactly the
	// head a witness would have signed at admission time.
	HeadAt(ctx context.Context, logDID string, asOfSequence uint64) (Head, error)

	// HeadAtTime returns the head whose CommittedAt is at or
	// before t for the given log on the BURN-FREE history.
	// Useful for forensic queries phrased as wall-clock times
	// ("what was active on 2026-06-15?") rather than sequence
	// numbers. Same error semantics as HeadAt.
	HeadAtTime(ctx context.Context, logDID string, t time.Time) (Head, error)

	// HeadByRootHash returns the EXACT head identified by the
	// composite key. Works on burned logs (forensic forks need
	// retrievability). Returns ErrNoHead if no head matches.
	HeadByRootHash(ctx context.Context, logDID string, sequence uint64, rootHash [32]byte) (Head, error)

	// HeadsAtSequence returns EVERY head observed at the given
	// (LogDID, Sequence). On a clean log returns at most one
	// entry. On an equivocated log returns ≥ 2 (the diverging
	// roots). This is the equivocation responder's primary read
	// — it must see both forks to assemble a finding.
	HeadsAtSequence(ctx context.Context, logDID string, sequence uint64) ([]Head, error)

	// LatestHead returns the highest-sequence head for the log
	// on the BURN-FREE history. Equivalent to a hypothetical
	// HeadAt(maxUint64). Returns ErrEquivocatedLog on a burned
	// log; ErrNoHead if no head has ever been recorded.
	LatestHead(ctx context.Context, logDID string) (Head, error)

	// BurnStatus reports whether the log has been BURNED due to
	// detected equivocation. A burned log surfaces
	// ErrEquivocatedLog from HeadAt, HeadAtTime, and LatestHead;
	// HeadByRootHash and HeadsAtSequence remain readable for
	// forensic analysis.
	BurnStatus(ctx context.Context, logDID string) (BurnStatus, error)
}

// Head is the journal's persistence shape for one cosigned head.
// Preserves the full witness signature set verbatim so a year-15
// verifier can authenticate against the ORIGINAL witness public
// keys — even if the live witness set has rotated through dozens
// of generations since.
type Head struct {
	// LogDID identifies the source log (the originator DID of
	// the gossip event that delivered this head).
	LogDID string

	// TreeHead is the cosigned tree head — RootHash, SMTRoot,
	// ReceiptRoot, TreeSize. Embedded so callers can access
	// Head.RootHash and Head.TreeSize without traversing.
	types.TreeHead

	// Signatures is the witness cosignature set captured at
	// publish time. Preserved verbatim. A year-15 verifier
	// looking up the PubKeyIDs in this slice retrieves the
	// ORIGINAL witnesses (the W1 set), not the current W4.
	Signatures []types.WitnessSignature

	// CanonicalBytes is the exact wire encoding the original
	// witnesses signed. Preserved verbatim for the bundle
	// wire-format freeze (Goal 11) — a year-15 binary can
	// re-verify the year-1 signatures byte-for-byte without
	// translation shims.
	//
	// Implementations MAY omit this field on Read if the
	// caller does not need it (e.g., HeadAt for a quick
	// activation-delay verdict), but MUST preserve it on
	// Record.
	CanonicalBytes []byte

	// LamportTime is the gossip event's LamportTime — the
	// logical sequence of THIS head event within the gossip
	// stream from the originator. Distinct from TreeSize (which
	// is the log's leaf count). Used by the equivocation
	// responder to order conflicting reports.
	LamportTime uint64

	// CommittedAt is the wall-clock time the ledger committed
	// this tree head. SOURCE OF TRUTH for time-based as-of
	// queries. Implementations populate from the gossip event's
	// committed time when available, otherwise from
	// RecordedAt — but ONLY at Record time, never after.
	CommittedAt time.Time

	// RecordedAt is the wall-clock time THIS journal first
	// observed this head. Used for operational forensics
	// ("when did we learn of this fork?"); NOT for asOf
	// verification (use CommittedAt or LamportTime).
	RecordedAt time.Time
}

// RecordVerdict classifies the result of a Record call.
type RecordVerdict struct {
	// Persisted is true if this Record inserted a new row.
	// False on duplicate (LogDID, Sequence, RootHash) — same
	// head re-observed.
	Persisted bool

	// Equivocation is true if a head already exists at
	// (LogDID, Sequence) with a DIFFERENT RootHash. The caller
	// is responsible for emitting a KindEquivocationFinding via
	// the gossip network. The conflicting row is still
	// persisted (forks are physical reality; both sides must be
	// archivable).
	Equivocation bool

	// BurnTransition is true ONLY on the first Record call
	// that observes the equivocation. Subsequent Record calls
	// on the now-burned log keep Equivocation:true but
	// BurnTransition:false. Lets the caller trigger
	// one-time-only escalation logic (page on-call, freeze
	// upstream verification for this LogDID, etc.).
	BurnTransition bool

	// ConflictingRoot is the RootHash of the head this Record
	// collided with at (LogDID, Sequence) — populated only
	// when Equivocation is true. Lets the caller include both
	// roots in the KindEquivocationFinding without a second
	// read.
	ConflictingRoot [32]byte
}

// BurnStatus reports whether a log has been BURNED due to detected
// equivocation. Burned logs cannot resume — clearing the burn
// requires out-of-band human governance (new witness root,
// operator agreement, etc.) and a new bootstrap.
type BurnStatus struct {
	// Burned is true iff equivocation has been detected for
	// this LogDID at least once.
	Burned bool

	// BurnedAt is the wall-clock time the first equivocation
	// was recorded. Zero when Burned is false.
	BurnedAt time.Time

	// FirstForkSequence is the (LogDID, Sequence) at which the
	// first equivocation was detected. Useful for narrowing
	// forensic queries.
	FirstForkSequence uint64

	// ConflictingRoots are the RootHashes that triggered the
	// burn — the original root plus the divergent one observed
	// at FirstForkSequence. Two entries on the first burn;
	// more if additional forks accumulate before human
	// intervention.
	ConflictingRoots [][32]byte
}

// Sentinel errors. Callers discriminate via errors.Is.
var (
	// ErrEquivocatedLog is returned by HeadAt, HeadAtTime, and
	// LatestHead when the log has been BURNED due to detected
	// equivocation. A burned log halts all upstream verification
	// until human governance re-establishes trust.
	ErrEquivocatedLog = errors.New("monitoring/heads_journal: log burned due to equivocation")

	// ErrNoHead is returned when no head exists at the requested
	// position (HeadAt before any head has been recorded;
	// HeadByRootHash with an unknown root).
	ErrNoHead = errors.New("monitoring/heads_journal: no head at requested position")

	// ErrInvalidHead is returned by Record when the supplied
	// Head fails structural validation (empty LogDID, zero
	// TreeSize, zero RecordedAt, nil Signatures).
	ErrInvalidHead = errors.New("monitoring/heads_journal: invalid head record")
)

// ValidateForRecord returns nil if h is structurally valid for
// insertion into a HeadsJournal: non-empty LogDID, non-empty
// CanonicalBytes, at least one signature, non-zero TreeSize, and
// a non-zero CommittedAt (asOf-by-time queries cannot resolve
// against an unset timestamp). Implementations call this from
// Record before touching storage.
func ValidateForRecord(h Head) error {
	if h.LogDID == "" {
		return errInvalid("empty LogDID")
	}
	if h.TreeSize == 0 {
		return errInvalid("zero TreeSize (the genesis is sequence 1, never 0)")
	}
	if len(h.CanonicalBytes) == 0 {
		return errInvalid("empty CanonicalBytes (the wire-format freeze requires the original bytes)")
	}
	if len(h.Signatures) == 0 {
		return errInvalid("empty Signatures (year-15 verification needs the original witness set)")
	}
	if h.CommittedAt.IsZero() {
		return errInvalid("zero CommittedAt (time-based as-of queries cannot resolve)")
	}
	return nil
}

func errInvalid(reason string) error {
	return &invalidHeadError{reason: reason}
}

type invalidHeadError struct{ reason string }

func (e *invalidHeadError) Error() string {
	return "monitoring/heads_journal: invalid head record: " + e.reason
}
func (e *invalidHeadError) Is(target error) bool { return target == ErrInvalidHead }
