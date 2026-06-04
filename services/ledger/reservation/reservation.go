/*
FILE PATH:

	reservation/reservation.go

DESCRIPTION:

	The artifact-upload reservation — the staging record of the
	RESERVE -> token -> UPLOAD -> FINISH protocol (ledger#193 Phase 4). A
	reservation is created (PENDING_UPLOAD) when admission accepts an artifact
	genesis entry and the accounting (PoW / credits) clears; it advances to
	COMMITTED only at FINISH, once the bytes are present and (for public content)
	validated. Abandoned reservations are reaped to EXPIRED. The CID always
	survives on the log; only the staged bytes are transient.

KEY ARCHITECTURAL DECISIONS:
  - The state machine is explicit and the only legal transitions are encoded in
    CanTransition, so every store impl and the Manager share one definition of
    "legal move" (no divergence between Postgres and the in-memory fake).
  - Terminal non-commit states (EXPIRED / REJECTED) are distinct so audits can
    tell *why* an artifact never reached the log: TTL elapsed vs. validation
    failed.
*/
package reservation

import "time"

// Status is the staging state of a reservation.
type Status string

const (
	// StatusPendingUpload — reserved + accounted; awaiting the bytes.
	StatusPendingUpload Status = "pending_upload"
	// StatusUploaded — bytes present; awaiting FINISH confirmation.
	StatusUploaded Status = "uploaded"
	// StatusCommitted — terminal success: bytes durable + entry committed.
	StatusCommitted Status = "committed"
	// StatusExpired — terminal: TTL elapsed before FINISH (reaped).
	StatusExpired Status = "expired"
	// StatusRejected — terminal: FINISH validation (e.g. MIME) failed.
	StatusRejected Status = "rejected"
)

// Reservation is one staging row.
//
// It is keyed by ArtifactCID (the bytes to be uploaded), NOT by an entry
// sequence: the artifact-genesis entry's sequence is assigned asynchronously by
// the sequencer, long after the synchronous submission handler stages the
// reservation and returns the upload token. The content address is known at
// submission time and is what the token, the upload, and FINISH all key on.
type Reservation struct {
	ArtifactCID   string    // CID of the bytes that will be uploaded (PRIMARY KEY)
	ContentDigest string    // CID of the plaintext (stable identity; "" = public)
	MIMEType      string    // declared MIME (validated at FINISH for public content; "" = no claim)
	MaxSize       int64     // the reserved / paid byte cap
	Owner         string    // owner DID (genesis custody)
	Status        Status    //
	ExpiresAt     time.Time // token / reservation TTL
	CreatedAt     time.Time //
}

// terminal reports whether s admits no further transition.
func (s Status) terminal() bool {
	return s == StatusCommitted || s == StatusExpired || s == StatusRejected
}

// CanTransition reports whether from -> to is a legal state move. It is the
// single source of truth shared by every Store implementation and the Manager.
func CanTransition(from, to Status) bool {
	if from.terminal() {
		return false
	}
	switch to {
	case StatusUploaded:
		return from == StatusPendingUpload
	case StatusCommitted:
		return from == StatusPendingUpload || from == StatusUploaded
	case StatusExpired:
		return from == StatusPendingUpload || from == StatusUploaded
	case StatusRejected:
		return from == StatusPendingUpload || from == StatusUploaded
	default:
		return false
	}
}
