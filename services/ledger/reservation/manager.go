/*
FILE PATH:

	reservation/manager.go

DESCRIPTION:

	Manager — the RESERVE -> token -> UPLOAD -> FINISH -> REAP lifecycle logic
	(ledger#193 Phase 4), written entirely against the Store port, the
	storage.ContentStore port, and an injectable clock, so it is fully unit-tested
	against the in-memory fake + an in-memory content store + a fake clock — no
	database, no wall-clock flakiness (the Kubernetes controller-test pattern).

	- Reserve: create a PENDING_UPLOAD row + mint a signed UploadToken. Called by
	  admission AFTER accounting (PoW / credits) clears.
	- Finish: confirm the bytes Exist; for public content, validate the declared
	  MIME; CAS to COMMITTED. Missing bytes => ErrIncomplete (retryable until
	  TTL); validation failure => REJECTED. Idempotent on an already-COMMITTED row.
	- Reap: move expired PENDING/UPLOADED reservations to EXPIRED and GC their
	  staged bytes (best-effort).

KEY ARCHITECTURAL DECISIONS:
  - The clock is a field (func() time.Time), defaulting to time.Now, so expiry
    and reaping are deterministic under test.
  - "Done" is defined by the artifact store (Exists), never by trusting the
    client — the completeness oracle of the protocol.
  - All transitions go through Store.SetStatus CAS, so concurrent FINISH/REAP
    cannot double-commit or commit-after-expire.
*/
package reservation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/crypto/artifact"
	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

// ErrIncomplete is returned by Finish when the artifact bytes are not yet present
// in the store — the upload has not landed. Not terminal: the client may retry
// FINISH until the reaper expires the reservation past its TTL.
var ErrIncomplete = errors.New("reservation: artifact bytes not present (incomplete upload)")

// ErrRejected is returned by Finish when FINISH-time validation fails. The
// reservation is moved to REJECTED and never committed.
var ErrRejected = errors.New("reservation: content rejected at finish")

// Manager runs the reservation lifecycle over its ports.
type Manager struct {
	store     Store
	content   storage.ContentStore
	validator artifact.ContentValidator // nil => no MIME validation
	signKey   ed25519.PrivateKey
	networkID string
	ttl       time.Duration
	now       func() time.Time
}

// Config configures a Manager.
type Config struct {
	Store   Store
	Content storage.ContentStore
	// Validator is the content-type validator for the FINISH gate — the SDK
	// crypto/artifact mechanism (a ValidatorRegistry of reference + custom
	// validators), built once from deployment config. nil => no MIME validation.
	// It is plain verification code, not an on-log fact: the integrity invariant
	// is "the committed bytes match their signed MIME claim", and an auditor
	// re-checks it with the SAME SDK mechanism — no policy needs to live on the log.
	Validator artifact.ContentValidator
	SignKey   ed25519.PrivateKey
	NetworkID string
	TTL       time.Duration
	// Now is an injectable clock for deterministic tests; nil => time.Now.
	Now func() time.Time
}

// NewManager builds a Manager. TTL defaults to 15m; Now defaults to time.Now.
func NewManager(cfg Config) *Manager {
	if cfg.TTL <= 0 {
		cfg.TTL = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{
		store: cfg.Store, content: cfg.Content, validator: cfg.Validator,
		signKey: cfg.SignKey, networkID: cfg.NetworkID, ttl: cfg.TTL, now: cfg.Now,
	}
}

// ReserveRequest is the admission-supplied detail of an artifact genesis entry
// (decoded from storage.ArtifactGenesis at submission time).
type ReserveRequest struct {
	ArtifactCID   string
	ContentDigest string
	MIMEType      string
	MaxSize       int64
	Owner         string
}

// Reserve stages a PENDING_UPLOAD reservation and returns a signed upload token.
// Called synchronously by the submission handler once PoW / credit accounting has
// cleared and the artifact-genesis entry is durable. Keyed by ArtifactCID — the
// content address known at submission time (the entry's sequence is not).
func (m *Manager) Reserve(ctx context.Context, req ReserveRequest) (string, error) {
	if req.ArtifactCID == "" {
		return "", fmt.Errorf("reservation: ArtifactCID required")
	}
	now := m.now()
	expiresAt := now.Add(m.ttl)
	r := Reservation{
		ArtifactCID: req.ArtifactCID, ContentDigest: req.ContentDigest,
		MIMEType: req.MIMEType, MaxSize: req.MaxSize, Owner: req.Owner,
		Status: StatusPendingUpload, ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := m.store.Create(ctx, r); err != nil {
		return "", err
	}
	tok := artifactstore.UploadToken{
		NetworkID:   m.networkID,
		ArtifactCID: req.ArtifactCID,
		MaxSize:     req.MaxSize,
		ExpiresAt:   expiresAt.UnixMicro(),
	}
	return artifactstore.SignUploadToken(tok, m.signKey)
}

// Finish confirms the upload and commits the reservation. Idempotent: an
// already-COMMITTED reservation returns success. Returns ErrIncomplete if the
// bytes are absent and ErrRejected if validation fails.
func (m *Manager) Finish(ctx context.Context, artifactCID string) (Reservation, error) {
	r, err := m.store.Get(ctx, artifactCID)
	if err != nil {
		return Reservation{}, err
	}
	if r.Status == StatusCommitted {
		return r, nil // idempotent
	}
	if r.Status != StatusPendingUpload && r.Status != StatusUploaded {
		return r, fmt.Errorf("reservation %s not finishable from %s", artifactCID, r.Status)
	}

	cid, err := storage.ParseCID(r.ArtifactCID)
	if err != nil {
		return r, fmt.Errorf("reservation %s: bad ArtifactCID: %w", artifactCID, err)
	}

	// Completeness oracle: are the bytes durably present?
	present, err := m.content.Exists(ctx, cid)
	if err != nil {
		return r, fmt.Errorf("reservation %s: exists check: %w", artifactCID, err)
	}
	if !present {
		return r, ErrIncomplete
	}

	// FINISH-time MIME validation for public content (a declared MIME). The
	// integrity check is simply: "do I have a validator for this declared type,
	// and do these bytes match it?" The validator is verification code (the SDK
	// crypto/artifact mechanism, reference + custom validators), not an on-log
	// fact. Sealed content carries no MIME here; its signed claim is validated by
	// the consumer against the decrypted plaintext at disclosure.
	if m.validator != nil && r.MIMEType != "" {
		data, err := m.content.Fetch(ctx, cid)
		if err != nil {
			return r, fmt.Errorf("reservation %s: fetch for validation: %w", artifactCID, err)
		}
		if verr := m.validator.Validate(ctx, r.MIMEType, data); verr != nil {
			if serr := m.store.SetStatus(ctx, artifactCID, r.Status, StatusRejected); serr != nil && !errors.Is(serr, ErrConflict) {
				return r, serr
			}
			return r, fmt.Errorf("%w: %v", ErrRejected, verr)
		}
	}

	if err := m.store.SetStatus(ctx, artifactCID, r.Status, StatusCommitted); err != nil {
		// A concurrent reaper/finisher won the CAS — re-read to report the truth.
		if errors.Is(err, ErrConflict) {
			if cur, gerr := m.store.Get(ctx, artifactCID); gerr == nil {
				if cur.Status == StatusCommitted {
					return cur, nil
				}
				return cur, fmt.Errorf("reservation %s: lost finish race, now %s", artifactCID, cur.Status)
			}
		}
		return r, err
	}
	r.Status = StatusCommitted
	return r, nil
}

// Reap moves every expired non-terminal reservation to EXPIRED and best-effort
// GCs its staged bytes. Returns the number reaped. Intended to run on a ticker
// (see Reaper).
func (m *Manager) Reap(ctx context.Context, limit int) (int, error) {
	now := m.now()
	expirable, err := m.store.ListExpirable(ctx, now, limit)
	if err != nil {
		return 0, err
	}
	reaped := 0
	for _, r := range expirable {
		if err := m.store.SetStatus(ctx, r.ArtifactCID, r.Status, StatusExpired); err != nil {
			continue // lost the race to a concurrent finish/reap — fine
		}
		reaped++
		if cid, perr := storage.ParseCID(r.ArtifactCID); perr == nil {
			_ = m.content.Delete(ctx, cid) // best-effort staged-byte GC
		}
	}
	return reaped, nil
}
