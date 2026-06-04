/*
FILE PATH: store/credits.go

Mode A fiat write credit management. One conditional UPDATE per deduction
— the row lock is held only for the UPDATE's commit (no SELECT-then-UPDATE
round-trip), so per-exchange contention is bounded to the UPDATE itself.

KEY ARCHITECTURAL DECISIONS:
  - One rule: a deduction proceeds iff the pre-deduction balance > 0.
    The deduction MAY take the balance negative — a 200-credit caller
    submitting a 256-cost batch ends at -56, fully honored. Subsequent
    deductions while balance <= 0 return ErrInsufficientCredits until
    BulkPurchase restores balance > 0. Each top-up grants exactly ONE
    over-spend window because the gate is the pre-deduction balance.
  - cost parameter: per-entry submissions pass cost=1; batch submissions
    pass cost=N. ONE row UPDATE per HTTP request regardless of the
    entry count — the bottleneck for batch admission was N deductions
    per batch, not the lock itself.
  - BulkPurchase is UPSERT: idempotent for retry safety.
*/
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CreditStore manages Mode A write credits.
type CreditStore struct {
	db *pgxpool.Pool
}

// NewCreditStore creates a credit store.
func NewCreditStore(db *pgxpool.Pool) *CreditStore {
	return &CreditStore{db: db}
}

// DeductInTx atomically subtracts cost from the exchange's balance
// within the supplied transaction, PROVIDED the pre-deduction balance
// is > 0. Returns the post-deduction balance (which MAY be negative —
// a 200-credit caller deducting 256 returns -56). Returns
// ErrInsufficientCredits when no row exists for the exchange or the
// pre-deduction balance is already <= 0.
//
// The check + deduction is a single UPDATE … WHERE balance > 0 RETURNING
// balance. PG's row-level lock serializes concurrent updaters, but is
// held only for the UPDATE's commit — not a SELECT FOR UPDATE round-trip.
//
// Useful when the caller already has a tx open and wants the deduction
// to share its commit boundary. Most callers should use Deduct instead —
// it manages its own ReadCommitted transaction internally and lets the
// api/ side keep zero pgx imports (— Pure CQRS).
func (s *CreditStore) DeductInTx(ctx context.Context, tx pgx.Tx, exchangeDID string, cost int64) (int64, error) {
	if cost <= 0 {
		return 0, fmt.Errorf("store/credits: cost must be > 0, got %d", cost)
	}
	var newBalance int64
	err := tx.QueryRow(ctx,
		`UPDATE credits
		    SET balance        = balance - $1,
		        total_consumed = total_consumed + $1,
		        updated_at     = NOW()
		  WHERE exchange_did = $2
		    AND balance > 0
		RETURNING balance`,
		cost, exchangeDID,
	).Scan(&newBalance)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either no row for this exchange, or balance was already <= 0.
		// Both surface as 402 upstream.
		return 0, ErrInsufficientCredits
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: deduct: %w", err)
	}
	return newBalance, nil
}

// Deduct atomically subtracts cost from the exchange's balance, opening
// + committing its own ReadCommitted transaction internally. See
// DeductInTx for the semantic. Returns ErrInsufficientCredits when no
// row exists for the exchange or the pre-deduction balance is <= 0.
//
// This is the api/ → CreditDeducter surface. The pgx.Tx-taking
// DeductInTx variant is preserved for callers that need to share
// a transaction (e.g., admission paths that bundle credit
// deduction with another DML in one commit).
func (s *CreditStore) Deduct(ctx context.Context, exchangeDID string, cost int64) error {
	return WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		_, err := s.DeductInTx(ctx, tx, exchangeDID, cost)
		return err
	})
}

// BulkPurchase adds credits. UPSERT for idempotent retries.
func (s *CreditStore) BulkPurchase(ctx context.Context, exchangeDID string, amount int64) (int64, error) {
	if amount <= 0 {
		return 0, fmt.Errorf("store/credits: purchase amount must be positive, got %d", amount)
	}
	var newBalance int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO credits (exchange_did, balance, total_purchased, updated_at)
		VALUES ($1, $2, $2, NOW())
		ON CONFLICT (exchange_did) DO UPDATE SET
			balance = credits.balance + $2,
			total_purchased = credits.total_purchased + $2,
			updated_at = NOW()
		RETURNING balance`,
		exchangeDID, amount,
	).Scan(&newBalance)
	if err != nil {
		return 0, fmt.Errorf("store/credits: purchase: %w", err)
	}
	return newBalance, nil
}

// Balance returns the current credit balance for an exchange.
func (s *CreditStore) Balance(ctx context.Context, exchangeDID string) (int64, error) {
	var balance int64
	err := s.db.QueryRow(ctx,
		"SELECT balance FROM credits WHERE exchange_did = $1", exchangeDID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: balance: %w", err)
	}
	return balance, nil
}
