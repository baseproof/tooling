package loadgen

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
)

// SubmitParams configures a single-entry submission — the unified CLI's `submit`
// command (one real client action), as opposed to Run's bulk load. HTTPClient and
// LogDID are required.
type SubmitParams struct {
	LedgerURL      string
	LogDID         string
	Token          string // "" ⇒ Mode B PoW; non-empty ⇒ Mode A credit
	Difficulty     uint32 // Mode B; 0 ⇒ queried from the ledger
	EpochWindowSec uint64
	SeqTimeout     time.Duration
	HTTPClient     *http.Client
}

// SubmitOne admits one already-built, keyed entry and returns its assigned
// sequence. It drives the SAME admission/transport engine as Run, so a single
// client submit and a bulk load can never drift in how they stamp, sign, or post.
func SubmitOne(ctx context.Context, p SubmitParams, entry *envelope.Entry, priv *ecdsa.PrivateKey, signerDID string) (uint64, error) {
	if p.HTTPClient == nil {
		return 0, fmt.Errorf("loadgen: SubmitParams.HTTPClient is required")
	}
	if p.LogDID == "" {
		return 0, fmt.Errorf("loadgen: SubmitParams.LogDID is required")
	}
	e := &engine{
		client: p.HTTPClient, ledgerURL: p.LedgerURL, logDID: p.LogDID,
		token: p.Token, difficulty: p.Difficulty, epochWindowSec: p.EpochWindowSec,
		seqTimeout: p.SeqTimeout,
	}
	if e.epochWindowSec == 0 {
		e.epochWindowSec = 3600
	}
	if e.seqTimeout <= 0 {
		e.seqTimeout = 120 * time.Second
	}
	if e.token == "" && e.difficulty == 0 {
		d, err := e.queryDifficulty(ctx)
		if err != nil {
			return 0, fmt.Errorf("loadgen: query difficulty: %w", err)
		}
		e.difficulty = d
	}
	hash, err := e.signAndSubmit(ctx, entry, priv, signerDID)
	if err != nil {
		return 0, err
	}
	return e.waitForSequence(ctx, hash)
}
