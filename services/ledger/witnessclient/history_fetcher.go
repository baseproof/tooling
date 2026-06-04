/*
FILE PATH: witnessclient/history_fetcher.go

WitnessHistoryFetcher adapter — implements api.WitnessHistoryFetcher
over the witness_sets Postgres table. Part II.1 wires this
adapter into the HTTP handlers; api/ stays pgx-free.

The adapter is stateless beyond the *pgxpool.Pool handle —
LoadCurrentSet / LoadSetByHash / LoadSetAtSeq each issue one
query against witness_sets. Boot-time construction takes the
pool; per-request handlers call through.
*/
package witnessclient

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
)

// HistoryFetcher implements api.WitnessHistoryFetcher over the
// witness_sets table. Constructed at boot with a *pgxpool.Pool;
// per-request handlers consume it via the interface.
type HistoryFetcher struct {
	db *pgxpool.Pool
}

// NewHistoryFetcher constructs the adapter. nil pool is rejected
// — a programmer error: the binary's read-side wiring should
// always have a pool by the time handlers compose.
func NewHistoryFetcher(db *pgxpool.Pool) *HistoryFetcher {
	if db == nil {
		panic("witnessclient/HistoryFetcher: nil *pgxpool.Pool (wiring bug)")
	}
	return &HistoryFetcher{db: db}
}

// LoadCurrentSet returns the currently-active witness set. Backs
// GET /v1/network/witnesses/current.
func (h *HistoryFetcher) LoadCurrentSet(ctx context.Context) (*api.WitnessSetView, error) {
	row, err := LoadCurrentSetRow(ctx, h.db)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.Join(api.ErrWitnessSetNotFound, err)
		}
		return nil, err
	}
	return rowToView(row)
}

// LoadSetByHash returns the witness set with the supplied
// content-addressable hash. Backs GET /v1/network/witnesses/
// {set_hash}.
func (h *HistoryFetcher) LoadSetByHash(ctx context.Context, setHash [32]byte) (*api.WitnessSetView, error) {
	row, err := LoadSetByHash(ctx, h.db, setHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.Join(api.ErrWitnessSetNotFound, err)
		}
		return nil, err
	}
	return rowToView(row)
}

// LoadSetAtSeq returns the witness set active at the supplied log
// tree size. Backs GET /v1/network/witnesses/at/{seq}.
func (h *HistoryFetcher) LoadSetAtSeq(ctx context.Context, seq uint64) (*api.WitnessSetView, error) {
	row, err := LoadSetAtSeq(ctx, h.db, seq)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.Join(api.ErrWitnessSetNotFound, err)
		}
		return nil, err
	}
	return rowToView(row)
}

// rowToView projects a WitnessSetRow into the api wire shape.
// keys_json is the serialized []types.WitnessPublicKey produced by
// RotationHandler at persist time (witnessclient/rotation_handler.go's
// keys_json column). The decode unwraps that into typed witness
// records + hex-encodes the pubkey bytes for the JSON wire.
func rowToView(row *WitnessSetRow) (*api.WitnessSetView, error) {
	if row == nil {
		return nil, errors.New("witnessclient/HistoryFetcher: nil row (caller bug)")
	}
	var keys []types.WitnessPublicKey
	if len(row.KeysJSON) > 0 {
		if err := json.Unmarshal(row.KeysJSON, &keys); err != nil {
			return nil, fmt.Errorf("witnessclient/HistoryFetcher: decode keys_json: %w", err)
		}
	}
	wireKeys := make([]api.WitnessPublicKey, 0, len(keys))
	for _, k := range keys {
		entry := api.WitnessPublicKey{
			ID:        hex.EncodeToString(k.ID[:]),
			PublicKey: hex.EncodeToString(k.PublicKey),
			SchemeTag: k.SchemeTag,
		}
		if len(k.ProofOfPossession) > 0 {
			entry.ProofOfPossession = hex.EncodeToString(k.ProofOfPossession)
		}
		wireKeys = append(wireKeys, entry)
	}
	return &api.WitnessSetView{
		SetHash:      hex.EncodeToString(row.SetHash[:]),
		SchemeTag:    row.SchemeTag,
		EffectiveSeq: row.EffectiveSeq,
		RetiredSeq:   row.RetiredSeq,
		Keys:         wireKeys,
	}, nil
}
