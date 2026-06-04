/*
FILE PATH: libs/accounting/schema.go

DESCRIPTION:

	Defines the load accounting schema published as a root entity on
	the consortium governance log. This schema declares settlement
	parameters: SLA response windows, max drill frequency, exchange
	rates for surplus/deficit, and settlement period length.

	The schema is published via BuildSchemaEntry (guide §11.3) and
	governed by scope amendment (unanimous consent to change).

KEY DEPENDENCIES:
  - baseproof/builder: BuildSchemaEntry (guide §11.3)
  - baseproof/builder: BuildRootEntity (guide §11.3)
*/
package accounting

import (
	"encoding/json"
	"fmt"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
)

// LoadAccountingParams defines the settlement policy for a consortium.
type LoadAccountingParams struct {
	// SettlementUnit: "USD", "write_credits", "pin_ratio",
	// "state_allocation", "" (free/subsidized)
	SettlementUnit string `json:"settlement_unit"`

	// SettlementPeriodDays is the settlement cycle length.
	SettlementPeriodDays int `json:"settlement_period_days"`

	// SLAResponseWindowSec is the maximum time an escrow node may
	// take to respond to a fire drill before being flagged.
	SLAResponseWindowSec int `json:"sla_response_window_sec"`

	// MaxDrillFrequencyPerDay caps how often fire drills run per
	// escrow node per day. Prevents harassment.
	MaxDrillFrequencyPerDay int `json:"max_drill_frequency_per_day"`

	// StorageRatePerGBMonth is the cost per GB per month for shared
	// storage (relevant for USD and write_credits units).
	StorageRatePerGBMonth float64 `json:"storage_rate_per_gb_month,omitempty"`

	// PinObligationPercent is the percentage of other members'
	// structural blobs each member must pin (for pin_ratio unit).
	PinObligationPercent float64 `json:"pin_obligation_percent,omitempty"`

	// MinStructuralPinners is the minimum number of parties that
	// must pin each structural blob. Default: 3.
	MinStructuralPinners int `json:"min_structural_pinners"`
}

// DefaultLoadAccountingParams returns sensible defaults for a
// state-funded consortium.
func DefaultLoadAccountingParams() LoadAccountingParams {
	return LoadAccountingParams{
		SettlementUnit:          "",
		SettlementPeriodDays:    90,
		SLAResponseWindowSec:    300,
		MaxDrillFrequencyPerDay: 4,
		MinStructuralPinners:    3,
	}
}

// BuildLoadAccountingSchema creates the schema entry payload for the
// load accounting schema. This is published as a root entity on the
// consortium governance log.
func BuildLoadAccountingSchema(params LoadAccountingParams, destination string) ([]byte, error) {
	payload, err := json.Marshal(map[string]any{
		"schema_type":     "load_accounting_v1",
		"load_accounting": params,
	})
	if err != nil {
		return nil, fmt.Errorf("accounting/schema: marshal: %w", err)
	}
	return payload, nil
}

// PublishLoadAccountingEntity creates a root entity entry carrying the
// load accounting parameters. Submit to the consortium log ledger.
func PublishLoadAccountingEntity(
	signerDID string, destination string,
	params LoadAccountingParams,
) (*envelope.Entry, error) {
	payload, err := BuildLoadAccountingSchema(params, destination)
	if err != nil {
		return nil, err
	}

	return builder.BuildRootEntity(builder.RootEntityParams{
		Destination: destination,
		SignerDID:   signerDID,
		Payload:     payload,
	})
}
