/*
FILE PATH: libs/federation/formation.go

DESCRIPTION:

	Creates a new consortium scope entity and provisions the consortium
	log. A consortium is a governance body over multiple member networks
	that share infrastructure, schemas, or economic settlement.

KEY DEPENDENCIES:
  - baseproof/lifecycle: ProvisionSingleLog, SingleLogConfig,
    LogProvision (guide §20.1)
  - baseproof/builder: BuildScopeCreation (guide §11.3)
  - baseproof/types: used for result types

OVERVIEW:

	FormConsortium(cfg) →
	  ProvisionSingleLog for the consortium log
	  Returns ConsortiumProvision with scope entry + log provision
*/
package federation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/lifecycle"
)

// ConsortiumConfig defines a new consortium.
type ConsortiumConfig struct {
	// ConsortiumDID is the institutional DID for the consortium.
	// Example: did:web:example.org:consortium
	ConsortiumDID string

	// Destination is the DID of the destination EXCHANGE the provisioning
	// entries are signature-bound to (SDK envelope ControlHeader.Destination —
	// the cross-exchange replay defense). It is distinct from the network
	// (NetworkID / witness trust domain) and from the log (LogDID / physical
	// storage): one network's single log may host several exchanges. Required.
	Destination string

	// LogDID is the DID for the consortium's governance log (physical storage —
	// distinct from Destination). One network = one log.
	// Example: did:web:example.org:consortium:governance
	LogDID string

	// AuthoritySet is the initial scope authority set. Must include
	// the consortium DID, plus the DIDs of the member networks'
	// representatives.
	AuthoritySet map[string]struct{}

	// Name is a human-readable consortium name.
	Name string

	// SettlementUnit declares the economic settlement unit.
	// Options: "USD", "write_credits", "pin_ratio",
	//          "state_allocation", "" (free/subsidized)
	SettlementUnit string

	// SettlementPeriodDays is the settlement cycle length in days.
	// 0 means no periodic settlement.
	SettlementPeriodDays int

	// EventTime overrides the formation timestamp. Zero → time.Now().
	EventTime int64
}

// ConsortiumProvision carries the provisioned consortium log.
type ConsortiumProvision struct {
	Log *lifecycle.LogProvision
}

// FormConsortium provisions the consortium governance log and creates
// the scope entity. The returned entries must be submitted to the
// consortium log's ledger.
func FormConsortium(cfg ConsortiumConfig) (*ConsortiumProvision, error) {
	if cfg.ConsortiumDID == "" {
		return nil, fmt.Errorf("consortium/formation: empty consortium DID")
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("consortium/formation: empty log DID")
	}
	if cfg.Destination == "" {
		return nil, fmt.Errorf("consortium/formation: empty destination DID")
	}
	if len(cfg.AuthoritySet) == 0 {
		return nil, fmt.Errorf("consortium/formation: empty authority set")
	}
	if _, ok := cfg.AuthoritySet[cfg.ConsortiumDID]; !ok {
		return nil, fmt.Errorf("consortium/formation: consortium DID must be in authority set")
	}

	eventTime := cfg.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	scopePayload, err := json.Marshal(map[string]any{
		"consortium_did":         cfg.ConsortiumDID,
		"log_did":                cfg.LogDID,
		"name":                   cfg.Name,
		"settlement_unit":        cfg.SettlementUnit,
		"settlement_period_days": cfg.SettlementPeriodDays,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/formation: marshal scope payload: %w", err)
	}

	logProvision, err := lifecycle.ProvisionSingleLog(lifecycle.SingleLogConfig{
		Destination:  cfg.Destination,
		SignerDID:    cfg.ConsortiumDID,
		LogDID:       cfg.LogDID,
		AuthoritySet: cfg.AuthoritySet,
		ScopePayload: scopePayload,
		EventTime:    eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("consortium/formation: provision log: %w", err)
	}

	return &ConsortiumProvision{Log: logProvision}, nil
}
