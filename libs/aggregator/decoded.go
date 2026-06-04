// Package aggregator is the domain-agnostic ledger→projection ingestion engine.
//
// It polls a transparency log, decodes each entry's SDK envelope into a
// DecodedEntry (header fields + raw payload — nothing domain-specific), and
// drives it through an injected Projector. The network supplies the Projector
// (classify + index) and its own schema; the engine owns only polling,
// decoding, and per-log watermark progress. This is Ledger Principle 12
// (schema-aware extractor inversion): the domain dictates WHAT to extract, the
// engine dictates HOW the scan advances.
//
// State is a REBUILDABLE projection: reset a log's watermark to 0 and re-scan to
// reconstruct it from the log — the engine never holds authoritative state.
package aggregator

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/envelope"

	"github.com/baseproof/tooling/libs/clitools"
)

// DecodedEntry is the agnostic, envelope-derived view of a ledger entry. Every
// field comes from the SDK control header or the raw domain payload; none from
// any network schema. A Projector classifies and indexes it.
type DecodedEntry struct {
	LogDID        string
	Sequence      uint64
	LogTime       time.Time
	SignerDID     string
	AuthorityPath string // "", "same_signer", "delegation", "scope_authority"
	TargetRootSeq *uint64
	DelegateDID   *string
	Payload       map[string]any
	Entry         *envelope.Entry
}

// Decode deserializes a raw ledger entry into a DecodedEntry. It performs only
// SDK-level envelope parsing — never any domain classification (that is the
// Projector's job, injected by the network).
func Decode(logDID string, raw clitools.RawEntry) (*DecodedEntry, error) {
	canonicalBytes, err := hex.DecodeString(raw.CanonicalHex)
	if err != nil {
		return nil, fmt.Errorf("aggregator: decode canonical: %w", err)
	}
	entry, err := envelope.Deserialize(canonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("aggregator: deserialize: %w", err)
	}
	h := &entry.Header

	var payload map[string]any
	if len(entry.DomainPayload) > 0 {
		_ = json.Unmarshal(entry.DomainPayload, &payload)
	}
	if payload == nil {
		payload = map[string]any{}
	}

	d := &DecodedEntry{
		LogDID:    logDID,
		Sequence:  raw.Sequence,
		SignerDID: h.SignerDID,
		Payload:   payload,
		Entry:     entry,
	}
	if raw.LogTimeUnixMicro != 0 {
		d.LogTime = time.UnixMicro(raw.LogTimeUnixMicro)
	}
	if h.TargetRoot != nil {
		seq := h.TargetRoot.Sequence
		d.TargetRootSeq = &seq
	}
	if h.DelegateDID != nil {
		d.DelegateDID = h.DelegateDID
	}
	if h.AuthorityPath != nil {
		switch *h.AuthorityPath {
		case envelope.AuthoritySameSigner:
			d.AuthorityPath = "same_signer"
		case envelope.AuthorityDelegation:
			d.AuthorityPath = "delegation"
		case envelope.AuthorityScopeAuthority:
			d.AuthorityPath = "scope_authority"
		}
	}
	return d, nil
}
