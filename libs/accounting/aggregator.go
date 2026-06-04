/*
FILE PATH: libs/accounting/aggregator.go

DESCRIPTION:

	Computes deterministic settlement between two cosigned tree head
	boundaries. Uses ScanFromPosition (guide §27.3) to iterate entries
	in the bounded range and ClassifyEntry (guide §11.1) to identify
	entry types. Counts per-county contributions for settlement.

	The aggregator is deterministic: given the same tree head boundaries,
	every node computes the same settlement ledger. This is critical
	for dispute resolution — any party can independently verify the
	aggregation.

KEY DEPENDENCIES:
  - baseproof/log: LedgerQueryAPI.ScanFromPosition (guide §27.3)
  - baseproof/builder: ClassifyEntry (guide §11.1)
  - baseproof/types: EntryWithMetadata, CosignedTreeHead
*/
package accounting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/crosslog"
)

// SettlementLedger records per-member usage between two tree head
// boundaries.
type SettlementLedger struct {
	// StartTreeHead is the lower boundary (inclusive).
	StartPos uint64 `json:"start_pos"`

	// EndTreeHead is the upper boundary (exclusive).
	EndPos uint64 `json:"end_pos"`

	// MemberUsage maps member DID → usage counters.
	MemberUsage map[string]*MemberUsage `json:"member_usage"`

	// TotalEntries is the total entry count in the range.
	TotalEntries uint64 `json:"total_entries"`
}

// MemberUsage tracks a single member's contributions in a settlement
// period.
type MemberUsage struct {
	EntryCount      uint64 `json:"entry_count"`
	DelegationCount uint64 `json:"delegation_count"`
	SchemaCount     uint64 `json:"schema_count"`
	CommentaryCount uint64 `json:"commentary_count"`
	AmendmentCount  uint64 `json:"amendment_count"`
	// NetworkCount counts network-walker entries (witness endpoint
	// declarations, witness identity labels, auditor registrations,
	// auditor scope amendments) the signer published. Distinct from
	// AmendmentCount (authority-scope amendments) — network records are
	// admin surfaces, not member workload.
	NetworkCount uint64 `json:"network_count"`
	OtherCount   uint64 `json:"other_count"`
}

// Aggregator computes settlement ledgers from log scans.
type Aggregator struct {
	queryAPI log.LedgerQueryAPI
}

// NewAggregator creates an aggregator bound to a specific log's query API.
func NewAggregator(queryAPI log.LedgerQueryAPI) *Aggregator {
	return &Aggregator{queryAPI: queryAPI}
}

// ComputeSettlement scans entries between startPos and endPos and
// produces a deterministic settlement ledger.
func (a *Aggregator) ComputeSettlement(ctx context.Context, startPos, endPos uint64) (*SettlementLedger, error) {
	if startPos >= endPos {
		return nil, fmt.Errorf("accounting/aggregator: start %d >= end %d", startPos, endPos)
	}

	ledger := &SettlementLedger{
		StartPos:    startPos,
		EndPos:      endPos,
		MemberUsage: make(map[string]*MemberUsage),
	}

	// Scan entries in the bounded range.
	entries, err := a.queryAPI.ScanFromPosition(ctx, startPos, int(endPos-startPos))
	if err != nil {
		return nil, fmt.Errorf("accounting/aggregator: scan: %w", err)
	}

	for _, meta := range entries {
		ledger.TotalEntries++

		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			continue
		}
		signerDID := entry.Header.SignerDID
		usage := ledger.ensureMember(signerDID)

		// Kind-discriminate the domain payload BEFORE the header
		// classification. Network-walker entries (witness endpoints/
		// labels, auditor registrations + scope amendments) are admin
		// surfaces, not member workload — they get their own counter so a
		// settlement run that includes a burst of admin records doesn't
		// mis-attribute them to the signer's OtherCount bucket.
		decoded, ndErr := crosslog.DecodeNetworkEntry(entry.DomainPayload)
		if ndErr != nil {
			if errors.Is(ndErr, crosslog.ErrMalformedNetworkPayload) {
				slog.Warn("accounting/aggregator: malformed network payload",
					"pos", meta.Position.Sequence, "err", ndErr)
			}
			// Either malformed (counted as Other below for visibility)
			// or a kind-matched SDK validation failure (same — operator
			// has a structural bug; an Other increment surfaces it via
			// the settlement diff).
			usage.OtherCount++
			usage.EntryCount++
			continue
		}
		if decoded != nil {
			usage.NetworkCount++
			usage.EntryCount++
			continue
		}

		// Lightweight classification from header fields.
		// Full ClassifyEntry requires LeafReader+Fetcher (not available here).
		h := &entry.Header
		switch {
		case h.DelegateDID != nil:
			usage.DelegationCount++
		case h.TargetRoot == nil && h.AuthorityPath == nil:
			usage.CommentaryCount++
		case h.AuthoritySet != nil || (h.AuthorityPath != nil && *h.AuthorityPath == envelope.AuthorityScopeAuthority):
			usage.AmendmentCount++ // scope amendments
		default:
			usage.OtherCount++
		}
		usage.EntryCount++
	}

	return ledger, nil
}

// ensureMember returns the MemberUsage for a DID, creating it if needed.
func (l *SettlementLedger) ensureMember(did string) *MemberUsage {
	if u, ok := l.MemberUsage[did]; ok {
		return u
	}
	u := &MemberUsage{}
	l.MemberUsage[did] = u
	return u
}

// ToJSON serializes the ledger for on-log publication or off-log audit.
func (l *SettlementLedger) ToJSON() ([]byte, error) {
	return json.Marshal(l)
}

// ComputeArtifactUsage scans a log between two positions and extracts
// per-member artifact storage usage via the caller-supplied extractCID
// callback. Domain Payload opacity is absolute — this library never
// parses domain payloads; the domain supplies the extractor.
func (a *Aggregator) ComputeArtifactUsage(
	ctx context.Context,
	startPos, endPos uint64,
	extractCID func(entry types.EntryWithMetadata) (string, int64, bool),
) (map[string]int64, error) {
	if extractCID == nil {
		return nil, fmt.Errorf("accounting/aggregator: nil extractCID function")
	}

	usage := make(map[string]int64) // member DID → total bytes

	entries, err := a.queryAPI.ScanFromPosition(ctx, startPos, int(endPos-startPos))
	if err != nil {
		return nil, fmt.Errorf("accounting/aggregator: artifact scan: %w", err)
	}

	for _, meta := range entries {
		_, sizeBytes, hasCID := extractCID(meta)
		if !hasCID {
			continue
		}
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			continue
		}
		signerDID := entry.Header.SignerDID
		usage[signerDID] += sizeBytes
	}

	return usage, nil
}
