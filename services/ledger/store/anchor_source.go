/*
FILE PATH: store/anchor_source.go

AnchorSourceLogDID — the ONE extraction home for the entry_index
source_log_did projection (migration 0020). Both EntryRow producers call it
(sequencer/loop.go buildLiveStagedEntry and recovery/rebuild.go entryRowFor),
so the forward path and the rebuild path cannot drift — the bit-exact-rebuild
integration test rides on that.
*/
package store

import (
	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
)

// MaxSourceLogDIDLen bounds the projected DID. A larger value is not a valid
// log DID and is dropped (discovery projection — never authority).
const MaxSourceLogDIDLen = 512

// AnchorSourceLogDID returns the SourceLogDID of a cosigned-anchor entry
// (BP-ENTRY-ANCHOR-COSIGNED-HEAD-V1 domain payload), or "" for every other
// entry. "" means "no projection" (SQL NULL — invisible to idx_anchor_source).
//
// DISCOVERY, NOT AUTHORITY: the value is the publisher's own payload field,
// recorded so by-source consumers can FIND the entry; everything trust-bearing
// (inclusion, parent quorum, child-lineage binding) is re-established by the
// consumer from the entry bytes. A payload that does not parse as a cosigned
// anchor projects nothing — omission fails toward alarm (the child's read-back
// and the auditor's feed see no anchor, and the monitor degrades), never
// toward false compliance, so this probe is deliberately tolerant.
func AnchorSourceLogDID(entry *envelope.Entry) string {
	if entry == nil || len(entry.DomainPayload) == 0 {
		return ""
	}
	if !sdkanchor.IsCosignedAnchor(entry.DomainPayload) {
		return ""
	}
	a, err := sdkanchor.ParseCosignedAnchorV1(entry.DomainPayload)
	if err != nil || a.SourceLogDID == "" || len(a.SourceLogDID) > MaxSourceLogDIDLen {
		return ""
	}
	return a.SourceLogDID
}
