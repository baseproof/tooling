/*
FILE PATH: libs/anchorfeed/feed.go

The forensic anchor feed: by-source discovery → parent-provenanced entry bytes
→ decoded anchor payloads → verifier.AnchorEvidence. The one bridge both
consumers share (the child publisher's confirmation read-back and the
auditors' constitutional monitor).

# COMPOSITION + PERSISTENCE ONLY — NO ACCEPT/REJECT

This package wraps existing SDK seams and deliberately contains no judgment:

  - Parent-side PROVENANCE goes through the SDK's MultiLog/EntryProof path:
    the parent log is registered in an anchor.MultiLog under ITS verified
    head + witness set (anchor.ForeignLogFromAnchor or a locally-trusted
    LogConfig — the caller's choice), and entry bytes are read via
    MultiLog.Entry. No hand-rolled Merkle/cosign calls live here.
  - Payload decoding is anchor.ParseCosignedAnchorV1 — the SDK's parse-only
    codec. A payload it refuses is reported as an error item, never silently
    classified.
  - CHILD-LINEAGE BINDING IS NOT DONE HERE. The embedded head is NOT
    pre-verified against any witness set: that rule belongs to
    verifier.LatestAnchorObservation against the rotation-replayed CURRENT
    set, and a feed-side check against a static set would duplicate the rule
    against the wrong set. Evidence flows through un-judged; the SDK
    reduction accepts or ignores it. (The moment any accept/reject logic
    appears in this package, that rule moves SDK-side, next to
    ParseCosignedAnchorV1.)
  - PERSISTENCE is the FirstSeen hook: VerifiedAt must be the durable FIRST
    successful observation, never refreshed (or a stale anchor re-polled
    every cycle reads permanently fresh — the lazy-fresh hole). The durable
    home is the caller's store (the ledger's anchor_confirmations, the
    auditor's journal); a nil hook degrades to the in-process observation
    time, which is correct only for single-shot offline use.

The by-source discovery page (the parent's
GET /v1/network/anchors/by-source/{log_did}) supplies POSITIONS only —
discovery, not authority. Bytes are then read through the MultiLog so what is
decoded is exactly what the parent's trust root vouches for.
*/
package anchorfeed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// FirstSeen returns the durable first-observation time for the anchor entry
// at parentSeq on parentLogDID (keyed however the caller's store keys it —
// the payload's network-bound head digest is the natural key). observedAt is
// the current observation; an implementation MUST return the stored earlier
// time when one exists and MUST NOT advance it on re-observation.
type FirstSeen func(parentLogDID string, parentSeq uint64, treeHeadRef string, observedAt time.Time) time.Time

// Item is one decoded anchor observation, paired with where it came from.
type Item struct {
	ParentSeq uint64
	Anchor    anchor.CosignedAnchorV1
	Evidence  verifier.AnchorEvidence
}

// CollectEvidence reads the anchor entries at seqs from parentLogDID — which
// MUST be registered in ml under the parent's trust root — decodes each
// payload, and assembles verifier.AnchorEvidence:
//
//	Head            ← the payload's embedded cosigned head (decoded, NOT verified)
//	AnchorNetworkID ← parentNetworkID (the caller-established parent pin)
//	AnchoredAt      ← the payload's self-reported RFC3339 claim (zero if absent/bad)
//	VerifiedAt      ← firstSeen(...) — the durable first observation
//
// Entries that cannot be read, deserialized, or parsed as cosigned anchors
// are returned as errors (one per failed seq), never dropped silently and
// never judged here. now is the observation clock (testability).
func CollectEvidence(
	ctx context.Context,
	ml *anchor.MultiLog,
	parentLogDID string,
	parentNetworkID [32]byte,
	seqs []uint64,
	firstSeen FirstSeen,
	now func() time.Time,
) ([]Item, []error) {
	if now == nil {
		now = time.Now
	}
	var items []Item
	var errs []error
	for _, seq := range seqs {
		pos := types.LogPosition{LogDID: parentLogDID, Sequence: seq}
		proof, err := ml.Entry(ctx, pos, verifier.AsOf{})
		if err != nil {
			errs = append(errs, fmt.Errorf("anchorfeed: seq %d: read via parent trust root: %w", seq, err))
			continue
		}
		if proof.Meta == nil {
			errs = append(errs, fmt.Errorf("anchorfeed: seq %d: empty entry proof", seq))
			continue
		}
		entry, err := envelope.Deserialize(proof.Meta.CanonicalBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("anchorfeed: seq %d: deserialize: %w", seq, err))
			continue
		}
		a, err := anchor.ParseCosignedAnchorV1(entry.DomainPayload)
		if err != nil {
			errs = append(errs, fmt.Errorf("anchorfeed: seq %d: %w", seq, err))
			continue
		}
		finding, err := findings.CosignedTreeHeadFromWire(a.Head)
		if err != nil {
			errs = append(errs, fmt.Errorf("anchorfeed: seq %d: decode embedded head: %w", seq, err))
			continue
		}
		// The child's self-reported claim. A missing/bad timestamp parses to
		// the zero time and the SDK reduction ignores the item (fail-closed
		// THERE, where the rule lives — not here).
		var anchoredAt time.Time
		if a.AnchoredAt != "" {
			if t, perr := time.Parse(time.RFC3339, a.AnchoredAt); perr == nil {
				anchoredAt = t
			}
		}
		observed := now().UTC()
		verifiedAt := observed
		if firstSeen != nil {
			verifiedAt = firstSeen(parentLogDID, seq, a.TreeHeadRef, observed)
		}
		items = append(items, Item{
			ParentSeq: seq,
			Anchor:    a,
			Evidence: verifier.AnchorEvidence{
				Head:            finding.Head,
				AnchorNetworkID: parentNetworkID,
				AnchoredAt:      anchoredAt,
				VerifiedAt:      verifiedAt,
			},
		})
	}
	return items, errs
}

// Evidence projects just the AnchorEvidence slice from items — the shape
// verifier.LatestAnchorObservation / CheckAnchoringEvidence consume.
func Evidence(items []Item) []verifier.AnchorEvidence {
	out := make([]verifier.AnchorEvidence, 0, len(items))
	for _, it := range items {
		out = append(out, it.Evidence)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// By-source discovery pager (positions only)
// ─────────────────────────────────────────────────────────────────────

// bySourcePage mirrors the parent's /v1/network/anchors/by-source page
// envelope (the standard query-page shape). Only sequence numbers are
// consumed: DISCOVERY, never authority — bytes come from the MultiLog.
type bySourcePage struct {
	Entries []struct {
		SequenceNumber uint64 `json:"sequence_number"`
	} `json:"entries"`
	Count int `json:"count"`
}

// FetchBySourceSeqs pages the parent's by-source discovery endpoint and
// returns every anchor-entry sequence it lists for sourceLogDID, walking the
// keyset cursor until a short page. client is REQUIRED (the no-silent-
// -fallback contract: the caller chooses transport + TLS posture).
func FetchBySourceSeqs(ctx context.Context, client *http.Client, parentBaseURL, sourceLogDID string, pageSize int) ([]uint64, error) {
	if client == nil {
		return nil, fmt.Errorf("anchorfeed: nil http client (no silent fallback — the caller owns transport posture)")
	}
	if pageSize <= 0 {
		pageSize = 256
	}
	var seqs []uint64
	start := uint64(0)
	for {
		u := fmt.Sprintf("%s/v1/network/anchors/by-source/%s?start=%d&count=%d",
			parentBaseURL, url.PathEscape(sourceLogDID), start, pageSize)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return seqs, fmt.Errorf("anchorfeed: build by-source request: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return seqs, fmt.Errorf("anchorfeed: by-source fetch: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return seqs, fmt.Errorf("anchorfeed: by-source %s returned %d", u, resp.StatusCode)
		}
		var page bySourcePage
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return seqs, fmt.Errorf("anchorfeed: by-source page decode: %w", err)
		}
		for _, e := range page.Entries {
			seqs = append(seqs, e.SequenceNumber)
		}
		if len(page.Entries) < pageSize {
			return seqs, nil
		}
		start = page.Entries[len(page.Entries)-1].SequenceNumber + 1
	}
}
