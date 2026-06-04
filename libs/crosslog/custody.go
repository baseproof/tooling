/*
FILE PATH: libs/crosslog/custody.go

Projects the on-log artifact-custody entries — the ArtifactGenesis owner +
BP-ENTRY-ARTIFACT-CUSTODY-TRANSFER-V1 links + BP-ENTRY-ARTIFACT-DESTRUCTION-V1
records — from a flat slice of pre-positioned envelope entries into per-artifact
chains keyed by ContentDigest, ready for storage.ArtifactCustodyAt.

# WHY THIS HELPER EXISTS

The ledger gates restricted artifact reads on the on-log custody chain
(artifactstore.CustodyHook → storage.ArtifactCustodyAt). The auditor must
INDEPENDENTLY re-derive that chain to detect one the ledger should never have
admitted (a forged transfer whose FromOwner is not the current owner, a
cross-content splice, …). The SDK ships the walk + the wire decoders; this helper
does the kind-discriminated decode + per-ContentDigest grouping + EffectivePos
stamping in one place, mirroring the ledger's own projector
(ledger/custody/query_source.go), which stamps EffectivePos from each entry's
on-log Position. EffectivePos is NOT a wire field — the SDK walk orders + bounds
by it, so it MUST be the authoritative on-log position, not anything the payload
claims.

# WARN-AND-CONTINUE

Mirrors MaterializeFromEntries / MaterializeGovernance: a per-entry decode
failure logs a structured warn and continues; a non-custody entry is silently
skipped. A single malformed custody entry never aborts the projection.

KEY DEPENDENCIES: baseproof/storage (the custody carriage + walk), baseproof/kinds.
*/
package crosslog

import (
	"encoding/json"
	"log/slog"

	"github.com/baseproof/baseproof/kinds"
	"github.com/baseproof/baseproof/storage"
)

// CustodyChain is one artifact's on-log custody chain: the genesis record
// (derived from its ArtifactGenesis entry), the EffectivePos-stamped transfer
// links, and an optional destruction record. It is exactly the input
// storage.ArtifactCustodyAt walks.
type CustodyChain struct {
	Genesis     storage.ArtifactCustodyRecord
	Transfers   []storage.ArtifactCustodyTransfer
	Destruction *storage.ArtifactDestruction
}

// MaterializedCustody holds the per-artifact custody chains keyed by the
// ContentDigest the chain binds to (CID.String()).
type MaterializedCustody struct {
	Chains map[string]*CustodyChain
}

// MaterializeCustody decodes the artifact-genesis / custody-transfer /
// destruction entries into per-ContentDigest chains, stamping EffectivePos on
// each transfer/destruction from its on-log Position. logger nil routes to
// slog.Default().
func MaterializeCustody(entries []EntryAtPosition, logger *slog.Logger) MaterializedCustody {
	if logger == nil {
		logger = slog.Default()
	}
	out := MaterializedCustody{Chains: map[string]*CustodyChain{}}
	chainFor := func(cd storage.CID) *CustodyChain {
		k := cd.String()
		ch := out.Chains[k]
		if ch == nil {
			ch = &CustodyChain{}
			out.Chains[k] = ch
		}
		return ch
	}

	for _, e := range entries {
		if e.Entry == nil || len(e.Entry.DomainPayload) == 0 {
			continue
		}
		payload := e.Entry.DomainPayload
		var probe kindProbe
		if err := json.Unmarshal(payload, &probe); err != nil {
			logger.Warn("crosslog/custody: payload not JSON-parseable",
				"seq", e.Position.Sequence, "err", err)
			continue
		}
		switch probe.Kind {
		case kinds.EntryArtifactGenesisV1:
			g, err := storage.DecodeArtifactGenesisPayload(payload)
			if err != nil {
				logger.Warn("crosslog/custody: artifact_genesis decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			rec := storage.CustodyGenesisFromArtifactGenesis(g, e.Position)
			chainFor(rec.ContentDigest).Genesis = rec
			logger.Debug("crosslog/custody: artifact_genesis",
				"seq", e.Position.Sequence, "content_digest", rec.ContentDigest.String())
		case kinds.EntryArtifactCustodyTransferV1:
			t, err := storage.DecodeArtifactCustodyTransferPayload(payload)
			if err != nil {
				logger.Warn("crosslog/custody: custody_transfer decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			t.EffectivePos = e.Position // authority is where the entry landed
			ch := chainFor(t.ContentDigest)
			ch.Transfers = append(ch.Transfers, t)
			logger.Debug("crosslog/custody: custody_transfer",
				"seq", e.Position.Sequence, "content_digest", t.ContentDigest.String())
		case kinds.EntryArtifactDestructionV1:
			d, err := storage.DecodeArtifactDestructionPayload(payload)
			if err != nil {
				logger.Warn("crosslog/custody: destruction decode rejected",
					"seq", e.Position.Sequence, "err", err)
				continue
			}
			d.EffectivePos = e.Position
			ch := chainFor(d.ContentDigest)
			// Earliest destruction wins (the first in-effect erasure).
			if ch.Destruction == nil || d.EffectivePos.Less(ch.Destruction.EffectivePos) {
				rec := d
				ch.Destruction = &rec
			}
			logger.Debug("crosslog/custody: destruction",
				"seq", e.Position.Sequence, "content_digest", d.ContentDigest.String())
		default:
			// Some other kind — silently skip.
		}
	}

	logger.Info("crosslog/custody: complete", "chains", len(out.Chains))
	return out
}
