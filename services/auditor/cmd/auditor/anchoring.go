/*
FILE PATH: cmd/auditor/anchoring.go

PR-4b main-composition: build the constitutional-anchoring scheduler job from
the auditor's verified inputs.

PARENT SET SELECTION (the wiring rule the check itself stays pure over):
constitutional Targets when the network's policy declares them — every
configured parent MUST then name a declared target (WHICH from the
constitution; the auditor only chooses WHERE to read it from) — else the
legacy trust-root config (pre-targets networks: parents carry no target id
and evidence rides the no-targets ladder).

AUDITOR_ANCHOR_PARENTS is a CSV of parent read sources:

	targets mode:  <64-hex targetNetworkID>@<parentLogDID>@<readBaseURL>
	legacy mode:   <parentLogDID>@<readBaseURL>

AUDITOR_ANCHORING_INTERVAL (default 10m) is the scan cadence. Empty parents ⇒
the job is not registered (and for a targets network that is a VISIBLE gap:
the monitor would have reported under-quota; main logs the omission loudly).

VerifiedAt at this altitude is the scan's observation clock (firstSeen nil):
the auditor's own durable first-seen journal is a refinement that slots into
the FirstSeen hook without touching the check.
*/
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdklog "github.com/baseproof/baseproof/log"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/verifier"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/anchorfeed"
	"github.com/baseproof/tooling/libs/monitoring"
)

// anchoringParentSpec is one parsed AUDITOR_ANCHOR_PARENTS element.
type anchoringParentSpec struct {
	TargetHex   string // "" in legacy mode
	ParentLogID string
	ReadBase    string
}

// parseAnchorParents parses the CSV (see file header). Mixing modes is a
// config error; so is a malformed element.
func parseAnchorParents(csv string) ([]anchoringParentSpec, error) {
	var specs []anchoringParentSpec
	modeTargets := false
	for i, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.Split(raw, "@")
		switch len(parts) {
		case 3:
			if len(specs) > 0 && !modeTargets {
				return nil, fmt.Errorf("element %d mixes targets mode into a legacy list", i)
			}
			modeTargets = true
			specs = append(specs, anchoringParentSpec{TargetHex: parts[0], ParentLogID: parts[1], ReadBase: parts[2]})
		case 2:
			if modeTargets {
				return nil, fmt.Errorf("element %d mixes legacy mode into a targets list", i)
			}
			specs = append(specs, anchoringParentSpec{ParentLogID: parts[0], ReadBase: parts[1]})
		default:
			return nil, fmt.Errorf("element %d: want target@logdid@readbase or logdid@readbase, got %q", i, raw)
		}
	}
	return specs, nil
}

// buildAnchoringCheck composes the scheduler job, or (nil, 0) when not
// configured. ownLogDID is the monitored network's log DID (the by-source
// key its anchors carry); witnessDIDs+quorumK derive the genesis witness set
// the reduction binds lineage against.
func buildAnchoringCheck(
	parentsCSV string,
	interval time.Duration,
	policy *network.GenesisAnchoringPolicy,
	pin [32]byte,
	ownLogDID string,
	witnessDIDs []string,
	quorumK int,
	client *http.Client,
	logger *slog.Logger,
) (func(ctx context.Context) ([]sdkmonitoring.Alert, error), time.Duration, error) {
	if strings.TrimSpace(parentsCSV) == "" {
		if policy != nil && len(policy.Targets) > 0 {
			logger.Warn("anchoring: the constitution declares targets but AUDITOR_ANCHOR_PARENTS is empty — the constitutional monitor is NOT running; the commitment is unwatched")
		}
		return nil, 0, nil
	}
	specs, err := parseAnchorParents(parentsCSV)
	if err != nil {
		return nil, 0, fmt.Errorf("AUDITOR_ANCHOR_PARENTS: %w", err)
	}

	// Targets-mode validation: every configured parent names a DECLARED
	// constitutional target (the auditor cannot widen WHICH — only choose
	// WHERE to read).
	declaredTargets := map[string]bool{}
	if policy != nil {
		for _, t := range policy.Targets {
			declaredTargets[t.NetworkID] = true
		}
	}
	for _, s := range specs {
		if s.TargetHex == "" {
			continue
		}
		if !declaredTargets[s.TargetHex] {
			return nil, 0, fmt.Errorf("AUDITOR_ANCHOR_PARENTS names target %s which the constitution does not declare — the auditor cannot widen WHICH", s.TargetHex[:16])
		}
	}

	keys, err := witness.KeysFromDIDs(witnessDIDs)
	if err != nil {
		return nil, 0, fmt.Errorf("anchoring: witness keys: %w", err)
	}
	currentSet, err := cosign.NewWitnessKeySet(keys, cosign.NetworkID(pin), quorumK, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("anchoring: witness set: %w", err)
	}

	parents := make([]monitoring.AnchoringParent, 0, len(specs))
	for _, s := range specs {
		s := s
		fetcher, err := sdklog.NewHTTPEntryFetcher(sdklog.HTTPEntryFetcherConfig{
			BaseURL: s.ReadBase, LogDID: s.ParentLogID, Client: client,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("anchoring: parent %s fetcher: %w", s.ParentLogID, err)
		}
		ml := sdkanchor.NewMultiLog(map[string]sdkanchor.LogConfig{
			s.ParentLogID: {Fetcher: fetcher},
		})
		var targetID [32]byte
		if s.TargetHex != "" {
			tb, terr := network.AnchorTarget{NetworkID: s.TargetHex}.Bytes()
			if terr != nil {
				return nil, 0, fmt.Errorf("anchoring: parent %s target id: %w", s.ParentLogID, terr)
			}
			targetID = tb
		}
		parents = append(parents, monitoring.AnchoringParent{
			LogDID: s.ParentLogID,
			Collect: func(cctx context.Context) ([]verifier.AnchorEvidence, []error) {
				seqs, serr := anchorfeed.FetchBySourceSeqs(cctx, client, s.ReadBase, ownLogDID, 256)
				if serr != nil {
					return nil, []error{serr}
				}
				items, errs := anchorfeed.CollectEvidence(cctx, ml, s.ParentLogID, targetID, seqs, nil, time.Now)
				return anchorfeed.Evidence(items), errs
			},
		})
	}

	if interval <= 0 {
		interval = 10 * time.Minute
	}
	check := func(ctx context.Context) ([]sdkmonitoring.Alert, error) {
		_, alerts := monitoring.CheckConstitutionalAnchoring(ctx, monitoring.ConstitutionalAnchoringConfig{
			Policy: policy, Pin: pin, CurrentSet: currentSet, Parents: parents,
		}, time.Now().UTC())
		return alerts, nil
	}
	logger.Info("anchoring: constitutional monitor composed",
		"parents", len(parents), "targets_mode", len(declaredTargets) > 0, "interval", interval)
	return check, interval, nil
}
