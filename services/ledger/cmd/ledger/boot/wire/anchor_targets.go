/*
FILE PATH: cmd/ledger/boot/wire/anchor_targets.go

PR-4d — the anchoring WHERE derivation chain, as pure functions wire.go
composes at boot:

	WHICH networks to anchor   = the constitution (GenesisAnchoring.Targets;
	                             immutable, identity-bound)
	WHERE each one lives       = the on-log BP-ENTRY-ANCHOR-TARGET-V1
	                             declaration projection (witnessed, amendable;
	                             SDK walker network.ResolveAnchorTargetAt)
	env (LEDGER_PARENT_*)      = CANARY, live only PRE-first-declaration;
	                             once a declaration covers a target, a
	                             mismatching env is FATAL (the demotion)

BOOT-FATAL RULE (the chain's closure): a constitutional target with NO
resolvable endpoint — no declaration AND no canary — refuses boot. You cannot
promise what you cannot publish to. Extras (env-configured parents beyond the
constitution) stay allowed, like anchoring more often than the bound.

This file also closes #94: projectAnchorTargetGraph is the producer the
DefaultAuthoritativeResolver.FederationGraph never had — ResolvePeer's on-log
branch becomes reachable, and the env canary is reachable only in the genuine
pre-first-declaration window.
*/
package wire

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/baseproof/baseproof/log/discover"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// projectAnchorTargetGraph resolves, for each constitutional target, the
// declaration in effect at asOf (the SDK walker — supersession + retirement
// semantics) and projects the result into the resolver's FederationGraph.
// Targets with no declaration are returned in `undeclared` — the caller
// decides whether the canary covers them or boot dies.
//
// The graph is a REBUILDABLE CACHE of the log (cold reconstruction = walk
// from seq-0), never a source. Returns a nil graph when nothing is declared
// (the resolver stays on its canary, and the caller logs that honestly).
func projectAnchorTargetGraph(
	doc network.BootstrapDocument,
	ourLogDID string,
	recs []network.AnchorTargetDeclarationRecord,
	asOf types.LogPosition,
) (graph *discover.FederationGraph, declared map[string]network.AnchorTargetDeclaration, undeclared []string) {
	declared = map[string]network.AnchorTargetDeclaration{}
	if doc.GenesisAnchoring == nil || len(doc.GenesisAnchoring.Targets) == 0 {
		return nil, declared, nil
	}
	var nodes []discover.LogNode
	for _, t := range doc.GenesisAnchoring.Targets {
		tb, err := t.Bytes()
		if err != nil {
			// Unreachable on a minted constitution (validate() owns the rule);
			// skipped defensively rather than trusted.
			undeclared = append(undeclared, t.NetworkID)
			continue
		}
		decl, err := network.ResolveAnchorTargetAt(recs, tb, asOf)
		if err != nil {
			undeclared = append(undeclared, t.NetworkID)
			continue
		}
		declared[t.NetworkID] = decl
		nodes = append(nodes, discover.LogNode{
			LogDID:       decl.LogDID,
			NetworkID:    tb,
			AdmissionURL: decl.AdmissionURL(),
		})
	}
	if len(nodes) == 0 {
		return nil, declared, undeclared
	}
	return &discover.FederationGraph{
		ThisLog:  discover.LogNode{LogDID: ourLogDID},
		Siblings: nodes,
	}, declared, undeclared
}

// parentEndpoint is one derived publish target: WHICH (the constitutional
// target id, hex) bound to WHERE (admission URL) and the WHERE's source.
type parentEndpoint struct {
	TargetNetworkID string // 64-hex constitutional id
	LogDID          string
	AdmissionURL    string
	FromDeclaration bool // false = the pre-first-declaration canary
}

// deriveParentEndpoints applies the chain for the PUBLISHER's target list:
// every constitutional target must resolve to an admission URL from its
// declaration, or — only while NO declaration for it exists — from the env
// canary. Returns an error (boot-fatal) when:
//
//   - a constitutional target has neither declaration nor canary (the
//     unfulfillable promise), or
//   - a declaration exists AND the env canary names a DIFFERENT admission
//     URL for that parent (the demotion: on-log wins, a disagreeing env is
//     a misconfiguration to fix, not to silently shadow).
//
// envParentDID/envParentURL may be empty (no canary). A nil/empty target set
// derives nothing — the legacy single-parent env path stays as-is for
// pre-targets constitutions.
func deriveParentEndpoints(
	doc network.BootstrapDocument,
	declared map[string]network.AnchorTargetDeclaration,
	envParentDID, envParentURL string,
) ([]parentEndpoint, error) {
	if doc.GenesisAnchoring == nil || len(doc.GenesisAnchoring.Targets) == 0 {
		return nil, nil
	}
	// Pass 1 — declared targets. The env canary is CONSUMED as a cross-check
	// when its DID names a declared target's parent: agreeing is a passing
	// check, disagreeing is fatal (the demotion: on-log wins), and either way
	// that env pair is no longer available to stand in for anything else.
	out := make([]parentEndpoint, 0, len(doc.GenesisAnchoring.Targets))
	envConsumed := false
	var undeclaredTargets []string
	for _, t := range doc.GenesisAnchoring.Targets {
		decl, ok := declared[t.NetworkID]
		if !ok {
			undeclaredTargets = append(undeclaredTargets, t.NetworkID)
			continue
		}
		if envParentURL != "" && envParentDID == decl.LogDID {
			envConsumed = true
			if envParentURL != decl.AdmissionURL() {
				return nil, fmt.Errorf(
					"anchoring target %s: env LEDGER_PARENT_ADMISSION_URL %q disagrees with the on-log declaration %q — the declaration is authoritative; fix or unset the env canary",
					t.NetworkID[:16], envParentURL, decl.AdmissionURL())
			}
		}
		out = append(out, parentEndpoint{
			TargetNetworkID: t.NetworkID,
			LogDID:          decl.LogDID,
			AdmissionURL:    decl.AdmissionURL(),
			FromDeclaration: true,
		})
	}
	// Pass 2 — undeclared targets. One env pair can stand in for at most ONE
	// target, and only unambiguously (exactly one undeclared target, and the
	// pair not already consumed as a declared target's cross-check) — the env
	// carries no NetworkID, so any wider reading would be guessing WHICH.
	canaryFree := envParentURL != "" && envParentDID != "" && !envConsumed
	for _, id := range undeclaredTargets {
		if canaryFree && len(undeclaredTargets) == 1 {
			out = append(out, parentEndpoint{
				TargetNetworkID: id,
				LogDID:          envParentDID,
				AdmissionURL:    envParentURL,
				FromDeclaration: false,
			})
			continue
		}
		return nil, fmt.Errorf(
			"anchoring target %s has NO resolvable endpoint: no BP-ENTRY-ANCHOR-TARGET-V1 declaration on-log and no unambiguous env canary — a constitutional commitment that cannot be published to refuses boot (declare the target's endpoints via declare-anchor-target, then retire the env)",
			id[:16])
	}
	return out, nil
}

// logAnchorTargetPosture is the honest-state line #94 demanded: when the
// graph is empty and a parent canary is live, say so at boot — and once
// declarations exist, count endpoint CHANGES at Info (a counter, never a
// page; endpoint churn is witnessed, sequenced, expected).
func logAnchorTargetPosture(
	logger *slog.Logger,
	graph *discover.FederationGraph,
	declared map[string]network.AnchorTargetDeclaration,
	undeclared []string,
	envParentURL string,
	now time.Time,
) {
	if graph == nil {
		if envParentURL != "" {
			logger.Info("anchoring WHERE: pre-first-declaration window — parent resolution is running on the ENV CANARY with no on-log source; "+
				"declare targets via declare-anchor-target to retire it",
				"env_parent_admission_url", envParentURL,
				"undeclared_targets", len(undeclared),
				"at", now.UTC())
		}
		return
	}
	logger.Info("anchoring WHERE: federation graph projected from on-log declarations",
		"declared_targets", len(declared),
		"undeclared_targets", len(undeclared),
		"at", now.UTC())
}
