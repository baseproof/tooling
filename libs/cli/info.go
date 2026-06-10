package cli

// info.go — `baseproof info`: fetch the network's public introspection surface
// (the /v1/network/* endpoints + horizon + admission) and present it as ONE
// picture, VERIFYING it on fetch rather than trusting it.
//
// Closes the five "understand a network" gaps:
//   - aggregation        — one view from the bundle;
//   - verify-on-fetch     — --verify recomputes the network id, the horizon K-of-N
//                           cosignatures (clitools.VerifyHorizon), and each cited
//                           peer's id; trusts nothing;
//   - recursive federation — --federation walks the peer graph (bounded --depth,
//                           cycle-guarded), reaching + verifying each peer;
//   - auditor-health rollup — probes each auditor's /healthz (live) and /v1/log-info
//                           (in-sync vs the ledger horizon);
//   - server summary      — the client aggregates, so no server /v1/network/summary
//                           is required (a future server aggregate is optional).
//
// The hard Zero-Trust gate is identity: the served network_id MUST equal
// SHA-256(served bootstrap) AND the bundle's pinned id ("this endpoint really is
// the network I trust") — a mismatch fails closed. The other checks are reported
// per component (✔/✗) so the operator sees exactly what held.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/messages"
	"github.com/baseproof/tooling/libs/networkbundle"
)

// ── wire shapes (client-side mirrors of the ledger api responses) ──────────

type wireIdentity struct {
	NetworkID  string `json:"network_id"`
	NetworkDID string `json:"network_did"`
}
type wireWitnessKey struct {
	ID string `json:"id"`
}
type wireWitnessSet struct {
	SetHash string           `json:"set_hash"`
	Keys    []wireWitnessKey `json:"keys"`
}
type wireAuditorEntry struct {
	AuditorDID  string `json:"auditor_did"`
	FindingsURL string `json:"findings_url"`
}
type wireAuditors struct {
	Auditors []wireAuditorEntry `json:"auditors"`
}
type wireMirrorEntry struct {
	URL string `json:"url"`
}
type wireMirrors struct {
	Mirrors []wireMirrorEntry `json:"mirrors"`
}
type wireLogNode struct {
	NetworkID    string `json:"network_id"`
	AdmissionURL string `json:"admission_url,omitempty"` // peer's reachable read base
}
type wireFederation struct {
	Parent   *wireLogNode  `json:"parent,omitempty"`
	Siblings []wireLogNode `json:"siblings,omitempty"`
	Root     *wireLogNode  `json:"root,omitempty"`
}
type wireHorizon struct {
	TreeSize uint64 `json:"tree_size"`
	SMTRoot  string `json:"smt_root"`
}
type wireAnchorHop struct {
	ParentLogDID         string `json:"parent_log_did"`
	WitnessSetHash       string `json:"witness_set_hash"`
	LatestAnchorTreeSize uint64 `json:"latest_anchor_tree_size,omitempty"`
}
type wireAnchors struct {
	Hops []wireAnchorHop `json:"hops"`
}
type wireLabelEntry struct {
	PubKeyID string `json:"pub_key_id"`
	Label    string `json:"label"`
}
type wireLabels struct {
	Labels []wireLabelEntry `json:"labels"`
}
type wireWitnessEndpointEntry struct {
	PubKeyID  string            `json:"pub_key_id"`
	Endpoints map[string]string `json:"endpoints"`
}
type wireWitnessEndpoints struct {
	Witnesses []wireWitnessEndpointEntry `json:"witnesses"`
}

// auditorHealth is one auditor's probe result.
type auditorHealth struct {
	DID    string
	Live   bool
	InSync bool
}

// peerResult is one cited peer's verified-reachability verdict.
type peerResult struct {
	NetworkID string
	Reached   bool
	IDMatches bool
}

// netInfo is the aggregated, verified picture of one network.
type netInfo struct {
	Endpoint   string
	Identity   wireIdentity
	Witnesses  wireWitnessSet
	Auditors   wireAuditors
	Mirrors    wireMirrors
	Federation wireFederation
	Horizon    wireHorizon
	Anchors    wireAnchors
	Labels     wireLabels
	WitnessEPs wireWitnessEndpoints
	Difficulty uint64
	Accepts    []string
	QuorumK    int

	// WitnessesGenesis marks Witnesses as DERIVED from the hash-verified
	// bootstrap (genesis fallback) rather than fetched from the ledger's
	// witness-history endpoint — a never-rotated network, an image predating
	// the genesis-baseline row, or a PG-off reader.
	WitnessesGenesis bool

	// verdicts
	IdentityOK bool
	HorizonOK  bool
	HorizonErr string
	Cosigs     clitools.HorizonResult
	AuditorHP  []auditorHealth
	Peers      []peerResult

	verify bool
}

// RunInfo implements `baseproof info`.
func RunInfo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		verify     = fs.Bool("verify", false, "recompute the cryptographic checks (horizon K-of-N, auditor liveness, peer ids)")
		federation = fs.Bool("federation", false, "walk + verify the cited federation peers")
		depth      = fs.Int("depth", 1, "federation walk depth (bounded)")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	httpClient, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	n, err := gatherNetwork(ctx, b, httpClient, *verify, *federation, *depth)
	if err != nil {
		return err
	}
	renderNetwork(fs.Output(), n)

	if *verify && (!n.IdentityOK || !n.HorizonOK) {
		return fmt.Errorf("info: one or more verification checks FAILED (see ✗ above)")
	}
	return nil
}

// gatherNetwork fetches the introspection surface and verifies it on fetch. The
// identity recompute is a HARD gate (wrong network ⇒ error); everything else is
// recorded as per-component verdicts.
func gatherNetwork(ctx context.Context, b *ClientBundle, httpClient *http.Client, verify, federation bool, depth int) (*netInfo, error) {
	n := &netInfo{Endpoint: b.Endpoint, Accepts: b.Messages, QuorumK: b.QuorumK, verify: verify}

	// Identity + bootstrap — the trust anchor. fetchBootstrap fails closed unless
	// SHA-256(bytes) == the bundle's pinned hash ("the right network").
	doc, err := fetchBootstrap(ctx, httpClient, b.Endpoint, b.BootstrapHash)
	if err != nil {
		return nil, err
	}
	if err := getJSON(ctx, httpClient, b.Endpoint+"/v1/network/identity", &n.Identity); err != nil {
		return nil, fmt.Errorf("fetch identity: %w", err)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	recomputed := sha256.Sum256(canonical)
	n.IdentityOK = strings.EqualFold(n.Identity.NetworkID, hex.EncodeToString(recomputed[:]))
	if want, err := b.NetworkID32(); err == nil {
		if !strings.EqualFold(n.Identity.NetworkID, hex.EncodeToString(want[:])) {
			return nil, fmt.Errorf("info: endpoint serves network %s but the bundle pins %x… (fail-closed)", short(n.Identity.NetworkID), want[:8])
		}
	}

	// Discovery surface — a 404 means "not configured for this network", skip.
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/witnesses/current", &n.Witnesses)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/auditors", &n.Auditors)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/mirrors", &n.Mirrors)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/peers", &n.Federation)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/anchors", &n.Anchors)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/labels", &n.Labels)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/network/witness-endpoints", &n.WitnessEPs)
	_ = getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/tree/horizon", &n.Horizon)
	var diff struct {
		Difficulty uint64 `json:"difficulty"`
	}
	if getJSONOptional(ctx, httpClient, b.Endpoint+"/v1/admission/difficulty", &diff) == nil {
		n.Difficulty = diff.Difficulty
	}

	// Genesis fallback: a network that serves no witness history (never
	// rotated, an image predating the genesis-baseline row, or a PG-off
	// reader) still cosigns heads with the genesis set. Derive that set from
	// the hash-verified bootstrap — the trust root — so the roster shown is
	// the one verification actually uses, marked as bootstrap-derived.
	if len(n.Witnesses.Keys) == 0 && len(doc.GenesisWitnessSet) > 0 {
		if gkeys, gerr := witness.KeysFromDIDs(doc.GenesisWitnessSet); gerr == nil {
			n.WitnessesGenesis = true
			for _, k := range gkeys {
				n.Witnesses.Keys = append(n.Witnesses.Keys, wireWitnessKey{ID: hex.EncodeToString(k.ID[:])})
			}
			if b.QuorumK > 0 {
				if gset, serr := cosign.NewECDSAWitnessKeySet(gkeys, cosign.NetworkID(recomputed), b.QuorumK); serr == nil {
					h := gset.SetHash()
					n.Witnesses.SetHash = hex.EncodeToString(h[:])
				}
			}
		}
	}

	if verify {
		// Horizon: recompute K-of-N cosignatures (+ sampled SMT proofs) against the
		// witness set DERIVED from the genesis bootstrap — recompute, never trust.
		if nb, berr := networkbundle.Build(doc, b.Endpoint, b.QuorumK, networkbundle.Vocabulary{}); berr != nil {
			n.HorizonErr = berr.Error()
		} else if hr, herr := clitools.VerifyHorizon(ctx, b.Endpoint, nb.Witnesses, 8, httpClient); herr != nil {
			n.HorizonErr = herr.Error()
		} else {
			n.Cosigs, n.HorizonOK = hr, true
		}
		for _, a := range n.Auditors.Auditors {
			n.AuditorHP = append(n.AuditorHP, probeAuditor(ctx, httpClient, a, n.Horizon.TreeSize))
		}
	}

	if federation {
		walkFederation(ctx, httpClient, n, depth)
	}
	return n, nil
}

// walkFederation does a bounded, CYCLE-GUARDED breadth-first walk of the cited
// peers: it REACHES each peer (via the federation graph's admission URL) and
// confirms the network_id it serves equals the id the parent graph names it by —
// turning a list of ids into a verified graph.
//
// Guards (so a hostile or misconfigured graph can never loop or run away):
//   - `visited`, seeded with THIS network's own id, marks every peer before it is
//     processed, so each id is walked at most once — a citation cycle (A↔B) or a
//     diamond terminates, and a peer cannot trigger a re-walk of itself or the
//     origin;
//   - `maxDepth` bounds how many hops out the walk goes;
//   - an empty/unidentified peer id is skipped.
func walkFederation(ctx context.Context, httpClient *http.Client, n *netInfo, maxDepth int) {
	if maxDepth < 1 {
		maxDepth = 1
	}
	type frontier struct {
		graph wireFederation
		depth int
	}
	visited := map[string]bool{strings.ToLower(n.Identity.NetworkID): true}
	queue := []frontier{{n.Federation, 1}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		peers := append([]wireLogNode(nil), cur.graph.Siblings...)
		if cur.graph.Parent != nil {
			peers = append(peers, *cur.graph.Parent)
		}
		if cur.graph.Root != nil {
			peers = append(peers, *cur.graph.Root)
		}
		for _, p := range peers {
			key := strings.ToLower(p.NetworkID)
			if key == "" || visited[key] {
				continue // self / already-seen / unidentified — cycle guard
			}
			visited[key] = true

			r := peerResult{NetworkID: p.NetworkID}
			if base := strings.TrimRight(p.AdmissionURL, "/"); base != "" {
				var id wireIdentity
				if err := getJSON(ctx, httpClient, base+"/v1/network/identity", &id); err == nil {
					r.Reached = true
					r.IDMatches = strings.EqualFold(id.NetworkID, p.NetworkID)
				}
				// Enqueue this peer's own graph, one hop further, bounded by maxDepth.
				if cur.depth < maxDepth && r.Reached {
					var sub wireFederation
					if getJSONOptional(ctx, httpClient, base+"/v1/network/peers", &sub) == nil {
						queue = append(queue, frontier{sub, cur.depth + 1})
					}
				}
			}
			n.Peers = append(n.Peers, r)
		}
	}
}

// probeAuditor checks an auditor's liveness (/healthz) and whether it is in sync
// with the ledger horizon (/v1/log-info tree_size within a checkpoint of it).
func probeAuditor(ctx context.Context, httpClient *http.Client, a wireAuditorEntry, ledgerTreeSize uint64) auditorHealth {
	h := auditorHealth{DID: a.AuditorDID}
	base := ""
	if u, err := url.Parse(a.FindingsURL); err == nil && u.Host != "" {
		base = u.Scheme + "://" + u.Host
	}
	if base == "" {
		return h
	}
	h.Live = reqOK(ctx, httpClient, base+"/healthz")
	var li struct {
		TreeSize uint64 `json:"tree_size"`
	}
	if getJSONOptional(ctx, httpClient, base+"/v1/log-info", &li) == nil && ledgerTreeSize > 0 {
		// the auditor follows the ledger; in-sync ⇒ within ~one checkpoint behind.
		h.InSync = li.TreeSize > 0 && li.TreeSize+64 >= ledgerTreeSize
	}
	return h
}

// ── rendering ──────────────────────────────────────────────────────────────

func renderNetwork(w io.Writer, n *netInfo) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	mk := func(ok bool) string {
		if ok {
			return "✔"
		}
		return "✗"
	}
	fmt.Fprintf(tw, "network\t%s\tidentity %s%s\n", n.Identity.NetworkDID, mk(n.IdentityOK), cond(n.IdentityOK, " (recomputed)", " MISMATCH"))
	fmt.Fprintf(tw, "id\t%s\t\n", n.Identity.NetworkID)
	fmt.Fprintf(tw, "endpoint\t%s\t\n", n.Endpoint)

	wl := fmt.Sprintf("%d-of-%d  set %s", n.QuorumK, len(n.Witnesses.Keys), short(n.Witnesses.SetHash))
	if n.WitnessesGenesis {
		wl += " (genesis, derived from bootstrap)"
	}
	if n.verify && n.HorizonOK {
		wl += fmt.Sprintf("   cosigns horizon %s (%d/%d)", mk(true), n.Cosigs.ValidCosigs, n.Cosigs.Quorum)
	} else if n.verify {
		wl += "   horizon " + mk(false)
	}
	fmt.Fprintf(tw, "witnesses\t%s\t\n", wl)

	if len(n.Labels.Labels) > 0 {
		names := make([]string, len(n.Labels.Labels))
		for i, l := range n.Labels.Labels {
			names[i] = fmt.Sprintf("%s=%q", short(l.PubKeyID), l.Label)
		}
		fmt.Fprintf(tw, "witness-labels\t%s\t\n", strings.Join(names, "  "))
	}
	if len(n.WitnessEPs.Witnesses) > 0 {
		fmt.Fprintf(tw, "witness-endpoints\t%d declared\t\n", len(n.WitnessEPs.Witnesses))
	}

	if len(n.Auditors.Auditors) > 0 {
		line := fmt.Sprintf("%d registered", len(n.Auditors.Auditors))
		if n.verify {
			live, sync := 0, 0
			for _, a := range n.AuditorHP {
				if a.Live {
					live++
				}
				if a.InSync {
					sync++
				}
			}
			line += fmt.Sprintf("   %d/%d live   %d/%d in-sync", live, len(n.AuditorHP), sync, len(n.AuditorHP))
		}
		fmt.Fprintf(tw, "auditors\t%s\t\n", line)
	}

	if n.Horizon.TreeSize > 0 {
		fmt.Fprintf(tw, "horizon\ttree_size %d  smt_root %s\t\n", n.Horizon.TreeSize, short(n.Horizon.SMTRoot))
	}
	if len(n.Anchors.Hops) > 0 {
		parts := make([]string, len(n.Anchors.Hops))
		for i, h := range n.Anchors.Hops {
			parts[i] = fmt.Sprintf("%s@%d", short(h.ParentLogDID), h.LatestAnchorTreeSize)
		}
		fmt.Fprintf(tw, "anchors\tonto %s\t\n", strings.Join(parts, "  "))
	}
	fmt.Fprintf(tw, "admission\tPoW difficulty %d\t\n", n.Difficulty)

	if len(n.Accepts) > 0 {
		fmt.Fprintf(tw, "messages\t%s\t\n", strings.Join(n.Accepts, ", "))
	} else {
		fmt.Fprintf(tw, "messages\t(unconstrained: %s)\t\n", strings.Join(messages.Names(), ", "))
	}

	if len(n.Peers) > 0 {
		parts := make([]string, len(n.Peers))
		for i, p := range n.Peers {
			parts[i] = short(p.NetworkID) + " " + mk(p.Reached && p.IDMatches)
		}
		fmt.Fprintf(tw, "federation\t%s\t\n", strings.Join(parts, "  "))
	} else if len(n.Federation.Siblings) > 0 {
		ids := make([]string, len(n.Federation.Siblings))
		for i, s := range n.Federation.Siblings {
			ids[i] = short(s.NetworkID)
		}
		fmt.Fprintf(tw, "federation\t%s (run --federation to verify)\t\n", strings.Join(ids, "  "))
	}

	if len(n.Mirrors.Mirrors) > 0 {
		urls := make([]string, len(n.Mirrors.Mirrors))
		for i, m := range n.Mirrors.Mirrors {
			urls[i] = m.URL
		}
		fmt.Fprintf(tw, "mirrors\t%s\t\n", strings.Join(urls, ", "))
	}
	_ = tw.Flush()
}

// ── helpers ──────────────────────────────────────────────────────────────────

func getJSON(ctx context.Context, httpClient *http.Client, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{Code: resp.StatusCode, URL: u}
	}
	return json.Unmarshal(raw, out)
}

// httpStatusError reports a non-200 from getJSON. errors.As lets callers
// branch on the status (the witnesses genesis fallback keys off 404) without
// string-matching; Error() keeps the exact prior message, which
// getJSONOptional's "HTTP 404" match still relies on.
type httpStatusError struct {
	Code int
	URL  string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d from %s", e.Code, e.URL) }

func getJSONOptional(ctx context.Context, httpClient *http.Client, u string, out any) error {
	err := getJSON(ctx, httpClient, u, out)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		return nil
	}
	return err
}

func reqOK(ctx context.Context, httpClient *http.Client, target string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

func cond(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
