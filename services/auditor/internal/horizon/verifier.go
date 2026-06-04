// Package horizon adds the auditor's DURABILITY audit — the piece the gossip-only
// path can't see.
//
// The gossip feed (TrustedHeadStore) verifies cosigned HEADS as they propagate.
// But a head is only durable once the ledger republishes it as the cosigned
// /v1/tree/horizon, gated on its SMT tiles being durable. This auditor pulls each
// peer's published horizon, performs the light-client check (baseproof v1.22.0
// log.HTTPCheckpointClient.FetchVerifiedHorizon — fetch + K-of-N quorum — then
// samples proofs that must resolve against the witnessed SMTRoot), and
// cross-checks the horizon against the gossip-trusted head at the same TreeSize.
//
// A published checkpoint that DIVERGES from the gossip-verified head at the same
// size is an equivocation signal the gossip path alone cannot detect; a sub-quorum
// or unresolvable-proof horizon is a durability/availability failure. Both surface
// as monitoring.Alerts (the job is registered on the auditor's scheduler).
package horizon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdklog "github.com/baseproof/baseproof/log"
	sdkmon "github.com/baseproof/baseproof/monitoring"

	"github.com/baseproof/tooling/libs/clitools"
	libmon "github.com/baseproof/tooling/libs/monitoring"
)

// MonitorHorizonAudit is the alert MonitorID for this audit.
const MonitorHorizonAudit sdkmon.MonitorID = "horizon_audit"

// Peer is a ledger to audit: its base URL + the gossip-originator did:key its
// horizon cosignatures verify under (the witness-set key).
type Peer struct {
	OriginatorDID string
	BaseURL       string
}

// Config wires the verifier. Heads is the SAME TrustedHeadStore the gossip path
// feeds, read-only here for the divergence cross-check.
type Config struct {
	Peers []Peer
	Sets  map[string]*cosign.WitnessKeySet
	Heads *libmon.TrustedHeadStore

	// HTTPClient is the *http.Client used for every peer-horizon fetch
	// (checkpoint + proof reader). Required. Built once at boot by the
	// auditor binary (mirror of the ledger's d.OutboundHTTPClient) so
	// every outbound surface — gossip pull, horizon audit, did:web
	// resolution, peer originator discovery — uses the same transport
	// posture (mTLS material, timeout, retry, pool). v1.27.1 deleted
	// the prior plaintext-fallback path; nil is now an error.
	HTTPClient *http.Client

	Samples int // random keys to probe per peer (0 → quorum-only)
	Logger  *slog.Logger
}

// ErrInvalidConfig is returned by NewVerifier when a required field is missing.
var ErrInvalidConfig = errors.New("horizon: invalid Config")

// Verifier audits each peer's published horizon on the scheduler's cadence.
type Verifier struct {
	peers      []Peer
	sets       map[string]*cosign.WitnessKeySet
	heads      *libmon.TrustedHeadStore
	httpClient *http.Client
	samples    int
	logger     *slog.Logger

	mu     sync.Mutex
	status map[string]PeerStatus // by BaseURL — last audit outcome
}

// PeerStatus is the last audit outcome for a peer (served read-only for ops).
type PeerStatus struct {
	State     string // ok | pre_genesis | not_trusted | unreachable | diverged | no_witness_set
	TreeSize  uint64
	ProofsOK  int
	Detail    string
	CheckedAt time.Time
}

// NewVerifier returns a verifier, or (nil, nil) when there is nothing to
// audit (no peers) so the caller can skip registering the job. Returns
// (nil, ErrInvalidConfig) when peers are configured but HTTPClient is nil:
// the auditor's binary-level outbound client MUST be threaded in so every
// peer-horizon fetch shares the same transport posture as the rest of the
// auditor's outbound surfaces (gossip pull, did:web resolution, etc.).
func NewVerifier(cfg Config) (*Verifier, error) {
	if len(cfg.Peers) == 0 {
		return nil, nil
	}
	if cfg.HTTPClient == nil {
		return nil, fmt.Errorf("%w: HTTPClient is required (thread the binary's outbound client; build it via libs/outbound.HoistFromEnv)", ErrInvalidConfig)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Samples < 0 {
		cfg.Samples = 0
	}
	return &Verifier{
		peers:      cfg.Peers,
		sets:       cfg.Sets,
		heads:      cfg.Heads,
		httpClient: cfg.HTTPClient,
		samples:    cfg.Samples,
		logger:     cfg.Logger,
		status:     make(map[string]PeerStatus),
	}, nil
}

// AuditOnce audits every peer once. It is a monitoring.JobFunc: it returns the
// Alerts to route (durability failures + divergences) and never a hard error —
// one unreachable peer must not abort the others or tear down the scheduler.
func (v *Verifier) AuditOnce(ctx context.Context) ([]sdkmon.Alert, error) {
	var alerts []sdkmon.Alert
	for _, p := range v.peers {
		alerts = append(alerts, v.auditPeer(ctx, p)...)
	}
	return alerts, nil
}

func (v *Verifier) auditPeer(ctx context.Context, p Peer) []sdkmon.Alert {
	set := v.sets[p.OriginatorDID]
	if set == nil {
		v.record(p, PeerStatus{State: "no_witness_set", Detail: p.OriginatorDID})
		v.logger.Warn("horizon audit: no witness set for originator — skipping",
			"peer", p.BaseURL, "originator", p.OriginatorDID)
		return nil
	}

	res, err := clitools.VerifyHorizon(ctx, p.BaseURL, set, v.samples, v.httpClient)
	switch {
	case errors.Is(err, sdklog.ErrHorizonNotPublished):
		// Pre-genesis: no cosigned checkpoint yet. Not a failure.
		v.record(p, PeerStatus{State: "pre_genesis"})
		return nil
	case errors.Is(err, sdklog.ErrHorizonNotTrusted):
		v.record(p, PeerStatus{State: "not_trusted", Detail: err.Error()})
		v.logger.Error("horizon audit: published checkpoint does NOT meet quorum",
			"peer", p.BaseURL, "error", err)
		return []sdkmon.Alert{v.alert(sdkmon.Critical, "published horizon does not meet witness quorum", p, map[string]any{
			"error": err.Error(),
		})}
	case err != nil:
		// Transport / unresolvable proof / decode — availability or durability gap.
		v.record(p, PeerStatus{State: "unreachable", Detail: err.Error()})
		v.logger.Error("horizon audit: verification failed", "peer", p.BaseURL, "error", err)
		return []sdkmon.Alert{v.alert(sdkmon.Warning, "horizon verification failed", p, map[string]any{
			"error": err.Error(),
		})}
	}

	// Cross-check the published horizon against the gossip-trusted head: a
	// DIVERGENCE at the same TreeSize is an equivocation the gossip path can't see.
	if v.heads != nil {
		if gh, ok := v.heads.TrustedHead(p.OriginatorDID); ok &&
			gh.TreeSize == res.TreeSize && gh.RootHash != res.RootHash {
			v.record(p, PeerStatus{State: "diverged", TreeSize: res.TreeSize, ProofsOK: res.ProofsOK,
				Detail: fmt.Sprintf("horizon root %x != gossip root %x", res.RootHash[:8], gh.RootHash[:8])})
			v.logger.Error("horizon audit: EQUIVOCATION — published horizon diverges from gossip-trusted head",
				"peer", p.BaseURL, "originator", p.OriginatorDID, "tree_size", res.TreeSize,
				"horizon_root", fmt.Sprintf("%x", res.RootHash[:8]),
				"gossip_root", fmt.Sprintf("%x", gh.RootHash[:8]))
			return []sdkmon.Alert{v.alert(sdkmon.Critical,
				"published horizon diverges from gossip-trusted head (equivocation)", p, map[string]any{
					"tree_size":    res.TreeSize,
					"horizon_root": fmt.Sprintf("%x", res.RootHash),
					"gossip_root":  fmt.Sprintf("%x", gh.RootHash),
				})}
		}
	}

	v.record(p, PeerStatus{State: "ok", TreeSize: res.TreeSize, ProofsOK: res.ProofsOK})
	v.logger.Info("horizon audit: verified",
		"peer", p.BaseURL, "tree_size", res.TreeSize, "cosigs", res.ValidCosigs,
		"quorum", res.Quorum, "proofs_ok", res.ProofsOK, "proofs_total", res.ProofsTotal)
	return nil
}

func (v *Verifier) alert(sev sdkmon.Severity, msg string, p Peer, details map[string]any) sdkmon.Alert {
	details["peer"] = p.BaseURL
	details["originator"] = p.OriginatorDID
	return sdkmon.Alert{
		Monitor:     MonitorHorizonAudit,
		Severity:    sev,
		Destination: sdkmon.Both,
		Message:     msg,
		Details:     details,
		EmittedAt:   time.Now().UTC(),
	}
}

func (v *Verifier) record(p Peer, st PeerStatus) {
	st.CheckedAt = time.Now().UTC()
	v.mu.Lock()
	v.status[p.BaseURL] = st
	v.mu.Unlock()
}

// Status returns a snapshot of the last per-peer audit outcomes (for ops).
func (v *Verifier) Status() map[string]PeerStatus {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]PeerStatus, len(v.status))
	for k, s := range v.status {
		out[k] = s
	}
	return out
}
