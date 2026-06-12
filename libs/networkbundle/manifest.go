/*
FILE PATH: libs/networkbundle/manifest.go

DESCRIPTION:

	The network consumption manifest — the wire half of the network bundle,
	served at GET /v1/network/bundle and published on-log as an entry citing
	the manifest anchor schema.

	One policy source, three projections: a network's gate VALIDATES against
	its cosignature + prerequisite policies; a composer AUTHORS from them;
	this schema SERIALIZES them — so the served contract structurally cannot
	drift from what the gate enforces. The wire shape EMBEDS the enforced
	types verbatim (policy.CosignatureRule, prereq.Prereq — both JSON-tagged)
	rather than re-modeling them.

	MECHANISM vs CONTENT: this file owns the document shape, validation, the
	operation-graph mechanics (cycle check, topological order, dependents),
	canonical bytes + content hash, and strict decode. A network owner's
	composer (e.g. a domain's jurisdiction projection, or the platform
	ledger's introspection composer) supplies the CONTENT.

	History: relocated verbatim-in-spirit from the judicial-network's
	netmanifest package; the format string and every JSON tag are unchanged,
	so previously published manifests decode bit-for-bit. Additions since the
	move (all optional, additive): NetworkRef.LogDID, Endpoint.Auth,
	Admission.EpochWindowSec, Manifest.Federation.
*/
package networkbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/baseproof/tooling/libs/policy"
	"github.com/baseproof/tooling/libs/prereq"
)

// ManifestFormat tags the wire document so a reader rejects an unknown
// vintage.
const ManifestFormat = "baseproof-network-manifest/v1"

// Manifest is the served + on-log document: how to consume ONE exchange on ONE
// network. Wire types use slices (never maps) so CanonicalBytes is
// deterministic.
type Manifest struct {
	Format   string     `json:"format"`
	Network  NetworkRef `json:"network"`
	Exchange string     `json:"exchange"` // the institution this manifest describes

	Endpoints []Endpoint `json:"endpoints,omitempty"`
	Admission Admission  `json:"admission"`

	// Submit + Status are uniform for every operation on this network: where a
	// write goes in, and how any instance's state is probed.
	Submit Submit       `json:"submit"`
	Status StatusProbes `json:"status"`

	Roles      []policy.Role `json:"roles,omitempty"`
	Datatypes  []Datatype    `json:"datatypes,omitempty"`
	Operations []Operation   `json:"operations"`

	// Federation lists the networks this one cites (cross-log anchors), so a
	// client can see the whole federation, not just one log.
	Federation []FederatedNet `json:"federation,omitempty"`
}

// NetworkRef names the network by REFERENCE — identity + the genesis pin.
// Trust material is NOT embedded: a consumer fetches the bootstrap from
// BootstrapEndpoint and verifies it against NetworkID (the established
// content-address + TOFU pattern).
//
// There is no bootstrap_hash sibling: NetworkID IS the canonical-bytes hash
// (NetworkID = SHA-256(canonical bootstrap)) — the manifest must not re-mint
// it.
type NetworkRef struct {
	NetworkID         string `json:"network_id,omitempty"` // 64-hex = SHA-256(canonical bootstrap)
	Name              string `json:"name,omitempty"`
	BootstrapEndpoint string `json:"bootstrap_endpoint,omitempty"`
	QuorumK           int    `json:"quorum_k,omitempty"`

	// LogDID is the destination log for platform writes on this network —
	// what a generic submit targets when an operation does not name its own
	// log. Optional: a manifest describing a read-only or multi-log posture
	// may omit it.
	LogDID string `json:"log_did,omitempty"`
}

// Endpoint is one service surface of the network, with its status probe and
// the endpoints it depends on (the deployment DAG).
type Endpoint struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Protocol  string    `json:"protocol,omitempty"`
	Transport Transport `json:"transport"`
	Status    string    `json:"status,omitempty"` // probe path, e.g. /healthz
	DependsOn []string  `json:"depends_on,omitempty"`

	// Auth is the credential posture a caller needs beyond transport:
	// "" / "none" (anonymous), "mtls" (client certificate), or
	// "signed-envelope" (a signed request envelope). Transport says how the
	// pipe is secured; Auth says what the caller must present over it.
	Auth string `json:"auth,omitempty"`
}

// Auth posture values for Endpoint.Auth.
const (
	AuthNone           = "none"
	AuthMTLS           = "mtls"
	AuthSignedEnvelope = "signed-envelope"
)

// Transport is the TLS posture a caller needs to reach an endpoint.
type Transport struct {
	TLS   string `json:"tls"`              // "server-verify" | "mtls" | "plaintext"
	CAPin string `json:"ca_pin,omitempty"` // optional 64-hex sha256 of the CA cert
}

// Admission states the two write-admission axes explicitly. Derived from boot
// state, never asserted: WriteVia is the gate iff the gate mints
// WriteAuthorizations; Payment lists the modes the forward actually supports.
type Admission struct {
	Payment     []string `json:"payment,omitempty"` // "credit", "pow"
	Gating      string   `json:"gating,omitempty"`  // "write-authorization" | "open"
	WriteVia    string   `json:"write_via"`         // endpoint ID writes go through
	PolicyProbe string   `json:"policy_probe,omitempty"`

	// EpochWindowSec is the proof-of-work epoch window for Mode B admission
	// (0 ⇒ not applicable / query the ledger). Carried so a client can build
	// admissible PoW without a pre-flight query.
	EpochWindowSec uint64 `json:"epoch_window_sec,omitempty"`
}

// Submit is where a write enters the network.
type Submit struct {
	Endpoint string `json:"endpoint"` // endpoint ID
	Path     string `json:"path"`     // e.g. /v1/entries/submit
}

// StatusProbes names how state is read, uniformly for every operation:
// protocol state (accepted → sequenced) at Protocol, finality at Finality
// (cosigned horizon ≥ seq), and DOMAIN state by the amendment-chain rule —
// an instance's status is the terminal entry of its closed_by/amended_by
// chain.
type StatusProbes struct {
	Protocol string `json:"protocol"` // e.g. ledger:/v1/entries-hash/{hash}
	Finality string `json:"finality"` // e.g. ledger:/v1/tree/horizon
	Domain   string `json:"domain"`
}

// Datatype is a payload vocabulary entry, referenced verifiably: by URI and —
// when published — by on-log position + content hash.
type Datatype struct {
	Name        string `json:"name"`
	URI         string `json:"uri,omitempty"`
	LogDID      string `json:"log_did,omitempty"`
	Sequence    uint64 `json:"sequence,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
}

// FederatedNet names a network cited by this one in the federation.
type FederatedNet struct {
	Name      string `json:"name,omitempty"`
	NetworkID string `json:"network_id"`         // 64-hex
	Endpoint  string `json:"endpoint,omitempty"` // optional ledger base URL
}

// Operation is one node of the operation DAG. Signing and Requires EMBED the
// enforced policy types verbatim — the same structs the network's gate checks —
// so describe and validate share one source. The overlay fields carry the
// authoring knowledge that exists nowhere else (primary signer, datatype,
// minted/cited identifiers, lifecycle edges).
type Operation struct {
	EventType string `json:"event_type"`

	// Kind: "origin" when no Hard RequiredAncestor rule orders this operation
	// after another (it may still be authority-gated); "dependent" otherwise.
	Kind string `json:"kind"`

	// Signing is the enforced cosignature mix (nil ⇒ no cosignature rule — a
	// bootstrap/vocabulary-only event the gate admits on prerequisites alone).
	Signing *policy.CosignatureRule `json:"signing,omitempty"`

	// Requires are the enforced admission-order edges (hard/advisory;
	// RequiredAncestor lists carry OR semantics).
	Requires []prereq.Prereq `json:"requires,omitempty"`

	// Overlay (authoring knowledge; optional).
	PrimaryRole string   `json:"primary_role,omitempty"`
	Datatype    string   `json:"datatype,omitempty"`
	Mints       []string `json:"mints,omitempty"`
	References  []string `json:"references,omitempty"`
	ClosedBy    []string `json:"closed_by,omitempty"` // lifecycle: events that close/amend an instance
}

// OpOverlay is the per-event authoring overlay a composer supplies (the
// knowledge the policies don't carry: who signs first, what shape, what it
// mints, what closes it).
type OpOverlay struct {
	PrimaryRole string
	Datatype    string
	Mints       []string
	References  []string
	ClosedBy    []string
}

// BuildInput carries everything outside a network owner's policy sources:
// network identity by reference, the endpoint inventory, admission posture,
// probes, federation, and the optional per-event overlay. Composers (a
// domain's jurisdiction projection, the platform ledger's introspection
// composer) fill one of these and assemble Operations beside it.
type BuildInput struct {
	Network    NetworkRef
	Endpoints  []Endpoint
	Admission  Admission
	Submit     Submit
	Status     StatusProbes
	Overlay    map[string]OpOverlay
	Datatypes  []Datatype
	Federation []FederatedNet
}

// OperationKind classifies an operation from its prerequisite rules:
// "dependent" when any Hard RequiredAncestor rule orders it after another
// operation; "origin" otherwise (authority-gated events with no log-order
// dependency are origins of the DAG).
func OperationKind(rules []prereq.Prereq) string {
	for i := range rules {
		if rules[i].Mode == prereq.PrereqModeHard && rules[i].IsAncestorRule() {
			return "dependent"
		}
	}
	return "origin"
}

// NewOperation assembles one DAG node from the enforced policy pieces and the
// authoring overlay, computing Kind — so every composer classifies operations
// by exactly one rule.
func NewOperation(eventType string, signing *policy.CosignatureRule, requires []prereq.Prereq, ov OpOverlay) Operation {
	return Operation{
		EventType:   eventType,
		Kind:        OperationKind(requires),
		Signing:     signing,
		Requires:    requires,
		PrimaryRole: ov.PrimaryRole,
		Datatype:    ov.Datatype,
		Mints:       append([]string(nil), ov.Mints...),
		References:  append([]string(nil), ov.References...),
		ClosedBy:    append([]string(nil), ov.ClosedBy...),
	}
}

// Validate checks the manifest's internal structure:
//
//   - format tag, exchange, and per-operation event types are non-empty;
//     operation event types are unique;
//   - every overlay edge (ClosedBy / References) targets an operation IN the
//     manifest — a lifecycle edge to an unknown event is authoring drift;
//   - endpoint DependsOn edges and Submit.Endpoint resolve to declared
//     endpoint IDs (when any endpoints are declared), endpoint Auth values
//     are from the closed posture set, and federation entries carry a
//     network id;
//   - the UNAMBIGUOUS-hard-edge subgraph is acyclic: an edge evt→anc exists
//     when a Hard rule names exactly ONE ancestor. OR-alternative lists are
//     excluded from the cycle check (an OR edge is not an unconditional
//     dependency), so a legitimate either-or policy never false-positives.
func (m *Manifest) Validate() error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("networkbundle: format %q, want %q", m.Format, ManifestFormat)
	}
	if m.Exchange == "" {
		return errors.New("networkbundle: exchange is required")
	}
	known := make(map[string]bool, len(m.Operations))
	for i := range m.Operations {
		evt := m.Operations[i].EventType
		if evt == "" {
			return fmt.Errorf("networkbundle: operations[%d] has empty event_type", i)
		}
		if known[evt] {
			return fmt.Errorf("networkbundle: duplicate operation %q", evt)
		}
		known[evt] = true
	}
	for i := range m.Operations {
		op := &m.Operations[i]
		for _, t := range op.ClosedBy {
			if !known[t] {
				return fmt.Errorf("networkbundle: %s closed_by %q: not an operation in this manifest", op.EventType, t)
			}
		}
		for _, t := range op.References {
			if !known[t] {
				return fmt.Errorf("networkbundle: %s references %q: not an operation in this manifest", op.EventType, t)
			}
		}
	}
	if len(m.Endpoints) > 0 {
		eps := make(map[string]bool, len(m.Endpoints))
		for i := range m.Endpoints {
			if m.Endpoints[i].ID == "" || m.Endpoints[i].URL == "" {
				return fmt.Errorf("networkbundle: endpoints[%d] needs id + url", i)
			}
			if eps[m.Endpoints[i].ID] {
				return fmt.Errorf("networkbundle: duplicate endpoint id %q", m.Endpoints[i].ID)
			}
			eps[m.Endpoints[i].ID] = true
		}
		for i := range m.Endpoints {
			for _, d := range m.Endpoints[i].DependsOn {
				if !eps[d] {
					return fmt.Errorf("networkbundle: endpoint %q depends_on unknown %q", m.Endpoints[i].ID, d)
				}
			}
		}
		if m.Submit.Endpoint != "" && !eps[m.Submit.Endpoint] {
			return fmt.Errorf("networkbundle: submit.endpoint %q not a declared endpoint", m.Submit.Endpoint)
		}
	}
	for i := range m.Endpoints {
		switch m.Endpoints[i].Auth {
		case "", AuthNone, AuthMTLS, AuthSignedEnvelope:
		default:
			return fmt.Errorf("networkbundle: endpoint %q auth %q: want none|mtls|signed-envelope",
				m.Endpoints[i].ID, m.Endpoints[i].Auth)
		}
	}
	for i := range m.Federation {
		if m.Federation[i].NetworkID == "" {
			return fmt.Errorf("networkbundle: federation[%d] needs network_id", i)
		}
	}
	if cycle := findHardCycle(m.Operations); len(cycle) > 0 {
		return fmt.Errorf("networkbundle: hard-prerequisite cycle: %v", cycle)
	}
	return nil
}

// findHardCycle DFS-checks the unambiguous hard-edge subgraph (single-ancestor
// Hard rules between in-manifest operations). Returns a witness path or nil.
func findHardCycle(ops []Operation) []string {
	edges := make(map[string][]string, len(ops))
	in := make(map[string]bool, len(ops))
	for i := range ops {
		in[ops[i].EventType] = true
	}
	for i := range ops {
		for _, r := range ops[i].Requires {
			if r.Mode == prereq.PrereqModeHard && len(r.RequiredAncestor) == 1 && in[r.RequiredAncestor[0]] {
				edges[ops[i].EventType] = append(edges[ops[i].EventType], r.RequiredAncestor[0])
			}
		}
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	color := make(map[string]int, len(ops))
	var stack []string
	var visit func(string) []string
	visit = func(n string) []string {
		color[n] = grey
		stack = append(stack, n)
		for _, next := range edges[n] {
			switch color[next] {
			case grey:
				return append(stack, next) // cycle witness
			case white:
				if c := visit(next); c != nil {
					return c
				}
			}
		}
		color[n] = black
		stack = stack[:len(stack)-1]
		return nil
	}
	for i := range ops {
		if color[ops[i].EventType] == white {
			if c := visit(ops[i].EventType); c != nil {
				return c
			}
		}
	}
	return nil
}

// TopoOrder returns the operations in a dependency-respecting order (origins
// first), using the same unambiguous hard edges as the cycle check; ties
// resolve alphabetically so the order is deterministic. A scenario driver
// submits in this order.
func (m *Manifest) TopoOrder() []string {
	in := make(map[string]bool, len(m.Operations))
	for i := range m.Operations {
		in[m.Operations[i].EventType] = true
	}
	deps := make(map[string]map[string]bool, len(m.Operations))
	for i := range m.Operations {
		evt := m.Operations[i].EventType
		deps[evt] = map[string]bool{}
		for _, r := range m.Operations[i].Requires {
			if r.Mode == prereq.PrereqModeHard && len(r.RequiredAncestor) == 1 && in[r.RequiredAncestor[0]] {
				deps[evt][r.RequiredAncestor[0]] = true
			}
		}
	}
	out := make([]string, 0, len(deps))
	done := make(map[string]bool, len(deps))
	for len(out) < len(deps) {
		progressed := false
		var ready []string
		for evt, d := range deps {
			if done[evt] {
				continue
			}
			ok := true
			for anc := range d {
				if !done[anc] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, evt)
			}
		}
		sort.Strings(ready)
		for _, evt := range ready {
			done[evt] = true
			out = append(out, evt)
			progressed = true
		}
		if !progressed { // cycle residue: append the rest deterministically
			var rest []string
			for evt := range deps {
				if !done[evt] {
					rest = append(rest, evt)
				}
			}
			sort.Strings(rest)
			return append(out, rest...)
		}
	}
	return out
}

// DependentsOf returns the operations that transitively REQUIRE evt over Hard
// ancestor edges (OR-alternatives included here — any rule NAMING evt makes
// the dependent's status sensitive to it). This is the monitoring cascade: an
// instance of evt changing domain status is relevant to every returned
// operation.
func (m *Manifest) DependentsOf(evt string) []string {
	rev := make(map[string][]string)
	for i := range m.Operations {
		for _, r := range m.Operations[i].Requires {
			if r.Mode != prereq.PrereqModeHard {
				continue
			}
			for _, anc := range r.RequiredAncestor {
				rev[anc] = append(rev[anc], m.Operations[i].EventType)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(string)
	walk = func(n string) {
		for _, d := range rev[n] {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
				walk(d)
			}
		}
	}
	walk(evt)
	sort.Strings(out)
	return out
}

// CanonicalBytes is the deterministic wire form (struct-ordered JSON; the wire
// types use slices, never maps). The on-log entry payload and the served body
// are exactly these bytes; ContentHash is their sha256.
func (m *Manifest) CanonicalBytes() ([]byte, error) {
	return json.Marshal(m)
}

// ContentHash is sha256(CanonicalBytes) — the pin a consumer verifies the
// served document against (ETag) and the on-log payload hash.
func (m *Manifest) ContentHash() ([32]byte, error) {
	b, err := m.CanonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DecodeManifest parses + validates a wire manifest (strict: unknown fields
// rejected, so a reader can't silently misread a future vintage).
func DecodeManifest(data []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("networkbundle: decode: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
