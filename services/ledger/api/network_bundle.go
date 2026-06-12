/*
FILE PATH: api/network_bundle.go

DESCRIPTION:

	GET /v1/network/bundle — the platform ledger's introspection COMPOSER for
	the baseproof-network-manifest/v1 document, mounted through the shared
	libs/networkbundle serve handler (the same handler a domain composer
	mounts, so ETag semantics and published-vs-enforced drift detection can
	never diverge between the platform and any tenant).

	DERIVED, NEVER ASSERTED: every field comes from the same boot-frozen
	sources the sibling /v1/network/* handlers serve — the bootstrap document
	(identity via BuildNetworkIdentity, quorum, name), the destination log
	DID, the federation graph (/v1/network/peers' siblings), and the
	admission posture. The platform document carries an EMPTY operation DAG:
	the platform has no domain vocabulary; a domain network composes its own
	manifest with Operations on its own gate.

	The manifest's destination key is the network DID — the discoverable
	identifier /v1/network/identity publishes — so a client that has read
	identity can ask for the bundle by exactly that handle.
*/
package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/networkbundle"
)

// NetworkBundleSources is everything the introspection composer derives the
// platform manifest from. All values are boot-frozen — the same freeze the
// sibling /v1/network/* handlers serve.
type NetworkBundleSources struct {
	// Doc is the genesis bootstrap document (identity, quorum, name). A zero
	// document means the network is not bootstrap-configured: the handler is
	// not mounted (NewNetworkBundleHandler returns nil, nil).
	Doc network.BootstrapDocument

	// LogDID is the destination log for platform writes.
	LogDID string

	// PublicURL is the ledger's advertised base URL (LEDGER_PUBLIC_URL).
	// Empty ⇒ the manifest declares no Endpoints section: a consumer already
	// knows the URL it fetched the bundle from, and the document must not
	// assert an address the operator never configured. The transport posture
	// is derived from the scheme: https ⇒ server-verify, http ⇒ plaintext.
	PublicURL string

	// Payment lists the admission payment modes the /v1/entries forward
	// actually supports (e.g. "credit", "pow").
	Payment []string

	// EpochWindowSec is the Mode-B proof-of-work epoch window (0 ⇒ omitted).
	EpochWindowSec uint64

	// Federation is the boot-frozen peers snapshot (the same graph
	// /v1/network/peers serves); mapped to the manifest's federation list.
	Federation WireFederationGraph

	// Anchor optionally names the on-log manifest anchor "<log-did>@<seq>".
	// When set, the shared serve handler resolves the PUBLISHED manifest
	// from this ledger itself (LedgerBaseURL below) and surfaces drift
	// against this compiled projection.
	Anchor string

	// LedgerBaseURL is where the serve handler resolves publications when
	// Anchor is set — for the platform ledger, its own base URL.
	LedgerBaseURL string

	Client *http.Client
	Logger *slog.Logger
}

// NewNetworkBundleHandler composes the platform manifest and mounts it on the
// shared networkbundle serve handler. Returns (nil, nil) when the node has no
// bootstrap document — the route is then simply not mounted, matching the
// 404 posture of the other identity-derived surfaces.
func NewNetworkBundleHandler(s NetworkBundleSources) (http.Handler, error) {
	id, err := BuildNetworkIdentity(s.Doc)
	if err != nil {
		return nil, fmt.Errorf("network bundle: identity: %w", err)
	}
	if id.NetworkID == "" {
		return nil, nil // pre-bootstrap node: nothing to describe
	}

	m, err := composePlatformManifest(id, s)
	if err != nil {
		return nil, fmt.Errorf("network bundle: compose: %w", err)
	}

	return networkbundle.NewServeHandler(networkbundle.ServeConfig{
		Compile: func(destination string) (*networkbundle.Manifest, error) {
			if destination != id.NetworkDID {
				return nil, fmt.Errorf("%w: %s", networkbundle.ErrUnknownDestination, destination)
			}
			return m, nil
		},
		Destinations:  func() []string { return []string{id.NetworkDID} },
		Anchor:        s.Anchor,
		LedgerBaseURL: s.LedgerBaseURL,
		Client:        s.Client,
		Logger:        s.Logger,
	})
}

// composePlatformManifest assembles + validates the document once at boot.
func composePlatformManifest(id NetworkIdentity, s NetworkBundleSources) (*networkbundle.Manifest, error) {
	const ledgerEndpointID = "ledger"

	var endpoints []networkbundle.Endpoint
	writeVia, submitEndpoint := "", ""
	if s.PublicURL != "" {
		tls := "server-verify"
		if strings.HasPrefix(s.PublicURL, "http://") {
			tls = "plaintext"
		}
		endpoints = []networkbundle.Endpoint{{
			ID:        ledgerEndpointID,
			URL:       strings.TrimRight(s.PublicURL, "/"),
			Protocol:  "baseproof-ledger/v1",
			Transport: networkbundle.Transport{TLS: tls},
			Status:    "/healthz",
		}}
		writeVia, submitEndpoint = ledgerEndpointID, ledgerEndpointID
	}

	var federation []networkbundle.FederatedNet
	for _, sib := range s.Federation.Siblings {
		federation = append(federation, networkbundle.FederatedNet{
			NetworkID: sib.NetworkID,
			Endpoint:  sib.AdmissionURL,
		})
	}

	m := &networkbundle.Manifest{
		Format: networkbundle.ManifestFormat,
		Network: networkbundle.NetworkRef{
			NetworkID:         id.NetworkID,
			Name:              s.Doc.NetworkName,
			BootstrapEndpoint: strings.TrimRight(s.PublicURL, "/"),
			QuorumK:           s.Doc.GenesisQuorumK,
			LogDID:            s.LogDID,
		},
		Exchange:  id.NetworkDID,
		Endpoints: endpoints,
		Admission: networkbundle.Admission{
			Payment:        append([]string(nil), s.Payment...),
			Gating:         "open", // direct writes; a gated tenant fronts its own composer
			WriteVia:       writeVia,
			PolicyProbe:    "/v1/admission/policy",
			EpochWindowSec: s.EpochWindowSec,
		},
		Submit: networkbundle.Submit{Endpoint: submitEndpoint, Path: "/v1/entries"},
		Status: networkbundle.StatusProbes{
			Protocol: "ledger:/v1/entries-hash/{hash}",
			Finality: "ledger:/v1/tree/horizon",
			Domain:   "closed_by chain",
		},
		// The platform carries no domain vocabulary: no roles, no datatypes,
		// an empty operation DAG. Domain networks publish their own manifest.
		Operations: []networkbundle.Operation{},
		Federation: federation,
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}
