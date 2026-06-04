/*
Package anchorcache is the filesystem-backed trust-anchor cache —
the local state a long-running verifier (auditor binary, future
CLI) keeps under ~/.baseproof/ for each network it interacts with.

# THE 20-YEAR CONTRACT

A verifier that pins a network at year-1 must still be able to
verify a bundle produced under that network's year-1 witness set
in year-20 even after:

  - The original ledger has been retired (archive fallback via
    SDK discover.FetchArchivedMirrors)
  - The witness set has rotated N times (witness_sets history;
    libs/bundle/HTTPWitnessSetResolver resolves by historical
    SetHash)
  - The network's signature policy has changed
    (BootstrapDocument.GenesisSignaturePolicy is hashed into
    NetworkID, so the NetworkID itself anchors the policy)

This package is the disk-resident layer that survives across
process restarts. The in-memory caches in libs/bundle/
(HTTPWitnessSetResolver's sync.Map) are convenience; this cache
is the AUTHORITY for "what network did I trust on first contact?"

# LAYOUT

	~/.baseproof/
	  config.json                       — global CLI / auditor config
	  networks/
	    did:baseproof:network:<crockford>/
	      bootstrap.json                — pinned on TOFU; refuses to change
	      identity.json                 — NetworkID, UUID, DID, BootstrapHash
	      witnesses/
	        <set_hash>.json             — historical sets; immutable
	        index.json                  — optional set_hash → effective_seq
	      mirrors.json                  — last-known-good mirror URLs
	      peers.json                    — cached FederationGraph
	      anchors.json                  — cached AnchorChain
	      policy/
	        signature.json              — cached SignaturePolicyView
	        algorithm.json              — (future) AlgorithmPolicyView
	        version.json                — (future) ProtocolVersionView

The per-network directory is keyed by the network's DID (a
content-addressed identifier — did:baseproof:network:<crockford-
encoded UUID-from-NetworkID-prefix>). Two networks with
different bootstraps land in different directories.

# TOFU SEMANTICS

  - First contact with a network → fetch bootstrap, derive
    NetworkID, create networks/<did>/bootstrap.json. The
    bootstrap is the trust anchor; everything else can be
    rebuilt by re-fetching from the network's endpoints.
  - Subsequent contact → re-fetch bootstrap, verify its
    fingerprint matches the pinned bootstrap.json. Mismatch →
    refuse to proceed (ErrPinMismatch). This is the SSH
    known-hosts model.
  - The cache is FAIL-CLOSED — a damaged bootstrap.json (e.g.,
    truncated, malformed JSON, missing required fields) is an
    error, NOT a silent re-pin. Recovery requires operator
    intervention (delete the directory and accept a fresh
    first-contact pin).

# RELATIONSHIP TO SDK log/discover/tofu.go

The SDK ships PinStore + ComputeFingerprint as the abstract
interface. This package ships a filesystem-backed impl plus the
broader directory layout that holds the network's cached views.
The PinStore aspect (FSPinStore below) satisfies the SDK
interface; consumers requiring just TOFU pinning use that. The
full ManagedDir interface adds the per-network view stash.

# ATOMIC WRITES

Every write goes through an os.WriteFile + os.Rename pair so a
process crash mid-write cannot leave a partial file. The
filesystem boundary is the durability guarantee — a sync after
every write would be more conservative but is overkill for cache
data that's rebuildable from the network on miss.

# CONCURRENCY

A single process is expected to be the sole writer to its
~/.baseproof/ directory (the auditor binary, OR a CLI session,
NOT both at once). The cache does NOT take a lockfile; if two
processes race, the LAST writer wins on each individual file.
Per-file atomicity prevents corruption, but cross-file
consistency (e.g., witnesses/index.json + witnesses/<hash>.json
disagreeing) is the operator's responsibility to manage by NOT
running two writers.

# SCOPE BOUNDARY

This package OWNS the disk layout + the TOFU primitive. It does
NOT own:

  - The HTTP fetch (libs/bundle's HTTPWitnessSetResolver,
    libs/clitools's HTTPCheckpointClient).
  - The federation walker (SDK log/discover/FindCrossLogPath).
  - The CLI command structure (cmd/baseproof/).

Consumers compose this package with those.
*/
package anchorcache
