/*
Package bundle is the tooling wrapper around the SDK's
log/bundle/ surface. It provides:

  - HTTP fetch from /v1/bundle/{seq} with mirror failover
    (consumes the SDK's MirrorManifest discovery shape).
  - WitnessSetResolver implementations that consume
    /v1/network/witnesses/{set_hash}.
  - VerifyBundle wrapper with operator-friendly error
    classification.
  - Pretty-print rendering for CLI tools (baseproof inspect).

# WHY THIS LAYER EXISTS (vs. directly using SDK log/bundle)

The SDK's log/bundle ships the WIRE FORMAT (Decode/Encode), the
ASSEMBLER (BuildBundle), and the VERIFIER (VerifyBundle). It does
NOT ship the OPERATOR-FACING CONCERNS:

  - HTTP transport with mirror failover + DoS-bounded response
  - TOFU pinning on first contact with a NetworkID
  - Caller-friendly error taxonomy (transport vs. crypto vs.
    structural-rejection)
  - Pretty-print for CLI inspect

Those concerns belong in TOOLING, not in the SDK. The SDK stays
small and verifier-focused; this package adds the operator-grade
plumbing the auditor binary and a future `baseproof inspect` CLI
share.

# DRIFT-PROOF BY CONSTRUCTION

This package delegates EVERY cryptographic check to the SDK
(log/bundle.VerifyBundle). It MUST NOT re-implement Merkle, SMT,
or cosignature verification. The auditor and a future CLI consume
the same SDK code path through this package, so a regression in
one cannot diverge from the other — the SDK is the canonical
implementation.

# PRODUCT-GOAL ALIGNMENT

  - #4 cross-log attestation/verification — the bundle is the
    portable artifact that lets one log's verifier prove
    inclusion of another log's entry; this package is the
    fetch+verify transport.
  - #6 Zero-Trust — every byte the package returns has either
    been verified by SDK VerifyBundle or is informational
    (raw bytes accompanied by a Report.AllChecksGreen() verdict).
  - #11 bundle-format wire freeze — package consumes SDK
    log/bundle.Decode exclusively; no parallel decoder.
  - #13 historical bundles remain verifiable — package's
    witness-set resolver consumes
    /v1/network/witnesses/{set_hash} which is content-
    addressable + immutable; a bundle minted under retired
    witness set A continues to verify in year-20 because the
    set lookup is by hash, not by current-set.
  - #15 archive fallback — mirror failover composes with SDK
    log/discover.FetchArchivedMirrors when the live ledger is
    offline.
*/
package bundle
