/*
Package didregistry constructs the canonical baseproof DID
VerifierRegistry every tooling binary uses to verify
gossip events, cross-log proofs, and other DID-signed payloads.

Why this package exists
=======================

Pre-v1.37 the auditor and other tools-side consumers each built
their own *did.VerifierRegistry. The constructors were
near-identical (Register("key", did.NewKeyVerifier())) so the
duplication was tolerable. v1.37 changes that calculus on two
axes simultaneously:

 1. The SDK's did.NewKeyVerifier() now dispatches three new
    algorithms (ML-DSA-65, ML-DSA-87, SLH-DSA-128s) via
    multicodec multiplex. Existing call sites that registered
    only "key" pick those up automatically — no code change.

 2. The SDK's did.NewWebVerifier(resolver) gains the same PQ
    dispatch path. To actually use the v1.37 PQ surface for
    entities that publish their keys via DID Documents, the
    registry must register "web" too. Every consumer that
    OMITS that registration silently rejects every PQ-signed
    did:web event.

Centralizing the registry build here means every tools-side
consumer gets both methods registered, with the same outbound
HTTP posture (mTLS material flows through), and any future
algorithm or method addition lands in one place instead of N.

What the canonical registry includes
====================================

  - "key" → did.NewKeyVerifier()
    Handles did:key:z6Mk... (secp256k1), did:key:z6Mk... (Ed25519),
    did:key:zPq... (ML-DSA-65), did:key:zPq8... (ML-DSA-87),
    did:key:zSlh... (SLH-DSA-128s).
    Multicodec multiplex: a single Register call covers all.

  - "web" → did.NewWebVerifier(resolver)
    Same five algorithms, surfaced via the W3C VC
    verification-method type strings the SDK ships
    constants for (did.VerificationMethodMLDSA65 etc.).

For PQ signing on the witness daemon (the other half of end-to-end
PQ) the SDK does NOT yet ship a cosign.NewMLDSAWitnessSigner
equivalent. That gap is tracked separately; the verify side
adopted here is complete and ships standalone.
*/
package didregistry
