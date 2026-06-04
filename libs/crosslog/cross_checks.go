/*
FILE PATH: libs/crosslog/cross_checks.go

T9 — Advisory cross-check runner for v1.32.0 materialized network
records vs the live did:web documents of their identifiers.

# WHAT THIS DOES

For each record in a MaterializedNetwork (the output of
MaterializeFromEntries), fetch the corresponding did:web document
via the supplied did.DIDResolver and run the SDK's
CrossCheckAgainstDIDDocument helper to detect drift between the
on-log surface (network-signed) and the did:web surface
(domain-controlled).

  - WitnessEndpointDeclaration.CrossCheckAgainstDIDDocument compares
    the on-log endpoints map vs did:web service[Type="Baseproof*"]
    entries (per-service-type URL equality).
  - WitnessIdentityLabel.CrossCheckAgainstDIDDocument compares the
    on-log DIDHint (if set) vs the did:web document's ID.
  - AuditorRegistration.CrossCheckAgainstDIDDocument compares the
    on-log public key + findings URL vs the did:web's verificationMethod
  - service[Type=BaseproofAuditor] entries.

# WHY ADVISORY

The on-log surface is AUTHORITATIVE — the resolver returns on-log
URLs regardless of cross-check outcome. The cross-check is a
DETECTION primitive: a domain-level compromise of an auditor's
or witness's did:web origin manifests as a mismatch HERE without
ever changing what the resolver returns to consumers. Operators
who grep for "cross_check_mismatch" log lines see the compromise
attempt before any cryptographic failure surfaces.

# WHY THIS LIVES IN CROSSLOG

The cross-check operates on the SDK's typed records (the output of
MaterializeFromEntries), not on cached bytes. anchorcache holds
the bytes; crosslog holds the typed view; the cross-check
naturally lives next to MaterializeFromEntries — same domain.

# WHY A SLICE, NOT slog-WARN-ONLY

The function emits slog.Warn for each mismatch (operator
visibility) AND returns the list (programmatic consumption by
T11's url_drift_audit). Returning the list lets the periodic
monitor convert each mismatch into a monitoring.Alert without
re-running the check. A nil return + slog-only design would force
the monitor to re-run the check every cycle just to compute the
alert payload.

# WHAT IT DOES NOT DO

  - No HTTP retry on did:web fetch failure. The did.DIDResolver
    typically caches; a failure means the DID is genuinely
    unreachable. We log the skip (Debug level) and continue —
    transient resolution failures are a normal operational state
    that the cross-check should NOT flag as a mismatch.
  - No verification of the did:web document's signature. Did:web
    is a content-addressed off-log surface; the SDK does not
    validate signatures on did:web docs (a hostile DNS surface
    can rewrite them at will — that's exactly why the on-log
    surface is authoritative).
*/
package crosslog

import (
	"context"
	"errors"
	"log/slog"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

// MismatchKind classifies which record class produced the mismatch.
type MismatchKind string

const (
	MismatchKindEndpoint MismatchKind = "witness_endpoint_declaration"
	MismatchKindLabel    MismatchKind = "witness_identity_label"
	MismatchKindAuditor  MismatchKind = "auditor_registration"
)

// CrossCheckMismatch describes one (record, did:web doc, reason)
// triple where the SDK's CrossCheckAgainstDIDDocument helper
// returned a non-nil error. Carried by RunAdvisoryCrossChecks so
// callers (T11's url_drift_audit) can convert each into a
// monitoring.Alert.
type CrossCheckMismatch struct {
	// Kind classifies which record type the mismatch came from.
	Kind MismatchKind

	// Identifier is the human-readable identifier of the record:
	//   - For endpoints / labels: the hex-encoded PubKeyID prefix
	//     (8 chars — enough to disambiguate, short enough for logs).
	//   - For auditors: the AuditorDID string.
	Identifier string

	// DID is the DID resolved during the cross-check (the witness's
	// DIDHint, or the auditor's AuditorDID).
	DID string

	// Reason is the SDK's structural error message (e.g.,
	// "service-type=BaseproofWitness on-log=https://x did:web=https://y").
	Reason string
}

// RunAdvisoryCrossChecks compares every record in materialized
// against its corresponding did:web document via resolver and
// returns the list of mismatches.
//
// resolver may be nil — in which case the function returns
// (nil, nil) immediately. Production deployments pair this with
// clienttls.BuildDIDResolverWithMTLS so the did:web fetches go
// through the binary's hoisted outbound mTLS client.
//
// Per-record DID-resolution failures (network errors, DID not
// found, etc.) are logged at Debug level and skipped — they do
// NOT contribute to the returned mismatch list. Only structural
// drift between the on-log record and a SUCCESSFULLY resolved
// did:web document counts.
//
// Mismatches are also emitted as slog.Warn under
// "crosslog.cross_check_mismatch" so an operator grepping the
// logs sees the drift in real time even without wiring a
// monitor on top.
func RunAdvisoryCrossChecks(
	ctx context.Context,
	materialized MaterializedNetwork,
	resolver did.DIDResolver,
	logger *slog.Logger,
) []CrossCheckMismatch {
	if logger == nil {
		logger = slog.Default()
	}
	if resolver == nil {
		return nil
	}

	var out []CrossCheckMismatch

	// WitnessEndpointDeclarationV1 — cross-check the endpoints map
	// against the witness's did:web service[] entries. The DID to
	// resolve comes from the most-recent matching WitnessIdentityLabelV1
	// record's DIDHint; if no label exists or the label has no
	// DIDHint, the endpoint record's cross-check is skipped (the
	// SDK's check requires a did:web target).
	for _, rec := range materialized.Endpoints {
		didHint := latestDIDHint(materialized.Labels, rec.Payload.PubKeyID)
		if didHint == "" {
			logger.Debug("crosslog.cross_check_skipped",
				"kind", MismatchKindEndpoint,
				"pub_key_id", shortPubKeyID(rec.Payload.PubKeyID),
				"reason", "no DIDHint in matching WitnessIdentityLabelV1 record")
			continue
		}
		doc, err := resolver.Resolve(ctx, didHint)
		if err != nil {
			logger.Debug("crosslog.cross_check_skipped",
				"kind", MismatchKindEndpoint,
				"pub_key_id", shortPubKeyID(rec.Payload.PubKeyID),
				"did", didHint,
				"reason", "DID resolve failed",
				"error", err.Error())
			continue
		}
		if cerr := rec.Payload.CrossCheckAgainstDIDDocument(doc); cerr != nil {
			m := CrossCheckMismatch{
				Kind:       MismatchKindEndpoint,
				Identifier: shortPubKeyID(rec.Payload.PubKeyID),
				DID:        didHint,
				Reason:     cerr.Error(),
			}
			out = append(out, m)
			logger.Warn("crosslog.cross_check_mismatch",
				"kind", m.Kind,
				"identifier", m.Identifier,
				"did", m.DID,
				"reason", m.Reason)
		}
	}

	// WitnessIdentityLabelV1 — the SDK's check returns nil when the
	// DIDHint is empty (it's optional). When set, the check compares
	// the on-log DIDHint vs the resolved doc's ID.
	for _, rec := range materialized.Labels {
		if rec.Payload.DIDHint == "" {
			continue
		}
		doc, err := resolver.Resolve(ctx, rec.Payload.DIDHint)
		if err != nil {
			logger.Debug("crosslog.cross_check_skipped",
				"kind", MismatchKindLabel,
				"pub_key_id", shortPubKeyID(rec.Payload.PubKeyID),
				"did", rec.Payload.DIDHint,
				"reason", "DID resolve failed",
				"error", err.Error())
			continue
		}
		if cerr := rec.Payload.CrossCheckAgainstDIDDocument(doc); cerr != nil {
			// ErrWitnessLabelConsistencyMismatch is the expected wrap
			// — surface it verbatim so the operator sees the offending
			// DIDHint/doc.ID pair.
			m := CrossCheckMismatch{
				Kind:       MismatchKindLabel,
				Identifier: shortPubKeyID(rec.Payload.PubKeyID),
				DID:        rec.Payload.DIDHint,
				Reason:     cerr.Error(),
			}
			out = append(out, m)
			logger.Warn("crosslog.cross_check_mismatch",
				"kind", m.Kind,
				"identifier", m.Identifier,
				"did", m.DID,
				"reason", m.Reason)
		}
	}

	// AuditorRegistrationV1 — every auditor's DID is by definition
	// a DID (validated at construction), so the resolve is always
	// attempted.
	for _, rec := range materialized.Auditors {
		doc, err := resolver.Resolve(ctx, rec.Payload.AuditorDID)
		if err != nil {
			logger.Debug("crosslog.cross_check_skipped",
				"kind", MismatchKindAuditor,
				"auditor_did", rec.Payload.AuditorDID,
				"reason", "DID resolve failed",
				"error", err.Error())
			continue
		}
		if cerr := rec.Payload.CrossCheckAgainstDIDDocument(doc); cerr != nil {
			m := CrossCheckMismatch{
				Kind:       MismatchKindAuditor,
				Identifier: rec.Payload.AuditorDID,
				DID:        rec.Payload.AuditorDID,
				Reason:     cerr.Error(),
			}
			out = append(out, m)
			logger.Warn("crosslog.cross_check_mismatch",
				"kind", m.Kind,
				"identifier", m.Identifier,
				"did", m.DID,
				"reason", m.Reason)
		}
	}

	return out
}

// latestDIDHint walks the labels slice backwards for the most
// recent label record matching pubKeyID and returns its DIDHint.
// Empty string when no record or no hint. Mirrors the SDK's
// internal lookupDIDHint in discover/endpoint_resolver.go (kept
// private there; duplicated here so the cross-check can find the
// DID without going through the full Resolve path).
func latestDIDHint(labels network.WitnessIdentityLabelByPosition, pubKeyID [32]byte) string {
	for i := len(labels) - 1; i >= 0; i-- {
		rec := labels[i]
		if rec.Payload.PubKeyID != pubKeyID {
			continue
		}
		return rec.Payload.DIDHint
	}
	return ""
}

// ensure the network package's sentinels are referenced so a
// regression that removes them (or renames them) surfaces at
// build time, not at first cross-check.
var _ = errors.Is
var _ = network.ErrEndpointConsistencyMismatch
