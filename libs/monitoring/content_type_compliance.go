/*
content_type_compliance.go — judicial.content_type_compliance (Tier 7h).

Independent re-verification that every committed PUBLIC artifact's bytes match
its SIGNED MIME claim. The claim is per-artifact and immutable — it rides on the
log in the ArtifactGenesis entry (the signed MIMEType) — and the bytes are
content-addressed. There is NO on-log content-type policy: the auditor simply
runs the SAME crypto/artifact validator mechanism the producer FINISH gate runs,
over the same immutable inputs. Same code + same inputs => same verdict, so a
mismatch is a genuine finding, not drift.

A mismatch is CRITICAL: in steady state it is impossible (the producer's FINISH
gate already rejected type-mismatched artifacts), so when it fires it has caught
a producer-gate bypass or backend corruption — exactly the defense-in-depth this
monitor exists for.

For SEALED content the auditor holds only ciphertext and cannot re-validate the
plaintext; the signed claim's presence + well-formedness is established by the
ArtifactGenesis entry decoding at all (the claim is on the log, signed), and
consumer-reported false-claim findings are surfaced through the normal alert path.

KEY DEPENDENCIES: baseproof/crypto/artifact (the validator mechanism),
baseproof/storage, baseproof/monitoring.
*/
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/crypto/artifact"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
)

const MonitorContentTypeCompliance monitoring.MonitorID = "judicial.content_type_compliance"

// ArtifactClaim is a committed artifact's signed content-type claim, projected
// from its ArtifactGenesis entry: the public bytes' CID + the signed MIME type.
type ArtifactClaim struct {
	ContentCID   storage.CID
	DeclaredMIME string
}

// ContentTypeCheckConfig configures the content-type-compliance monitor.
type ContentTypeCheckConfig struct {
	// Claims are the committed PUBLIC artifacts to re-verify (CID + signed MIME),
	// projected from ArtifactGenesis entries on the log.
	Claims []ArtifactClaim

	// Validator is the SAME crypto/artifact mechanism the producer FINISH gate
	// runs — the SDK reference validators plus any custom validators the auditor
	// shares with the network. nil disables byte-level validation (the monitor
	// then only confirms the claim is present, which decoding the genesis entry
	// already established).
	Validator artifact.ContentValidator

	// Backend names the store being checked, for alert details.
	Backend string
}

// ContentTypeComplianceResult holds the outcome.
type ContentTypeComplianceResult struct {
	Checked    int
	Mismatches int
	Alerts     []monitoring.Alert
}

// CheckContentTypeCompliance fetches each committed public artifact and re-runs
// the validator for its declared MIME. A byte/claim mismatch fires Critical; a
// fetch or non-mismatch validation error fires Warning (presence itself is the
// blob_availability monitor's job — here a fetch failure only means the type
// could not be re-checked).
func CheckContentTypeCompliance(
	ctx context.Context,
	cfg ContentTypeCheckConfig,
	contentStore storage.ContentStore,
	now time.Time,
) (*ContentTypeComplianceResult, error) {
	if contentStore == nil {
		return nil, fmt.Errorf("monitoring/content_type: nil content store")
	}

	result := &ContentTypeComplianceResult{}
	for _, claim := range cfg.Claims {
		if claim.DeclaredMIME == "" {
			continue // no claim to enforce (opaque content)
		}
		result.Checked++

		data, err := contentStore.Fetch(ctx, claim.ContentCID) // verify-on-read
		if err != nil {
			result.Alerts = append(result.Alerts, monitoring.Alert{
				Monitor:     MonitorContentTypeCompliance,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message:     fmt.Sprintf("cannot fetch %s to re-verify type %q: %v", claim.ContentCID, claim.DeclaredMIME, err),
				Details:     map[string]any{"cid": claim.ContentCID.String(), "mime": claim.DeclaredMIME, "backend": cfg.Backend},
				EmittedAt:   now,
			})
			continue
		}

		if cfg.Validator == nil {
			continue // claim-presence only (no validator configured)
		}
		verr := cfg.Validator.Validate(ctx, claim.DeclaredMIME, data)
		if verr == nil {
			continue
		}
		if errors.Is(verr, artifact.ErrContentTypeMismatch) {
			result.Mismatches++
			result.Alerts = append(result.Alerts, monitoring.Alert{
				Monitor:     MonitorContentTypeCompliance,
				Severity:    monitoring.Critical,
				Destination: monitoring.Both,
				Message: fmt.Sprintf("committed artifact %s does not match its signed MIME claim %q "+
					"(producer FINISH-gate bypass or backend corruption)", claim.ContentCID, claim.DeclaredMIME),
				Details:   map[string]any{"cid": claim.ContentCID.String(), "mime": claim.DeclaredMIME, "backend": cfg.Backend},
				EmittedAt: now,
			})
			continue
		}
		result.Alerts = append(result.Alerts, monitoring.Alert{
			Monitor:     MonitorContentTypeCompliance,
			Severity:    monitoring.Warning,
			Destination: monitoring.Ops,
			Message:     fmt.Sprintf("validation error on %s (type %q): %v", claim.ContentCID, claim.DeclaredMIME, verr),
			Details:     map[string]any{"cid": claim.ContentCID.String(), "mime": claim.DeclaredMIME, "backend": cfg.Backend},
			EmittedAt:   now,
		})
	}
	return result, nil
}
