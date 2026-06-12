/*
FILE PATH: libs/monitoring/blob_availability.go
DESCRIPTION: Periodically checks that structural blobs (not expunged ones)

	remain retrievable from the content store. Flags unexpected disappearance.

KEY ARCHITECTURAL DECISIONS:
  - Uses storage.ContentStore.Exists (HEAD request) — cheap, no decrypt.
  - CIDs to check are provided by the caller (typically a periodic sampler
    over recent filings + all unexpired evidence).
  - Expungement is NOT a failure: the caller supplies a set of
    known-expunged CIDs that should NOT exist, and this monitor flags
    them only if they DO exist (defense-in-depth erasure failure).

OVERVIEW: CheckBlobAvailability partitions CIDs into three groups and reports.
KEY DEPENDENCIES: baseproof/storage, baseproof/monitoring
*/
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/storage"
)

const MonitorBlobAvailability monitoring.MonitorID = "platform.blob_availability"

// BlobCheckConfig configures the blob availability monitor.
type BlobCheckConfig struct {
	// ExpectedPresent are CIDs that must exist (recent filings, evidence).
	ExpectedPresent []storage.CID

	// ExpectedAbsent are CIDs that must NOT exist (expunged artifacts).
	// Present-when-expected-absent is a defense-in-depth erasure failure.
	ExpectedAbsent []storage.CID

	// Backend names the store being checked, for alert details.
	Backend string
}

// BlobAvailabilityResult holds the outcome.
type BlobAvailabilityResult struct {
	MissingCount        int
	UnexpectedlyPresent int
	Checked             int
	Alerts              []monitoring.Alert
}

// CheckBlobAvailability issues Exists() calls for each CID and classifies results.
//
// A missing ExpectedPresent CID fires Critical (possible data loss).
// A present ExpectedAbsent CID fires Critical (erasure failed).
// Errors on individual HEAD requests fire Warning.
func CheckBlobAvailability(
	ctx context.Context,
	cfg BlobCheckConfig,
	contentStore storage.ContentStore,
	now time.Time,
) (*BlobAvailabilityResult, error) {
	if contentStore == nil {
		return nil, fmt.Errorf("monitoring/blob: nil content store")
	}

	result := &BlobAvailabilityResult{}

	for _, cid := range cfg.ExpectedPresent {
		result.Checked++
		exists, err := contentStore.Exists(ctx, cid)
		if err != nil {
			result.Alerts = append(result.Alerts, monitoring.Alert{
				Monitor:     MonitorBlobAvailability,
				Severity:    monitoring.Warning,
				Destination: monitoring.Ops,
				Message:     fmt.Sprintf("HEAD error on %s: %v", cid, err),
				Details:     map[string]any{"cid": cid.String(), "backend": cfg.Backend},
				EmittedAt:   now,
			})
			continue
		}
		if !exists {
			result.MissingCount++
			result.Alerts = append(result.Alerts, monitoring.Alert{
				Monitor:     MonitorBlobAvailability,
				Severity:    monitoring.Critical,
				Destination: monitoring.Both,
				Message:     fmt.Sprintf("expected artifact missing: %s", cid),
				Details:     map[string]any{"cid": cid.String(), "backend": cfg.Backend},
				EmittedAt:   now,
			})
		}
	}

	for _, cid := range cfg.ExpectedAbsent {
		result.Checked++
		exists, err := contentStore.Exists(ctx, cid)
		if err != nil {
			// HEAD errors on expunged CIDs are expected on some backends.
			continue
		}
		if exists {
			result.UnexpectedlyPresent++
			result.Alerts = append(result.Alerts, monitoring.Alert{
				Monitor:     MonitorBlobAvailability,
				Severity:    monitoring.Critical,
				Destination: monitoring.Both,
				Message:     fmt.Sprintf("expunged artifact still present: %s", cid),
				Details: map[string]any{
					"cid":           cid.String(),
					"backend":       cfg.Backend,
					"erasure_state": "failed",
				},
				EmittedAt: now,
			})
		}
	}

	return result, nil
}
