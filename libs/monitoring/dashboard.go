/*
FILE PATH: libs/monitoring/dashboard.go
DESCRIPTION: Aggregates health signals from all other monitoring services into

	a single AOC-style dashboard view. Runs each monitor once per tick and
	produces a CourtHealth summary per court + a NetworkHealth rollup.

KEY ARCHITECTURAL DECISIONS:
  - Pure reducer over other monitors' outputs. Does NOT re-read the log.
  - Alerts are not re-emitted — they're summarized. Callers route the
    underlying monitors' alerts; the dashboard is read-only reporting.
  - Health grades are deterministic: Critical > Warning > Info > OK.

OVERVIEW: BuildDashboard takes per-court MonitorResults and produces a rollup.
KEY DEPENDENCIES: baseproof/monitoring (types only)
*/
package monitoring

import (
	"sort"
	"time"

	"github.com/baseproof/baseproof/monitoring"
)

// HealthGrade is the aggregate health score for a court or network.
type HealthGrade uint8

const (
	GradeOK HealthGrade = iota
	GradeInfo
	GradeWarning
	GradeCritical
)

func (g HealthGrade) String() string {
	switch g {
	case GradeCritical:
		return "CRITICAL"
	case GradeWarning:
		return "WARNING"
	case GradeInfo:
		return "INFO"
	default:
		return "OK"
	}
}

// MonitorResult is one monitor's output for one court.
type MonitorResult struct {
	Monitor monitoring.MonitorID
	Alerts  []monitoring.Alert
}

// CourtHealth is the per-court dashboard row.
type CourtHealth struct {
	CourtDID        string
	Grade           HealthGrade
	CriticalCount   int
	WarningCount    int
	InfoCount       int
	AlertsByMonitor map[monitoring.MonitorID]int
	LastCheckedAt   time.Time
}

// NetworkHealth is the network-wide rollup.
type NetworkHealth struct {
	Grade          HealthGrade
	TotalCourts    int
	CriticalCourts int
	WarningCourts  int
	Courts         []CourtHealth
	GeneratedAt    time.Time
}

// BuildDashboard reduces per-court monitor results into a dashboard view.
// Input: map of courtDID → list of MonitorResult.
func BuildDashboard(
	perCourt map[string][]MonitorResult,
	now time.Time,
) *NetworkHealth {
	nh := &NetworkHealth{
		TotalCourts: len(perCourt),
		GeneratedAt: now,
	}

	for courtDID, results := range perCourt {
		court := CourtHealth{
			CourtDID:        courtDID,
			AlertsByMonitor: make(map[monitoring.MonitorID]int),
			LastCheckedAt:   now,
		}
		for _, result := range results {
			court.AlertsByMonitor[result.Monitor] += len(result.Alerts)
			for _, alert := range result.Alerts {
				switch alert.Severity {
				case monitoring.Critical:
					court.CriticalCount++
				case monitoring.Warning:
					court.WarningCount++
				case monitoring.Info:
					court.InfoCount++
				}
			}
		}
		court.Grade = classifyGrade(court.CriticalCount, court.WarningCount, court.InfoCount)

		switch court.Grade {
		case GradeCritical:
			nh.CriticalCourts++
		case GradeWarning:
			nh.WarningCourts++
		}
		nh.Courts = append(nh.Courts, court)
	}

	nh.Grade = classifyNetworkGrade(nh.CriticalCourts, nh.WarningCourts)

	// Sort courts: critical first, then warning, then by DID.
	sort.Slice(nh.Courts, func(i, j int) bool {
		if nh.Courts[i].Grade != nh.Courts[j].Grade {
			return nh.Courts[i].Grade > nh.Courts[j].Grade
		}
		return nh.Courts[i].CourtDID < nh.Courts[j].CourtDID
	})

	return nh
}

func classifyGrade(critical, warning, info int) HealthGrade {
	switch {
	case critical > 0:
		return GradeCritical
	case warning > 0:
		return GradeWarning
	case info > 0:
		return GradeInfo
	default:
		return GradeOK
	}
}

func classifyNetworkGrade(criticalCourts, warningCourts int) HealthGrade {
	switch {
	case criticalCourts > 0:
		return GradeCritical
	case warningCourts > 0:
		return GradeWarning
	default:
		return GradeOK
	}
}
