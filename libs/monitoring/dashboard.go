/*
FILE PATH: libs/monitoring/dashboard.go
DESCRIPTION: Aggregates health signals from all other monitoring services into

	a single AOC-style dashboard view. Runs each monitor once per tick and
	produces a LogHealth summary per row + a NetworkHealth rollup.

KEY ARCHITECTURAL DECISIONS:
  - Pure reducer over other monitors' outputs. Does NOT re-read the log.
  - Alerts are not re-emitted — they're summarized. Callers route the
    underlying monitors' alerts; the dashboard is read-only reporting.
  - Health grades are deterministic: Critical > Warning > Info > OK.

OVERVIEW: BuildDashboard takes per-row MonitorResults and produces a rollup.
KEY DEPENDENCIES: baseproof/monitoring (types only)
*/
package monitoring

import (
	"sort"
	"time"

	"github.com/baseproof/baseproof/monitoring"
)

// HealthGrade is the aggregate health score for a row or network.
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

// MonitorResult is one monitor's output for one row.
type MonitorResult struct {
	Monitor monitoring.MonitorID
	Alerts  []monitoring.Alert
}

// LogHealth is the per-row dashboard row.
type LogHealth struct {
	LogDID          string
	Grade           HealthGrade
	CriticalCount   int
	WarningCount    int
	InfoCount       int
	AlertsByMonitor map[monitoring.MonitorID]int
	LastCheckedAt   time.Time
}

// NetworkHealth is the network-wide rollup.
type NetworkHealth struct {
	Grade        HealthGrade
	TotalLogs    int
	CriticalLogs int
	WarningLogs  int
	Logs         []LogHealth
	GeneratedAt  time.Time
}

// BuildDashboard reduces per-row monitor results into a dashboard view.
// Input: map of logDID → list of MonitorResult.
func BuildDashboard(
	perLog map[string][]MonitorResult,
	now time.Time,
) *NetworkHealth {
	nh := &NetworkHealth{
		TotalLogs:   len(perLog),
		GeneratedAt: now,
	}

	for logDID, results := range perLog {
		row := LogHealth{
			LogDID:          logDID,
			AlertsByMonitor: make(map[monitoring.MonitorID]int),
			LastCheckedAt:   now,
		}
		for _, result := range results {
			row.AlertsByMonitor[result.Monitor] += len(result.Alerts)
			for _, alert := range result.Alerts {
				switch alert.Severity {
				case monitoring.Critical:
					row.CriticalCount++
				case monitoring.Warning:
					row.WarningCount++
				case monitoring.Info:
					row.InfoCount++
				}
			}
		}
		row.Grade = classifyGrade(row.CriticalCount, row.WarningCount, row.InfoCount)

		switch row.Grade {
		case GradeCritical:
			nh.CriticalLogs++
		case GradeWarning:
			nh.WarningLogs++
		}
		nh.Logs = append(nh.Logs, row)
	}

	nh.Grade = classifyNetworkGrade(nh.CriticalLogs, nh.WarningLogs)

	// Sort logs: critical first, then warning, then by DID.
	sort.Slice(nh.Logs, func(i, j int) bool {
		if nh.Logs[i].Grade != nh.Logs[j].Grade {
			return nh.Logs[i].Grade > nh.Logs[j].Grade
		}
		return nh.Logs[i].LogDID < nh.Logs[j].LogDID
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

func classifyNetworkGrade(criticalLogs, warningLogs int) HealthGrade {
	switch {
	case criticalLogs > 0:
		return GradeCritical
	case warningLogs > 0:
		return GradeWarning
	default:
		return GradeOK
	}
}
