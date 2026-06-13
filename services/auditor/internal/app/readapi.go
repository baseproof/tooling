/*
FILE PATH: internal/app/readapi.go

PRE-7 (tooling#115): the auditor's read surface — the routes the registry
already ADVERTISES (auditor_registry "findings_url") but never served.

	GET /v1/findings  — the finding events the custodial gossip store holds
	                    (default kind: ledger equivocation findings), cursor-
	                    paginated via the store's own IterSince primitive.
	                    Evidence-tier by the alarm taxonomy: a projection of
	                    what the sink ingested, rebuildable by re-ingest,
	                    never a pager.
	GET /v1/monitors  — the periodic monitors' live status: registered job
	                    names + each job's last Result from the scheduler's
	                    HealthCache (last_run, ok, error, alert counts) —
	                    staleness is the reader's subtraction.

Both fail closed and honest: no store ⇒ /v1/findings 503 (this node is
health-only, not an evidence custodian); no scheduler ⇒ /v1/monitors
serves an empty, explicit monitors:[] — absent is absent, never invented.
*/
package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/baseproof/baseproof/gossip"

	"github.com/baseproof/tooling/libs/monitoring"
)

const (
	defaultFindingsLimit = 100
	maxFindingsLimit     = 500
)

// NewFindingsHandler serves GET /v1/findings over the custodial store.
// Query params: kind (default: the equivocation-finding kind),
// originator (optional), cursor (opaque, from a prior response), limit.
func NewFindingsHandler(store gossip.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			http.Error(w, `{"error":"this auditor runs health-only (no evidence store)"}`, http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		limit := defaultFindingsLimit
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				http.Error(w, `{"error":"limit must be a positive integer"}`, http.StatusBadRequest)
				return
			}
			if n > maxFindingsLimit {
				n = maxFindingsLimit
			}
			limit = n
		}

		cursor := gossip.IterCursor{
			Kind:       gossip.KindEquivocationFinding,
			Originator: q.Get("originator"),
		}
		if k := q.Get("kind"); k != "" {
			cursor.Kind = gossip.Kind(k)
		}
		if c := q.Get("cursor"); c != "" {
			raw, err := base64.RawURLEncoding.DecodeString(c)
			if err != nil || json.Unmarshal(raw, &cursor) != nil {
				http.Error(w, `{"error":"malformed cursor"}`, http.StatusBadRequest)
				return
			}
		}

		events, next, err := store.IterSince(r.Context(), cursor, limit)
		if err != nil {
			http.Error(w, `{"error":"findings scan failed"}`, http.StatusInternalServerError)
			return
		}
		nextRaw, err := json.Marshal(next)
		if err != nil {
			http.Error(w, `{"error":"cursor encode failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"findings":    events,
			"next_cursor": base64.RawURLEncoding.EncodeToString(nextRaw),
		})
	})
}

// NewMonitorsHandler serves GET /v1/monitors from the scheduler's
// registered jobs + HealthCache results. A nil scheduler is the honest
// empty surface, never a fabrication.
func NewMonitorsHandler(sched *monitoring.Scheduler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type monitorStatus struct {
			Name   string             `json:"name"`
			Result *monitoring.Result `json:"last_result,omitempty"`
		}
		out := []monitorStatus{}
		if sched != nil {
			snap := sched.Cache().Snapshot()
			for _, name := range sched.JobNames() {
				ms := monitorStatus{Name: name}
				if res, ok := snap[name]; ok {
					r := res
					ms.Result = &r
				}
				out = append(out, ms)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"monitors": out})
	})
}
