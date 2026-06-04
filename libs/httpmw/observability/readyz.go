/*
FILE PATH: libs/httpmw/observability/readyz.go

DESCRIPTION:

	Generic /readyz handler. Aggregates a list of named checks
	and serves the result over HTTP. Each check is a closure
	returning an error; nil means the dependency is healthy.

	Two contracts:

	  ReadyCheck.Run takes a context with a soft-cap timeout so a
	  single slow upstream doesn't pin the readyz handler. Each
	  check should respect ctx and return promptly on cancellation.

	  Handler returns 200 with a JSON map of {check_name: "ok"}
	  when ALL checks pass. Returns 503 with {check_name: "<error>"}
	  including every check's outcome — ledgers see at a glance
	  which dependency is unhealthy.

	Mounted unauthenticated by the composer alongside /healthz +
	/metrics so k8s + load balancers reach it without credentials.
*/
package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// ReadyCheck is a single dependency check. Run returns nil when
// the dependency is healthy; non-nil error means the readyz
// response includes this check's failure.
type ReadyCheck struct {
	Name string
	Run  func(ctx context.Context) error
}

// ReadyzConfig configures the handler. Empty Checks → /readyz
// always returns 200 ("nothing to check, process is up").
type ReadyzConfig struct {
	// Checks runs in parallel on every /readyz call. Order
	// doesn't matter; the response always reports every check.
	Checks []ReadyCheck

	// Timeout caps the wall-clock budget for ALL checks combined.
	// Default 5s.
	Timeout time.Duration
}

// ReadyzHandler returns an http.Handler that runs every check
// in parallel and writes a JSON response.
func ReadyzHandler(cfg ReadyzConfig) http.Handler {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		results := make(map[string]string, len(cfg.Checks))
		var mu sync.Mutex
		allOK := true

		var wg sync.WaitGroup
		wg.Add(len(cfg.Checks))
		for _, c := range cfg.Checks {
			c := c
			go func() {
				defer wg.Done()
				err := c.Run(ctx)
				mu.Lock()
				if err == nil {
					results[c.Name] = "ok"
				} else {
					results[c.Name] = err.Error()
					allOK = false
				}
				mu.Unlock()
			}()
		}
		wg.Wait()

		w.Header().Set("Content-Type", "application/json")
		if !allOK {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(results)
	})
}

// CheckHTTPGet returns a ReadyCheck that fetches the supplied URL
// and considers the dependency healthy iff the response is 2xx.
// Used for ledger + artifact-store reachability checks from the
// composer / aggregator / witness binaries.
//
// client is REQUIRED: thread the binary's hoisted outbound *http.Client
// (see libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv) so
// the readyz probe shares the operator-chosen mTLS posture. A probe
// that can't present the binary's client cert can only succeed against
// a plaintext endpoint — which would silently mask the real readiness
// of an mTLS-fronted dependency. v1.27.x: no silent demotion.
//
// Panics on a nil client to fail the binary loudly at construction
// (readyz checks are registered once at boot, before serve, so the
// panic surfaces in tests / CI / pre-flight rather than at request
// time).
func CheckHTTPGet(name, url string, client *http.Client) ReadyCheck {
	if client == nil {
		panic("observability: CheckHTTPGet requires a non-nil *http.Client (thread the binary's hoisted outbound client; see libs/clienttls.BuildFromEnv or libs/outbound.HoistFromEnv)")
	}
	return ReadyCheck{
		Name: name,
		Run: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				return errStatus(resp.StatusCode)
			}
			return nil
		},
	}
}

type errStatus int

func (e errStatus) Error() string {
	return http.StatusText(int(e))
}
