/*
FILE PATH: libs/httpmw/reliability/transport_test.go

DESCRIPTION:

	Unit pin for the tuned http.Transport defaults. The hot
	invariant is MaxIdleConnsPerHost — the stdlib default of 2
	silently caps each replica to ~2 concurrent ledger submits.
*/
package reliability

import (
	"net/http"
	"testing"
	"time"
)

func TestNewTunedClient_DefaultsApplied(t *testing.T) {
	c := NewTunedClient(ClientConfig{})
	if c == nil {
		t.Fatal("NewTunedClient returned nil")
	}
	if c.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.MaxIdleConnsPerHost != 256 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 256 (stdlib default of 2 caps replicas at ~2 TPS)",
			tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost != 1024 {
		t.Errorf("MaxConnsPerHost = %d, want 1024", tr.MaxConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 must be true to enable connection multiplexing")
	}
}

func TestNewTunedClient_OverridesRespected(t *testing.T) {
	c := NewTunedClient(ClientConfig{
		Timeout:             5 * time.Second,
		MaxIdleConnsPerHost: 64,
	})
	if c.Timeout != 5*time.Second {
		t.Errorf("Timeout override not honored: %v", c.Timeout)
	}
	tr := c.Transport.(*http.Transport)
	if tr.MaxIdleConnsPerHost != 64 {
		t.Errorf("MaxIdleConnsPerHost override not honored: %d", tr.MaxIdleConnsPerHost)
	}
	// Defaults still applied to fields the caller didn't override.
	if tr.MaxConnsPerHost != 1024 {
		t.Errorf("MaxConnsPerHost should still be default 1024; got %d", tr.MaxConnsPerHost)
	}
}

func TestDefaultClientConfig_StableValues(t *testing.T) {
	d := DefaultClientConfig()
	if d.Timeout != 30*time.Second {
		t.Errorf("Timeout default drifted: %v", d.Timeout)
	}
	if d.MaxIdleConnsPerHost != 256 {
		t.Errorf("MaxIdleConnsPerHost default drifted: %d", d.MaxIdleConnsPerHost)
	}
	if d.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout default drifted: %v (90s matches AWS ELB)", d.IdleConnTimeout)
	}
}
