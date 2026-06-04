/*
FILE PATH: libs/httpmw/reliability/jsonlimit_test.go

DESCRIPTION:

	Pins the body-size limit:
	  1. A request under cap passes through; downstream sees the body.
	  2. A request over cap gets 413; downstream never runs.
	  3. maxBytes <= 0 disables the wrapper (controlled bulk paths).
*/
package reliability

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
	})
}

func TestMaxBodyBytes_UnderCap_PassesThrough(t *testing.T) {
	h := MaxBodyBytes(1024, echoHandler())
	rec := httptest.NewRecorder()
	body := bytes.Repeat([]byte("x"), 512)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 512 {
		t.Errorf("downstream got %d bytes; want 512", rec.Body.Len())
	}
}

func TestMaxBodyBytes_OverCap_413(t *testing.T) {
	h := MaxBodyBytes(64, echoHandler())
	rec := httptest.NewRecorder()
	body := strings.Repeat("y", 1024)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestMaxBodyBytes_ZeroDisablesLimit(t *testing.T) {
	h := MaxBodyBytes(0, echoHandler())
	rec := httptest.NewRecorder()
	body := bytes.Repeat([]byte("z"), 4096)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (limit disabled)", rec.Code)
	}
}

func TestDefaultMaxBodyBytes_Stable(t *testing.T) {
	if DefaultMaxBodyBytes != 1<<20 {
		t.Errorf("DefaultMaxBodyBytes = %d, want 1 MiB", DefaultMaxBodyBytes)
	}
}
