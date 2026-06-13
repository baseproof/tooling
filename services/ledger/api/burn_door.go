/*
FILE PATH: api/burn_door.go

POST /v1/network/burn — the public inbound door for the burn ceremony
(tooling#110). The body is a finalized BP-ENTRY-NETWORK-BURN-V1 (the bytes
`network burn finalize` mints from collected consents); the door decodes it
(the SDK decode validates: quorum signatures present, caps) and feeds the
SINGLE BurnProcessor chokepoint, which runs network.VerifyBurn under the
CURRENT witness set, commits the on-log entry via its own appender, and
flips the declared-burn state /v1/burn serves.

THE DOOR MINTS NO TRUST — the K-of-N cosignatures ARE the authority — so
it is public but DoS-bounded (size-capped body, structural decode first).
An invalid or under-quorum burn is a Domain Violation (422, dimensional
counter); a second burn is 409 (burn is terminal); only infrastructure
failures are 5xx. Mirrors the rotation door exactly.
*/
package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/baseproof/baseproof/network"
)

// ErrAlreadyBurned — a burn is terminal and monotonic; a second burn is
// refused (409). Defined here (the door's vocabulary) because the
// processor package already imports api; the processor returns it.
var ErrAlreadyBurned = errors.New("ledger: network is already burned — burn is terminal")

const maxBurnBody = 64 * 1024

// BurnDoorProcessor is the single chokepoint the door feeds — satisfied by
// *witnessclient.BurnProcessor. Injected, not imported, on the handler
// struct so tests drive the door with fakes.
type BurnDoorProcessor interface {
	ProcessBurn(ctx context.Context, b network.NetworkBurn) (uint64, error)
}

// NewBurnDoorHandler mounts POST /v1/network/burn.
func NewBurnDoorHandler(proc BurnDoorProcessor, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBurnBody))
		if err != nil {
			http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
			return
		}
		// Structural decode BEFORE the processor — malformed is a 422
		// Domain Violation at the front door (decode runs the SDK's
		// Validate: unsigned burns never reach the processor).
		b, err := network.DecodeNetworkBurnPayload(body)
		if err != nil {
			http.Error(w, `{"error":"decode burn: `+jsonEscape(err.Error())+`"}`, http.StatusUnprocessableEntity)
			return
		}
		seq, err := proc.ProcessBurn(r.Context(), b)
		switch {
		case errors.Is(err, ErrAlreadyBurned):
			http.Error(w, `{"error":"already burned"}`, http.StatusConflict)
			return
		case errors.Is(err, network.ErrNetworkBurnUnauthorized),
			errors.Is(err, network.ErrNetworkBurnWrongNetwork):
			// Domain Violation: counted, never paged.
			http.Error(w, `{"error":"`+jsonEscape(err.Error())+`"}`, http.StatusUnprocessableEntity)
			return
		case err != nil:
			logger.Error("burn door: process", "err", err)
			http.Error(w, `{"error":"burn processing failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"burned","sequence":` + itoa(seq) + `}`))
	})
}

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}

func jsonEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\n':
			out = append(out, '\\', 'n')
		default:
			if c >= 0x20 {
				out = append(out, c)
			}
		}
	}
	return string(out)
}
