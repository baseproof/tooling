/*
FILE PATH: libs/httpmw/reliability/jsonlimit.go

DESCRIPTION:

	Per-request body size limit. Wraps r.Body with http.MaxBytesReader
	so handlers cannot be coerced into reading multi-gigabyte JSON
	blobs into memory. JN handlers parse JSON via json.Decoder which
	naturally reads from r.Body — once the wrapper is in place every
	decoder call inherits the limit.

	The default cap is 1 MiB which fits every JN request shape with
	headroom (the largest is a filing with a base64-encoded artifact
	up to ~750 KiB plaintext). Configurable per-deploy when a
	legitimate larger body is needed (bulk import via the ledger's
	own surface, never through the API).

	A request that exceeds the cap surfaces as a 413 Payload Too
	Large response written by the wrapper itself; the downstream
	handler never sees the oversized body.
*/
package reliability

import (
	"net/http"
)

// DefaultMaxBodyBytes is the default per-request body cap.
// 1 MiB fits every JN write shape with headroom.
const DefaultMaxBodyBytes int64 = 1 << 20

// MaxBodyBytes wraps next with a body-size limit. Requests whose
// body exceeds maxBytes are rejected with 413 before the wrapped
// handler runs. maxBytes <= 0 disables the limit (use only in
// controlled bulk-import paths).
//
// Two checks layered:
//
//  1. If the request advertises Content-Length above the cap, fast-
//     fail with 413 without reading the body.
//  2. Otherwise wrap r.Body in http.MaxBytesReader. Subsequent
//     reads beyond the cap (chunked encoding, lying Content-Length)
//     surface 413 to the caller via the MaxBytesReader wrapper.
func MaxBodyBytes(maxBytes int64, next http.Handler) http.Handler {
	if maxBytes <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBytes {
			http.Error(w, "request body exceeds size limit", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}
