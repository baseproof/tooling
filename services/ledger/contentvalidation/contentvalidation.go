/*
FILE PATH: contentvalidation/contentvalidation.go

DESCRIPTION:

	The composition seam for the FINISH-gate content-type validator. The integrity
	model is deliberately simple and policy-free: the artifact's signed MIME claim
	rides on the log (the artifact-genesis entry), the bytes are content-addressed,
	and the ledger just asks "do I have a validator for this declared type, and do
	the bytes match it?". The set of validators is verification CODE — it evolves
	freely and never needs to be written to the log.

	EXTENSIBILITY (custom validators / custom MIME types):

	The SDK crypto/artifact.ContentValidator interface is the extension point. A
	network (e.g. the judicial network) that supports artifact types beyond the SDK
	reference set implements a ContentValidator and registers it here from an
	init() — the database/sql driver pattern — so the ledger binary picks it up
	WITHOUT forking boot:

	    package jnvalidators
	    func init() {
	        contentvalidation.Register("application/x-jn-evidence", jnEvidenceValidator{})
	    }

	Link that package into the binary and the custom type is validated at FINISH,
	exactly like the SDK reference types.
*/
package contentvalidation

import (
	"sync"

	"github.com/baseproof/baseproof/crypto/artifact"
)

var (
	mu     sync.RWMutex
	custom = map[string]artifact.ContentValidator{}
)

// Register installs a custom content validator for mimeType (last registration
// wins). A nil validator is ignored. Intended to be called from an init() in a
// deployment-specific package; safe for concurrent use.
func Register(mimeType string, v artifact.ContentValidator) {
	if v == nil || mimeType == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	custom[mimeType] = v
}

// Registered reports how many custom validators are installed (for boot logging).
func Registered() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(custom)
}

// BuildValidator builds the FINISH-gate validator from deployment config: the SDK
// reference validators for the accepted MIME types, PLUS every custom-registered
// validator, under the given deny-unknown stance. It returns nil — meaning "no
// MIME validation" — only when there is genuinely nothing to enforce (no accepted
// types, no custom validators, and not deny-unknown), so the FINISH gate can skip
// the fetch entirely.
//
// accepted is the network's gating config (which reference types it admits) — a
// deployment knob, NOT an on-log fact. Custom-registered types are always
// validated (and thereby admitted) regardless of accepted.
func BuildValidator(accepted []string, denyUnknown bool) artifact.ContentValidator {
	mu.RLock()
	defer mu.RUnlock()
	if len(accepted) == 0 && len(custom) == 0 && !denyUnknown {
		return nil
	}
	reg := artifact.BuildRegistry(accepted, denyUnknown)
	for mime, v := range custom {
		reg.Register(mime, v)
	}
	return reg
}
