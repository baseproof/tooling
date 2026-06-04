/*
FILE PATH: admission/write_auth_gate.go

DESCRIPTION:

	Admission gate 5 — the write-path GATING axis ("is this write approved?"),
	deliberately distinct from the PAYMENT axis (Mode A credit / Mode B PoW
	stamp — "can you pay?"). On a gated log, a submission is admitted only if it
	carries a valid detached WriteAuthorization (baseproof/authz, v1.19.0) from a
	currently-authorized admission authority.

	This is the ledger's structural/cryptographic enforcement of the JN gate's
	approval: the ledger verifies ONE secp256k1 signature against the on-log
	admission-authority keyset. It performs NO domain-policy evaluation (that
	stays in the JN gate + auditor) — verifying "an authorized gate signed this"
	is a signature check, consistent with A1's "ledger does only structural/
	cryptographic validation."

	The authorization is carried OUT-OF-BAND (an HTTP header / a per-entry batch
	field), verified, and dropped — never sequenced or stored (non-polluting).

KEY DECISIONS:

  - CURRENT keyset, not as-of-anchor: the authorized set is resolved at the
    latest on-log admission_authority_v1 snapshot, so a revoked authority
    cannot admit new writes (revocation applies immediately). The
    authorization still binds its as-of anchor in the signature for the
    auditor's independent re-derivation.

  - Gate OFF (default) ⇒ no-op. Enabled via LEDGER_ADMISSION_WRITE_AUTH_ENABLE
    once the JN gate (C6) emits authorizations. Same opt-in posture as the
    other admission gates.
*/
package admission

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/authz"
)

// WriteAuthHeader is the out-of-band header carrying the base64-encoded
// authz.WriteAuthorization on the single-submission path (POST /v1/entries).
// The batch path carries it per entry (api.BatchEntry.WriteAuthorizationB64).
const WriteAuthHeader = "X-Baseproof-Write-Authorization"

var (
	// ErrWriteAuthMissing is returned when the gate is on but the submission
	// carries no authorization. Maps to 403.
	ErrWriteAuthMissing = errors.New("admission: gated log requires a write authorization")

	// ErrWriteAuthMalformed is returned when the authorization is present but
	// not decodable. Maps to 403.
	ErrWriteAuthMalformed = errors.New("admission: malformed write authorization")
)

// AdmissionKeyset resolves the CURRENT authorized admission-authority EOA set
// from the on-log admission_authority_v1 keyset. "Current" (the latest
// snapshot) — not as-of-anchor — so a revocation applies immediately.
type AdmissionKeyset interface {
	Current(ctx context.Context) ([][20]byte, error)
}

// VerifyWriteAuthorization implements gate 5. encoded is the base64 detached
// authorization (header value or batch field); entryIdentity is the entry's
// canonical hash (envelope.EntryIdentity — the sequencer's dedup key the
// authorization binds). Returns nil on success.
//
// Fail-closed: empty ⇒ ErrWriteAuthMissing; undecodable ⇒ ErrWriteAuthMalformed;
// nil keyset or empty authorized set ⇒ authz.ErrEmptyAuthoritySet; non-member
// signer ⇒ authz.ErrUnauthorizedWriter. The caller maps these to HTTP via the
// switch in api/submission.go (401/403).
func VerifyWriteAuthorization(
	ctx context.Context,
	encoded string,
	entryIdentity [32]byte,
	logDID string,
	keyset AdmissionKeyset,
) error {
	if encoded == "" {
		return ErrWriteAuthMissing
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: base64: %v", ErrWriteAuthMalformed, err)
	}
	wa, err := authz.DecodeWriteAuthorization(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWriteAuthMalformed, err)
	}
	if keyset == nil {
		return authz.ErrEmptyAuthoritySet
	}
	set, err := keyset.Current(ctx)
	if err != nil {
		return fmt.Errorf("admission: resolve admission keyset: %w", err)
	}
	if _, err := authz.VerifyWriteAuthorization(wa, logDID, entryIdentity, set); err != nil {
		return err
	}
	return nil
}
