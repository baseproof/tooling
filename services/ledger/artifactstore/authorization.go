/*
FILE PATH:

	artifactstore/authorization.go

DESCRIPTION:

	Phase 6 — access posture + the AuthorizationHook seam. The CID is transparent
	in both postures (it rides the witnessed log entry); what varies is whether
	fetch-by-CID is open (PUBLIC — the #190 commitment-sidecar path) or gated
	(RESTRICTED — paid / sealed records, resolved through the hook to a
	short-lived credential). The authorization DECISION (payment, disclosure
	order, custody-chain check) is the deployment's domain; the store only
	executes the hook's verdict. Default AllowAllHook; deployments inject a real
	one.
*/
package artifactstore

import (
	"context"
	"errors"
	"net/http"

	"github.com/baseproof/baseproof/storage"
)

// ErrUnauthorized is the hook verdict that denies a request (mapped to 403).
var ErrUnauthorized = errors.New("artifactstore: unauthorized")

// Posture is the access class of a served bucket.
type Posture int

const (
	// PosturePublic — anonymous fetch-by-CID is allowed (commitment sidecars,
	// public filings). Confidentiality is not a concern; the content is public.
	PosturePublic Posture = iota
	// PostureRestricted — no anonymous read; the only path is GET .../resolve
	// through the AuthorizationHook to a short-lived retrieval credential.
	PostureRestricted
)

func (p Posture) String() string {
	if p == PostureRestricted {
		return "restricted"
	}
	return "public"
}

// AuthorizationHook gates a gated request (restricted fetch / resolve / delete).
// A nil return allows; a non-nil error denies (403). The hook may inspect the
// request (auth headers, payment proof) and the target CID.
type AuthorizationHook interface {
	Authorize(ctx context.Context, r *http.Request, cid storage.CID) error
}

// AllowAllHook permits everything — the default, and correct for a PUBLIC store.
type AllowAllHook struct{}

func (AllowAllHook) Authorize(context.Context, *http.Request, storage.CID) error { return nil }

// DenyAllHook refuses everything — a safe default for a freshly-stood-up
// RESTRICTED store before a real hook is wired.
type DenyAllHook struct{}

func (DenyAllHook) Authorize(context.Context, *http.Request, storage.CID) error {
	return ErrUnauthorized
}
