// FILE PATH: libs/clitools/delegation_querier.go
//
// DESCRIPTION:
//
//	v0.3.0 adapter bridging the SDK's two QueryBySignerDID
//	contracts:
//
//	  sdklog.LedgerQueryAPI.QueryBySignerDID(ctx, did) — production
//	  verifier.DelegationQuerier.QueryBySignerDID(did)  — pure-CPU walker
//
//	The verifier's DelegationQuerier predates the SDK's broad
//	ctx-threading sweep; its methods are intentionally context-free
//	because the delegation-tree walker treats querier calls as
//	in-memory lookups that share their bounded budget with the
//	caller. Production callers driving the walker against a real
//	HTTP-backed LedgerQueryAPI need this adapter so their ctx
//	deadline still propagates into the underlying RPCs.
//
//	NewDelegationQuerier(ctx, queryAPI) closes over ctx and exposes
//	the ctx-free shape DelegationQuerier expects. The ctx is the
//	caller's request-scoped context; the adapter MUST be re-created
//	per request — never cached across request boundaries.
package clitools

import (
	"context"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// DelegationQuerierAdapter wraps a sdklog.LedgerQueryAPI to satisfy
// the verifier.DelegationQuerier interface, threading the
// per-request ctx into the underlying RPC.
type DelegationQuerierAdapter struct {
	ctx context.Context
	api sdklog.LedgerQueryAPI
}

// NewDelegationQuerier returns an adapter that calls api.QueryBySignerDID(ctx, did)
// for every verifier.DelegationQuerier.QueryBySignerDID(did) invocation.
// ctx is bound at construction; create a fresh adapter per request.
func NewDelegationQuerier(ctx context.Context, api sdklog.LedgerQueryAPI) verifier.DelegationQuerier {
	return &DelegationQuerierAdapter{ctx: ctx, api: api}
}

// QueryBySignerDID satisfies verifier.DelegationQuerier.
func (a *DelegationQuerierAdapter) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	return a.api.QueryBySignerDID(a.ctx, did)
}
