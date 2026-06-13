/*
FILE PATH: witnessclient/burn_processor.go

The SINGLE burn chokepoint (tooling#110): quorum-verify under the CURRENT
witness set → commit the on-log burn entry through the door's own appender
(the admission firewall's outright refusal of external burns in
admission/network_payload_validator.go exists precisely because THIS path
is the only legitimate author) → flip the declared-burn state that
GET /v1/burn's declared leg serves.

Mirrors ProcessRotation's order: verify BEFORE append (fail-closed), nil
appender = fail closed, and the in-memory declared state is an enforcer's
cache of the on-log record — rebuilt at boot by re-walking the log (the
projection law; the walk is network.ResolveBurnAt under the era-correct
set).
*/
package witnessclient

import (
	"context"
	"fmt"
	"sync"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/ledger/api"
)

// ErrAlreadyBurned is api.ErrAlreadyBurned — the door's 409 vocabulary
// (defined there because this package already imports api; one sentinel,
// two homes would drift).
var ErrAlreadyBurned = api.ErrAlreadyBurned

// BurnLogAppender commits the canonical burn payload as a sequenced on-log
// entry, bypassing the admission gate by construction (same class as the
// rotation appender).
type BurnLogAppender interface {
	AppendBurnEntry(ctx context.Context, payload []byte) (seq uint64, err error)
}

// CurrentSetSource yields the witness set authoritative NOW — the set a
// new burn must be quorum-signed by.
type CurrentSetSource interface {
	Current() *cosign.WitnessKeySet
}

// BurnProcessor is the chokepoint. One writer; concurrency-safe.
type BurnProcessor struct {
	keys     CurrentSetSource
	appender BurnLogAppender

	mu       sync.RWMutex
	declared *network.NetworkBurn // nil until burned
	seq      uint64
}

func NewBurnProcessor(keys CurrentSetSource, appender BurnLogAppender) *BurnProcessor {
	return &BurnProcessor{keys: keys, appender: appender}
}

// ProcessBurn verifies and commits ONE burn. Fail-closed at every step;
// nothing half-applied (state flips only after the on-log append returns).
func (p *BurnProcessor) ProcessBurn(ctx context.Context, b network.NetworkBurn) (uint64, error) {
	p.mu.RLock()
	burned := p.declared != nil
	p.mu.RUnlock()
	if burned {
		return 0, ErrAlreadyBurned
	}
	if p.keys == nil || p.keys.Current() == nil {
		return 0, fmt.Errorf("witnessclient/burn: no current witness set wired")
	}
	if err := network.VerifyBurn(b, p.keys.Current()); err != nil {
		return 0, err // the SDK's named verdict surfaces verbatim (422 class)
	}
	payload, err := network.EncodeNetworkBurnPayload(b)
	if err != nil {
		return 0, err
	}
	if p.appender == nil {
		return 0, fmt.Errorf("witnessclient/burn: on-log appender not wired (fail closed; a burn must be a sequenced on-log event)")
	}
	seq, err := p.appender.AppendBurnEntry(ctx, payload)
	if err != nil {
		return 0, fmt.Errorf("witnessclient/burn: append on-log entry: %w", err)
	}
	p.mu.Lock()
	cp := b
	p.declared = &cp
	p.seq = seq
	p.mu.Unlock()
	return seq, nil
}

// DeclaredBurn serves GET /v1/burn's DECLARED leg: the authoritative,
// quorum-verified on-log verdict. (bool, nil) always — an unverifiable
// state never reaches this struct because ProcessBurn is the one writer.
func (p *BurnProcessor) DeclaredBurn(ctx context.Context) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.declared != nil, nil
}
