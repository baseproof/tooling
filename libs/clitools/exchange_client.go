package clitools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/tooling/libs/httpmw/reliability"
)

// ExchangeClient wraps the exchange's build-sign-submit API.
// Tools NEVER hold signing keys. Every write goes through here.
type ExchangeClient struct {
	baseURL string
	client  *http.Client
}

// NewExchangeClient creates a non-mTLS client pointing at the exchange.
//
// HTTP transport: sdklog.DefaultClient — same SDK-tuned client the
// exchange itself uses internally for ledger submits.
// Honors 503 + Retry-After from the exchange when WAL pressure
// upstream propagates back as 503; absorbs locally instead of
// surfacing to the human/CMS caller.
//
// Production deployments that require mTLS to the exchange MUST use
// NewMTLSExchangeClient instead. This constructor is retained for
// dev/test paths where TLS material is not yet provisioned.
func NewExchangeClient(baseURL string) *ExchangeClient {
	return &ExchangeClient{
		baseURL: baseURL,
		client:  sdklog.DefaultClient(30*time.Second, nil),
	}
}

// NewMTLSExchangeClient is the production constructor: same
// SDK-tuned retry semantics as NewExchangeClient, plus a client
// certificate presented on every connection (mTLS) so the exchange
// can identify the caller cryptographically.
//
// Returns (nil, err) on any TLS-material failure — missing cert,
// missing key, unparseable CA. Callers MUST fail startup; the
// constructor refuses to silently fall back to plaintext.
func NewMTLSExchangeClient(baseURL string, tlsCfg sdklog.ClientTLSConfig) (*ExchangeClient, error) {
	c, err := reliability.NewMTLSClient(reliability.ClientConfig{Timeout: 30 * time.Second}, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("clitools: exchange mTLS client: %w", err)
	}
	return &ExchangeClient{baseURL: baseURL, client: c}, nil
}

// SubmitEntry sends builder params to the exchange, which constructs,
// signs, and submits the entry to the ledger.
//
// params must include: "builder", "signer_did", "log_did", "domain_payload".
// Optional: "target_root", "scope_pointer", "delegation_pointers", etc.
func (c *ExchangeClient) SubmitEntry(params map[string]any) (*SubmitResult, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("exchange: marshal: %w", err)
	}

	resp, err := c.client.Post(
		c.baseURL+"/v1/build-sign-submit",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("exchange: submit: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("exchange: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("exchange: HTTP %d: %s", resp.StatusCode, respBody)
	}

	var result SubmitResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("exchange: decode response: %w", err)
	}
	return &result, nil
}

// SubmitRootEntity is a convenience for BuildRootEntity submissions.
func (c *ExchangeClient) SubmitRootEntity(signerDID, logDID string, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "root_entity",
		"signer_did":     signerDID,
		"log_did":        logDID,
		"domain_payload": payload,
	})
}

// SubmitAmendment is a convenience for BuildAmendment submissions.
func (c *ExchangeClient) SubmitAmendment(signerDID, logDID string, targetRoot uint64, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "amendment",
		"signer_did":     signerDID,
		"log_did":        logDID,
		"target_root":    targetRoot,
		"domain_payload": payload,
	})
}

// SubmitEnforcement is a convenience for BuildEnforcement submissions.
func (c *ExchangeClient) SubmitEnforcement(signerDID, logDID string, targetRoot, scopePointer uint64, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "enforcement",
		"signer_did":     signerDID,
		"log_did":        logDID,
		"target_root":    targetRoot,
		"scope_pointer":  scopePointer,
		"domain_payload": payload,
	})
}

// SubmitPathB is a convenience for BuildPathBEntry submissions.
func (c *ExchangeClient) SubmitPathB(signerDID, logDID string, targetRoot uint64, delegationPointers []uint64, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":             "path_b",
		"signer_did":          signerDID,
		"log_did":             logDID,
		"target_root":         targetRoot,
		"delegation_pointers": delegationPointers,
		"domain_payload":      payload,
	})
}

// SubmitDelegation is a convenience for BuildDelegation submissions.
func (c *ExchangeClient) SubmitDelegation(signerDID, delegateDID, logDID string, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "delegation",
		"signer_did":     signerDID,
		"delegate_did":   delegateDID,
		"log_did":        logDID,
		"domain_payload": payload,
	})
}

// SubmitRevocation is a convenience for BuildRevocation submissions.
func (c *ExchangeClient) SubmitRevocation(signerDID, logDID string, targetRoot uint64, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "revocation",
		"signer_did":     signerDID,
		"log_did":        logDID,
		"target_root":    targetRoot,
		"domain_payload": payload,
	})
}

// SubmitCommentary is a convenience for BuildCommentary submissions.
func (c *ExchangeClient) SubmitCommentary(signerDID, logDID string, payload map[string]any) (*SubmitResult, error) {
	return c.SubmitEntry(map[string]any{
		"builder":        "commentary",
		"signer_did":     signerDID,
		"log_did":        logDID,
		"domain_payload": payload,
	})
}
