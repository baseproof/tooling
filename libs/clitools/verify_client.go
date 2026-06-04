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

// VerifyClient calls the domain verification API (api/core/).
// Read-only. No privilege. Public verification.
type VerifyClient struct {
	baseURL string
	client  *http.Client
}

// NewVerifyClient creates a non-mTLS client pointing at the verification API.
//
// HTTP transport: sdklog.DefaultClient — connection pool of 100
// idle conns/host (vs stdlib 2) + RetryAfterRoundTripper that
// honors verification-API 503 + Retry-After responses
// transparently. Verification calls are read-only and benefit from
// session warmup under sustained polling.
//
// Production deployments that require mTLS to the verification API
// MUST use NewMTLSVerifyClient instead. This constructor is retained
// for dev/test paths and for the canonical public-verification
// surface, which is deliberately unauthenticated.
func NewVerifyClient(baseURL string) *VerifyClient {
	return &VerifyClient{
		baseURL: baseURL,
		client:  sdklog.DefaultClient(15*time.Second, nil),
	}
}

// NewMTLSVerifyClient is the production constructor for deployments
// that front the verification API with mTLS (internal-tier
// deployments where verification is not yet public). Public
// verification deployments — where any external auditor must be able
// to call /v1/verify/* without credentials — should keep using
// NewVerifyClient.
//
// Returns (nil, err) on any TLS-material failure. Callers MUST fail
// startup; the constructor refuses to silently fall back to plaintext.
func NewMTLSVerifyClient(baseURL string, tlsCfg sdklog.ClientTLSConfig) (*VerifyClient, error) {
	c, err := reliability.NewMTLSClient(reliability.ClientConfig{Timeout: 15 * time.Second}, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("clitools: verify mTLS client: %w", err)
	}
	return &VerifyClient{baseURL: baseURL, client: c}, nil
}

// VerifyOrigin calls GET /v1/verify/origin/{logID}/{pos}.
func (c *VerifyClient) VerifyOrigin(logID string, pos uint64) (map[string]any, error) {
	url := fmt.Sprintf("%s/v1/verify/origin/%s/%d", c.baseURL, logID, pos)
	return c.getJSON(url)
}

// VerifyAuthority calls GET /v1/verify/authority/{logID}/{pos}.
func (c *VerifyClient) VerifyAuthority(logID string, pos uint64) (map[string]any, error) {
	url := fmt.Sprintf("%s/v1/verify/authority/%s/%d", c.baseURL, logID, pos)
	return c.getJSON(url)
}

// VerifyDelegation calls GET /v1/verify/delegation/{logID}/{pos}.
func (c *VerifyClient) VerifyDelegation(logID string, pos uint64) (map[string]any, error) {
	url := fmt.Sprintf("%s/v1/verify/delegation/%s/%d", c.baseURL, logID, pos)
	return c.getJSON(url)
}

// VerifyBatch calls GET /v1/verify/batch/{logID}/{positions}.
func (c *VerifyClient) VerifyBatch(logID, positions string) (map[string]any, error) {
	url := fmt.Sprintf("%s/v1/verify/batch/%s/%s", c.baseURL, logID, positions)
	return c.getJSON(url)
}

// VerifyCrossLog calls POST /v1/verify/cross-log.
func (c *VerifyClient) VerifyCrossLog(proof map[string]any) (map[string]any, error) {
	return c.postJSON(c.baseURL+"/v1/verify/cross-log", proof)
}

// VerifyFraudProof calls POST /v1/verify/fraud-proof.
func (c *VerifyClient) VerifyFraudProof(commitment map[string]any) (map[string]any, error) {
	return c.postJSON(c.baseURL+"/v1/verify/fraud-proof", commitment)
}

func (c *VerifyClient) getJSON(url string) (map[string]any, error) {
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("verify: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("verify: read: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("verify: parse: %w", err)
	}
	result["_status_code"] = float64(resp.StatusCode)
	return result, nil
}

func (c *VerifyClient) postJSON(url string, payload map[string]any) (map[string]any, error) {
	data, _ := json.Marshal(payload)
	resp, err := c.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("verify: POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("verify: read: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("verify: parse: %w", err)
	}
	result["_status_code"] = float64(resp.StatusCode)
	return result, nil
}
