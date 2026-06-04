package clitools

import "time"

// ═════════════════════════════════════════════════════════════════════
// Domain types — used by courts/, providers/, aggregator/
// ═════════════════════════════════════════════════════════════════════

// CaseRecord is the aggregated view of a case from Postgres.
type CaseRecord struct {
	ID            int64     `json:"id"`
	DocketNumber  string    `json:"docket_number"`
	CaseType      string    `json:"case_type"`
	Division      string    `json:"division,omitempty"`
	Status        string    `json:"status"`
	FiledDate     string    `json:"filed_date,omitempty"`
	CourtDID      string    `json:"court_did"`
	LogDID        string    `json:"log_did"`
	LogPosition   uint64    `json:"log_position"`
	SignerDID     string    `json:"signer_did"`
	SchemaRefPos  *uint64   `json:"schema_ref_pos,omitempty"`
	Sealed        bool      `json:"sealed"`
	Expunged      bool      `json:"expunged"`
	AssignedJudge string    `json:"assigned_judge,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CaseEvent is a single event in a case's timeline.
type CaseEvent struct {
	ID             int64          `json:"id"`
	CaseID         int64          `json:"case_id"`
	EventType      string         `json:"event_type"` // amendment, enforcement, path_b_order, cosignature
	LogPosition    uint64         `json:"log_position"`
	SignerDID      string         `json:"signer_did"`
	AuthorityPath  string         `json:"authority_path,omitempty"`
	PayloadSummary map[string]any `json:"payload_summary,omitempty"`
	LogTime        *time.Time     `json:"log_time,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

// OfficerRecord is the aggregated view of a delegation.
type OfficerRecord struct {
	ID           int64    `json:"id"`
	DelegateDID  string   `json:"delegate_did"`
	SignerDID    string   `json:"signer_did"`
	Role         string   `json:"role,omitempty"`
	Division     string   `json:"division,omitempty"`
	ScopeLimit   []string `json:"scope_limit,omitempty"`
	LogPosition  uint64   `json:"log_position"`
	IsLive       bool     `json:"is_live"`
	RevokedAtPos *uint64  `json:"revoked_at_pos,omitempty"`
	Depth        int      `json:"depth"`
	CourtDID     string   `json:"court_did"`
}

// ArtifactRecord tracks an artifact CID referenced in a filing.
type ArtifactRecord struct {
	ID             int64  `json:"id"`
	CID            string `json:"cid"`
	ContentDigest  string `json:"content_digest,omitempty"`
	CaseID         int64  `json:"case_id"`
	FilingPosition uint64 `json:"filing_position"`
	SignerDID      string `json:"signer_did"`
	Sealed         bool   `json:"sealed"`
	Expunged       bool   `json:"expunged"`
}

// SealingOrderRecord tracks active sealing orders.
type SealingOrderRecord struct {
	ID           int64    `json:"id"`
	CaseID       int64    `json:"case_id"`
	OrderType    string   `json:"order_type"` // sealing_order, unsealing_order, expungement
	LogPosition  uint64   `json:"log_position"`
	SignerDID    string   `json:"signer_did"`
	Authority    string   `json:"authority,omitempty"`
	AffectedCIDs []string `json:"affected_cids,omitempty"`
	IsActive     bool     `json:"is_active"`
	SupersededBy *uint64  `json:"superseded_by,omitempty"`
}

// AssignmentRecord is a parsed daily assignment.
type AssignmentRecord struct {
	ID             int64    `json:"id"`
	AssignmentDate string   `json:"assignment_date"`
	Division       string   `json:"division"`
	JudgeDID       string   `json:"judge_did"`
	Courtrooms     []string `json:"courtrooms,omitempty"`
	CaseTypes      []string `json:"case_types,omitempty"`
	LogPosition    uint64   `json:"log_position"`
	SupersededBy   *uint64  `json:"superseded_by,omitempty"`
}

// ScanWatermark tracks the aggregator's progress on each log.
type ScanWatermark struct {
	LogDID       string    `json:"log_did"`
	LastPosition uint64    `json:"last_position"`
	LastScanAt   time.Time `json:"last_scan_at"`
}

// ═════════════════════════════════════════════════════════════════════
// Request/response types for tools HTTP APIs
// ═════════════════════════════════════════════════════════════════════

// SubmitResult is the exchange's response after build-sign-submit.
type SubmitResult struct {
	Position      uint64 `json:"position"`
	CanonicalHash string `json:"canonical_hash,omitempty"`
	LogTime       string `json:"log_time,omitempty"`
}

// CreateCaseRequest is the body for POST /v1/cases.
type CreateCaseRequest struct {
	DocketNumber string `json:"docket_number"`
	CaseType     string `json:"case_type"`
	Division     string `json:"division,omitempty"`
	FiledDate    string `json:"filed_date,omitempty"`
	SchemaURI    string `json:"schema_uri,omitempty"`
}

// UpdateStatusRequest is the body for PATCH /v1/cases/{docket}/status.
type UpdateStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// OrderRequest is the body for POST /v1/cases/{docket}/orders.
type OrderRequest struct {
	OrderType           string   `json:"order_type"`
	Ruling              string   `json:"ruling,omitempty"`
	JudgeDID            string   `json:"judge_did"`
	DelegationPositions []uint64 `json:"delegation_positions"`
}

// SealRequest is the body for POST /v1/cases/{docket}/seal.
type SealRequest struct {
	Authority         string   `json:"authority"`
	AffectedArtifacts []string `json:"affected_artifacts,omitempty"`
	Reason            string   `json:"reason,omitempty"`
}

// UnsealRequest is the body for POST /v1/cases/{docket}/unseal.
type UnsealRequest struct {
	Reason            string `json:"reason"`
	PriorSealPosition uint64 `json:"prior_seal_position"`
}

// OfficerRequest is the body for POST /v1/officers.
type OfficerRequest struct {
	DelegateDID string   `json:"delegate_did"`
	Role        string   `json:"role"`
	Division    string   `json:"division,omitempty"`
	ScopeLimit  []string `json:"scope_limit,omitempty"`
}

// DocketRequest is the body for POST /v1/docket.
type DocketRequest struct {
	Date        string             `json:"date"`
	Assignments []DocketAssignment `json:"assignments"`
}

// DocketAssignment is a single judge assignment in a docket.
type DocketAssignment struct {
	JudgeDID   string   `json:"judge_did"`
	Courtrooms []string `json:"courtrooms"`
	CaseTypes  []string `json:"case_types,omitempty"`
}

// BackgroundCheckRequest is the body for POST /v1/background-check.
type BackgroundCheckRequest struct {
	SubjectDID    string   `json:"subject_did"`
	Courts        []string `json:"courts,omitempty"`
	IncludeSealed bool     `json:"include_sealed"`
}

// BackgroundCheckResult is the response for POST /v1/background-check.
type BackgroundCheckResult struct {
	SubjectDID  string       `json:"subject_did"`
	Cases       []CaseRecord `json:"cases"`
	SealedCount int          `json:"sealed_count"`
}
