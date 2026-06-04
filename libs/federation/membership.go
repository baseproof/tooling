package federation

import (
	"encoding/json"
	"fmt"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/lifecycle"
	"github.com/baseproof/baseproof/types"
)

// MembershipProposal describes a request to add or remove a consortium MEMBER
// NETWORK from the consortium authority set.
type MembershipProposal struct {
	// Destination is the DID of the destination EXCHANGE the proposal entry is
	// signature-bound to (SDK envelope ControlHeader.Destination — the
	// cross-exchange replay defense). NOT the network (NetworkID / witness trust
	// domain) and NOT the log (LogDID / physical storage); they are distinct.
	// Required by envelope.ValidateDestination on the underlying entry.
	Destination string
	// ProposerDID is the authority-set member proposing the change.
	ProposerDID string
	// TargetDID is the DID of the member NETWORK being added or removed.
	TargetDID string
	// MemberName is a human-readable label for the member network.
	MemberName string
	// Reason is a free-text justification recorded in the proposal payload.
	Reason string
}

// ProposeMemberAddition creates a scope amendment proposal to add a
// new member to the consortium authority set.
func ProposeMemberAddition(proposal MembershipProposal) (*lifecycle.AmendmentProposal, error) {
	if proposal.ProposerDID == "" || proposal.TargetDID == "" {
		return nil, fmt.Errorf("federation/membership: proposer and target DIDs required")
	}
	if proposal.Destination == "" {
		return nil, fmt.Errorf("federation/membership: destination DID required")
	}

	payload, err := json.Marshal(map[string]any{
		"action":      "add_member",
		"member_did":  proposal.TargetDID,
		"member_name": proposal.MemberName,
		"reason":      proposal.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("federation/membership: marshal payload: %w", err)
	}

	return lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:     proposal.Destination,
		ProposerDID:     proposal.ProposerDID,
		ProposalType:    lifecycle.ProposalAddAuthority,
		TargetDID:       proposal.TargetDID,
		Description:     fmt.Sprintf("Add %s to consortium", proposal.MemberName),
		ProposalPayload: payload,
	})
}

// ProposeMemberRemoval creates a scope amendment proposal to remove a member.
func ProposeMemberRemoval(proposal MembershipProposal) (*lifecycle.AmendmentProposal, error) {
	if proposal.ProposerDID == "" || proposal.TargetDID == "" {
		return nil, fmt.Errorf("federation/membership: proposer and target DIDs required")
	}
	if proposal.Destination == "" {
		return nil, fmt.Errorf("federation/membership: destination DID required")
	}

	payload, err := json.Marshal(map[string]any{
		"action":      "remove_member",
		"member_did":  proposal.TargetDID,
		"member_name": proposal.MemberName,
		"reason":      proposal.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("federation/membership: marshal payload: %w", err)
	}

	return lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:     proposal.Destination,
		ProposerDID:     proposal.ProposerDID,
		ProposalType:    lifecycle.ProposalRemoveAuthority,
		TargetDID:       proposal.TargetDID,
		Description:     fmt.Sprintf("Remove %s from consortium", proposal.MemberName),
		ProposalPayload: payload,
	})
}

// CollectMemberApprovals gathers cosignatures from authority set members.
func CollectMemberApprovals(params lifecycle.CollectApprovalsParams) (*lifecycle.ApprovalStatus, error) {
	return lifecycle.CollectApprovals(params)
}

// ExecuteMemberAddition executes a fully-approved add-member amendment.
// ExecuteAmendment returns *envelope.Entry (a scope amendment entry).
func ExecuteMemberAddition(params lifecycle.ExecuteAmendmentParams) (*envelope.Entry, error) {
	return lifecycle.ExecuteAmendment(params)
}

// ExecuteMemberRemoval initiates scope removal. Starts the time-lock.
func ExecuteMemberRemoval(params lifecycle.RemovalParams) (*lifecycle.RemovalExecution, error) {
	return lifecycle.ExecuteRemoval(params)
}

// ActivateMemberRemoval finalizes a removal after time-lock expires.
// ActivateRemoval returns *envelope.Entry (the activation entry).
func ActivateMemberRemoval(params lifecycle.ActivateRemovalParams) (*envelope.Entry, error) {
	return lifecycle.ActivateRemoval(params)
}

// ActivateWithObjectiveTrigger builds ActivateRemovalParams with evidence
// pointers from objective misbehavior proofs (7-day reduced time-lock).
func ActivateWithObjectiveTrigger(
	executorDID string,
	scopePos types.LogPosition,
	newAuthoritySet map[string]struct{},
	removalEntryPos types.LogPosition,
	triggerPositions []types.LogPosition,
	priorAuthority *types.LogPosition,
) (*envelope.Entry, error) {
	return lifecycle.ActivateRemoval(lifecycle.ActivateRemovalParams{
		ExecutorDID:      executorDID,
		ScopePos:         scopePos,
		NewAuthoritySet:  newAuthoritySet,
		RemovalEntryPos:  removalEntryPos,
		EvidencePointers: triggerPositions,
		PriorAuthority:   priorAuthority,
	})
}
