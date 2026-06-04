package federation

import "testing"

// ProposeMemberAddition builds a valid amendment proposal and validates inputs.
func TestProposeMemberAddition_BuildsAndValidates(t *testing.T) {
	p, err := ProposeMemberAddition(MembershipProposal{
		Destination: "did:web:exchange.test",
		ProposerDID: "did:web:proposer",
		TargetDID:   "did:web:new-member",
		MemberName:  "Member A",
		Reason:      "onboarding",
	})
	if err != nil {
		t.Fatalf("ProposeMemberAddition: %v", err)
	}
	if p == nil || p.Entry == nil {
		t.Fatal("expected a non-nil proposal entry")
	}

	// Missing proposer/target ⇒ error.
	if _, e := ProposeMemberAddition(MembershipProposal{Destination: "did:web:x", TargetDID: "did:web:t"}); e == nil {
		t.Fatal("missing proposer must error")
	}
	// Missing destination ⇒ error.
	if _, e := ProposeMemberAddition(MembershipProposal{ProposerDID: "did:web:p", TargetDID: "did:web:t"}); e == nil {
		t.Fatal("missing destination must error")
	}
}

func TestProposeMemberRemoval_Builds(t *testing.T) {
	p, err := ProposeMemberRemoval(MembershipProposal{
		Destination: "did:web:exchange.test",
		ProposerDID: "did:web:proposer",
		TargetDID:   "did:web:member-x",
		MemberName:  "Member X",
		Reason:      "SLA breach",
	})
	if err != nil {
		t.Fatalf("ProposeMemberRemoval: %v", err)
	}
	if p == nil || p.Entry == nil {
		t.Fatal("expected a non-nil proposal entry")
	}
}

// FormConsortium provisions a governance log and validates its inputs.
func TestFormConsortium_ProvisionsAndValidates(t *testing.T) {
	cfg := ConsortiumConfig{
		ConsortiumDID:        "did:web:example.org:consortium",
		Destination:          "did:web:example.org:exchange",
		LogDID:               "did:web:example.org:consortium:governance",
		Name:                 "Example Consortium",
		SettlementUnit:       "",
		SettlementPeriodDays: 90,
		AuthoritySet: map[string]struct{}{
			"did:web:example.org:consortium": {},
			"did:web:member-a":               {},
		},
	}
	prov, err := FormConsortium(cfg)
	if err != nil {
		t.Fatalf("FormConsortium: %v", err)
	}
	if prov == nil || prov.Log == nil {
		t.Fatal("expected a provision with a governance log")
	}

	// Empty consortium DID ⇒ error.
	if _, e := FormConsortium(ConsortiumConfig{LogDID: cfg.LogDID, AuthoritySet: cfg.AuthoritySet}); e == nil {
		t.Fatal("empty consortium DID must error")
	}
	// Consortium DID absent from the authority set ⇒ error.
	bad := cfg
	bad.AuthoritySet = map[string]struct{}{"did:web:member-a": {}}
	if _, e := FormConsortium(bad); e == nil {
		t.Fatal("consortium DID not in authority set must error")
	}
}
