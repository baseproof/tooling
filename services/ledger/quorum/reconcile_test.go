package quorum_test

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/ledger/quorum"
)

// TestReconcileFlagK pins the three arms of the -quorum demotion rule shared by
// the governance tools (audit, admission-authority, signature-policy): the
// constitution's genesis_quorum_k is the single source of K; the flag is a
// cross-check only. doc.IDs() validation is each tool's job before calling, so a
// doc carrying only GenesisQuorumK suffices here.
func TestReconcileFlagK(t *testing.T) {
	doc := network.BootstrapDocument{GenesisQuorumK: 2}
	cases := []struct {
		name    string
		flagK   int
		wantK   int
		wantErr bool
	}{
		{name: "unset_adopts_constitutional", flagK: 0, wantK: 2},
		{name: "set_and_equal_honoured", flagK: 2, wantK: 2},
		{name: "set_and_different_fatal", flagK: 3, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := quorum.ReconcileFlagK(doc, tc.flagK)
			if tc.wantErr {
				if err == nil {
					t.Fatal("a flag K disagreeing with the constitution must be fatal")
				}
				// The message must name both values and point at the fix.
				for _, want := range []string{"-quorum=3", "genesis_quorum_k=2", "omit -quorum"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("mismatch message missing %q: %v", want, err)
					}
				}
				return
			}
			if err != nil || k != tc.wantK {
				t.Fatalf("got K=%d err=%v, want K=%d", k, err, tc.wantK)
			}
		})
	}
}
