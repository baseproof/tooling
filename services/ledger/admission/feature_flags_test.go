/*
FILE PATH:

	admission/feature_flags_test.go

DESCRIPTION:

	Pin LoadGatesFromEnv parsing semantics and the per-gate default
	posture. The defaults are load-bearing — a regression that
	silently flips a gate's default would change the admission
	contract without code review.
*/
package admission

import (
	"testing"
)

func TestGates_DefaultsMatchTrustBoundaryPosture(t *testing.T) {
	// Gates 1 and 2 are at the ledger trust boundary — every
	// downstream consumer (JN, witnesses, monitors) inherits the
	// protection. They default ON. Gate 4 (evidence-chain
	// structural walk) depends on production wiring that lands as a
	// follow-up; it defaults OFF and fails-open on missing
	// capability. SignaturePolicy (Part II.6) defaults OFF during
	// rollout. ModeBPoW (Post-II #3) defaults ON — preserves the
	// pre-refactor unconditional Mode-B-PoW behaviour.
	t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", "")
	t.Setenv("LEDGER_ADMISSION_MODEB_POW_ENABLE", "")

	g := LoadGatesFromEnv()
	if !g.MultiSig {
		t.Error("MultiSig defaulted OFF; want ON (trust-boundary gate)")
	}
	if !g.CosigBinding {
		t.Error("CosigBinding defaulted OFF; want ON (trust-boundary gate)")
	}
	if g.EvidenceChain {
		t.Error("EvidenceChain defaulted ON; want OFF (depends on wiring)")
	}
	if g.SignaturePolicy {
		t.Error("SignaturePolicy defaulted ON; want OFF (II.6 rollout)")
	}
	if !g.ModeBPoW {
		t.Error("ModeBPoW defaulted OFF; want ON (preserves pre-refactor Mode-B-PoW behavior)")
	}
}

func TestGates_TruthyValues(t *testing.T) {
	cases := []string{"true", "TRUE", "True", "1", "yes", "YES", "on", "ON", " true "}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_MODEB_POW_ENABLE", val)

			g := LoadGatesFromEnv()
			if !g.MultiSig || !g.CosigBinding || !g.EvidenceChain ||
				!g.SignaturePolicy || !g.ModeBPoW {
				t.Errorf("value %q did not enable all gates: %+v", val, g)
			}
		})
	}
}

func TestGates_FalsyValuesDisableAllGates(t *testing.T) {
	// Explicit falsy values MUST override the per-gate default —
	// otherwise gates 1 + 2 (default ON) could never be turned
	// off, defeating the canary-disable knob. Same applies to
	// ModeBPoW (default ON — operators flip OFF to run a network
	// that admits only authenticated Mode-A submissions).
	cases := []string{"false", "FALSE", "0", "no", "NO", "off", "OFF", " false "}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_MODEB_POW_ENABLE", val)

			g := LoadGatesFromEnv()
			if g.MultiSig || g.CosigBinding || g.EvidenceChain ||
				g.SignaturePolicy || g.ModeBPoW {
				t.Errorf("value %q did not disable all gates: %+v", val, g)
			}
		})
	}
}

func TestGates_UnrecognisedValuesPreserveDefault(t *testing.T) {
	// An operator who sets the var to something weird (typo,
	// experimental flag value) gets the per-gate default, NOT a
	// silent flip in either direction.
	cases := []string{"garbage", "2", "enable", "maybe"}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", val)
			t.Setenv("LEDGER_ADMISSION_MODEB_POW_ENABLE", val)

			g := LoadGatesFromEnv()
			if !g.MultiSig || !g.CosigBinding || !g.ModeBPoW {
				t.Errorf("value %q dropped default-ON gate: %+v", val, g)
			}
			if g.EvidenceChain || g.SignaturePolicy {
				t.Errorf("value %q flipped default-OFF gate: %+v", val, g)
			}
		})
	}
}

func TestGates_IndependentToggling(t *testing.T) {
	// Each gate must be flippable in isolation. A composite kill-
	// switch would force "all on / all off" decisions; this test
	// pins the independence property that motivated splitting the
	// flags in the first place.
	t.Setenv("LEDGER_ADMISSION_MULTISIG_ENABLE", "false") // canary disable gate 1
	t.Setenv("LEDGER_ADMISSION_COSIG_BINDING_ENABLE", "true")
	t.Setenv("LEDGER_ADMISSION_EVIDENCE_CHAIN_ENABLE", "false")
	t.Setenv("LEDGER_ADMISSION_SIGNATURE_POLICY_ENABLE", "true") // enable II.6
	t.Setenv("LEDGER_ADMISSION_MODEB_POW_ENABLE", "false")       // Mode-A-only network

	g := LoadGatesFromEnv()
	if g.MultiSig {
		t.Error("MultiSig should be OFF (explicit disable)")
	}
	if !g.CosigBinding {
		t.Error("CosigBinding should be ON")
	}
	if g.EvidenceChain {
		t.Error("EvidenceChain should be OFF")
	}
	if !g.SignaturePolicy {
		t.Error("SignaturePolicy should be ON (explicit enable)")
	}
	if g.ModeBPoW {
		t.Error("ModeBPoW should be OFF (Mode-A-only network)")
	}
}
