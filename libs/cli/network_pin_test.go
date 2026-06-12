package cli

/*
network_pin_test.go — P0 store hardening: the trust-root pin.

pins.json separates the IDENTITY of a stored network name (write-once, changed
only by an explicit --repin) from the mutable bundle file (endpoints, TLS).
These tests pin the four behaviors that make the name a trust boundary:

  1. First contact records a pin; a same-identity re-add refreshes the bundle
     freely (endpoints may move; the network may not).
  2. A different network id claiming a KNOWN name is REFUSED at `network add`
     — including for legacy stores that predate pins.json (the previously
     stored bundle's id is the de-facto pin).
  3. --repin replaces the trust root explicitly (and only then).
  4. The pin is authoritative at LOAD time too: a bundle file whose identity
     drifted from the pin (tampered, overwritten, wrong-backup-restored) is
     refused by every verb that resolves the name, not just by add.

Plus the resolution ladder: --network beats $BASEPROOF_NETWORK beats the
active network.
*/

import (
	"context"
	"strings"
	"testing"
)

const (
	pinIDa = "aa" // repeated to 64 hex below
	pinIDb = "bb"
)

func pinBundle(t *testing.T, idByte, endpoint string) string {
	t.Helper()
	return writeBundle(t, ClientBundle{NetworkID: strings.Repeat(idByte, 32), Endpoint: endpoint})
}

func addNet(t *testing.T, args ...string) error {
	t.Helper()
	return RunNetwork(context.Background(), append(append([]string{"add"}, args[1:]...), args[0]))
}

func TestNetworkAdd_FirstContact_RecordsPin(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	pins, err := loadPins()
	if err != nil {
		t.Fatalf("loadPins: %v", err)
	}
	pin, ok := pins["alpha"]
	if !ok || pin.NetworkID != strings.Repeat(pinIDa, 32) {
		t.Fatalf("first contact must record the pin; got %+v", pins)
	}
}

func TestNetworkAdd_SameIdentity_RefreshesBundleKeepsPin(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	// Same network id, new endpoint: the mutable half refreshes freely.
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a2")); err != nil {
		t.Fatalf("same-identity refresh must be allowed: %v", err)
	}
	b, err := loadNetwork("alpha")
	if err != nil {
		t.Fatalf("loadNetwork: %v", err)
	}
	if b.Endpoint != "https://a2" {
		t.Errorf("endpoint = %s, want the refreshed https://a2", b.Endpoint)
	}
	pins, _ := loadPins()
	if pins["alpha"].NetworkID != strings.Repeat(pinIDa, 32) {
		t.Errorf("the pin must survive a refresh untouched: %+v", pins["alpha"])
	}
}

func TestNetworkAdd_DifferentIdentity_Refused(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	err := addNet(t, "alpha", "--from", pinBundle(t, pinIDb, "https://evil"))
	if err == nil {
		t.Fatal("a different network id claiming a known name MUST refuse")
	}
	if !strings.Contains(err.Error(), "refusing") || !strings.Contains(err.Error(), "--repin") {
		t.Errorf("refusal should explain itself and name the escape hatch: %v", err)
	}
	// Nothing was written: the stored bundle and the pin are untouched.
	b, lerr := loadNetwork("alpha")
	if lerr != nil || b.NetworkID != strings.Repeat(pinIDa, 32) || b.Endpoint != "https://a1" {
		t.Fatalf("refusal must leave the store untouched: %v / %+v", lerr, b)
	}
}

func TestNetworkAdd_LegacyUnpinnedStore_StillRefused(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	// A store written before pins.json existed: bundle on disk, no pin.
	if err := saveNetwork("alpha", &ClientBundle{NetworkID: strings.Repeat(pinIDa, 32), Endpoint: "https://a1"}); err != nil {
		t.Fatalf("saveNetwork: %v", err)
	}
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDb, "https://evil")); err == nil {
		t.Fatal("the previously stored bundle's id is the de-facto pin — a different id must refuse")
	}
	// And a same-identity re-add adopts a pin going forward.
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a2")); err != nil {
		t.Fatalf("same-identity re-add over a legacy store: %v", err)
	}
	pins, _ := loadPins()
	if pins["alpha"].NetworkID != strings.Repeat(pinIDa, 32) {
		t.Errorf("legacy store should become pinned on the next add: %+v", pins)
	}
}

func TestNetworkAdd_Repin_ReplacesTrustRootExplicitly(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDb, "https://b1"), "--repin"); err != nil {
		t.Fatalf("--repin must allow an explicit identity change: %v", err)
	}
	pins, _ := loadPins()
	if pins["alpha"].NetworkID != strings.Repeat(pinIDb, 32) {
		t.Errorf("repin must record the NEW trust root: %+v", pins["alpha"])
	}
	if b, err := loadNetwork("alpha"); err != nil || b.Endpoint != "https://b1" {
		t.Errorf("repin stores the new bundle: %v / %+v", err, b)
	}
}

func TestLoadNetwork_BundleDriftedFromPin_RefusedEverywhere(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Tamper: overwrite the bundle file underneath the pin (saveNetwork is the
	// raw store write — exactly what a hostile or buggy writer would do).
	if err := saveNetwork("alpha", &ClientBundle{NetworkID: strings.Repeat(pinIDb, 32), Endpoint: "https://evil"}); err != nil {
		t.Fatalf("tamper write: %v", err)
	}
	if _, err := loadNetwork("alpha"); err == nil {
		t.Fatal("a stored bundle whose identity drifted from the pin must refuse at load")
	}
	// …and therefore at every verb's resolver.
	if _, err := resolveBundle("", "alpha"); err == nil {
		t.Fatal("resolveBundle must surface the pin mismatch")
	}
}

func TestResolveBundle_EnvAndFlagPrecedence(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("add alpha: %v", err)
	}
	if err := addNet(t, "beta", "--from", pinBundle(t, pinIDb, "https://b1")); err != nil {
		t.Fatalf("add beta: %v", err)
	}
	if err := setActiveNetwork("alpha"); err != nil {
		t.Fatalf("use alpha: %v", err)
	}

	// $BASEPROOF_NETWORK overrides the active network…
	t.Setenv("BASEPROOF_NETWORK", "beta")
	if b, err := resolveBundle("", ""); err != nil || b.Endpoint != "https://b1" {
		t.Fatalf("env must beat the active network: %v / %s", err, mustEndpoint(b))
	}
	// …and an explicit --network beats the env.
	if b, err := resolveBundle("", "alpha"); err != nil || b.Endpoint != "https://a1" {
		t.Fatalf("--network must beat the env: %v / %s", err, mustEndpoint(b))
	}
	// An env naming a missing network fails loudly, not silently falling back.
	t.Setenv("BASEPROOF_NETWORK", "ghost")
	if _, err := resolveBundle("", ""); err == nil {
		t.Fatal("an env pointing at a missing network must error, not fall back")
	}
}

// ─── PRE-0b: --pin at first contact ──────────────────────────────────

func TestNetworkAdd_PinFlag_FirstContactVerified(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	idA := strings.Repeat(pinIDa, 32)

	// The right pin: first contact is VERIFICATION, not TOFU.
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1"), "--pin", idA); err != nil {
		t.Fatalf("matching --pin must accept: %v", err)
	}

	// The wrong pin: refused BEFORE anything is written.
	err := addNet(t, "beta", "--from", pinBundle(t, pinIDb, "https://b1"), "--pin", idA)
	if err == nil || !strings.Contains(err.Error(), "refusing first contact") {
		t.Fatalf("a source claiming a different id than --pin must refuse: %v", err)
	}
	if _, lerr := loadNetwork("beta"); lerr == nil {
		t.Fatal("refused first contact must leave no stored bundle")
	}
	if pins, _ := loadPins(); pins["beta"].NetworkID != "" {
		t.Fatal("refused first contact must leave no pin")
	}

	// Malformed pin: rejected with the format named.
	err = addNet(t, "gamma", "--from", pinBundle(t, pinIDa, "https://c1"), "--pin", "not-hex")
	if err == nil || !strings.Contains(err.Error(), "64-hex") {
		t.Fatalf("a malformed --pin must name the expected format: %v", err)
	}
}

// ─── PRE-0b: remove with the pin tombstone ───────────────────────────

func TestNetworkRemove_PinTombstonesClosingTheResetSideDoor(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := RunNetwork(context.Background(), []string{"remove", "alpha"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := loadNetwork("alpha"); err == nil {
		t.Fatal("remove must delete the stored bundle")
	}
	// The side door: remove + re-add with a DIFFERENT identity must STILL
	// refuse — the pin tombstones.
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDb, "https://evil")); err == nil {
		t.Fatal("remove+add must not reset the trust pin")
	}
	// Same identity re-adds fine.
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a2")); err != nil {
		t.Fatalf("same-identity re-add after remove: %v", err)
	}
}

func TestNetworkRemove_ClearsActiveAndRejectsUnknown(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	if err := addNet(t, "alpha", "--from", pinBundle(t, pinIDa, "https://a1")); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := setActiveNetwork("alpha"); err != nil {
		t.Fatal(err)
	}
	if err := RunNetwork(context.Background(), []string{"remove", "alpha"}); err != nil {
		t.Fatalf("remove active: %v", err)
	}
	if cfg, _ := loadConfig(); cfg.ActiveNetwork != "" {
		t.Errorf("removing the active network must clear the active pointer, got %q", cfg.ActiveNetwork)
	}
	if err := RunNetwork(context.Background(), []string{"remove", "ghost"}); err == nil {
		t.Error("removing an unknown name must error")
	}
}
