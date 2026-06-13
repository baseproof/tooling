/*
FILE PATH: libs/cli/rotation_cmd.go

DESCRIPTION:

	`baseproof network rotation <draft|finalize|submit>` — the operator's
	driver for the witness-rotation ceremony (PRE-6c). The assembly lives in
	the SDK (witness.RotationDraft) behind libs/rotationdraft (the relay
	seam); these verbs are the operator's file choreography around it:

	  draft     fetch the network's CURRENT witness set from the LIVE
	            history (/v1/network/witnesses/current — keys, never just a
	            hash, and never asserted), cross-check the served set_hash
	            against the hash DERIVED from those keys, pair the set with
	            the proposed NEW set (--new-set DIDs) and the bundle's
	            constitutional quorum K, self-check the proposal through the
	            SDK constructor, and write a rotation-draft to relay to each
	            witness host.
	  finalize  merge a draft + its collected consent files (ONE list — the
	            SDK's membership routing buckets each consent to its
	            side(s); the operator never sorts) into the on-log
	            types.WitnessRotation; the SDK self-verifies through the
	            full VerifyRotation recipe before anything is written.
	  submit    re-validate fail-closed (structural decode + era-drift
	            staleness pre-check + a LOCAL VerifyRotation against the
	            live set), then POST to the network's public
	            POST /v1/network/rotation door, which feeds the ledger's
	            single ProcessRotation chokepoint — the authority. A
	            rotation this driver cannot verify locally is never posted.

	The driver mints no trust: the consents ARE the authority, ProcessRotation
	is the verifier. Local checks exist to refuse by NAME before a wasted
	relay round or POST — convenience, never authority.
*/
package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"
)

// runNetworkRotation dispatches `baseproof network rotation <sub>`.
func runNetworkRotation(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: baseproof network rotation <draft|finalize|submit> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "draft":
		return rotationDraftCmd(ctx, rest)
	case "finalize":
		return rotationFinalizeCmd(ctx, rest)
	case "submit":
		return rotationSubmitCmd(ctx, rest)
	default:
		return fmt.Errorf("network rotation: unknown subcommand %q (draft|finalize|submit)", sub)
	}
}

// ─── draft ───────────────────────────────────────────────────────────

func rotationDraftCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network rotation draft", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		newSet     = fs.String("new-set", "", "comma-separated did:key witnesses for the NEW set — REQUIRED")
		out        = fs.String("out", "", "write the rotation-draft here — REQUIRED")
		output     = fs.String("output", "table", "output format: table|json")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newSet == "" || *out == "" {
		return fmt.Errorf("network rotation draft: --new-set and --out are required")
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	if b.NetworkID == "" {
		return fmt.Errorf("network rotation draft: the bundle carries no network id")
	}
	// The quorum K is constitutional (the verified bootstrap is its single
	// source; the bundle only carries it). A bundle without it cannot
	// coordinate a ceremony — refuse, never guess a threshold.
	if b.QuorumK <= 0 {
		return fmt.Errorf("network rotation draft: the bundle carries no witness quorum (quorum_k) — re-add the network to refresh the bundle from the verified constitution")
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	// CURRENT set from the LIVE history — the KEYS, never just a hash, and
	// never asserted by the operator.
	var cur wireWitnessSetFull
	if err := getJSON(ctx, hc, b.Endpoint+"/v1/network/witnesses/current", &cur); err != nil {
		return fmt.Errorf("fetch current witness set: %w", err)
	}
	if len(cur.Keys) == 0 {
		return fmt.Errorf("network rotation draft: the ledger serves no current witness keys")
	}
	liveKeys, err := wireWitnessKeys(cur.Keys)
	if err != nil {
		return fmt.Errorf("network rotation draft: current witness set: %w", err)
	}
	// Two sources, one truth: the served set_hash must equal the hash DERIVED
	// from the served keys. A mismatch is a poisoned projection — fatal.
	derived := witness.ComputeSetHash(liveKeys)
	if !strings.EqualFold(cur.SetHash, hex.EncodeToString(derived[:])) {
		return fmt.Errorf("network rotation draft: the ledger's witness projection is inconsistent: served set_hash %s != %s derived from the served keys",
			short(cur.SetHash), short(hex.EncodeToString(derived[:])))
	}

	dids := splitCSV(*newSet)
	newKeys, err := witness.KeysFromDIDs(dids)
	if err != nil {
		return fmt.Errorf("network rotation draft: --new-set: %w", err)
	}
	draft := &rotationdraft.Draft{
		SchemaVersion: rotationdraft.DraftFormat,
		NetworkIDHex:  b.NetworkID,
		QuorumK:       b.QuorumK,
	}
	for _, k := range liveKeys {
		draft.CurrentSet = append(draft.CurrentSet, rotationdraftKey(k))
	}
	for _, k := range newKeys {
		draft.NewSet = append(draft.NewSet, rotationdraftKey(k))
	}
	// Round-trip the proposal through the consumption chokepoint BEFORE it is
	// written: the SDK constructor refuses an unsatisfiable ceremony (quorum
	// range, 2K>N, mixed schemes, duplicates) here, not on a witness host.
	if _, err := draft.SDKDraft(); err != nil {
		return fmt.Errorf("network rotation draft: %w", err)
	}
	nsh, err := draft.NewSetHash()
	if err != nil {
		return err
	}
	if err := rotationdraft.Save(*out, draft); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "rotation: drafted %s (current=%s → new_set_hash=%s, K=%d) — relay to each witness host for `genesis-endorse -kind rotation-consent`\n",
		*out, short(cur.SetHash), short(hex.EncodeToString(nsh[:])), b.QuorumK)
	return emitOutput(*output, "rotation-draft", map[string]any{
		"network_id":       draft.NetworkIDHex,
		"quorum_k":         draft.QuorumK,
		"current_set_hash": cur.SetHash,
		"current_set":      len(draft.CurrentSet),
		"new_set_hash":     hex.EncodeToString(nsh[:]),
		"new_witnesses":    len(draft.NewSet),
	}, func() error {
		tablef("rotation draft: network=%s K=%d current=%d witnesses (%s) new=%d witnesses (%s)\n",
			short(draft.NetworkIDHex), draft.QuorumK, len(draft.CurrentSet), short(cur.SetHash),
			len(draft.NewSet), short(hex.EncodeToString(nsh[:])))
		return nil
	})
}

// ─── finalize ────────────────────────────────────────────────────────

func rotationFinalizeCmd(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("network rotation finalize", flag.ContinueOnError)
	var (
		draftPath = fs.String("draft", "", "the rotation-draft — REQUIRED")
		consents  = fs.String("consents", "", "comma-separated consent files, ANY order — the SDK's membership routing buckets each one; REQUIRED")
		out       = fs.String("out", "", "write the finalized rotation here — REQUIRED")
		output    = fs.String("output", "table", "output format: table|json")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *draftPath == "" || *out == "" || *consents == "" {
		return fmt.Errorf("network rotation finalize: --draft, --consents and --out are required")
	}
	draft, err := rotationdraft.LoadDraft(*draftPath)
	if err != nil {
		return err
	}
	list, err := loadConsents(*consents)
	if err != nil {
		return fmt.Errorf("consents: %w", err)
	}

	rotation, err := draft.Finalize(list)
	if err != nil {
		return fmt.Errorf("network rotation finalize: %w", err)
	}
	payload, err := witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		return fmt.Errorf("network rotation finalize: encode: %w", err)
	}
	if err := os.WriteFile(*out, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("network rotation finalize: write %s: %w", *out, err)
	}
	fmt.Fprintf(os.Stderr, "rotation: finalized %s (%d current + %d new signatures) — submit to the network's rotation door\n",
		*out, len(rotation.CurrentSignatures), len(rotation.NewSignatures))
	return emitOutput(*output, "rotation-finalize", map[string]any{
		"out":                *out,
		"current_signatures": len(rotation.CurrentSignatures),
		"new_signatures":     len(rotation.NewSignatures),
		"new_set":            len(rotation.NewSet),
	}, func() error {
		tablef("rotation finalized → %s (%d current + %d new signatures, %d new witnesses)\n",
			*out, len(rotation.CurrentSignatures), len(rotation.NewSignatures), len(rotation.NewSet))
		return nil
	})
}

// ─── submit ──────────────────────────────────────────────────────────

func rotationSubmitCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network rotation submit", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		output     = fs.String("output", "table", "output format: table|json")
		dryRun     = fs.Bool("dry-run", false, "run every local verification, then stop BEFORE the POST")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: baseproof network rotation submit <finalized-rotation.json>")
	}
	payload, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read finalized rotation %q: %w", fs.Arg(0), err)
	}
	// Fail-closed, in widening circles: the rotation must decode + pass the
	// SDK structural door before any network I/O happens.
	r, err := witness.DecodeWitnessRotationPayload(payload)
	if err != nil {
		return fmt.Errorf("network rotation submit: not a valid rotation payload: %w", err)
	}
	if err := witness.ValidateWitnessRotation(r); err != nil {
		return fmt.Errorf("network rotation submit: %w", err)
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	if b.QuorumK <= 0 {
		return fmt.Errorf("network rotation submit: the bundle carries no witness quorum (quorum_k) — re-add the network to refresh the bundle from the verified constitution")
	}
	nid, err := b.NetworkID32()
	if err != nil {
		return fmt.Errorf("network rotation submit: %w", err)
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	// Era-drift staleness pre-check: the rotation binds the current set it
	// was drafted against; if the network rotated since, refuse by NAME
	// before the POST — the fix is a re-draft, not a retry.
	var cur wireWitnessSetFull
	if err := getJSON(ctx, hc, b.Endpoint+"/v1/network/witnesses/current", &cur); err != nil {
		return fmt.Errorf("fetch current witness set: %w", err)
	}
	if !strings.EqualFold(cur.SetHash, hex.EncodeToString(r.CurrentSetHash[:])) {
		return fmt.Errorf("network rotation submit: the network's current witness set (%s) is not the set this rotation was drafted against (%s) — the set rotated since the draft was cut; re-draft against the live set",
			short(cur.SetHash), short(hex.EncodeToString(r.CurrentSetHash[:])))
	}
	// Local full re-verify against the LIVE set: a tampered finalized file is
	// refused HERE, never posted. The v1 relay transport is ECDSA-only (the
	// same bound the consent leg enforces), so a set this driver cannot
	// verify is a named refusal, not a blind POST.
	liveKeys, err := wireWitnessKeys(cur.Keys)
	if err != nil {
		return fmt.Errorf("network rotation submit: current witness set: %w", err)
	}
	liveSet, err := cosign.NewECDSAWitnessKeySet(liveKeys, cosign.NetworkID(nid), b.QuorumK)
	if err != nil {
		return fmt.Errorf("network rotation submit: cannot verify locally against the live set (the v1 driver is ECDSA-only): %w", err)
	}
	if _, err := witness.VerifyRotation(r, liveSet); err != nil {
		return fmt.Errorf("network rotation submit: refused locally — the rotation does not verify against the live set (the door would reject it): %w", err)
	}

	if *dryRun {
		// PRE-1 two-phase contract: the full local recipe ran (structural
		// decode, era-drift pre-check, VerifyRotation against the live
		// set); the write does not happen.
		return emitOutput(*output, "rotation-submit", map[string]any{
			"dry_run": true, "verified": true, "endpoint": b.Endpoint + "/v1/network/rotation",
			"payload_bytes": len(payload),
		}, func() error { tableln("dry-run: rotation verified locally; stopping before POST"); return nil })
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Endpoint+"/v1/network/rotation", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("post rotation: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("network rotation submit: the rotation door refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return emitOutput(*output, "rotation-submit", json.RawMessage(body), func() error {
		tablef("rotation: ✔ accepted by the network's rotation door (%d new witnesses applied)\n", len(r.NewSet))
		return nil
	})
}

// ─── helpers ─────────────────────────────────────────────────────────

// wireWitnessKeys decodes the ledger's witness-key wire records into SDK keys.
func wireWitnessKeys(in []wireWitnessKeyFull) ([]types.WitnessPublicKey, error) {
	out := make([]types.WitnessPublicKey, 0, len(in))
	for i, k := range in {
		idRaw, err := hex.DecodeString(strings.TrimSpace(k.ID))
		if err != nil || len(idRaw) != 32 {
			return nil, fmt.Errorf("keys[%d].id is not a 32-byte hex id", i)
		}
		pub, err := hex.DecodeString(strings.TrimSpace(k.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("keys[%d].public_key: %w", i, err)
		}
		var id [32]byte
		copy(id[:], idRaw)
		out = append(out, types.WitnessPublicKey{ID: id, PublicKey: pub, SchemeTag: k.SchemeTag})
	}
	return out, nil
}

// rotationdraftKey renders one SDK key as the draft's wire shape.
func rotationdraftKey(k types.WitnessPublicKey) rotationdraft.Key {
	return rotationdraft.Key{
		IDHex:     hex.EncodeToString(k.ID[:]),
		PublicKey: hex.EncodeToString(k.PublicKey),
		SchemeTag: k.SchemeTag,
	}
}

func loadConsents(csv string) ([]*rotationdraft.Consent, error) {
	var out []*rotationdraft.Consent
	for _, p := range splitCSV(csv) {
		c, err := rotationdraft.LoadConsent(p)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
