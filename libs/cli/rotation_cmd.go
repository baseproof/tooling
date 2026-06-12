/*
FILE PATH: libs/cli/rotation_cmd.go

DESCRIPTION:

	`baseproof network rotation <draft|finalize|submit>` — the operator's
	driver for the witness-rotation ceremony (PRE-6c). The crypto lives in
	libs/rotationdraft (the seam); these verbs are the operator's file
	choreography around it:

	  draft     fetch the network's CURRENT witness set hash from the LIVE
	            history (/v1/network/witnesses/current — never asserted),
	            pair it with the proposed NEW set (--new-set DIDs), and write
	            a rotation-draft to relay to each witness host.
	  finalize  merge a draft + its collected consent files into the on-log
	            types.WitnessRotation, cross-checking every binding; refuses
	            (the SDK structural door) before writing anything.
	  submit    POST the finalized rotation to the network's public
	            POST /v1/network/rotation door, which feeds the ledger's
	            single ProcessRotation chokepoint (full crypto recipe there).

	The driver mints no trust: the consents ARE the authority, ProcessRotation
	is the verifier. submit is fail-closed — a rotation that doesn't assemble
	is never posted.
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
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	// CURRENT set hash from the LIVE history — never asserted.
	var cur wireWitnessSetFull
	if err := getJSON(ctx, hc, b.Endpoint+"/v1/network/witnesses/current", &cur); err != nil {
		return fmt.Errorf("fetch current witness set: %w", err)
	}
	if cur.SetHash == "" {
		return fmt.Errorf("network rotation draft: the ledger serves no current witness-set hash")
	}

	dids := splitCSV(*newSet)
	keys, err := witness.KeysFromDIDs(dids)
	if err != nil {
		return fmt.Errorf("network rotation draft: --new-set: %w", err)
	}
	draft := &rotationdraft.Draft{
		SchemaVersion:  rotationdraft.DraftFormat,
		NetworkIDHex:   b.NetworkID,
		CurrentSetHash: cur.SetHash,
	}
	for _, k := range keys {
		draft.NewSet = append(draft.NewSet, rotationdraft.Key{
			IDHex:     hex.EncodeToString(k.ID[:]),
			PublicKey: hex.EncodeToString(k.PublicKey),
			SchemeTag: k.SchemeTag,
		})
	}
	nsh, err := draft.NewSetHash()
	if err != nil {
		return err
	}
	if err := rotationdraft.Save(*out, draft); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "rotation: drafted %s (current=%s → new_set_hash=%s) — relay to each witness host for `genesis-endorse -kind rotation-consent`\n",
		*out, short(cur.SetHash), short(hex.EncodeToString(nsh[:])))
	return emitOutput(*output, "rotation-draft", rotationDraftData(draft, hex.EncodeToString(nsh[:])), func() error {
		fmt.Printf("rotation draft: network=%s current=%s new_witnesses=%d new_set_hash=%s\n",
			short(draft.NetworkIDHex), short(draft.CurrentSetHash), len(draft.NewSet), short(hex.EncodeToString(nsh[:])))
		return nil
	})
}

// ─── finalize ────────────────────────────────────────────────────────

func rotationFinalizeCmd(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("network rotation finalize", flag.ContinueOnError)
	var (
		draftPath = fs.String("draft", "", "the rotation-draft — REQUIRED")
		curList   = fs.String("current-consents", "", "comma-separated CURRENT-set consent files (the OLD K-of-N authority)")
		newList   = fs.String("new-consents", "", "comma-separated NEW-set consent files (the dual-sign attestation)")
		out       = fs.String("out", "", "write the finalized rotation here — REQUIRED")
		output    = fs.String("output", "table", "output format: table|json")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *draftPath == "" || *out == "" {
		return fmt.Errorf("network rotation finalize: --draft and --out are required")
	}
	draft, err := rotationdraft.LoadDraft(*draftPath)
	if err != nil {
		return err
	}
	curConsents, err := loadConsents(*curList)
	if err != nil {
		return fmt.Errorf("current consents: %w", err)
	}
	newConsents, err := loadConsents(*newList)
	if err != nil {
		return fmt.Errorf("new consents: %w", err)
	}

	rotation, err := draft.Finalize(curConsents, newConsents)
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
		fmt.Printf("rotation finalized → %s (%d current + %d new signatures, %d new witnesses)\n",
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
	// Fail-closed: the rotation must decode + pass the SDK structural door
	// before it is posted — a malformed file never reaches the network.
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
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
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
		fmt.Printf("rotation: ✔ accepted by the network's rotation door (%d new witnesses applied)\n", len(r.NewSet))
		return nil
	})
}

// ─── helpers ─────────────────────────────────────────────────────────

func rotationDraftData(d *rotationdraft.Draft, newSetHash string) map[string]any {
	return map[string]any{
		"network_id":       d.NetworkIDHex,
		"current_set_hash": d.CurrentSetHash,
		"new_set_hash":     newSetHash,
		"new_witnesses":    len(d.NewSet),
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
