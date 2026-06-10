package cli

// witnesses.go — `baseproof witnesses [--at <size>]`: the network's witness set,
// CURRENT or as-of a historical tree size (time-travel). Its own command rather
// than `info` clutter: `info` answers "who/what is this network now"; `witnesses
// --at` is a pointed historical query (which set cosigned the head at size N).

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/witness"
)

// wireWitnessKeyFull mirrors api.WitnessPublicKey (the /v1/network/witnesses/*
// key record): the content-addressable id + its public key + scheme.
type wireWitnessKeyFull struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	SchemeTag uint8  `json:"scheme_tag"`
}

// wireWitnessSetFull mirrors api.WitnessSetView: the set hash, when it took
// effect (and, if rotated out, when it retired), and its keys.
type wireWitnessSetFull struct {
	SetHash      string               `json:"set_hash"`
	SchemeTag    uint8                `json:"scheme_tag"`
	EffectiveSeq uint64               `json:"effective_seq"`
	RetiredSeq   *uint64              `json:"retired_seq,omitempty"`
	Keys         []wireWitnessKeyFull `json:"keys"`
}

// RunWitnesses implements `baseproof witnesses [--at <size>]`. With no --at it
// fetches the current set (/v1/network/witnesses/current); with --at N it
// time-travels to the set active at tree size N (/v1/network/witnesses/at/{N}).
// Witness human-name labels (/v1/network/labels) are overlaid when present.
func RunWitnesses(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("witnesses", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		at         = fs.Int64("at", -1, "witness set active as-of this tree size (omit ⇒ the current set)")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	url := b.Endpoint + "/v1/network/witnesses/current"
	label := "current"
	if *at >= 0 {
		url = fmt.Sprintf("%s/v1/network/witnesses/at/%d", b.Endpoint, *at)
		label = fmt.Sprintf("at tree_size %d", *at)
	}
	var set wireWitnessSetFull
	genesisDerived := false
	if err := getJSON(ctx, hc, url, &set); err != nil {
		var hs *httpStatusError
		if !errors.As(err, &hs) || hs.Code != http.StatusNotFound {
			return fmt.Errorf("fetch witness set (%s): %w", label, err)
		}
		// 404 ⇒ the ledger serves no witness history HERE. For --at, first
		// prove no history exists AT ALL: a 200 on /current means a real hole
		// in the recorded history (a ledger that rotated before the
		// genesis-baseline row existed) — surface that, never guess over it.
		if *at >= 0 {
			var cur wireWitnessSetFull
			if cerr := getJSON(ctx, hc, b.Endpoint+"/v1/network/witnesses/current", &cur); cerr == nil {
				return fmt.Errorf("fetch witness set (%s): %w — history exists but no recorded set covers this seq; reboot the ledger on a current image to reconcile the genesis baseline", label, err)
			}
		}
		// No history at all ⇒ the genesis set governs every committed seq.
		// Derive it from the hash-verified bootstrap (the trust root) —
		// strictly stronger evidence than the unauthenticated projection.
		gset, gerr := genesisWitnessSetFallback(ctx, hc, b)
		if gerr != nil {
			return fmt.Errorf("fetch witness set (%s): %w (genesis fallback failed: %v)", label, err, gerr)
		}
		set, genesisDerived = gset, true
	}

	// Overlay human-name labels (best-effort; absent ⇒ ids only).
	var labels wireLabels
	_ = getJSONOptional(ctx, hc, b.Endpoint+"/v1/network/labels", &labels)
	labelOf := make(map[string]string, len(labels.Labels))
	for _, l := range labels.Labels {
		labelOf[strings.ToLower(l.PubKeyID)] = l.Label
	}

	fmt.Printf("witnesses: %s — set %s  scheme=%d  effective_seq=%d  (%d keys)\n",
		label, short(set.SetHash), set.SchemeTag, set.EffectiveSeq, len(set.Keys))
	if genesisDerived {
		fmt.Printf("witnesses: GENESIS set — derived from the hash-verified bootstrap (the ledger serves no witness history)\n")
	}
	if set.RetiredSeq != nil {
		fmt.Printf("witnesses: this set RETIRED at seq %d — a later set is active (rotation)\n", *set.RetiredSeq)
	}
	for i, k := range set.Keys {
		name := ""
		if l := labelOf[strings.ToLower(k.ID)]; l != "" {
			name = "  " + l
		}
		fmt.Printf("  [%d] %s%s\n", i, short(k.ID), name)
	}
	return nil
}

// genesisWitnessSetFallback derives the genesis witness set from the
// hash-verified bootstrap. SetHash is the same row-identity hash a healed
// ledger would serve (the WitnessKeySet's JCS {network_id, quorum_k,
// witnesses[]} hash) — computable only when the bundle carries both the
// network id and quorum_k; left empty otherwise.
func genesisWitnessSetFallback(ctx context.Context, hc *http.Client, b *ClientBundle) (wireWitnessSetFull, error) {
	doc, err := fetchBootstrap(ctx, hc, b.Endpoint, b.BootstrapHash)
	if err != nil {
		return wireWitnessSetFull{}, err
	}
	if len(doc.GenesisWitnessSet) == 0 {
		return wireWitnessSetFull{}, fmt.Errorf("bootstrap carries no genesis witness set")
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		return wireWitnessSetFull{}, fmt.Errorf("derive genesis keys: %w", err)
	}
	set := wireWitnessSetFull{SchemeTag: 1, EffectiveSeq: 0}
	for _, k := range keys {
		set.Keys = append(set.Keys, wireWitnessKeyFull{
			ID:        hex.EncodeToString(k.ID[:]),
			PublicKey: hex.EncodeToString(k.PublicKey),
			SchemeTag: k.SchemeTag,
		})
	}
	if id, ierr := b.NetworkID32(); ierr == nil && b.QuorumK > 0 {
		if ks, kerr := cosign.NewECDSAWitnessKeySet(keys, cosign.NetworkID(id), b.QuorumK); kerr == nil {
			h := ks.SetHash()
			set.SetHash = hex.EncodeToString(h[:])
		}
	}
	return set, nil
}
