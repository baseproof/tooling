package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/baseproof/tooling/libs/cli"
)

func submitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "submit",
		Short: "Submit ONE entry to the network",
		Long: `Submit ONE entry: a new entity (default), a same-signer amendment
(--amend <seq>), a delegation (--delegate-to <did>), or a DELEGATED amendment
(--amend <seq> --delegation <seq>). Amendments/delegations sign with --key-file.

On a GATED network (the bundle carries a write_endpoint) the write goes THROUGH the
network's write gate, which runs its admission policy and mints the gate-5 WriteAuthorization
the ledger requires. Cosignatures come in two shapes: INLINE multi-sig
(--cosigner-keys k1,k2 — one entry, N signatures) or a TWO-PART attestation
(--cosign <log-did>@<seq> — a separate entry cosigning a prior primary).`,
		Args: cobra.NoArgs,
		RunE: forward(cli.RunSubmit),
	}
	bundleFlags(c)
	f := c.Flags()
	f.String("payload", "", "entry payload (UTF-8) — REQUIRED")
	f.Int64("amend", -1, "amend the entity at this sequence (signed by its key)")
	f.String("delegate-to", "", "mint a delegation: grant authority to this delegate DID")
	f.Int64("delegation", -1, "with --amend: a DELEGATED amendment citing the delegation at this seq")
	f.String("key-file", "", "32-byte hex secp256k1 signer key (required for amend/delegate/delegated)")
	f.String("out-key", "", "write the generated signer key (hex) here (new entity only)")
	f.String("token", "", "Mode A credit token; empty ⇒ Mode B PoW")
	f.Int("difficulty", 0, "Mode B PoW difficulty (0 ⇒ query the ledger)")
	f.String("cosigner-keys", "", "comma-separated key files (hex) added as INLINE cosignatures on ONE entry (in-band multi-sig; needs a gated write_endpoint)")
	f.String("cosign", "", "TWO-PART attestation: this entry cosigns the prior primary at <log-did>@<seq> (sets Header.CosignatureOf)")
	f.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	return c
}

func loadCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "load",
		Short: "Drive interconnected load (the memory-bounded loadgen engine)",
		Args:  cobra.NoArgs,
		RunE:  forward(cli.RunLoad),
	}
	bundleFlags(c)
	f := c.Flags()
	// Long-only: -n is the global network shorthand (a flag means the same
	// thing on every verb), so the count is --n, never -n.
	f.Int("n", 1000, "total entries to submit (roots + delegations + amendments)")
	f.Float64("amend-ratio", 0.5, "fraction of entries that amend a recent root")
	f.Float64("delegate-ratio", 0, "fraction of new entities given a delegation (⇒ delegated amendments)")
	f.Int("workers", 0, "concurrent PoW/submit workers (0 = NumCPU)")
	f.Int("batch-size", 1, "Mode A: entries per /v1/entries/batch (requires --token)")
	f.Int("amend-window", 0, "recent-root amend window K (0 = default; bounds memory)")
	f.Int64("seed", 1, "run seed — same seed reproduces the exact stream + identities")
	f.String("token", "", "Mode A credit token; empty ⇒ Mode B PoW")
	f.Int("difficulty", 0, "Mode B PoW difficulty (0 ⇒ query the ledger)")
	f.String("manifest", "", "write the JSONL expected-state oracle to this path")
	f.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	return c
}

func proofCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "proof",
		Short: "Generate a v2 self-anchored proof of an entry",
		Long: `Generate a portable v2 self-anchored proof of the entry at --seq, self-verify
it offline, and (with --out) write it to a file anyone can 'baseproof verify'.`,
		Args: cobra.NoArgs,
		RunE: forward(cli.RunProof),
	}
	bundleFlags(c)
	f := c.Flags()
	f.Uint64("seq", 0, "entry sequence to prove — REQUIRED")
	f.String("smt-key", "", "64-hex SMT key (default: derived from log DID + seq)")
	f.String("out", "", "write the portable v2 proof to this file (else verify + render)")
	f.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	return c
}

func verifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "verify <proof-file>",
		Short: "Verify a v2 proof fully offline (Zero-Trust)",
		Long: `Verify a v2 proof FILE fully offline (zero network): recompute the witness
K-of-N cosignatures, inclusion, and SMT membership — fail-closed. Network-agnostic
(self-anchored); --pin / --network / --bundle bind it to a network you trust.`,
		Args: cobra.ExactArgs(1),
		RunE: forward(cli.RunVerify),
	}
	f := c.Flags()
	f.String("pin", "", "require the proof's network id to equal this 64-hex id")
	f.StringP("network", "n", "", "pin against this stored/active network")
	f.String("bundle", "", "pin against this network bundle's id (content-addressed anchor)")
	f.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	return c
}

func infoCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "info",
		Short: "Understand a network in one verified view",
		Long: `Aggregate a network's public surface — identity (recomputed), trust root,
witnesses + K-of-N, auditors (live + in-sync), horizon, admission, accepted
messages, anchors/labels/endpoints, mirrors, federation. --verify recomputes the
crypto; --federation walks + verifies the cited peers (bounded, cycle-guarded).`,
		Args: cobra.NoArgs,
		RunE: forward(cli.RunInfo),
	}
	bundleFlags(c)
	f := c.Flags()
	f.Bool("verify", false, "recompute the cryptographic checks (horizon K-of-N, auditor liveness, peer ids)")
	f.Bool("federation", false, "walk + verify the cited federation peers")
	f.Int("depth", 1, "federation walk depth (bounded)")
	f.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	f.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	return c
}

func witnessesCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "witnesses",
		Short: "The network's witness set (current or time-travelled)",
		Args:  cobra.NoArgs,
		RunE:  forward(cli.RunWitnesses),
	}
	bundleFlags(c)
	f := c.Flags()
	f.Int64("at", -1, "witness set active as-of this tree size (omit ⇒ the current set)")
	f.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	f.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	return c
}

func networkCmd() *cobra.Command {
	n := &cobra.Command{Use: "network", Short: "Manage stored networks (gcloud-style)"}

	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Author (from a live ledger) or import a network bundle",
		Args:  cobra.ExactArgs(1),
		RunE:  forward(cli.RunNetwork, "add"),
	}
	af := add.Flags()
	af.String("from", "", "import a client bundle from this file or URL")
	af.String("from-ledger", "", "AUTHOR a bundle by introspecting this live ledger endpoint")
	af.String("ca-cert", "", "CA cert to pin (for --from-ledger HTTPS + the bundle's transport)")
	af.String("log-did", "", "log DID (--from-ledger; else taken from /v1/log-info)")
	af.Bool("use", false, "set this network active after adding")
	af.Bool("repin", false, "explicitly replace this name's pinned trust root if the offered network id differs (else a mismatch refuses)")
	af.String("pin", "", "REQUIRE the added network's id to equal this 64-hex id (out-of-band expected identity)")
	af.Duration("timeout", 30*time.Second, "per-request HTTP timeout")

	list := &cobra.Command{Use: "list", Short: "List stored networks", Args: cobra.NoArgs, RunE: forward(cli.RunNetwork, "list")}
	list.Flags().StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	use := &cobra.Command{Use: "use <name>", Short: "Set the active network", Args: cobra.ExactArgs(1), RunE: forward(cli.RunNetwork, "use")}
	show := &cobra.Command{Use: "show [name]", Short: "Show a network (default: active)", Args: cobra.MaximumNArgs(1), RunE: forward(cli.RunNetwork, "show")}
	show.Flags().StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	remove := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a stored network (its trust pin remains — tombstoned)",
		Args:  cobra.ExactArgs(1),
		RunE:  forward(cli.RunNetwork, "remove"),
	}

	bundle := &cobra.Command{Use: "bundle", Short: "The network bundle (the manifest/v1 discovery document)"}
	bGet := &cobra.Command{
		Use:   "get",
		Short: "Fetch the network's bundle and VERIFY it through the door (discovery is never authority)",
		Args:  cobra.NoArgs,
		RunE:  forward(cli.RunNetwork, "bundle", "get"),
	}
	bgf := bGet.Flags()
	bgf.String("bundle", "", "client bundle JSON (else --network or the active network)")
	bgf.StringP("network", "n", "", "stored network name (else $BASEPROOF_NETWORK, else the active network)")
	bgf.String("destination", "", "exchange/destination DID (default: the single destination served)")
	bgf.String("out", "", "also write the verified canonical bytes to this file")
	bgf.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	bgf.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	bVerify := &cobra.Command{
		Use:   "verify <manifest.json>",
		Short: "Verify a manifest FILE against the network's hash-verified constitution",
		Args:  cobra.ExactArgs(1),
		RunE:  forward(cli.RunNetwork, "bundle", "verify"),
	}
	bvf := bVerify.Flags()
	bvf.String("bundle", "", "client bundle JSON (else --network or the active network)")
	bvf.StringP("network", "n", "", "stored network name (else $BASEPROOF_NETWORK, else the active network)")
	bvf.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	bvf.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	bPublish := &cobra.Command{
		Use:   "publish",
		Short: "Publish a composed manifest on-log (two-step: --publish-anchor, then --manifest + --anchor)",
		Long: `Publish the network bundle on-log — the producer half of the manifest contract.

Step 1:  baseproof network bundle publish --publish-anchor --signer-key k.hex
         (publishes the anchor schema entry, waits, prints the exact --anchor)
Step 2:  baseproof network bundle publish --manifest m.json --anchor <log@seq> --signer-key k.hex
         (verifies the composed manifest through the door — an unverifiable
          manifest is NEVER signed — then publishes it citing the anchor;
          the LATEST citing entry is the current manifest)`,
		Args: cobra.NoArgs,
		RunE: forward(cli.RunNetwork, "bundle", "publish"),
	}
	bpf := bPublish.Flags()
	bpf.String("bundle", "", "client bundle JSON (else --network or the active network)")
	bpf.StringP("network", "n", "", "stored network name (else $BASEPROOF_NETWORK, else the active network)")
	bpf.String("manifest", "", "composed manifest JSON to publish (step 2)")
	bpf.String("anchor", "", "manifest anchor position <log-did>@<seq> (step 2)")
	bpf.Bool("publish-anchor", false, "publish the manifest ANCHOR schema entry (step 1 of 2)")
	bpf.String("destination", "", "destination DID for the anchor entry (step 1; default: the bundle's log DID)")
	bpf.String("signer-key", "", "32-byte hex secp256k1 signer key — REQUIRED")
	bpf.String("token", "", "Mode A credit token; empty ⇒ the network's posture decides")
	bpf.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
	bpf.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	bundle.AddCommand(bGet, bVerify, bPublish)

	n.AddCommand(add, list, use, show, remove, bundle)
	return n
}

func configCmd() *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Active-network default"}
	set := &cobra.Command{
		Use:   "set network <name>",
		Short: "Set the active network",
		Args:  cobra.ExactArgs(2), // "network" <name>
		RunE:  forward(cli.RunConfig, "set"),
	}
	list := &cobra.Command{Use: "list", Short: "List stored networks + the active one", Args: cobra.NoArgs, RunE: forward(cli.RunConfig, "list")}
	c.AddCommand(set, list)
	return c
}

func cosignCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cosign",
		Short: "The file-based cosign-request relay (multi-host in-band multi-sig)",
		Long: `Offline assembly of the in-band multi-sig the write gate verifies:
draft on one host, relay the file, render+countersign on others, submit.
The relay is convenience, never authority — the gate re-verifies everything.`,
	}
	flags := func(cmd *cobra.Command, withNet bool) *cobra.Command {
		f := cmd.Flags()
		if withNet {
			f.String("bundle", "", "client bundle JSON (else --network or the active network)")
			f.StringP("network", "n", "", "stored network name (else $BASEPROOF_NETWORK, else the active network)")
		}
		f.StringP("output", "o", "table", "output format: table|json (json = the versioned machine envelope)")
		return cmd
	}
	draft := flags(&cobra.Command{Use: "draft", Short: "Draft + primary-sign a cosign request (rule from the door-verified manifest)", Args: cobra.NoArgs, RunE: forward(cli.RunCosign, "draft")}, true)
	df := draft.Flags()
	df.String("operation", "", "manifest event_type — REQUIRED")
	df.String("payload", "", "entry payload (UTF-8; or --payload-file)")
	df.String("payload-file", "", "entry payload file")
	df.String("signer-key", "", "32-byte hex secp256k1 PRIMARY key — REQUIRED")
	df.String("role", "", "the primary's role label (default: the operation's primary_role)")
	df.String("out", "", "write the cosign-request here — REQUIRED")
	df.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	show := flags(&cobra.Command{Use: "show <request-file>", Short: "Render a request: digest-pinned, every signature verified", Args: cobra.ExactArgs(1), RunE: forward(cli.RunCosign, "show")}, false)
	sign := flags(&cobra.Command{Use: "sign <request-file>", Short: "Render-then-countersign (no blind signing)", Args: cobra.ExactArgs(1), RunE: forward(cli.RunCosign, "sign")}, false)
	sf := sign.Flags()
	sf.String("signer-key", "", "32-byte hex secp256k1 countersigner key — REQUIRED")
	sf.String("role", "", "the role this countersignature satisfies — REQUIRED")
	submit := flags(&cobra.Command{Use: "submit <request-file>", Short: "Assemble + submit through the write gate (refuses an incomplete mix)", Args: cobra.ExactArgs(1), RunE: forward(cli.RunCosign, "submit")}, true)
	submit.Flags().Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	c.AddCommand(draft, show, sign, submit)
	return c
}
