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
JN enforcer, which runs its admission gate and mints the gate-5 WriteAuthorization
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
	use := &cobra.Command{Use: "use <name>", Short: "Set the active network", Args: cobra.ExactArgs(1), RunE: forward(cli.RunNetwork, "use")}
	show := &cobra.Command{Use: "show [name]", Short: "Show a network (default: active)", Args: cobra.MaximumNArgs(1), RunE: forward(cli.RunNetwork, "show")}
	remove := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a stored network (its trust pin remains — tombstoned)",
		Args:  cobra.ExactArgs(1),
		RunE:  forward(cli.RunNetwork, "remove"),
	}

	n.AddCommand(add, list, use, show, remove)
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
