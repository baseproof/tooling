package cli

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Main is the unified client entrypoint; argv is os.Args. It returns a process
// exit code (cmd/baseproof is a one-line os.Exit(cli.Main(os.Args)) wrapper).
func Main(argv []string) int {
	if len(argv) < 2 {
		usage(os.Stderr)
		return 2
	}
	cmd, args := argv[1], argv[2:]
	ctx := context.Background()

	var err error
	switch cmd {
	case "submit":
		err = RunSubmit(ctx, args)
	case "proof":
		err = RunProof(ctx, args)
	case "verify":
		err = RunVerify(ctx, args)
	case "load":
		err = RunLoad(ctx, args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "baseproof: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseproof %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `baseproof — unified client for a baseproof network

A client bundle (--bundle <file.json>) binds the CLI to ONE network: its ledger
endpoint, trust root (network id, quorum, bootstrap hash), destination log DID,
and transport pinning. Ship one bundle per network.

usage:
  baseproof submit --bundle b.json --payload <text> [--amend <seq>] [--key-file f] [--out-key f] [--token t]
        Submit ONE entry to the network: a new entity, or an amendment of an
        existing entity (--amend <seq>, signed by its key via --key-file).

  baseproof proof  --bundle b.json --seq <n> [--smt-key <64hex>] [--out file.proof]
        Generate a portable v2 self-anchored proof of the entry and (with --out)
        write it to a file for sharing/submission; otherwise verify + render it.

  baseproof verify <proof-file> [--pin <64hex-network-id>]
        Verify a v2 proof FILE fully offline (zero network calls): recompute the
        witness K-of-N cosignatures, inclusion and SMT membership — fail-closed.
        Network-agnostic (self-anchored); --pin binds it to a network you trust.

  baseproof load   --bundle b.json -n <count> [--amend-ratio r] [--workers w]
                   [--batch-size b] [--token t] [--seed s] [--manifest oracle.jsonl]
        Drive interconnected load (the memory-bounded loadgen engine) and,
        optionally, stream the expected-state oracle as JSON Lines.
`)
}
