// Command baseproof is the unified client for a baseproof network: submit an
// entry, generate + verify portable proofs, understand a network, and drive load
// — each bound to ONE network by a client bundle (or the active network).
//
// This is the COBRA surface: each command is a cobra.Command with native POSIX
// flags (help, completion, man pages), but the WORK is the proven libs/cli RunX
// seams — the forwarder reconstructs the flags a user SET into the `--name=value`
// args those functions parse, so all defaults + logic live in libs/cli (untouched)
// and the platform e2e drives exactly what ships. cli.Main (the stdlib-flag
// dispatch) remains in libs for callers that embed it; this binary is the Cobra
// front end, staged for extraction to its own repository.
package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func main() {
	if err := root().Execute(); err != nil {
		os.Exit(1)
	}
}

func root() *cobra.Command {
	r := &cobra.Command{
		Use:   "baseproof",
		Short: "Unified client for a baseproof network",
		Long: `baseproof — unified client for a baseproof network.

A client bundle binds the CLI to ONE network: its ledger endpoint, trust root
(network id, quorum, content-addressed bootstrap hash), destination log DID, and
TLS posture. Pass --bundle <file> or --network <name>, else the active network
(set with 'baseproof network use' / 'baseproof config set network').

Zero-Trust by default: 'info --verify' recomputes the network id + K-of-N
cosignatures; 'proof' self-verifies before it emits; 'verify' recomputes every
check and fails closed. A v2 proof is standalone — 'verify' needs no network.`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	r.CompletionOptions.HiddenDefaultCmd = true
	r.AddCommand(
		submitCmd(), loadCmd(), proofCmd(), verifyCmd(),
		infoCmd(), witnessesCmd(), networkCmd(), configCmd(),
	)
	return r
}

// forward returns a RunE that reconstructs the args the libs/cli RunX seam parses:
// an optional command prefix (for sub-dispatched groups like `network add`), then
// every flag the user SET as `--name=value` (cmd.Flags().Visit visits only changed
// flags; `--name=value` is the form stdlib flag accepts for every type, including
// bools), then the positional args. Unset flags fall through to RunX's own
// defaults — so the defaults live in exactly one place.
func forward(run func(context.Context, []string) error, prefix ...string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		a := append([]string{}, prefix...)
		cmd.Flags().Visit(func(f *pflag.Flag) {
			a = append(a, "--"+f.Name+"="+f.Value.String())
		})
		a = append(a, args...)
		return run(cmd.Context(), a)
	}
}

// bundleFlags adds the network-selection flags every act-on-a-network command takes.
func bundleFlags(c *cobra.Command) {
	c.Flags().String("bundle", "", "client bundle JSON (else --network or the active network)")
	c.Flags().String("network", "", "stored network name (else the active network)")
}
