// Command baseproof is the unified client for a baseproof network: submit an
// entry, generate + verify portable proofs, understand a network, and drive load
// — each bound to ONE network by a client bundle (or the active network).
//
// All logic lives in github.com/baseproof/tooling/libs/cli (the platform e2e
// harness imports the same package, so what CI exercises is exactly what an
// operator runs), making this binary a thin dispatcher.
//
// ROADMAP: this module is staged for extraction to its own repository next
// sprint, where the command surface is rebuilt on Cobra (subcommands, flag
// completion, man pages) over the same libs/cli RunX seams. For now it stays a
// one-line os.Exit(cli.Main) wrapper so the proven stdlib-flag dispatch ships
// unchanged.
package main

import (
	"os"

	"github.com/baseproof/tooling/libs/cli"
)

func main() { os.Exit(cli.Main(os.Args)) }
