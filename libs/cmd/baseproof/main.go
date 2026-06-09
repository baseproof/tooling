// Command baseproof is the unified client for a baseproof network: submit an
// entry, generate + verify a proof, or drive load — each bound to one network by
// a client bundle. All logic lives in libs/cli (which the e2e harness imports
// too), so this binary is a thin dispatcher.
//
//	baseproof submit --bundle b.json --payload <text> [--amend <seq>]
//	baseproof proof  --bundle b.json --seq <n>
//	baseproof load   --bundle b.json -n <count> [--manifest oracle.jsonl]
package main

import (
	"os"

	"github.com/baseproof/tooling/libs/cli"
)

func main() {
	os.Exit(cli.Main(os.Args))
}
