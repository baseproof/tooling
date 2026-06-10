// Command e2e is the tooling platform end-to-end runner: it drives the unified
// baseproof CLI (libs/cli) against a real ledger fleet.
//
//	e2e selftest   drive the READ stages against the in-process real-crypto fixture
//	               (HTTPS, real cryptography, NO docker) — runs anywhere
//	e2e up         bring up the docker fleet (postgres + seaweedfs + witness +
//	               ledger[HTTPS] + auditor) and persist its manifest
//	e2e run        drive submit → proof → verify → info against the live fleet
//	e2e down       tear the fleet down
//
// up/run/down need a docker daemon; selftest does not. The SAME runner drives both,
// so `selftest` proves the read/verify side everywhere and `up`+`run` close the
// write pipeline (real admission → sequencer → builder → cosign) in your docker.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/baseproof/tooling/e2e/fixture"
	"github.com/baseproof/tooling/e2e/runner"
	"github.com/baseproof/tooling/e2e/stack"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "selftest":
		err = cmdSelftest()
	case "up":
		err = cmdUp(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "down", "wipe":
		err = cmdDown()
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "e2e: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `e2e — tooling platform end-to-end (drives the unified CLI against a real fleet)

  e2e selftest        READ stages vs the in-process real-crypto fixture (HTTPS, no docker)
  e2e up [--build]    bring up the docker fleet (pg + seaweedfs + witness + ledger + auditor)
  e2e run [--load N]  submit → proof → verify → info against the live fleet
  e2e down            tear the fleet down

env: BASEPROOF_E2E_DIR (state dir, default ./.run/e2e); E2E_LOG_DID; E2E_QUORUM_K
`)
}

func runDir() string {
	if d := os.Getenv("BASEPROOF_E2E_DIR"); d != "" {
		return d
	}
	return filepath.Join(".run", "e2e")
}
func manifestPath() string { return filepath.Join(runDir(), "manifest.json") }

func cmdSelftest() error {
	fmt.Println("== selftest: READ stages vs in-process real-crypto fixture (HTTPS, no docker) ==")
	fx, err := fixture.Start(3, 2)
	if err != nil {
		return err
	}
	defer fx.Close()
	res, err := runner.ReadStages(context.Background(), runner.Config{
		LedgerURL: fx.Ledger.URL, CAFile: fx.CAPath, LogDID: fx.LogDID, QuorumK: 2,
		WorkDir: filepath.Join(runDir(), "selftest"),
	}, fx.Seq, fx.SMTKeyHex)
	printResult(res)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("selftest read stages were not all green")
	}
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	build := fs.Bool("build", false, "build the ledger/witness/auditor images from the local Dockerfiles (else pull the published fleet)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := stack.Config{
		WorkDir:        filepath.Join(runDir(), "work"),
		BuildImages:    *build || os.Getenv("E2E_BUILD") == "1",
		LogDID:         os.Getenv("E2E_LOG_DID"),
		QuorumK:        envInt("E2E_QUORUM_K", 1),
		TesseraVariant: os.Getenv("E2E_TESSERA"), // "" → fork (default)
		LedgerImage:    os.Getenv("E2E_LEDGER_IMAGE"),
	}
	fmt.Println("== bringing up the docker fleet (pg + seaweedfs + witness + ledger[HTTPS] + auditor) ==")
	m, err := stack.Build(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir(), 0o755); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(manifestPath(), raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("== fleet UP ==\n  ledger : %s\n  auditor: %s\n  network: %s\n  run    : e2e run\n  down   : e2e down\n",
		m.LedgerURL, m.AuditorURL, m.NetworkID)
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	load := fs.Int("load", 50, "load-stage entry count (0 ⇒ skip the load stage)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(manifestPath())
	if err != nil {
		return fmt.Errorf("no fleet manifest at %s — bring one up first: e2e up", manifestPath())
	}
	var m stack.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	fmt.Printf("== driving the unified CLI against %s ==\n", m.LedgerURL)
	res, err := runner.Run(context.Background(), runner.Config{
		LedgerURL: m.LedgerURL, CAFile: m.CAPath, LogDID: m.LogDID, QuorumK: m.QuorumK,
		WorkDir: filepath.Join(runDir(), "run"), LoadN: *load,
	})
	printResult(res)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("e2e run had failed stages")
	}
	return nil
}

func cmdDown() error {
	cfg := stack.Config{WorkDir: filepath.Join(runDir(), "work"), LogDID: os.Getenv("E2E_LOG_DID")}
	stack.Wipe(cfg)
	_ = os.Remove(manifestPath())
	fmt.Println("== fleet torn down ==")
	return nil
}

func printResult(res *runner.Result) {
	if res == nil {
		return
	}
	for _, s := range res.Stages {
		mark := "✔"
		if !s.OK {
			mark = "✗"
		}
		fmt.Printf("  %s %s", mark, s.Name)
		if s.Detail != "" {
			fmt.Printf("  [%s]", s.Detail)
		}
		if s.Err != nil {
			fmt.Printf("  — %v", s.Err)
		}
		fmt.Println()
	}
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}
