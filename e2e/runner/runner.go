// Package runner drives the unified baseproof CLI (libs/cli) end to end against a
// LIVE ledger — the docker fleet (e2e up) or the in-process fixture (e2e selftest).
// Every stage is a real command an operator runs (network add, proof, verify, info,
// submit, load), so what CI exercises is exactly the shipped surface.
//
// Stages split cleanly:
//   - READ side (provable anywhere, incl. the fixture): author a bundle from the
//     ledger over HTTPS, generate a v2 proof of an entry, VERIFY it offline, and
//     `info --verify` the live horizon + auditor.
//   - WRITE side (needs the real admission→sequencer→builder→cosign pipeline):
//     submit an entry, wait for the cosigned horizon to cover it, load N entries.
//
// Run = WRITE then READ: submit a fresh entry, then prove THAT entry — exercising
// the real receipt_proof leg the builder produces.
package runner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/tooling/libs/cli"
)

// Config drives the runner against an already-live ledger. CAFile pins the
// ledger's HTTPS server cert (server-verify, open HTTPS — no client cert).
// There is no quorum knob: `network add` reads K from the ledger's verified
// constitution (doc.GenesisQuorumK).
type Config struct {
	LedgerURL string
	CAFile    string
	LogDID    string
	WorkDir   string // scratch (bundle store + proof files); a temp dir if empty
	LoadN     int    // load-stage entry count (0 ⇒ skip the load stage)
}

// Stage is one command's outcome.
type Stage struct {
	Name   string
	OK     bool
	Detail string
	Err    error
}

// Result is the ordered stage log.
type Result struct{ Stages []Stage }

func (r *Result) add(name, detail string, err error) {
	r.Stages = append(r.Stages, Stage{Name: name, OK: err == nil, Detail: detail, Err: err})
}

// OK reports whether every stage passed.
func (r *Result) OK() bool {
	for _, s := range r.Stages {
		if !s.OK {
			return false
		}
	}
	return true
}

const netName = "e2e"

var (
	reSeq = regexp.MustCompile(`seq=(\d+)`)
	reKey = regexp.MustCompile(`smt_key=([0-9a-fA-F]{64})`)
)

// prep sets BASEPROOF_CONFIG_DIR so `network add`/`use` write into the run's scratch
// dir (never the operator's ~/.config). Returns the resolved work dir.
func (cfg *Config) prep() (string, error) {
	dir := cfg.WorkDir
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "e2e-run-"); err != nil {
			return "", err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.Setenv("BASEPROOF_CONFIG_DIR", dir); err != nil {
		return "", err
	}
	return dir, nil
}

// ReadStages drives the read/verify side against a ledger that ALREADY holds the
// target entry at seq (the write side submitted it, or the fixture serves it):
// author bundle → proof → verify offline → info --verify.
func ReadStages(ctx context.Context, cfg Config, seq uint64, smtKeyHex string) (*Result, error) {
	r := &Result{}
	dir, err := cfg.prep()
	if err != nil {
		return r, err
	}

	r.add("network add (author bundle over HTTPS)", cfg.LedgerURL, activate(ctx, cfg))
	if !r.OK() {
		return r, fmt.Errorf("authoring failed; aborting")
	}

	proofPath := filepath.Join(dir, "entry.proof")
	pargs := []string{"--seq", strconv.FormatUint(seq, 10), "--out", proofPath}
	if smtKeyHex != "" {
		pargs = append(pargs, "--smt-key", smtKeyHex)
	}
	_, perr := capture(func() error { return cli.RunProof(ctx, pargs) })
	r.add(fmt.Sprintf("proof seq=%d (live gather over HTTPS → self-verify)", seq), proofPath, perr)

	if perr == nil {
		// Flags before the positional proof file.
		_, verr := capture(func() error { return cli.RunVerify(ctx, []string{"--network", netName, proofPath}) })
		r.add("verify (offline, pinned to network)", proofPath, verr)
	}

	_, ierr := capture(func() error { return cli.RunInfo(ctx, []string{"--verify"}) })
	r.add("info --verify (horizon K-of-N + auditor live)", cfg.LedgerURL, ierr)

	return r, nil
}

// WriteStages drives submit + (optional) load against the real admission pipeline,
// then WAITS for the cosigned horizon to cover the submitted entry (so a proof of
// it can anchor). Returns the submitted entry's sequence + SMT key.
func WriteStages(ctx context.Context, cfg Config) (uint64, string, *Result, error) {
	r := &Result{}
	if _, err := cfg.prep(); err != nil {
		return 0, "", r, err
	}
	if err := activate(ctx, cfg); err != nil {
		r.add("network add (author bundle over HTTPS)", cfg.LedgerURL, err)
		return 0, "", r, err
	}
	r.add("network add (author bundle over HTTPS)", cfg.LedgerURL, nil)

	out, serr := capture(func() error {
		return cli.RunSubmit(ctx, []string{"--payload", "e2e-platform-entry"})
	})
	var seq uint64
	var smtKey string
	if serr == nil {
		if m := reSeq.FindStringSubmatch(out); len(m) == 2 {
			seq, _ = strconv.ParseUint(m[1], 10, 64)
		} else {
			serr = fmt.Errorf("could not parse sequence from submit output: %q", strings.TrimSpace(out))
		}
		if m := reKey.FindStringSubmatch(out); len(m) == 2 {
			smtKey = strings.ToLower(m[1])
		}
	}
	r.add("submit (real admission → sequencer → builder)", fmt.Sprintf("seq=%d", seq), serr)
	if serr != nil {
		return 0, "", r, serr
	}

	// Wait for the cosigned horizon to cover the entry (builder commit + K-of-N
	// cosign lag the submission); a proof anchors on the horizon.
	werr := waitHorizon(cfg, seq+1, 90*time.Second)
	r.add("await cosigned horizon ≥ entry", fmt.Sprintf("tree_size ≥ %d", seq+1), werr)

	if cfg.LoadN > 0 {
		_, lerr := capture(func() error { return cli.RunLoad(ctx, []string{"-n", strconv.Itoa(cfg.LoadN)}) })
		r.add(fmt.Sprintf("load -n %d (streaming, memory-bounded)", cfg.LoadN), "", lerr)
	}
	return seq, smtKey, r, werr
}

// Run is the full platform e2e: WRITE a fresh entry through the real pipeline, then
// READ it back as a verifiable proof (incl. the builder's receipt_proof leg).
func Run(ctx context.Context, cfg Config) (*Result, error) {
	seq, smtKey, wr, err := WriteStages(ctx, cfg)
	if err != nil {
		return wr, err
	}
	rr, err := ReadStages(ctx, cfg, seq, smtKey)
	rr.Stages = append(wr.Stages, rr.Stages...)
	return rr, err
}

// activate authors a client bundle from the live ledger over HTTPS (server-verify
// via --ca-cert) and makes it the active network — the real `network add` path.
func activate(ctx context.Context, cfg Config) error {
	// Name LAST: networkAdd parses flags then takes the lone positional (Go's flag
	// package stops at the first non-flag token).
	args := []string{"add", "--from-ledger", cfg.LedgerURL, "--use"}
	if cfg.CAFile != "" {
		args = append(args, "--ca-cert", cfg.CAFile)
	}
	if cfg.LogDID != "" {
		args = append(args, "--log-did", cfg.LogDID)
	}
	return cli.RunNetwork(ctx, append(args, netName))
}

// waitHorizon polls the ledger's cosigned horizon over HTTPS until tree_size ≥ want
// or the timeout elapses.
func waitHorizon(cfg Config, want uint64, timeout time.Duration) error {
	hc, err := tlsClient(cfg.CAFile)
	if err != nil {
		return err
	}
	url := strings.TrimRight(cfg.LedgerURL, "/") + "/v1/tree/horizon"
	deadline := time.Now().Add(timeout)
	var last uint64
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			var h struct {
				TreeSize uint64 `json:"tree_size"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&h)
			_ = resp.Body.Close()
			last = h.TreeSize
			if h.TreeSize >= want {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("horizon never reached tree_size %d (last=%d) within %s", want, last, timeout)
}

// tlsClient builds an HTTPS client that pins caFile (server-verify, no client cert).
// An empty caFile uses the system roots.
func tlsClient(caFile string) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certs parsed from %s", caFile)
		}
		tc.RootCAs = pool
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

// capture redirects os.Stdout + os.Stderr for the duration of fn (the cli.RunX
// commands print there) and returns the combined output, so a stage can parse a
// command's output and the e2e log stays clean. The stage's pass/fail is the
// command's RETURNED error, never the captured text — so nothing is hidden.
func capture(fn func() error) (string, error) {
	oldOut, oldErr := os.Stdout, os.Stderr
	rp, wp, err := os.Pipe()
	if err != nil {
		return "", fn()
	}
	os.Stdout, os.Stderr = wp, wp
	runErr := fn()
	_ = wp.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	out, _ := io.ReadAll(rp)
	return string(out), runErr
}
