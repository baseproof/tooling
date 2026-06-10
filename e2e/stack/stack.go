// Package stack brings up the real tooling fleet in docker — postgres + seaweedfs
// (S3 byte store) + witness + ledger (HTTPS) + auditor — and tears it down. The
// container wiring mirrors the judicial-network e2e's proven config (services.go),
// adapted to the tooling-only fleet (no JN/aggregator) and an HTTPS ledger with a
// self-signed run CA (certs.go). The genesis bootstrap + witness key are minted by
// the ledger's own cmd/init-network (reused, not reinvented); the ledger serves
// OPEN HTTPS (server cert, no client CA — reads open, writes gated by in-body
// crypto), which the libs runner pins via --ca-cert.
//
// Build returns a Manifest the runner drives. Build/Wipe shell out through dockerx;
// they run wherever a docker daemon is reachable.
package stack

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/baseproof/tooling/e2e/dockerx"
)

const (
	pgUser = "baseproof"
	pgPass = "baseproof"
	pgRoot = "postgres"
	dbName = "baseproof_e2e"
	auditDB = "baseproof_e2e_gossip"
	bucket  = "e2e-entries"

	mntKeys  = "/keys"  // fixtures: network-bootstrap.json + witnesses/*.pem
	mntCerts = "/certs" // TLS: ca.crt, server.crt, server.key
)

// Config parameterises a single-network fleet.
type Config struct {
	RunID    string // short id; container/network names derive from it
	RepoRoot string // tooling repo root (for cmd/init-network + Dockerfiles); auto-detected if empty
	WorkDir  string // host scratch for fixtures + certs (bind-mounted); a temp dir if empty
	LogDID   string
	QuorumK  int

	LedgerPort  int // host → ledger :8080 (HTTPS)
	AuditorPort int // host → auditor :8088
	SeaweedPort int // host → seaweed :8333 (shipped-entry redirects)

	// Images. Default: pull the published fleet; set BuildImages to build the
	// ledger/witness/auditor from the local Dockerfiles (the code under test).
	BuildImages   bool
	LedgerImage   string
	WitnessImage  string
	AuditorImage  string
	PostgresImage string
	SeaweedImage  string
}

func (c *Config) defaults() {
	if c.RunID == "" {
		c.RunID = "e2e"
	}
	if c.LogDID == "" {
		c.LogDID = "did:baseproof:ledger:e2e"
	}
	if c.QuorumK == 0 {
		c.QuorumK = 1
	}
	if c.LedgerPort == 0 {
		c.LedgerPort = 8443
	}
	if c.AuditorPort == 0 {
		c.AuditorPort = 8088
	}
	if c.SeaweedPort == 0 {
		c.SeaweedPort = 8333
	}
	if c.LedgerImage == "" {
		c.LedgerImage = "ghcr.io/baseproof/tooling/ledger:latest"
	}
	if c.WitnessImage == "" {
		c.WitnessImage = "ghcr.io/baseproof/tooling/witness:latest"
	}
	if c.AuditorImage == "" {
		c.AuditorImage = "ghcr.io/baseproof/tooling/auditor:latest"
	}
	if c.PostgresImage == "" {
		c.PostgresImage = "postgres:16-alpine"
	}
	if c.SeaweedImage == "" {
		c.SeaweedImage = "chrislusf/seaweedfs:latest"
	}
}

func (c Config) net() string         { return "baseproof-" + c.RunID }
func (c Config) name(s string) string { return "baseproof-" + c.RunID + "-" + s }

// Manifest is the live fleet the runner drives.
type Manifest struct {
	LedgerURL  string
	AuditorURL string
	CAPath     string
	NetworkID  string
	LogDID     string
	QuorumK    int
	Containers []string
}

// Build brings up the fleet and returns its Manifest. On any step failure the
// partially-built fleet is left UP for log inspection (docker logs <name>).
func Build(cfg Config) (*Manifest, error) {
	cfg.defaults()
	if !dockerx.DaemonOK() {
		return nil, fmt.Errorf("docker daemon not reachable")
	}
	root, err := resolveRoot(cfg.RepoRoot)
	if err != nil {
		return nil, err
	}
	work := cfg.WorkDir
	if work == "" {
		if work, err = os.MkdirTemp("", "e2e-stack-"); err != nil {
			return nil, err
		}
	}
	fixtures := filepath.Join(work, "fixtures")
	certs := filepath.Join(work, "certs")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		return nil, err
	}

	// 1. Genesis fixtures via the ledger's own init-network (bootstrap + witness key).
	if err := initNetwork(root, fixtures, cfg); err != nil {
		return nil, fmt.Errorf("init-network: %w", err)
	}
	netID, err := networkIDFromBootstrap(filepath.Join(fixtures, "network-bootstrap.json"))
	if err != nil {
		return nil, err
	}

	// 2. Self-signed run CA + ledger server cert (SANs: in-network DNS + host).
	if err := MintCerts(certs, []string{cfg.name("ledger"), "localhost", "127.0.0.1"}); err != nil {
		return nil, fmt.Errorf("mint certs: %w", err)
	}

	// 3. Images: build from source, or rely on the published/pulled fleet.
	if cfg.BuildImages {
		if err := buildImages(root, cfg); err != nil {
			return nil, err
		}
	}

	// 4. Network + infra + services.
	dockerx.NetworkCreate(cfg.net())
	if err := upPostgres(cfg); err != nil {
		return nil, err
	}
	if err := upSeaweed(cfg); err != nil {
		return nil, err
	}
	if err := upWitness(cfg, fixtures); err != nil {
		return nil, err
	}
	if err := upLedger(cfg, fixtures, certs); err != nil {
		return nil, err
	}
	if err := upAuditor(cfg, fixtures, certs); err != nil {
		return nil, err
	}

	return &Manifest{
		LedgerURL:  fmt.Sprintf("https://localhost:%d", cfg.LedgerPort),
		AuditorURL: fmt.Sprintf("http://localhost:%d", cfg.AuditorPort),
		CAPath:     filepath.Join(certs, "ca.crt"),
		NetworkID:  netID,
		LogDID:     cfg.LogDID,
		QuorumK:    cfg.QuorumK,
		Containers: []string{cfg.name("postgres"), cfg.name("seaweedfs"), cfg.name("witness"), cfg.name("ledger"), cfg.name("auditor")},
	}, nil
}

// Wipe force-removes the fleet's containers + network (best-effort).
func Wipe(cfg Config) {
	cfg.defaults()
	dockerx.Remove(cfg.name("auditor"), cfg.name("ledger"), cfg.name("witness"), cfg.name("seaweedfs"), cfg.name("postgres"))
	dockerx.NetworkRemove(cfg.net())
}

// ── steps ───────────────────────────────────────────────────────────────────

func initNetwork(root, fixtures string, cfg Config) error {
	cmd := exec.Command("go", "run", "./cmd/init-network",
		"-out-dir", fixtures,
		"-out-bootstrap", filepath.Join(fixtures, "network-bootstrap.json"),
		"-log-did", cfg.LogDID,
		"-network-name", "e2e-"+cfg.RunID,
		"-witnesses", "1",
	)
	cmd.Dir = filepath.Join(root, "services", "ledger")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func upPostgres(cfg Config) error {
	if r := dockerx.Run(dockerx.RunSpec{
		Name: cfg.name("postgres"), Network: cfg.net(), Image: cfg.PostgresImage, Detached: true,
		Env:       map[string]string{"POSTGRES_USER": pgUser, "POSTGRES_PASSWORD": pgPass, "POSTGRES_DB": pgRoot},
		ImageArgs: []string{"-c", "fsync=off", "-c", "synchronous_commit=off"},
	}); !r.OK() {
		return fmt.Errorf("postgres run: %s", tail(r.Stderr))
	}
	if !dockerx.Poll(120*time.Second, func() bool { return dockerx.PGReady(cfg.name("postgres"), pgUser, pgRoot) }) {
		return fmt.Errorf("postgres never became ready")
	}
	dockerx.CreateDB(cfg.name("postgres"), pgUser, dbName)
	dockerx.CreateDB(cfg.name("postgres"), pgUser, auditDB)
	return nil
}

func upSeaweed(cfg Config) error {
	if r := dockerx.Run(dockerx.RunSpec{
		Name: cfg.name("seaweedfs"), Network: cfg.net(), Image: cfg.SeaweedImage, Detached: true,
		Ports:     []dockerx.Port{{Host: cfg.SeaweedPort, Container: 8333}},
		ImageArgs: []string{"server", "-s3", "-s3.port=8333", "-s3.allowEmptyFolder=true", "-ip.bind=0.0.0.0"},
	}); !r.OK() {
		return fmt.Errorf("seaweedfs run: %s", tail(r.Stderr))
	}
	if !dockerx.Poll(120*time.Second, func() bool {
		return dockerx.Exec(cfg.name("seaweedfs"), []string{"wget", "-q", "--spider", "http://localhost:9333/cluster/status"}, false).OK()
	}) {
		return fmt.Errorf("seaweedfs never became ready")
	}
	// Create the bucket (best-effort; the ledger's first write also creates it).
	dockerx.Run(dockerx.RunSpec{
		Network: cfg.net(), Image: cfg.SeaweedImage, Remove: true, Entrypoint: "/bin/sh",
		ImageArgs: []string{"-c", fmt.Sprintf("sleep 2; echo 's3.bucket.create -name %s' | weed shell -master %s:9333", bucket, cfg.name("seaweedfs"))},
	})
	return nil
}

func upWitness(cfg Config, fixtures string) error {
	name := cfg.name("witness")
	if r := dockerx.Run(dockerx.RunSpec{
		Name: name, Network: cfg.net(), Image: cfg.WitnessImage, Detached: true,
		Mounts: []dockerx.Mount{{Host: fixtures, Container: mntKeys + ":ro"}},
		ImageArgs: []string{
			"-addr=:8081",
			"-key-file=" + mntKeys + "/witnesses/witness-1.pem",
			"-bootstrap=" + mntKeys + "/network-bootstrap.json",
		},
	}); !r.OK() {
		return fmt.Errorf("witness run: %s", tail(r.Stderr))
	}
	if !dockerx.Poll(60*time.Second, func() bool {
		return dockerx.Exec(name, []string{"wget", "-q", "-O-", "http://localhost:8081/healthz"}, false).OK()
	}) {
		return fmt.Errorf("witness never became healthy")
	}
	return nil
}

func upLedger(cfg Config, fixtures, certs string) error {
	envm := map[string]string{
		"LEDGER_LOG_DID":                    cfg.LogDID,
		"LEDGER_ADDR":                       ":8080",
		"LEDGER_DATABASE_URL":               dsn(cfg.name("postgres"), dbName),
		"LEDGER_BYTE_STORE_BACKEND":         "s3",
		"LEDGER_BYTE_STORE_S3_ENDPOINT":     "http://" + cfg.name("seaweedfs") + ":8333",
		"LEDGER_BYTE_STORE_PUBLIC_BASE_URL": fmt.Sprintf("http://localhost:%d/%s", cfg.SeaweedPort, bucket),
		"LEDGER_BYTE_STORE_S3_BUCKET":       bucket,
		"LEDGER_BYTE_STORE_S3_REGION":       "us-east-1",
		"LEDGER_BYTE_STORE_S3_ACCESS_KEY":   "any",
		"LEDGER_BYTE_STORE_S3_SECRET_KEY":   "any",
		"LEDGER_BYTE_STORE_S3_PATH_STYLE":   "true",
		"LEDGER_WITNESS_ENDPOINTS":          "http://" + cfg.name("witness") + ":8081",
		"LEDGER_WITNESS_QUORUM_K":           strconv.Itoa(cfg.QuorumK),
		"LEDGER_NETWORK_BOOTSTRAP_FILE":     mntKeys + "/network-bootstrap.json",
		"LEDGER_TESSERA_STORAGE_DIR":        "/var/lib/baseproof/tessera",
		"LEDGER_WAL_PATH":                   "/var/lib/baseproof/wal",
		"LEDGER_TESSERA_ANTISPAM_PATH":      "/var/lib/baseproof/tessera-antispam",
		"LEDGER_SMT_TILE_EMIT_DIR":          "/var/lib/baseproof/tiles",
		// OPEN HTTPS: present a server cert (SAN covers localhost + the container
		// name), set NO inbound client CA — reads open, writes gated by in-body crypto.
		"LEDGER_TLS_CERT_FILE": mntCerts + "/server.crt",
		"LEDGER_TLS_KEY_FILE":  mntCerts + "/server.key",
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: cfg.name("ledger"), Network: cfg.net(), Image: cfg.LedgerImage, Detached: true,
		Env:   envm,
		Ports: []dockerx.Port{{Host: cfg.LedgerPort, Container: 8080}},
		Mounts: []dockerx.Mount{
			{Host: fixtures, Container: mntKeys + ":ro"},
			{Host: certs, Container: mntCerts + ":ro"},
		},
	}); !r.OK() {
		return fmt.Errorf("ledger run: %s", tail(r.Stderr))
	}
	if !dockerx.Poll(120*time.Second, func() bool {
		return httpsHealthy(filepath.Join(certs, "ca.crt"), fmt.Sprintf("https://localhost:%d/healthz", cfg.LedgerPort))
	}) {
		return fmt.Errorf("ledger open-HTTPS /healthz never == ok (docker logs %s)", cfg.name("ledger"))
	}
	return nil
}

func upAuditor(cfg Config, fixtures, certs string) error {
	envm := map[string]string{
		"AUDITOR_LISTEN_ADDR":            ":8088",
		"AUDITOR_GOSSIP_DSN":             dsn(cfg.name("postgres"), auditDB),
		"AUDITOR_NETWORK_BOOTSTRAP_FILE": mntKeys + "/network-bootstrap.json",
		"AUDITOR_WITNESS_QUORUM_K":       strconv.Itoa(cfg.QuorumK),
		"AUDITOR_ORIGINATOR_DISCOVERY":   "true",
		"AUDITOR_PEERS":                  cfg.LogDID + "=https://" + cfg.name("ledger") + ":8080",
		"AUDITOR_PEER_CA_FILE":           mntCerts + "/ca.crt",
		"AUDITOR_PEER_ALLOW_SELF_SIGNED": "true",
	}
	if r := dockerx.Run(dockerx.RunSpec{
		Name: cfg.name("auditor"), Network: cfg.net(), Image: cfg.AuditorImage, Detached: true,
		Env:   envm,
		Ports: []dockerx.Port{{Host: cfg.AuditorPort, Container: 8088}},
		Mounts: []dockerx.Mount{
			{Host: fixtures, Container: mntKeys + ":ro"},
			{Host: certs, Container: mntCerts + ":ro"},
		},
	}); !r.OK() {
		return fmt.Errorf("auditor run: %s", tail(r.Stderr))
	}
	if !dockerx.Poll(120*time.Second, func() bool {
		return httpStatus(fmt.Sprintf("http://localhost:%d/readyz", cfg.AuditorPort)) == 200
	}) {
		return fmt.Errorf("auditor /readyz never == 200 (docker logs %s)", cfg.name("auditor"))
	}
	return nil
}

func buildImages(root string, cfg Config) error {
	type img struct{ tag, dockerfile, ctx string }
	for _, b := range []img{
		{cfg.LedgerImage, filepath.Join(root, "services/ledger/scripts/local/Dockerfile"), root},
		{cfg.WitnessImage, filepath.Join(root, "services/witness/Dockerfile"), filepath.Join(root, "services/witness")},
		{cfg.AuditorImage, filepath.Join(root, "services/auditor/Dockerfile"), filepath.Join(root, "services/auditor")},
	} {
		fmt.Printf("== build %s ==\n", b.tag)
		if err := dockerx.Build(dockerx.BuildSpec{Tag: b.tag, Dockerfile: b.dockerfile, Context: b.ctx}); err != nil {
			return fmt.Errorf("build %s: %w", b.tag, err)
		}
	}
	return nil
}
