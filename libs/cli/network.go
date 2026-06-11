package cli

// network.go — `baseproof network` (add|list|use|show) and `baseproof config`
// (set network|list): gcloud-style active-network management, plus bundle
// AUTHORING — build a client bundle by introspecting a live ledger's
// /v1/network/* surface, so an operator can create a bundle, not only consume one.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baseproof/tooling/libs/clienttls"
)

// RunNetwork dispatches `baseproof network <subcommand>`.
func RunNetwork(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: baseproof network <add|list|use|show> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return networkAdd(ctx, rest)
	case "list":
		return networkList()
	case "use":
		return networkUse(rest)
	case "show":
		return networkShow(rest)
	default:
		return fmt.Errorf("network: unknown subcommand %q (add|list|use|show)", sub)
	}
}

// RunConfig dispatches `baseproof config set network <name>` and `config list`.
func RunConfig(ctx context.Context, args []string) error {
	switch {
	case len(args) == 3 && args[0] == "set" && args[1] == "network":
		return networkUse(args[2:])
	case len(args) == 1 && args[0] == "list":
		return configList()
	default:
		return fmt.Errorf("usage: baseproof config set network <name>  |  baseproof config list")
	}
}

func networkAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network add", flag.ContinueOnError)
	var (
		from       = fs.String("from", "", "import a client bundle from this file or URL")
		fromLedger = fs.String("from-ledger", "", "AUTHOR a bundle by introspecting this live ledger endpoint")
		caFile     = fs.String("ca-cert", "", "CA cert to pin (for --from-ledger HTTPS + the bundle's transport)")
		logDID     = fs.String("log-did", "", "log DID (--from-ledger; else taken from /v1/log-info)")
		use        = fs.Bool("use", false, "set this network active after adding")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: baseproof network add <name> [--from <file|url> | --from-ledger <endpoint>]")
	}
	name := rest[0]

	var (
		b   *ClientBundle
		err error
	)
	switch {
	case *fromLedger != "":
		b, err = authorBundleFromLedger(ctx, *fromLedger, *caFile, *logDID, *timeout)
	case *from != "":
		b, err = importBundle(ctx, *from, *timeout)
	default:
		return fmt.Errorf("network add: one of --from <file|url> or --from-ledger <endpoint> is required")
	}
	if err != nil {
		return err
	}
	if err := saveNetwork(name, b); err != nil {
		return err
	}
	fmt.Printf("network: added %q  (id %s, endpoint %s)\n", name, short(b.NetworkID), b.Endpoint)
	if *use {
		if err := setActiveNetwork(name); err != nil {
			return err
		}
		fmt.Printf("network: %q is now active\n", name)
	}
	return nil
}

func networkUse(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: baseproof network use <name>")
	}
	if err := setActiveNetwork(args[0]); err != nil {
		return err
	}
	fmt.Printf("network: %q is now active\n", args[0])
	return nil
}

func networkList() error {
	names, err := listNetworks()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Println("no networks — add one: baseproof network add <name> --from-ledger <url>")
		return nil
	}
	cfg, _ := loadConfig()
	for _, n := range names {
		mark := "  "
		if n == cfg.ActiveNetwork {
			mark = "* "
		}
		id, ep := "?", "?"
		if b, err := loadNetwork(n); err == nil {
			id, ep = short(b.NetworkID), b.Endpoint
		}
		fmt.Printf("%s%-16s %s  %s\n", mark, n, id, ep)
	}
	return nil
}

func networkShow(args []string) error {
	name := ""
	switch {
	case len(args) == 1:
		name = args[0]
	default:
		cfg, _ := loadConfig()
		name = cfg.ActiveNetwork
		if name == "" {
			return fmt.Errorf("no active network; usage: baseproof network show <name>")
		}
	}
	b, err := loadNetwork(name)
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	fmt.Println(string(data))
	return nil
}

func configList() error {
	cfg, _ := loadConfig()
	active := cfg.ActiveNetwork
	if active == "" {
		active = "(none)"
	}
	fmt.Printf("active network: %s\n", active)
	names, _ := listNetworks()
	fmt.Printf("networks: %s\n", strings.Join(names, ", "))
	return nil
}

// importBundle imports a client bundle from a file path or an http(s) URL.
func importBundle(ctx context.Context, from string, timeout time.Duration) (*ClientBundle, error) {
	if strings.HasPrefix(from, "http://") || strings.HasPrefix(from, "https://") {
		var b ClientBundle
		if err := getJSON(ctx, &http.Client{Timeout: timeout}, from, &b); err != nil {
			return nil, fmt.Errorf("download bundle %s: %w", from, err)
		}
		if err := b.validate(); err != nil {
			return nil, err
		}
		return &b, nil
	}
	return LoadClientBundle(from)
}

// authorBundleFromLedger builds a client bundle by introspecting a live ledger:
// it reads the network identity, CONFIRMS the served bootstrap hashes to the
// network id (the Zero-Trust "this endpoint is the network it claims" check), and
// records the log DID + federation peers. The witness quorum K comes from that
// verified constitution (doc.GenesisQuorumK, NetworkID-bound) — never from the
// operator, who could disagree with it. The operator supplies only the transport CA.
func authorBundleFromLedger(ctx context.Context, endpoint, caFile, logDID string, timeout time.Duration) (*ClientBundle, error) {
	endpoint = strings.TrimRight(endpoint, "/")
	f := clienttls.Flags{CAFile: caFile, AllowSelfSigned: caFile != ""}
	hc, _, err := f.Client(timeout)
	if err != nil {
		return nil, fmt.Errorf("build transport: %w", err)
	}

	var id struct {
		NetworkID     string `json:"network_id"`
		NetworkDID    string `json:"network_did"`
		BootstrapHash string `json:"bootstrap_hash"`
	}
	if err := getJSON(ctx, hc, endpoint+"/v1/network/identity", &id); err != nil {
		return nil, fmt.Errorf("fetch identity: %w", err)
	}
	if id.NetworkID == "" {
		return nil, fmt.Errorf("ledger %s returned no network id (not bootstrap-configured?)", endpoint)
	}
	// ZT: the served bootstrap MUST hash to the network id. The verified doc is
	// also the single source of the witness quorum K (GenesisQuorumK, rc4).
	doc, err := fetchBootstrap(ctx, hc, endpoint, id.NetworkID)
	if err != nil {
		return nil, err
	}

	if logDID == "" {
		var li struct {
			LogDID string `json:"log_did"`
		}
		_ = getJSONOptional(ctx, hc, endpoint+"/v1/log-info", &li)
		logDID = li.LogDID
	}

	var fed wireFederation
	_ = getJSONOptional(ctx, hc, endpoint+"/v1/network/peers", &fed)
	var federation []FederatedNet
	for _, s := range fed.Siblings {
		federation = append(federation, FederatedNet{NetworkID: s.NetworkID, Endpoint: s.AdmissionURL})
	}

	b := &ClientBundle{
		Format:        ClientBundleFormat,
		NetworkID:     id.NetworkID,
		Endpoint:      endpoint,
		LogDID:        logDID,
		QuorumK:       doc.GenesisQuorumK,
		BootstrapHash: id.NetworkID, // = SHA-256(canonical bootstrap)
		Transport:     Transport{CAFile: caFile, AllowSelfSigned: caFile != ""},
		Federation:    federation,
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}
