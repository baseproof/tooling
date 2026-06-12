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
	"os"
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
		return networkList(rest)
	case "use":
		return networkUse(rest)
	case "show":
		return networkShow(rest)
	case "remove":
		return networkRemove(rest)
	case "bundle":
		return runNetworkBundle(ctx, rest)
	case "rotation":
		return runNetworkRotation(ctx, rest)
	default:
		return fmt.Errorf("network: unknown subcommand %q (add|list|use|show|remove|bundle|rotation)", sub)
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
		repin      = fs.Bool("repin", false, "explicitly replace this name's pinned trust root if the offered network id differs (prints old → new; without it, a mismatch refuses)")
		pin        = fs.String("pin", "", "REQUIRE the added network's id to equal this 64-hex id (the out-of-band expected identity); first contact stops being trust-on-first-use")
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

	// Operator-supplied expected identity (--pin): the out-of-band check that
	// turns first contact from trust-on-first-use into verification. Checked
	// BEFORE anything is written, against whatever the source claimed.
	if *pin != "" {
		want := strings.ToLower(strings.TrimSpace(*pin))
		if len(want) != 64 || !isHex(want) {
			return fmt.Errorf("network add: --pin must be the 64-hex network id (got %q)", *pin)
		}
		if b.NetworkID != want {
			return fmt.Errorf("network add: the source claims network id %s but --pin expects %s — refusing first contact",
				short(b.NetworkID), short(want))
		}
	}

	// Trust-boundary moment: a known name may only ever mean ONE network.
	// The prior identity is the pin if one exists, else the already-stored
	// bundle's id (stores predating pins.json get the same protection). A
	// mismatch REFUSES before anything is written; --repin replaces the trust
	// root loudly. Same-identity re-adds are free: endpoints and TLS posture
	// refresh, the pin stands.
	pins, err := loadPins()
	if err != nil {
		return err
	}
	priorID := ""
	if pin, ok := pins[name]; ok {
		priorID = pin.NetworkID
	} else if old, lerr := loadNetwork(name); lerr == nil {
		priorID = old.NetworkID
	}
	switch {
	case priorID == "" || priorID == b.NetworkID:
		// first contact, or an identity-preserving refresh
	case *repin:
		fmt.Fprintf(os.Stderr, "network: REPINNING %q  %s → %s\n", name, short(priorID), short(b.NetworkID))
	default:
		return fmt.Errorf("network add: %q is pinned to network id %s, but the offered bundle claims %s — refusing: a different network is claiming a known name. If the identity change is genuine, re-run with --repin",
			name, short(priorID), short(b.NetworkID))
	}

	if err := saveNetwork(name, b); err != nil {
		return err
	}
	if pin, ok := pins[name]; !ok || pin.NetworkID != b.NetworkID {
		pins[name] = networkPin{NetworkID: b.NetworkID, BootstrapHash: b.BootstrapHash, AddedAt: time.Now().UTC().Format(time.RFC3339)}
		if err := savePins(pins); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "network: pinned %q to network id %s — verify this id out-of-band before trusting writes\n", name, b.NetworkID)
	}
	fmt.Fprintf(os.Stderr, "network: added %q  (id %s, endpoint %s)\n", name, short(b.NetworkID), b.Endpoint)
	if *use {
		if err := setActiveNetwork(name); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "network: %q is now active\n", name)
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
	fmt.Fprintf(os.Stderr, "network: %q is now active\n", args[0])
	return nil
}

// networkRemove deletes a stored network's BUNDLE — but the pin TOMBSTONES:
// the identity record survives removal, so re-adding the same name with a
// different network id still refuses. Otherwise remove+add would be a
// pin-reset side door around the --repin ceremony.
func networkRemove(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: baseproof network remove <name>")
	}
	name := args[0]
	p, err := networkFile(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("network remove: no stored network %q", name)
		}
		return fmt.Errorf("network remove: %w", err)
	}
	// A dangling active pointer would break every verb with a confusing
	// error; clear it loudly instead.
	if cfg, cErr := loadConfig(); cErr == nil && cfg.ActiveNetwork == name {
		if sErr := saveConfig(cliConfig{}); sErr != nil {
			return fmt.Errorf("network remove: clear active network: %w", sErr)
		}
		fmt.Fprintf(os.Stderr, "network: %q was the active network — no network is active now\n", name)
	}
	fmt.Fprintf(os.Stderr, "network: removed %q (its trust pin remains — re-adding this name with a DIFFERENT network id will refuse; use `network add --repin` if the identity change is genuine)\n", name)
	return nil
}

// isHex reports whether s is entirely lowercase hex digits.
func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// NetworkListEntry is one stored network in the list (kind "network-list").
type NetworkListEntry struct {
	Name      string `json:"name"`
	NetworkID string `json:"network_id,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	Pinned    bool   `json:"pinned"`
	Active    bool   `json:"active"`
	LoadError string `json:"load_error,omitempty"` // pin-mismatch / unreadable bundle, surfaced not hidden
}

// NetworkListData is the --output json data shape (kind "network-list").
type NetworkListData struct {
	Active   string             `json:"active,omitempty"`
	Networks []NetworkListEntry `json:"networks"`
}

func networkList(args []string) error {
	fs := flag.NewFlagSet("network list", flag.ContinueOnError)
	output := fs.String("output", "table", "output format: table|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names, err := listNetworks()
	if err != nil {
		return err
	}
	cfg, _ := loadConfig()
	pins, _ := loadPins()
	data := NetworkListData{Active: cfg.ActiveNetwork, Networks: []NetworkListEntry{}}
	for _, n := range names {
		e := NetworkListEntry{Name: n, Active: n == cfg.ActiveNetwork}
		if _, ok := pins[n]; ok {
			e.Pinned = true
		}
		if b, lerr := loadNetwork(n); lerr == nil {
			e.NetworkID, e.Endpoint = b.NetworkID, b.Endpoint
		} else {
			e.LoadError = lerr.Error()
		}
		data.Networks = append(data.Networks, e)
	}
	return emitOutput(*output, "network-list", data, func() error {
		if len(data.Networks) == 0 {
			fmt.Println("no networks — add one: baseproof network add <name> --from-ledger <url>")
			return nil
		}
		for _, e := range data.Networks {
			mark := "  "
			if e.Active {
				mark = "* "
			}
			id, ep := "?", "?"
			if e.LoadError == "" {
				id, ep = short(e.NetworkID), e.Endpoint
			}
			fmt.Printf("%s%-16s %s  %s\n", mark, e.Name, id, ep)
		}
		return nil
	})
}

// NetworkShowData is the --output json data shape (kind "network-show").
type NetworkShowData struct {
	Name         string        `json:"name"`
	Active       bool          `json:"active"`
	Pinned       bool          `json:"pinned"`
	PinNetworkID string        `json:"pin_network_id,omitempty"`
	Bundle       *ClientBundle `json:"bundle"`
}

func networkShow(args []string) error {
	fs := flag.NewFlagSet("network show", flag.ContinueOnError)
	output := fs.String("output", "table", "output format: table|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := ""
	switch {
	case fs.NArg() == 1:
		name = fs.Arg(0)
	case fs.NArg() == 0:
		cfg, _ := loadConfig()
		name = cfg.ActiveNetwork
		if name == "" {
			return fmt.Errorf("no active network; usage: baseproof network show <name>")
		}
	default:
		return fmt.Errorf("usage: baseproof network show [name]")
	}
	b, err := loadNetwork(name)
	if err != nil {
		return err
	}
	cfg, _ := loadConfig()
	pins, _ := loadPins()
	data := NetworkShowData{Name: name, Active: cfg.ActiveNetwork == name, Bundle: b}
	if pin, ok := pins[name]; ok {
		data.Pinned, data.PinNetworkID = true, pin.NetworkID
	}
	return emitOutput(*output, "network-show", data, func() error {
		out, _ := json.MarshalIndent(b, "", "  ")
		fmt.Println(string(out))
		return nil
	})
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
