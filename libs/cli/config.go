package cli

// config.go — the on-disk config + network store (gcloud-style):
//
//	~/.config/baseproof/
//	  config.json            { "active_network": "<name>" }
//	  networks/<name>.json   a ClientBundle (mutable: endpoints, TLS posture)
//	  pins.json              { "<name>": { network_id, … } } — the TRUST ROOT
//
// pins.json deliberately lives OUTSIDE the bundle files: the bundle is the
// mutable half (where to dial), the pin is the identity half (which network
// this name means), recorded once at first contact and changed only by an
// explicit --repin. Every load re-checks bundle vs pin, so neither a refresh
// nor on-disk tampering can quietly point a known name at a different network.
//
// The directory is $BASEPROOF_CONFIG_DIR, else $XDG_CONFIG_HOME/baseproof, else
// ~/.config/baseproof — so tests point it at a temp dir.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// configHome returns the baseproof config directory.
func configHome() (string, error) {
	if d := os.Getenv("BASEPROOF_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "baseproof"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: locate home dir: %w", err)
	}
	return filepath.Join(home, ".config", "baseproof"), nil
}

type cliConfig struct {
	ActiveNetwork string `json:"active_network,omitempty"`
}

func loadConfig() (cliConfig, error) {
	var c cliConfig
	h, err := configHome()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(filepath.Join(h, "config.json"))
	if os.IsNotExist(err) {
		return c, nil // no config yet — empty is valid
	}
	if err != nil {
		return c, fmt.Errorf("config: read: %w", err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("config: parse: %w", err)
	}
	return c, nil
}

func saveConfig(c cliConfig) error {
	h, err := configHome()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", h, err)
	}
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(h, "config.json"), append(data, '\n'), 0o600)
}

func networksDir() (string, error) {
	h, err := configHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "networks"), nil
}

// networkFile resolves networks/<name>.json, rejecting names that would escape
// the directory.
func networkFile(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\.`) {
		return "", fmt.Errorf("config: invalid network name %q (no slashes or dots)", name)
	}
	d, err := networksDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name+".json"), nil
}

func saveNetwork(name string, b *ClientBundle) error {
	d, err := networksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	p, err := networkFile(name)
	if err != nil {
		return err
	}
	b.Format = ClientBundleFormat
	data, _ := json.MarshalIndent(b, "", "  ")
	return os.WriteFile(p, append(data, '\n'), 0o600)
}

func loadNetwork(name string) (*ClientBundle, error) {
	p, err := networkFile(name)
	if err != nil {
		return nil, err
	}
	b, err := LoadClientBundle(p)
	if err != nil {
		return nil, err
	}
	// The pin is authoritative over the mutable bundle file: a stored bundle
	// whose identity drifted from the pin (overwritten, tampered, restored from
	// the wrong backup) is refused everywhere, not just at add time.
	pins, err := loadPins()
	if err != nil {
		return nil, err
	}
	if pin, ok := pins[name]; ok && pin.NetworkID != b.NetworkID {
		return nil, fmt.Errorf("network %q: stored bundle claims network id %s but the name is pinned to %s — the bundle changed underneath its trust root; if the identity change is genuine, re-add with `baseproof network add %s --from … --repin`",
			name, short(b.NetworkID), short(pin.NetworkID), name)
	}
	return b, nil
}

// ── trust pins ──────────────────────────────────────────────────────

// networkPin is the write-once identity record for a stored network name.
type networkPin struct {
	NetworkID     string `json:"network_id"`
	BootstrapHash string `json:"bootstrap_hash,omitempty"`
	AddedAt       string `json:"added_at,omitempty"` // RFC3339; informational
}

func pinsFile() (string, error) {
	h, err := configHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "pins.json"), nil
}

// loadPins returns the name→pin map; a missing file is an empty map (a store
// predating pins keeps working — names get pinned on their next add).
func loadPins() (map[string]networkPin, error) {
	p, err := pinsFile()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return map[string]networkPin{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: read pins: %w", err)
	}
	pins := map[string]networkPin{}
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("config: parse pins: %w", err)
	}
	return pins, nil
}

func savePins(pins map[string]networkPin) error {
	h, err := configHome()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", h, err)
	}
	p, err := pinsFile()
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(pins, "", "  ")
	return os.WriteFile(p, append(data, '\n'), 0o600)
}

func listNetworks() ([]string, error) {
	d, err := networksDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// setActiveNetwork marks name active after confirming it is stored + loadable.
func setActiveNetwork(name string) error {
	if _, err := loadNetwork(name); err != nil {
		return fmt.Errorf("network %q not found (add it first): %w", name, err)
	}
	return saveConfig(cliConfig{ActiveNetwork: name})
}

// resolveBundle resolves the network bundle a command uses: an explicit --bundle
// file wins, then --network <name>, then $BASEPROOF_NETWORK, then the active
// network — the gcloud pattern (a per-command flag overrides the env, which
// overrides the stored default).
func resolveBundle(bundlePath, networkName string) (*ClientBundle, error) {
	if bundlePath != "" {
		return LoadClientBundle(bundlePath)
	}
	if networkName != "" {
		return loadNetwork(networkName)
	}
	if env := os.Getenv("BASEPROOF_NETWORK"); env != "" {
		return loadNetwork(env)
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.ActiveNetwork == "" {
		return nil, fmt.Errorf("no --bundle, no --network, no $BASEPROOF_NETWORK, and no active network — run `baseproof network add <name> ...` then `baseproof network use <name>`")
	}
	return loadNetwork(cfg.ActiveNetwork)
}
