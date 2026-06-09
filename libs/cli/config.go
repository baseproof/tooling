package cli

// config.go — the on-disk config + network store (gcloud-style):
//
//	~/.config/baseproof/
//	  config.json            { "active_network": "<name>" }
//	  networks/<name>.json   a ClientBundle
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
	return LoadClientBundle(p)
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
// file wins, then --network <name>, then the active network — the gcloud pattern
// (a per-command flag overrides the active default).
func resolveBundle(bundlePath, networkName string) (*ClientBundle, error) {
	if bundlePath != "" {
		return LoadClientBundle(bundlePath)
	}
	if networkName != "" {
		return loadNetwork(networkName)
	}
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if cfg.ActiveNetwork == "" {
		return nil, fmt.Errorf("no --bundle, no --network, and no active network — run `baseproof network add <name> ...` then `baseproof network use <name>`")
	}
	return loadNetwork(cfg.ActiveNetwork)
}
