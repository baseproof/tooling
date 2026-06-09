package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The injection-resolution contract: an explicit AUDITOR_* value wins VERBATIM,
// else the first existing candidate (std mount path, then the PaaS
// /etc/secrets twin), else "".

func TestResolveFile_ExplicitWinsVerbatim(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "bootstrap.json")
	if err := os.WriteFile(existing, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveFile("/absent/explicit.json", existing); got != "/absent/explicit.json" {
		t.Fatalf("explicit value must win verbatim; got %q", got)
	}
}

func TestResolveFile_CandidateOrder(t *testing.T) {
	dir := t.TempDir()
	std := filepath.Join(dir, "std", "bootstrap.json")
	paas := filepath.Join(dir, "secrets", "bootstrap.json")
	for _, p := range []string{std, paas} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := resolveFile("", std, paas); got != std {
		t.Fatalf("std path must win; got %q", got)
	}
	if err := os.Remove(std); err != nil {
		t.Fatal(err)
	}
	if got := resolveFile("", std, paas); got != paas {
		t.Fatalf("must fall through to the PaaS path; got %q", got)
	}
	if err := os.Remove(paas); err != nil {
		t.Fatal(err)
	}
	if got := resolveFile("", std, paas); got != "" {
		t.Fatalf("no candidate ⇒ unset; got %q", got)
	}
}

// The PaaS listen contract: a platform-injected PORT yields ":$PORT" only when
// AUDITOR_LISTEN_ADDR is unset.

func TestPortAddrOr(t *testing.T) {
	t.Setenv("PORT", "10000")
	if got := portAddrOr(":8088"); got != ":10000" {
		t.Fatalf("PORT set ⇒ :$PORT; got %q", got)
	}
	t.Setenv("PORT", "")
	if got := portAddrOr(":8088"); got != ":8088" {
		t.Fatalf("PORT unset ⇒ fallback; got %q", got)
	}
}
