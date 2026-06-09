package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The injection-resolution contract (resolveFile): explicit env wins VERBATIM
// (even if the file is absent — an explicit path must fail loudly downstream,
// never be silently substituted), else the first existing candidate (std mount
// path, then the PaaS /etc/secrets twin), else "".

func TestResolveFile_ExplicitEnvWinsVerbatim(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "present.pem")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_RESOLVE_FILE", "/absent/explicit.pem")
	if got := resolveFile("TEST_RESOLVE_FILE", existing); got != "/absent/explicit.pem" {
		t.Fatalf("explicit env must win verbatim; got %q", got)
	}
}

func TestResolveFile_FirstExistingCandidateWins(t *testing.T) {
	dir := t.TempDir()
	std := filepath.Join(dir, "std", "tls.crt")
	paas := filepath.Join(dir, "secrets", "tls.crt")
	for _, p := range []string{std, paas} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TEST_RESOLVE_FILE", "")
	if got := resolveFile("TEST_RESOLVE_FILE", std, paas); got != std {
		t.Fatalf("std path must win over the PaaS path; got %q", got)
	}
	if err := os.Remove(std); err != nil {
		t.Fatal(err)
	}
	if got := resolveFile("TEST_RESOLVE_FILE", std, paas); got != paas {
		t.Fatalf("absent std path must fall through to the PaaS path; got %q", got)
	}
}

func TestResolveFile_NoCandidate(t *testing.T) {
	t.Setenv("TEST_RESOLVE_FILE", "")
	if got := resolveFile("TEST_RESOLVE_FILE", filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Fatalf("no env, no file ⇒ unset; got %q", got)
	}
}

func TestResolveFile_DirectoryIsNotAFile(t *testing.T) {
	t.Setenv("TEST_RESOLVE_FILE", "")
	if got := resolveFile("TEST_RESOLVE_FILE", t.TempDir()); got != "" {
		t.Fatalf("a directory candidate must be skipped; got %q", got)
	}
}

// The PaaS listen contract (listenAddr): the service var wins; else a
// platform-injected PORT (Render/Cloud Run/Heroku) yields ":$PORT"; else the
// baked default.

func TestListenAddr_ServiceVarWinsOverPORT(t *testing.T) {
	t.Setenv("TEST_LISTEN_ADDR", ":9999")
	t.Setenv("PORT", "10000")
	if got := listenAddr("TEST_LISTEN_ADDR", ":8080"); got != ":9999" {
		t.Fatalf("service var must win over PORT; got %q", got)
	}
}

func TestListenAddr_PORTFallback(t *testing.T) {
	t.Setenv("TEST_LISTEN_ADDR", "")
	t.Setenv("PORT", "10000")
	if got := listenAddr("TEST_LISTEN_ADDR", ":8080"); got != ":10000" {
		t.Fatalf("unset service var + PORT must yield :$PORT; got %q", got)
	}
}

func TestListenAddr_Default(t *testing.T) {
	t.Setenv("TEST_LISTEN_ADDR", "")
	t.Setenv("PORT", "")
	if got := listenAddr("TEST_LISTEN_ADDR", ":8080"); got != ":8080" {
		t.Fatalf("neither set ⇒ default; got %q", got)
	}
}
