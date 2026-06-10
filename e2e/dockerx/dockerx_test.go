package dockerx

import (
	"strings"
	"testing"
)

// TestRunArgv pins the `docker run` argv shape the stack relies on: detached,
// named, networked, host-loopback port publish, ro mounts, sorted -e env, then
// image + args. (The bring-up can't run here without a daemon; the argv can.)
func TestRunArgv(t *testing.T) {
	got := RunArgv(RunSpec{
		Name: "baseproof-e2e-ledger", Network: "baseproof-e2e", Image: "img:tag", Detached: true,
		Env:    map[string]string{"B": "2", "A": "1"},
		Ports:  []Port{{Host: 8443, Container: 8080}},
		Mounts: []Mount{{Host: "/keys", Container: "/keys:ro"}},
		ImageArgs: []string{"-addr=:8080"},
	})
	s := strings.Join(got, " ")
	for _, want := range []string{
		"docker run -d", "--name baseproof-e2e-ledger", "--network baseproof-e2e",
		"-p 127.0.0.1:8443:8080", "-v /keys:/keys:ro", "-e A=1 -e B=2", "img:tag -addr=:8080",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("argv missing %q\n got: %s", want, s)
		}
	}
	// env keys MUST be sorted (A before B) for determinism.
	if strings.Index(s, "-e A=1") > strings.Index(s, "-e B=2") {
		t.Errorf("env not sorted: %s", s)
	}
}

// TestBuildArgv pins the `docker build` argv (BuildKit-driven image builds).
func TestBuildArgv(t *testing.T) {
	got := strings.Join(BuildArgv(BuildSpec{Tag: "t:1", Dockerfile: "/d/Dockerfile", Context: "/ctx"}), " ")
	for _, want := range []string{"docker build", "-f /d/Dockerfile", "-t t:1", "/ctx"} {
		if !strings.Contains(got, want) {
			t.Errorf("build argv missing %q: %s", want, got)
		}
	}
}
