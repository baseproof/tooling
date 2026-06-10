// Package dockerx is the only layer that shells out to the `docker` CLI.
//
// Each command's argv is built by a pure function (testable without a daemon);
// thin wrappers execute it. Ported from the judicial-network e2e (proven against
// the same tooling fleet), trimmed to what the tooling platform e2e needs.
package dockerx

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Mount is a -v host:container bind.
type Mount struct{ Host, Container string }

// Port is a -p host:container publish.
type Port struct{ Host, Container int }

// RunSpec describes a `docker run`.
type RunSpec struct {
	Name       string
	Network    string
	Image      string
	Env        map[string]string
	Ports      []Port
	Mounts     []Mount
	User       string
	Entrypoint string
	ImageArgs  []string
	Detached   bool
	Remove     bool
}

// Result is a captured command outcome.
type Result struct {
	Code   int
	Stdout string
	Stderr string
}

// OK reports a zero exit.
func (r Result) OK() bool { return r.Code == 0 }

func run(argv []string) Result {
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
			errb.WriteString(err.Error())
		}
	}
	return Result{Code: code, Stdout: out.String(), Stderr: errb.String()}
}

// runArgv builds the argv for a `docker run`. Env keys are sorted for determinism.
func runArgv(s RunSpec) []string {
	a := []string{"docker", "run"}
	if s.Detached {
		a = append(a, "-d")
	}
	if s.Remove {
		a = append(a, "--rm")
	}
	if s.Name != "" {
		a = append(a, "--name", s.Name)
	}
	if s.Network != "" {
		a = append(a, "--network", s.Network)
	}
	if s.User != "" {
		a = append(a, "--user", s.User)
	}
	if s.Entrypoint != "" {
		a = append(a, "--entrypoint", s.Entrypoint)
	}
	for _, p := range s.Ports {
		a = append(a, "-p", fmt.Sprintf("127.0.0.1:%d:%d", p.Host, p.Container))
	}
	for _, m := range s.Mounts {
		a = append(a, "-v", m.Host+":"+m.Container)
	}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "-e", k+"="+s.Env[k])
	}
	a = append(a, s.Image)
	a = append(a, s.ImageArgs...)
	return a
}

// Run executes a RunSpec.
func Run(s RunSpec) Result { return run(runArgv(s)) }

// RunArgv exposes the pure argv builder (for tests).
func RunArgv(s RunSpec) []string { return runArgv(s) }

func execArgv(name string, argv []string, root bool) []string {
	a := []string{"docker", "exec"}
	if root {
		a = append(a, "-u", "0")
	}
	a = append(a, name)
	return append(a, argv...)
}

// Exec runs `docker exec` against a container.
func Exec(name string, argv []string, root bool) Result { return run(execArgv(name, argv, root)) }

// DaemonOK reports whether the docker daemon is reachable.
func DaemonOK() bool { return run([]string{"docker", "info"}).OK() }

// ImagePresent reports whether an image exists locally.
func ImagePresent(img string) bool { return run([]string{"docker", "image", "inspect", img}).OK() }

// BuildSpec describes a `docker build`. Used to build the tooling fleet images
// (ledger/witness/auditor) from the LOCAL working tree so the e2e exercises the
// code under test, never a stale published image.
type BuildSpec struct {
	Tag        string
	Dockerfile string
	Context    string
	BuildArgs  map[string]string
}

func buildArgv(s BuildSpec) []string {
	a := []string{"docker", "build", "-f", s.Dockerfile, "-t", s.Tag}
	keys := make([]string, 0, len(s.BuildArgs))
	for k := range s.BuildArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "--build-arg", k+"="+s.BuildArgs[k])
	}
	return append(a, s.Context)
}

// BuildArgv exposes the pure argv builder (for tests).
func BuildArgv(s BuildSpec) []string { return buildArgv(s) }

// Build runs `docker build`, streaming progress to stdout/stderr (a multi-stage
// Go build is slow; the operator wants live output). BuildKit is forced on.
func Build(s BuildSpec) error {
	argv := buildArgv(s)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// NetworkCreate / NetworkRemove manage the run's docker network (best-effort).
func NetworkCreate(net string) { _ = run([]string{"docker", "network", "create", net}) }
func NetworkRemove(net string) { _ = run([]string{"docker", "network", "rm", net}) }

// Remove force-removes containers (best-effort).
func Remove(names ...string) {
	if len(names) == 0 {
		return
	}
	_ = run(append([]string{"docker", "rm", "-f", "-v"}, names...))
}

// Logs returns a container's combined stdout+stderr.
func Logs(name string) string {
	r := run([]string{"docker", "logs", name})
	return r.Stdout + r.Stderr
}

// LogCount counts occurrences of substr in a container's logs.
func LogCount(name, substr string) int { return strings.Count(Logs(name), substr) }

// PGReady reports whether postgres in container `name` answers pg_isready.
func PGReady(name, user, db string) bool {
	return Exec(name, []string{"pg_isready", "-U", user, "-d", db}, false).OK()
}

// CreateDB creates a database (idempotent; already-exists ignored).
func CreateDB(pg, user, db string) { Exec(pg, []string{"createdb", "-U", user, db}, false) }

// Poll calls fn every second until it returns true or the timeout elapses.
func Poll(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if fn() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}
