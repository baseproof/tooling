/*
FILE PATH: tests/dockerfile_roster_test.go

The image-roster census guard.

scripts/local/Dockerfile hardcodes the `./cmd/<tool>` roster it builds into the
fleet image. That roster is a CONSUMER of the cmd/ tree, and it drifts silently:
renaming or superseding a tool passes every Go build and only fails an hour
later in the docker-image CI job ("stat /src/cmd/<old>: directory not found") —
exactly how the init-network→genesis-ceremony supersession was caught. Per the
census rule (a landed rename is not done until every consumer is proven moved,
with a guard against re-drift), this pins the contract at T0: every cmd path the
Dockerfile builds must exist in the tree. No docker, no DSN, no network.
*/
package tests

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestDockerfile_BuildsOnlyExistingCmds(t *testing.T) {
	const dockerfile = "../scripts/local/Dockerfile"
	raw, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("read %s: %v", dockerfile, err)
	}

	re := regexp.MustCompile(`\./cmd/([a-zA-Z0-9_-]+)`)
	matches := re.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("Dockerfile names no ./cmd/<tool> paths — the roster regex or the file moved")
	}

	seen := map[string]bool{}
	for _, m := range matches {
		tool := m[1]
		if seen[tool] {
			continue
		}
		seen[tool] = true
		dir := filepath.Join("..", "cmd", tool)
		if fi, statErr := os.Stat(dir); statErr != nil || !fi.IsDir() {
			t.Errorf("Dockerfile builds ./cmd/%s but %s does not exist — a renamed/superseded tool left a stale roster entry (this is the drift the docker-image CI job otherwise catches an hour late)", tool, dir)
		}
	}
}
