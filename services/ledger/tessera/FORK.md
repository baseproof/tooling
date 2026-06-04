# Choosing the Tessera implementation

The ledger embeds Tessera in-process (`tessera/embedded_appender.go`) and imports
it as `github.com/transparency-dev/tessera`. Two implementations are supported,
selected **at build time** with no source changes:

| | Module | Shutdown behaviour |
|---|---|---|
| **Fork (default)** | `github.com/baseproof/tessera`, released as **baseproof `v1.0.2-bp.1`** (the `third_party/tessera` submodule, linked by the committed `go.work`) | **deterministic**: drain, cancel, and **join** every background goroutine (`Appender.Shutdown`, transparency-dev#341) |
| **Upstream** | Google-published `github.com/transparency-dev/tessera` (pinned in `go.mod`) | best-effort: drain in-flight Adds, cancel, then wait out `DrainBudget` (no goroutine join) |

The ledger source is byte-identical for both. At construction,
`EmbeddedAppender` **fingerprints** whichever Tessera is linked — it asserts the
appender against the `forkShutdowner` interface (`Shutdown(context.Context) error`) —
and resolves a single teardown strategy once (`resolveTeardown`). `Close` just
calls it; there is no version branching elsewhere. `DeterministicShutdown()`
reports the resolved choice for logs, metrics, and tests.

## Default: the baseproof fork

The committed `go.work` links the submodule (`use ./third_party/tessera`), so
every `go build` / `go test` and the release image resolve
`github.com/transparency-dev/tessera` to the fork. **The submodule must be
present** — a fresh clone needs it initialized before any build:

```sh
git submodule update --init third_party/tessera   # or: git clone --recurse-submodules
make tessera-which                                # prints FORK or UPSTREAM
go build ./...                                    # links third_party/tessera (the fork)
```

CI checks the submodule out (`submodules: recursive`) and the release image
(`scripts/local/Dockerfile`, default `TESSERA_VARIANT=fork`) builds it. The
toggle never edits `go.mod` / `go.sum`.

## Opt out to Google upstream

```sh
GOWORK=off go build ./...   # one-shot: ignore the workspace -> the go.mod pin
# …or, to flip the workspace for a session:
make tessera-upstream       # `go work edit -dropuse ./third_party/tessera`
make tessera-fork           # restore the committed default (re-init + git checkout go.work)
```

`make tessera-upstream` drops `./third_party/tessera` from `go.work` locally;
run `make tessera-fork` to restore the committed default before committing so
nothing upstream-only is committed by accident. The published image's upstream
variant is built with `--build-arg TESSERA_VARIANT=upstream` (tagged
`…-upstream`); see `.github/workflows/publish-image.yml`.

This is why a versioned `replace => github.com/baseproof/tessera vX` is
**not** used: the fork deliberately keeps the upstream module path
(`module github.com/transparency-dev/tessera`) so it is a drop-in, and Go's
versioned-`replace` requires the replacement's declared path to match the
right-hand side. The submodule + `go.work use` avoids renaming the fork and keeps
upstream merges trivial.

## Fork versioning (baseproof)

The fork keeps the upstream module path (`module github.com/transparency-dev/tessera`),
so it is a drop-in but can **only** be consumed via this submodule + `go.work` —
never a versioned `require`/`replace` (Go would reject the path mismatch). Fork
releases are therefore git **tags** used as submodule refs, not Go module versions.

Versions track the upstream base plus a baseproof build counter:
**`v<upstream>-bp.<n>`** (`bp` = *baseproof*). The first release,
`v1.0.2-bp.1`, is upstream `v1.0.2` + the deterministic `Appender.Shutdown`.
Bump `-bp.2`, `-bp.3`, … for later fork changes on the same upstream base; when
rebasing onto a new upstream (e.g. `v1.1.0`), start `v1.1.0-bp.1`. We do **not**
reuse an identical `v1.0.2` tag — that would shadow upstream's release and risk a
checksum collision if ever resolved by version.

### Cutting a release (fork maintainer)

```sh
# in the fork (github.com/baseproof/tessera), on the release commit:
git tag -a v1.0.2-bp.1 -m "baseproof v1.0.2-bp.1: upstream v1.0.2 + Appender.Shutdown (#341)"
git push origin v1.0.2-bp.1
# optionally publish a GitHub Release from the tag.
```

### Pinning / bumping the submodule to a release

```sh
git -C third_party/tessera fetch --tags origin
git -C third_party/tessera checkout v1.0.2-bp.1     # detached at the tag
git add third_party/tessera
git commit -m "tessera: pin baseproof v1.0.2-bp.1"
```

Pinning to a **tag** (rather than a branch commit) keeps the pin reproducible and
immune to branch deletion or a squash-merge orphaning the commit.
