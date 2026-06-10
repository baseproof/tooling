# baseproof-cli

The unified **baseproof** client — one binary, bound to **one network** by a
client bundle (or the active network). All logic lives in
`github.com/baseproof/tooling/libs/cli`; this module is the thin binary, **staged
for extraction to its own repository next sprint** (Cobra rebuild).

```
go run .            # usage
go build -o baseproof .
```

## Commands

| Command | What it does |
|---|---|
| `baseproof submit` | Submit ONE entry to the network: a new entity, a same-signer **amendment** (`--amend <seq>`), a **delegation** (`--delegate-to`), or a **delegated amendment** (`--amend`+`--delegation`). |
| `baseproof proof` | Generate a **v2 self-anchored proof** of an entry (`--seq`), self-verify it offline, and (`--out`) write a portable file. |
| `baseproof verify <file>` | Verify a v2 proof **fully offline** (zero network): recompute witness K-of-N, inclusion, SMT membership — fail-closed. Network-agnostic; `--pin`/`--network`/`--bundle` binds it to a network you trust. |
| `baseproof info` | Understand a network in one view: identity (recomputed), trust root, witnesses + K-of-N, auditors (live + in-sync), horizon, admission, accepted messages, anchors/labels/endpoints, mirrors, federation. `--verify` recomputes the crypto; `--federation [--depth N]` walks + verifies the cited peers (bounded, cycle-guarded). |
| `baseproof witnesses` | The witness set — current, or as-of a historical tree size (`--at N`, time-travel); labels overlaid. |
| `baseproof network` | gcloud-style network store: `add` (author a bundle from a live ledger — `--from-ledger <url> --quorum K [--ca-cert]` — or import `--from <file\|url>`), `list`, `use`, `show`. |
| `baseproof config` | `config set network <name>` / `config list` — the active-network default (`~/.config/baseproof/`). |
| `baseproof load` | Drive the memory-bounded loadgen engine (`-n`, `--amend-ratio`, `--delegate-ratio`, `--workers`, `--batch-size`, `--seed`) and optionally stream the expected-state oracle (`--manifest oracle.jsonl`). |

## Design

- **One network per bundle.** A `clientbundle` (`--bundle <file>` or a stored
  `--network <name>`, else the active network) carries the endpoint, the trust
  root (network id, quorum K, content-addressed bootstrap hash), the destination
  log DID, the accepted message catalog, and the TLS transport posture
  (server-verify CA-pin / mTLS / plaintext).
- **Zero-Trust by default.** Nothing the server says is trusted: `info --verify`
  recomputes the network id from the served bootstrap and the K-of-N cosignatures
  against the genesis witness set; `proof` self-verifies offline before it emits;
  `verify` recomputes every cryptographic check and fails closed.
- **Standalone proofs.** A v2 proof is self-contained — it embeds its genesis
  bootstrap + witness set + network id — so `verify` needs no ledger and no
  network. `--pin` binds the proof's network id to one you already trust.
- **The logic is the library.** Every command is a `libs/cli` `RunX(ctx, args)`
  function; the platform e2e (`tooling/e2e`) drives the same functions against a
  real fleet, so the shipped surface is exactly what is tested.

### Cobra surface — DONE
Each command is a `cobra.Command` with native POSIX flags + shell completion +
per-command help (`main.go` + `commands.go`). A generic forwarder reconstructs the
flags a user **set** into the `--name=value` args the `libs/cli` `RunX` seams parse
(`cmd.Flags().Visit` → only changed flags; unset flags fall through to `RunX`'s own
defaults), so defaults + logic stay in `libs/cli` **untouched** and the platform
e2e drives exactly what ships. `cli.Main` (the stdlib-`flag` dispatch) remains in
libs for embedders.

### Roadmap — next sprint (extraction only, no code change)
Move this module to its own repository: drop the `replace ../libs` and require the
published `github.com/baseproof/tooling/libs vX.Y.Z`.
