# Witnessed configuration & the platform ceremony

**Status:** design (sequencing step 1 — the witness_sets genesis projection — is
implemented; the ceremony engine is specified here for the SDK+tooling pair)
**Scope:** `baseproof/baseproof` (SDK), `baseproof/tooling`, consumed by every
domain network (the JN today).

## 1. One pattern for everything on-log: the five rules

The platform already carries four partially-overlapping config mechanisms
(admission keyset snapshots, admission policy records, the six SDK governance
chains, witness rotation records). Consolidated, they are one pattern — and
anything that follows it is automatically witnessed and reconstructable:

1. **Anchor** — every configuration kind has a stable on-log name: a schema
   entry's position (the `LEDGER_ADMISSION_AUTHORITY_SCHEMA=<log-did>@<seq>`
   pattern; `protocol.NetworkBundle.GovernanceSchemas` already names six such
   chains).
2. **Elements** — config changes are sequenced entries citing the anchor via
   `Header.SchemaRef`, each **authorized by the predecessor state**: a rotation
   signs under the prior witness set, a keyset snapshot under a current
   authority G, a policy amendment under the governance rule.
   Authorized-by-predecessor is what makes the chain a chain.
3. **Witnessed by construction** — no config entry is witnessed directly; it is
   witnessed transitively: entry → inclusion proof → tree head → K-of-N
   cosignatures. That triple is exactly `protocol.ChainElement`. If an element
   cannot produce its triple, it does not exist.
4. **One walker** — resolution is always a walk, never a read of stored state
   (the `protocol.Source` doctrine). The same walker body runs online
   (ledger-backed Source) and offline (the v2 proof's embedded chain). New
   config kinds add an anchor + a payload codec — never a new walk.
5. **Projections are caches** — Postgres rows (`witness_sets`, the keyset
   cache, the served manifest) are rebuildable projections of the walk,
   re-derived at boot and by `rebuild-projection`. Never authoritative.

Measured against this: the manifest work conforms (anchor schema + citing
entries + latest-wins, hash-verified — `judicial-network/netmanifest` +
`api/manifesthttp`), the admission keyset conforms, witness rotations conform
(`effective_seq` is the intrinsic, inclusion-proven position). **The one thing
that does not is genesis itself.**

## 2. The gap: genesis is asserted, not witnessed

Today `init-network`/`gen-fixtures` runs on one host, mints every witness key
plus the admission authority G, writes a bootstrap JSON — and that is the
constitution. Its integrity story is self-certification (NetworkID =
SHA-256(JCS bytes)) plus TOFU pinning. Good — but nobody ever **signed** it:
the witnesses it names never endorsed being named, G never endorsed its
enrollment, and the mint host is a single point of total compromise. The
witness set that witnesses everything is the only unwitnessed object in the
system.

**Shipped now (sequencing step 1):** the `witness_sets` genesis projection —
`witnessclient.SeedGenesisBaseline` reconciles the genesis baseline row
(effective_seq 0, the slot migration 0014 reserved) from the trust root at
boot, idempotently, including the backfill of a genesis-era hole left by a
first rotation that retired nothing on an empty table. The CLI mirrors the
doctrine: `baseproof witnesses` / `info` fall back to the bootstrap-derived
genesis set when a ledger serves no history (and refuse to guess over a *real*
hole). This projection is correct under either provenance — once step 4 below
lands, the same row projects from the sequenced genesis record instead of from
config, and `rebuild-projection` reconstructs it from entry 0 like everything
else.

## 3. The genesis ceremony (sound creation)

Five steps, each on machinery that already exists:

1. **Distributed key generation.** Each genesis witness operator generates its
   own key locally (the witness daemon's witkey path) and publishes only its
   did:key; same for G's holder. The mint host never sees a private key.
2. **Candidate constitution.** The coordinator assembles the bootstrap from
   collected DIDs + policies — deterministic JCS bytes → candidate NetworkID.
   Pure data, no trust yet.
3. **Genesis endorsement cosignatures.** Every genesis witness (and G) signs
   the candidate's canonical hash with the cosign primitive used for tree
   heads, under a **distinct domain separator** (a genesis preamble, never the
   head preamble — an endorsement can never replay as a head cosignature, nor
   vice versa). Endorsements travel **beside** the canonical bytes — like
   cosignatures on a checkpoint — so the NetworkID is unchanged and the
   no-endorsement legacy shape stays decodable. First contact now checks two
   things: NetworkID == hash(doc) AND N-of-N endorsements verify under the
   keys the doc declares. An attacker can still mint a network with keys they
   control (different NetworkID — harmless); they can no longer publish a
   constitution *claiming these witnesses* without their signatures.
4. **Genesis as sequence 0.** At first boot the ledger sequences a
   `network_genesis` entry whose payload is the endorsed bootstrap (the
   bootstrap-exception write the admission-authority flow already defines,
   anchored to the genesis tree head). The first K-of-N cosigned head then
   commits a tree containing the witnesses' own endorsement record — the log's
   first witnessed act covers its own constitution. Every chain in §1 now has
   its element 0 inside the walk; `witness_sets`' seq-0 baseline projects from
   a sequenced, witnessed entry rather than from config.
5. **External attestation — REQUIRED, not optional.** Peer networks / genesis
   auditors publish anchor entries citing the new NetworkID + bootstrap hash
   (the existing CosignedAnchor machinery): the cross-network birth
   certificate.

### The three sharpenings (folded in as normative)

- **The endorsement is a birth certificate, not a living credential.** It
  hardens exactly one thing: first contact with the constitution (TOFU
  upgraded from "whatever file the endpoint serves" to "a file N named parties
  provably signed"). Ongoing trust is carried entirely by the chain — in year
  14 the founding keys are long retired and nobody trusts the network because
  of them.
- **Step 5 is the long-horizon fork defense and therefore constitutional.**
  The one attack predecessor-authorization cannot stop is post-retirement key
  compromise: with year-0 keys acquired in year 12, an attacker can fabricate
  an entire alternate history from sequence 1 under the *genuine* endorsed
  bootstrap. The defense that ages well is periodic cross-network anchoring —
  heads checkpointed into other logs and archive mirrors the attacker cannot
  rewrite. **Anchoring cadence belongs in the bootstrap's genesis policy**, so
  the network is born committed to it.
- **Rotations are dual-signed, uniformly; genesis is era 0's degenerate
  case.** Predecessor authorization alone lets a malicious outgoing set
  "rotate in" keys it controls while naming an innocent organization;
  successor consent (`rotation.IsDualSigned()` — checked and logged today)
  closes that, and becomes the policy norm. The symmetry: *every era's
  membership is endorsed by its own members; every transition is authorized by
  the predecessor and accepted by the successor; every era's acts are anchored
  beyond the network itself.* Genesis endorsement is the first case — an era
  with no predecessor, so its members' N-of-N self-endorsement stands alone.

## 4. The ceremony is REUSABLE: one engine for all platform events

Genesis must not get a bespoke signing flow. A **ceremony** is, generally:

> collect a **threshold** of **domain-separated endorsements** from a defined
> **roster** over a **canonical subject**, producing a portable **endorsement
> bundle** that travels beside the subject bytes (never inside its ID surface).

Everything multi-party in the platform is an instance of that sentence. The
engine is one SDK package; each platform event is a *kind registration* —
a subject codec, a roster rule, a threshold rule, and a versioned domain
separator following the established `kinds/` convention. New events add a kind,
never a new engine (the authoring-side mirror of §1's "new config kinds add an
anchor + a payload codec, never a new walk").

**Engine (SDK):**

- `Subject{Kind, Digest [32]byte}` — Kind is a registered
  `BP-CEREMONY-<NAMESPACE>-<OPERATION>-V<N>` discriminator; the DST derives
  from it, so no two kinds' endorsements are mutually replayable, and V<N>
  versions the preamble (crypto-agility of the ceremony itself).
- `Endorsement{SignerID/DID, SchemeTag, Sig}` — scheme-dispatched through the
  existing `signatures`/`cosign` primitives (ECDSA, BLS+PoP, PQ when admitted
  by the algorithm policy) — agile by construction.
- `Bundle{Kind, SubjectDigest, Endorsements[]}` + format tag — the detached
  artifact; encode/decode strict (`DisallowUnknownFields`).
- `Verify(bundle, roster, threshold)` — fail-closed; the *only* verification
  body, shared by every kind.

**Kind registrations (the platform events):**

| Platform event | Subject | Roster | Threshold | Unifies today's primitive |
|---|---|---|---|---|
| Genesis endorsement | bootstrap canonical hash | `GenesisWitnessSet` + G | N-of-N | (new) |
| Rotation, predecessor authorization | new-set hash | prior witness set | K-of-N | `WitnessRotation.CurrentSignatures` (the rotation DST) |
| Rotation, successor consent | rotation payload | incoming set | K'-of-N' | `NewSignatures` / `IsDualSigned()` |
| Governance update (admission keyset; signature / algorithm / protocol-version policies) | entry signing payload | G-keyset | per governance rule | `WriteAuthorization` + EOA-keyset walk |
| Crypto-agility cutover stages | policy amendment payload | G-keyset (+ dual-sign window) | per stage | staged `--require-hybrid-after` flow |
| Federation join / anchor agreement | anchor payload | both networks' sets | per side | CosignedAnchor |
| Hard-maintenance / DR declaration (Plane 4) | maintenance manifest anchored on the cosigned horizon | operator + witnesses | per genesis policy | (new — makes DR itself witnessed) |
| Domain multi-party events (e.g. JN cosignature rules) | entry signing payload | domain roster | `CosignatureRule` | inline multi-sig (`envelope.Signatures`, model #1) |

**Collection transport is pluggable and offline-first** — the bundle is the
contract, not the channel: file relay between operators (air-gapped HSM
ceremonies), a one-shot `endorse` on the witness daemon / CLI (online
collection), or on-log two-part attestations (model #2) for events whose
endorsements should themselves be sequenced. Same `Bundle` either way.

**Landing on-log** — ceremony output either *rides* the element it authorizes
(rotation signatures, multi-sig entries, the `WriteAuthorization` header) or
*is* the payload of a record entry (the `network_genesis` entry at seq 0, a DR
declaration). Both shapes are already walked; rule 4 of §1 is preserved.

**Surfaces (consolidation-plan aligned):**

- `libs/ceremony` driver (agnostic): assemble candidate → distribute → collect
  → `Verify` → emit bundle.
- `baseproof ceremony {propose, endorse, collect, verify}` as `libs/cli` RunX
  seams + Cobra wrappers — Plane 1/2, domain-agnostic, e2e-driven like every
  other command.
- Witness daemon: an `endorse` one-shot (reads its existing witkey; refuses
  unknown ceremony kinds).
- `init-network` gains a ceremony mode (assemble → collect → verify → emit
  endorsed bootstrap); today's single-host mode remains, explicitly labeled
  dev-only.
- Ledger boot: verify endorsements when present (fail-closed when the doc
  demands it); sequence the genesis record at first boot; seed `witness_sets`
  from it (the projection shipped in step 1 then reads the on-log record).

## 5. What changes where, and in what order

1. **DONE — projection:** `witness_sets` genesis baseline derived at boot +
   CLI genesis fallback. Correct under either provenance.
2. **SDK:** the `ceremony` engine (Subject/Endorsement/Bundle/Verify + kind
   registry + DSTs); `GenesisEndorsement` as the first kind;
   `VerifyGenesisEndorsements(doc, bundle)`; the `network_genesis` payload
   kind (a `kinds/` entry + codec, passing kindslint).
3. **tooling:** `libs/ceremony` driver + `baseproof ceremony` seams; witness
   `endorse` one-shot; `init-network --ceremony`; ledger boot endorsement
   verification + genesis sequencing; rotation dual-sign required by policy
   default; anchoring cadence read from genesis policy.
4. **JN/e2e:** unchanged consumption; fixture mint stays dev-mode; JN's
   cosignature rules become a registered ceremony kind when convenient.

## 6. The transparency checklist

- Every configuration claim resolvable from the log + the endorsed genesis
  record — ✔ after step 4 (constitution + endorsements inside the tree at
  seq 0).
- One walk pattern, online and offline identical — ✔ (`ChainElement` triples;
  the v2 proof carries the chains).
- All projections rebuildable from the walk — ✔ (`witness_sets` included,
  from entry 0).
- The irreducible off-log residue is a single 32-byte first-contact pin
  (NetworkID / bootstrap hash) — the TOFU floor every system has — backed by
  endorsements, cross-log anchors, and archives rather than by a bare file.
