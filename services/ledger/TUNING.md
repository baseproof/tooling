# Ledger tuning knobs (scaling ladder)

Every pipeline knob is an `LEDGER_*` env var. Defaults preserve prior behavior;
a `0`/empty value on any knob falls back to the default shown. The gauges in the
right column are the read-on-scrape signals (Prometheus `/metrics`) to watch the
effect of a change under load.

## Pipeline stages → knobs

| Stage | Env var | Default | Watch (gauge) |
|---|---|---|---|
| **Admission → WAL** (group commit) | `LEDGER_WAL_QUEUE_SIZE` | 4096 | `baseproof_wal_submit_duration_seconds` |
| | `LEDGER_WAL_BATCH_MAX_ENTRIES` | 256 | |
| | `LEDGER_WAL_BATCH_MAX_BYTES` | 5MiB | |
| | `LEDGER_WAL_BATCH_MAX_LATENCY` | 10ms | |
| **Sequencer** (WAL → tessera) | `LEDGER_SEQUENCER_MAX_INFLIGHT` | 64 | `baseproof_sequencer_drain_lag_seconds` |
| | `LEDGER_SEQUENCER_INTERVAL` | 1s | |
| **Tessera integration** | `LEDGER_TESSERA_BATCH_SIZE` | 256 | `baseproof_tessera_append_duration_seconds` |
| | `LEDGER_TESSERA_BATCH_MAX_AGE` | 100ms | |
| **Shipper** (WAL → bytestore, AIMD) | `LEDGER_SHIPPER_MAX_IN_FLIGHT` (AIMD ceiling) | 64 | `baseproof_shipper_aimd_limit` |
| | `LEDGER_SHIPPER_AIMD_STEP` (additive increase) | 0.5 | `baseproof_wal_backlog_total` |
| | `LEDGER_SHIPPER_POLL_INTERVAL` | 100ms | `baseproof_shipper_pending_total` |
| | `LEDGER_SHIPPER_MAX_ATTEMPTS` | 10 | |
| | `LEDGER_SHIPPER_BACKOFF_BASE` | 1s | |
| | `LEDGER_SHIPPER_BACKOFF_MAX` | 60s | |
| | `LEDGER_SHIPPER_HEALTHY_WINDOW` (poison-quarantine gate) | 60s | |
| **Checkpoint → horizon** | `LEDGER_CHECKPOINT_INTERVAL` (publish cadence) | 1s | `baseproof_horizon_lag_total` |

> The AIMD limiter floors at 1 (always probe for recovery); the ceiling is
> `LEDGER_SHIPPER_MAX_IN_FLIGHT`. Under a healthy store the limit settles near the
> ceiling; a depressed `baseproof_shipper_aimd_limit` means the store is the
> bottleneck — raise store capacity, not the ceiling.

## Recommended settings by rung

**Phase 1 — 3K (burst, quick):** all defaults. A 3K burst drains in seconds; the
gauges return to rest (`wal_backlog→0`, `horizon_lag→0`) within a checkpoint cycle
or two.

**Phase 2 — 30K (sustained / durability):** defaults sustain 30K, but for headroom
and smoother drain under a slower store:

```
LEDGER_SHIPPER_MAX_IN_FLIGHT=96      # more upload concurrency ceiling
LEDGER_SHIPPER_AIMD_STEP=1.0         # ramp back to the ceiling faster after a dip
LEDGER_SHIPPER_POLL_INTERVAL=50ms    # keep the worker channel full
LEDGER_SEQUENCER_MAX_INFLIGHT=96     # match the shipper so sequencing isn't the cap
LEDGER_WAL_BATCH_MAX_LATENCY=5ms     # tighter commit latency under steady ingest
LEDGER_CHECKPOINT_INTERVAL=1s        # 1s keeps horizon_lag bounded at this rate
```

Durability is healthy at 30K when, after the load: `baseproof_wal_backlog_total`
drains to 0, `baseproof_horizon_lag_total` returns to ~0 (the horizon caught up to
the committed head at K-of-N), and the manual queue (`baseproof_shipper` manual
counter) stays 0. A sustained positive `horizon_lag` or `wal_backlog` is the
"falling behind" signal — raise concurrency/cadence or store capacity.

Higher rungs (300K / 3M / 30M) layer on incremental tiles, stateful stores +
recovery, and horizontal/CDN/DR — out of scope for Phase 2.
