// Package accounting is the agnostic operational layer for federated-network LOAD
// ACCOUNTING over the baseproof SDK. It provides:
//
//   - LoadAccountingParams — the settlement policy schema + its root entity
//     publication (schema.go);
//   - Aggregator / SettlementLedger — deterministic per-member usage aggregation
//     between two cosigned tree-head boundaries (aggregator.go);
//   - SettlementManager — periodic settlement publication, deficit evaluation,
//     and free-rider scope removal (settlement.go);
//   - FireDrillRunner — escrow-node liveness and blob-availability fire drills
//     with SLA classification (fire_drills.go).
//
// Domain-free: it classifies generic entry kinds and tracks member DIDs; the
// domain supplies any payload extractor (e.g. for artifact usage). No
// court/case/jurisdiction concepts live here.
package accounting
