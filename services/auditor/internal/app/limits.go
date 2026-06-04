/*
FILE PATH: services/auditor/internal/app/limits.go

Ladder 5 P8 (#21) — operator-manifest loader resource caps.

# WHY HARD CAPS

The auditor's two operator-manifest loaders — LoadAuditorRegistryFromFile
and LoadAuditorAmendmentsFromFile — read JSON arrays from operator-
authored files and decode them into SDK records. Without an upstream
size bound, a misconfigured deployment (typo'd path pointing at a
large log file, accidentally committed test fixture, runaway editor
swap file) feeds an arbitrary blob into json.Unmarshal at boot.

At 15-operator scale, "one operator with a 100MB-typo manifest" is
plausible; the loader would happily allocate that blob, then allocate
the unmarshal'd struct slice on top — boot OOM with no actionable
error. With these caps the failure mode is a clean fail-closed boot
refusal naming the offending file + the limit it exceeded.

# WHY BOTH BYTES AND RECORDS

  - Bytes cap (io.LimitReader): prevents the case where the operator
    points at a non-JSON blob (binary, gzip, etc.) — even a malformed
    file gets caught at the bytes layer without invoking json.Unmarshal.

  - Records cap (post-unmarshal length check): the bytes cap is
    structural, not semantic; a pathological JSON-array could pack
    millions of tiny "{}" objects within the bytes cap. The records
    cap pins the next layer — even valid JSON can't allocate an
    unbounded record-shape slice.

# REUSE PATTERN

Both loaders apply both caps symmetrically. The constants live here so
a future log-scan loader / on-log walker / CLI verify tool can adopt
the same caps by reference rather than re-deriving sizes from intuition.

# SIZING RATIONALE

  - 1 MiB byte cap is the same order as ledger's MaxBundleBytes (8
    MiB) and four-times bootstrap's MaxBootstrapBytes (256 KiB).
    Registry + amendment manifests are intermediate in shape — a
    handful of fields per record, ~400-800 bytes JSON each. 1 MiB
    fits a few thousand records, well above realistic operator
    deployment scale (tens to hundreds of auditors per network).
  - 10,000 records is two orders of magnitude above typical
    deployment scale, leaving the records cap purely as a safety
    net for the "operator typo'd a generated file" case.

# RELATIONSHIP TO THE B3 BOOT-REFUSAL GATE

B3 (Ladder 1) refuses to boot on AUDITOR_ENFORCE_SCOPES=true + an
empty registry. P8 refuses to boot on a registry file that's too
large or has too many records. Both are operator-facing boot
diagnostics: surface the misconfig at the moment the operator's
deployment manifest is loaded, before the binary commits to running.
*/
package app

// MaxRegistryFileBytes caps the bytes read from operator-authored
// registry / amendment manifests. Read via io.LimitReader so even
// pathological non-JSON inputs (binary blobs, gzip, etc.) are
// truncated at this boundary; the loader surfaces a clean error
// when the cap is reached rather than allocating the whole file.
const MaxRegistryFileBytes int64 = 1 << 20 // 1 MiB

// MaxRegistryRecords caps the post-unmarshal record count from
// either loader. Even within the bytes cap, a JSON array of many
// tiny objects could allocate an unbounded record-shape slice;
// this cap pins the next layer.
const MaxRegistryRecords = 10_000
