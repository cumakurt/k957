# Remaining-space preflight — 0.11.0

`preflight --resume` reads an existing acquisition checkpoint and estimates the additional space required to finish it. It does not create an output, change the checkpoint, delete files, clear locks or reserve capacity.

```sh
k957 preflight --resume --root /source \
  --work /external/case-work --out /external/case.k957 \
  --reserve 268435456
```

Use the original source root and `--max-file`, `--max-total`, `--max-files` values. The defaults remain 256 MiB per file, 2 GiB total and 10,000 files. The source root must still exist, as required by the collector. Output must be a new path outside the source and work trees.

For encrypted work, add `--encryption-key /secure/case.key`. The checkpoint is decrypted and authenticated with the original key. `--encrypted` alone cannot inspect encrypted work. For fresh acquisitions, continue using `preflight --encrypted`: that mode estimates overhead without reading a key. Resume preflight JSON can contain source paths; store it with the same care as work-status output.

## Gate collection

```sh
k957 collect --resume --root /source \
  --work /external/case-work --out /external/case.k957 \
  --case CASE-001 --operator Analyst --scope "Authorized directory" \
  --check-space --reserve 268435456
```

Encrypted collection also requires the original `--encryption-key`. Case, operator, scope, source root and limits must match the original acquisition. `blocked` or `unknown` prevents collection; `warning` or `pass` permits the collector to perform its normal checks. Use the standalone preflight command for detailed JSON. Live system snapshots remain unsupported in resumable acquisition.

## What the plan counts

- `eligible_files` and `eligible_bytes`: the original frozen selection. Newly created source files are excluded.
- `completed_files`: files marked complete in the validated checkpoint. Their original sources do not need to remain present; the collector reuses saved parts.
- `acquired_bytes`: the sum of recorded part sizes, a logical byte count rather than physical disk allocation or a content-verification result.
- `remaining_bytes` and `remaining_parts`: data and chunks still to acquire. `planned_parts` includes both recorded and remaining parts.
- `estimated_output_bytes`: the entire final package allowance, including previously acquired data, ZIP/manifest overhead and encryption overhead when applicable.
- `estimated_work_bytes`: remaining logical bytes plus a 10% allowance, 4 KiB per remaining part/incomplete file, 64 MiB for checkpoint replacement, and applicable encryption overhead.

Already occupied staging space is reflected in current filesystem free space and is not charged again. Orphan chunks and temporary files are not deleted or counted as reclaimable space. Future content deduplication is not assumed. Even fully acquired work still needs space for checkpoint updates and a complete new output package.

Existing work and chunk directories are probed directly, because either can be a mount point. Storage roles are `output`, `work` (checkpoint metadata) and, when additional staging space is planned, `chunks`. Requirements sharing a filesystem are combined; the smallest observed free-space sample is used and `--reserve` is added once per filesystem. Separate filesystems receive separate reserves. Fresh acquisition estimates retain the existing `output`/`work` roles.

These are planning allowances, not guaranteed upper bounds. Allocation units, quotas, compression, snapshots, concurrent writers and device failures can change actual capacity. Filesystem identity does not establish physical-device separation.

## Rejections and integrity limits

The plan checks checkpoint structure/version, matching options, saved chunk existence/type/size, and incomplete source path/type/size/modification time. It reports blocked checks for a present lock, unavailable chunks, changed incomplete sources, existing output, overlap, insufficient estimated space or an exhausted acquisition-epoch limit. An unreadable/invalid checkpoint or a wrong encryption key returns an error. Capacity uncertainty returns `unknown`.

A lock may be active or stale. Preflight never removes it or claims to distinguish the two; confirm the collector has exited before applying the existing manual stale-lock recovery procedure.

Preflight does not read source contents or rehash saved chunks. A same-size content mutation can pass this metadata check. Actual resume still verifies chunk hashes/authentication and the saved source prefix before completing acquisition. Use `work-status --verify-parts` when independent staged-content verification is needed; it does not verify the live source prefix either. A successful plan is not an integrity certification or a reserved-space guarantee.

## Compatibility and validation

Evidence schemas v1/v2 remain readable. Checkpoints and review histories retain their existing exact-version binding. Finish 0.10.1 or older work directories with the original binary; do not edit version fields to force migration. This feature applies to 0.11.0 work. Preserve older signed review histories and create a new analysis for new-version review work.

Unit tests cover partial/completed work, plain/encrypted budgets, exact capacity boundaries, separate work/chunk filesystems, capacity uncertainty, option/lock/source/chunk failures, cancellation and checkpoint preservation. Independent Python integrations kill real child collectors and verify the remaining-space plan before plain/encrypted recovery, then check 192 MiB of content. The completed-work test removes the original source, adds a new file, and confirms only the frozen acquisition is reused. See [TEST_REPORT.md](TEST_REPORT.md) for actual platform results; synthetic tests do not establish physical USB or power-loss behavior.
