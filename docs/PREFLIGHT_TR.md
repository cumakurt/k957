# Acquisition preflight

Version 0.11.0 also supports `preflight --resume` and `collect --resume --check-space` for existing plain/encrypted checkpoints. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md) for remaining-space accounting, required original options/key and validation limits. The fresh-acquisition workflow is documented below. The historical filename is retained for existing links; this document is in English.

`preflight` reports a new logical acquisition's source inventory and estimated storage requirements as JSON. It does not read/copy file contents, create output/work directories or reserve space. Directory/metadata reads can affect operating-system access records; this is not a zero-change guarantee.

```sh
k957 preflight --root /source --out /external/case.k957 \
  --work /external/case-work --reserve 268435456
```

Destination parent directories must exist; output and work paths must be new. Without `--work`, only the output budget is calculated. `--encrypted` includes encrypted staging/output overhead without reading or validating a key. Stdout can include source paths and filenames. Save it outside the source tree with appropriate permissions.

## Outcomes

- `pass`: implemented checks found no issue; exit 0.
- `warning`: shared source/destination filesystem, empty selection or inventory exclusions; exit 0.
- `unknown`: filesystem identity or capacity unavailable; exit 1.
- `blocked`: overlapping paths, existing destination or insufficient estimated space; exit 1.

Precedence is blocked, unknown, warning, pass. Always inspect `checks` and `inventory_issues`; warning does not guarantee a complete inventory.

## Capacity accounting

Preflight uses the resumable collector's metadata inventory. Defaults are 256 MiB per file, 2 GiB total and 10,000 files, adjustable with `--max-file`, `--max-total` and `--max-files`. Symlinks, special files and files outside limits are skipped with reasons. Traversal stops at the file-count ceiling. `eligible_bytes` means selected logical bytes, not allocated disk space. Single-pass collection and a subsequently changed source may produce different results.

The output estimate adds 1% of selected bytes, 1 KiB per file and 128 MiB for ZIP/manifest overhead. Work storage adds 10%, 4 KiB per file/part and 512 MiB for checkpoint replacement. Encrypted blob/envelope overhead is added separately. These are planning allowances, not proven worst-case bounds. Allocation units, quotas, snapshots, compression, long paths, growing sources and concurrent writers affect actual consumption.

Output/work requirements sharing one filesystem are combined with one reserve. Different filesystems receive separate reserves. When samples differ, the smallest available capacity is used. The default reserve is 256 MiB. Space is neither reserved nor continuously rechecked during acquisition.

Linux/macOS use statfs/device identity; Windows uses GetDiskFreeSpaceExW and volume GUID. Different partitions may share a physical device. This module does not verify physical-device separation or write blockers. Unidentified network/shared filesystems may return unknown.

## Gate collection

```sh
k957 collect --root /source --out /external/case.k957 \
  --work /external/case-work --case CASE-001 --operator Examiner \
  --scope "Authorized directory" --check-space --reserve 268435456
```

`--check-space` is optional: blocked/unknown prevents collection, warning/pass permits it. Use standalone `preflight` for detailed JSON. `--encryption-key` selects the encrypted estimate; stderr shows the preflight outcome.

Fresh acquisition rebuilds its inventory after preflight. Resume planning uses the frozen checkpoint and supports `--check-space`; see [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md). System snapshots remain unsupported. Capacity planning does not establish permissions, destination health, content integrity, point-in-time consistency or reserved capacity; collection performs its own checks.

## Validation and compatibility

Controlled unit tests cover capacity boundaries, uncertainty, combined/separate budgets and resume guards. `scripts/preflight_integration.py`, `scripts/resume_integration.py` and `scripts/encrypted_integration.py` exercise native capacity, unchanged checkpoint bytes and gated recovery. Current platform receipts are in [TEST_REPORT.md](TEST_REPORT.md). Native Windows/macOS devices and physical disk exhaustion remain untested.

Complete earlier checkpoints with their original binary. Earlier v1/v2 final packages remain readable; review histories are bound to their analyzer version and must be regenerated for a new analysis.
