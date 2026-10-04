# Synthetic source collection and case load validation

## Executed scope

The scale implementation [Linux AMD64 validation](validation/0.15.0/linux-amd64-scale/validation.json) adds a [100,000-source-object receipt](validation/0.15.0/linux-amd64-scale/source-scale/scale.json). It exercises the release executable through full-mode collection, package verification and case generation. Source `4e755340e3196b288a74a76f6b6cd34d75d3d71cfe3163cdc9b0758d9934cf66` is embedded in the tested executable and recorded with its SHA-256.

Only temporary synthetic small regular files are collected. RAM, live system snapshots and OS artifact profiles are explicitly disabled. The fixtures have mixed whole/fractional modification timestamps and one two-object duplicate group. The check uses Python `cryptography` to verify both exact-byte Ed25519 signatures, compares every original/acquired byte and signed content hash/size, checks inventory CSV content/source order and all legacy export counts, checks numeric nanosecond timeline ordering, and uses Python `sqlite3` to check index counts and the final source reference. Temporary evidence/fixtures are removed after the check; command outputs, errors, executable/source/script identities and independent-check results are retained.

Observed command timings were **6.210 seconds collection**, **3.125 seconds package verification** and **13.322 seconds case generation**. Sampled command-process RSS was **447.871 MiB**, **508.516 MiB** and **638.004 MiB**, respectively. Sampling reads Linux `/proc/<pid>/status` every 50 ms; these values are neither exact peaks nor total child-process memory. The fixture creation and independent Python checks are outside those command timings and RSS samples. No product memory/latency SLA or improvement percentage is asserted.

The signed manifest was **84,234,311 bytes**. The case index was **315,072,512 bytes**, with **300,002 rows**: 100,000 inventory rows, 200,000 metadata events and two collection boundaries. Inventory CSV and bodyfile contained 100,000 records each; legacy timeline CSV contained 100,002 records. This source-based run complements the separate one-million-derived-row benchmark; it does not combine 100,000 diverse source artifacts with a million interpreted application events in one reference case.

The English application update repeated this same 100,000-source-object check successfully against source `c672c9e826462e1a1e5a43fa50eda8da3d0b4ab3f7d51b7a8298091c1e575dc6`; see the [latest receipt](validation/0.15.0/linux-amd64-english-release/source-scale/scale.json). The measurements above describe the earlier retained scale implementation run.

## Reproduction

Use the existing independent-test requirements and a new result directory:

```sh
python -m pip install -r scripts/requirements-test.txt
python scripts/validate.py --out validation-results --source-objects 100000
```

To exercise an existing executable without repeating the full suite:

```sh
python scripts/source_scale.py --binary dist/k957-linux-amd64 --out source-scale-results --objects 100000
```

`--objects` accepts 2..100000; `--timeout` bounds each application command (default 600 seconds standalone). The script never requests privileged, memory, system or artifact-profile collection. Python cryptography and SQLite provide the independent reference checks. Other platforms can run the fixture/check logic, but Linux process RSS sampling is unavailable there and the receipt leaves that measurement unset. A failed command or mismatch fails the check.

## Reproduced defects and corrections

The [before-fix run](validation/0.15.0/source-scale-before/scale.json) failed collection because 100,000 permitted files produced a manifest beyond the old 16 MiB ceiling. Its [collection record](validation/0.15.0/source-scale-before/collect.json) retains `manifest size limit exceeded`; a partial record is not treated as success. Single-pass and resumable manifest generation/verification now use the same 128 MiB bound. Per-entry encoding preserves signed JSON bytes and avoids an extra compact encoding of the full inventory, while exact-byte Ed25519 signing still needs a complete manifest buffer. A regression verifies a signed manifest larger than 16 MiB, as well as byte-compatible nil/empty/nested/Unicode encodings, byte limits and writer failures.

The first new-code [attempt](validation/0.15.0/source-scale-initial/scale.json) successfully collected and verified the package, then failed because the load harness expected `status` instead of the existing CLI `integrity` field. That harness mistake was corrected. The next [attempt](validation/0.15.0/source-scale-after/scale.json) reached successful case generation but could not parse the CLI's `Case:` stdout prefix as JSON. The product now sends that navigation hint to stderr and retains one JSON summary on piped stdout; a regression checks the contract. The final full validation and independent checks passed. Earlier failures are preserved against their original executable/script identities.

Legacy case exports now use additive SQLite projection tables and streamed exclusive files. Numeric seconds/nanoseconds preserve chronology and stable ties, independently of the million-row examination cap. Existing columns, CSV formula escaping and bodyfile semantics are retained. Failure cleanup, cancellation, zero timestamps, fractional/pre-epoch timestamps, exact ties and existing-output protection have regression coverage. The case database remains a rebuildable derived artifact with the same schema-1 reader contract and 2 GiB ceiling.

## Remaining scale work

- Full analysis arrays, strict manifest verification, exact-byte signing, duplicate grouping and some large JSON/report projections still consume memory. Analysis loading has a separate 128 MiB bound; this run does not validate large `analysis.json` review/report workflows.
- Resumable acquisition uses a complete checkpoint rewrite after each committed chunk and completed file. The checkpoint bound is now 256 MiB and preflight allows two generations, but its repeated serialization/I/O remains unsuitable for a claimed 100,000-file resume performance guarantee. This load check exercises single-pass full mode only.
- FTS, diverse artifact payloads, very long paths/metadata, multiple large collections, encrypted/resumable source load, independently measured exact process peaks and agreed production latency/memory budgets remain open. Independent byte and count agreement on this synthetic set does not establish forensic parser accuracy or real device behavior.
