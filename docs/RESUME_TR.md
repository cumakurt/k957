# k957 0.2.0 — Interruptible logical collection

Update for 0.11.0: `preflight --resume` estimates remaining space from saved work; `collect --resume --check-space` gates collection with that plan. See [RESUME_PREFLIGHT.md](RESUME_PREFLIGHT.md). Earlier-version checkpoints still require their original binary. The historical filename is retained for existing links; this document is in English.

`collect --work` saves 8 MiB chunks in a new work directory. `--resume` continues the frozen inventory/scope. Without `--work`, collection uses the single-pass workflow.

## Usage

Choose three distinct paths: an existing source, a new output and a new work directory:

```sh
k957 collect --root /source \
  --work /external/CASE-002-work --out /external/CASE-002.k957 \
  --case CASE-002 --operator Examiner --scope "Authorized directory"
```

After controlled cancellation (Ctrl+C) or an error, add `--resume`:

```sh
k957 collect --root /source \
  --work /external/CASE-002-work --out /external/CASE-002.k957 \
  --case CASE-002 --operator Examiner --scope "Authorized directory" --resume
```

Read-only status inspection:

```sh
k957 work-status --work /external/CASE-002-work --verify-parts
```

Status includes planned files/bytes, completed files, acquired bytes/parts, part verification, lock presence and epochs. Without `--verify-parts`, content hashes are not checked. Status checks stored parts rather than source prefixes. Lock presence alone does not prove a process is running.

Use normal `verify`/`analyze` commands on the completed package. Optional `--sign-key` signs the final package; its key must be outside source/work trees. A completed work directory can export another package with `--resume` and a new `--out`; this reuses acquisition rather than reading the source again.

## Recorded information

- Frozen initial source inventory, sizes and modification times.
- Per-part byte offset, size, SHA-256, acquisition epoch and time.
- Per-run start/end, host, OS/architecture and outcome.
- Complete-file SHA-256, size and completion time.
- Final v2 schema, with epochs and explicit analysis limitations.

A chunk is written to a temporary file, synced and renamed to its hash identity. Checkpoints use temporary write/sync/replacement; directory sync is attempted where supported. Checkpoints reference only committed chunks. Unreferenced chunks/temporary files are not accepted as acquired evidence during recovery.

## Resume verification

1. Scope, source root, case, operator and byte/file limits must match the original acquisition.
2. Saved chunk hashes and completed-file combined hashes are checked.
3. An incomplete source's size/mtime must match the frozen inventory.
4. Its acquired prefix is reread and compared per chunk; matching metadata alone is insufficient.
5. New parts record the new epoch.
6. Export verifies chunks again; package verification checks both part and complete-file hashes.

Changed sources/corrupt chunks are rejected without silently rewriting saved work. Start a new work directory for a changed acquisition.

## Frozen inventory and acquisition times

**A resumable package is not a point-in-time snapshot.** Files created after initial inventory are excluded. Completed files reuse saved chunks even if their source later changes or disappears. Incomplete files still require an accessible matching source. Prefix rereading does not establish live-system snapshot consistency.

Changing scope/operator requires new work. `--work --system` is rejected; collect live-system snapshots separately.

## Abrupt termination and stale locks

Each writer creates `active.lock`; another writer cannot open that work directory. Normal cancellation/error cleanup attempts to remove it. SIGKILL, power loss or disconnection can leave a stale lock.

1. Confirm with processes/operators that no collector uses the work directory.
2. Remove only that `active.lock` after confirming it is stale; never remove a running collector's lock.
3. Inspect `work-status --verify-parts`.
4. Resume. An unfinished `running` epoch is marked `interrupted; end time unknown`; no end time is invented.

SIGKILL during final ZIP writing can leave partial output. Do not treat it as evidence without verification. Resume into a new output name; existing outputs are never overwritten.

## Limits

- Plain staging contains plaintext evidence. `--encryption-key`, introduced in v0.5, encrypts checkpoints/chunks/final output; see [ENCRYPTED_COLLECTION_TR.md](ENCRYPTED_COLLECTION_TR.md). `seal` can separately encrypt an existing package.
- Plain checkpoints are unsigned; encrypted checkpoints have AEAD integrity. Keep work in trusted storage. Plain mode does not authenticate an attacker-controlled combination of checkpoint and chunk contents.
- Staging and final output both require space. Fresh/resume preflight is available; physical source/output separation is not verified.
- Directory sync/replacement durability depends on the filesystem/OS/hardware; no power-loss or damaged-USB guarantee is provided.
- Current bounds are 256 MiB checkpoint, 128 MiB final manifest and 1,000 epochs. Numerous small files/parts may reach metadata bounds.
- Interruption before initial inventory is saved may leave no resumable state; use a new work directory.
- Cross compilation does not establish native Windows/macOS USB behavior. Manage Windows ACLs and macOS application permissions separately.
- Work files are not automatically deleted. After verifying the final package, apply your retention policy; secure erasure is not claimed.

## Compatibility

Evidence schemas v1/v2 remain readable. Resumable packages use `k957-evidence/2`; the original 0.1 reader cannot open v2. Checkpoints use `k957-work/1` and the producing application version; automatic migration between application versions is not provided.
