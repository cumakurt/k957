# k957 0.5.0 — Encryption during collection

`collect --work ... --encryption-key ...` encrypts the checkpoint, evidence chunks and final package. The final ZIP streams directly into the encryption layer without a temporary plaintext ZIP. Without the flag, plaintext collection remains available. The historical filename is retained for existing links; this document is in English.

## Usage

Create a key in trusted storage outside the source/work trees:

```sh
k957 encryption-key --out /secure/CASE-005.key
k957 collect --root /source \
  --work /external/CASE-005-work --out /external/CASE-005.k957.enc \
  --case CASE-005 --operator Examiner --scope "Authorized directory" \
  --encryption-key /secure/CASE-005.key
```

An independent `--sign-key /secure/examiner.key` can sign acquisition. Signing and encryption serve different purposes. Encrypted collection requires resumable logical-file collection with `--work`; single-pass and `--system` modes are rejected rather than silently ignored.

After interruption, add `--resume` with the same source, scope, limits and **same key**. Follow the stale-lock procedure in [RESUME_TR.md](RESUME_TR.md); never remove an active collector's lock.

```sh
k957 work-status --work /external/CASE-005-work \
  --encryption-key /secure/CASE-005.key --verify-parts
```

Normal encrypted collection prints status/object/issue counts without the full manifest. Explicit `work-status` exposes decrypted case/source metadata; choose output destinations carefully. Errors may include paths and operating systems may record command lines.

Unseal and verify in the analysis environment:

```sh
k957 unseal --in /external/CASE-005.k957.enc \
  --out /secure-analysis/CASE-005.k957 --key /secure/CASE-005.key
k957 verify --in /secure-analysis/CASE-005.k957
k957 analyze --in /secure-analysis/CASE-005.k957 --out /secure-analysis/report
```

Use `--trusted-key` for signed acquisition. `unseal` intentionally creates plaintext; analysis/reports are not automatically encrypted. Use an encrypted analysis volume if required. Direct analysis of `.enc` files is not supported.

## Protected material

- `state.enc` encrypts case details, source paths, original hashes, part ranges and epochs.
- `chunks/` stores encrypted 8 MiB parts; keyed HMAC names replace plaintext SHA-256 filenames.
- Temporary checkpoint/chunk contents are encrypted in memory before writing.
- The final `K957ENC1` envelope unseals into a standard v2 package.
- Wrong keys and modified ciphertext are rejected; staging encryption mode cannot change in place.

`active.lock` remains plaintext with PID/start time. Directory structure, counts, sizes, filesystem timestamps and repeated chunk use under one key remain observable. Generate a fresh random key for every case.

## Cryptographic format

The key file contains a 32-byte random key as hexadecimal text, compatible with earlier transport encryption; it is not a password. HMAC-SHA256 derives purpose-separated keys:

- `k957/stage/aead/v1`: staged-blob AES-256-GCM key.
- `k957/stage/name/v1`: chunk-filename HMAC key.

Blob layout: `K957STG1` (8 bytes), random 12-byte nonce, ciphertext and 16-byte GCM tag. AAD is `aes256-gcm-stage/1:state` for checkpoints or `aes256-gcm-stage/1:chunk:<original-sha256-hex>` for chunks. This prevents checkpoint/chunk substitution. New blobs use fresh nonces. Final transport uses the existing master-key/envelope format independently of the staging key.

## Limits and operation

- Lost keys cannot be recovered. Keep keys separately from evidence; source/work key paths are rejected.
- Keys are read from files. Hardware keys, password KDFs, recipient-public-key encryption, key vaults and automatic rotation are not provided.
- Storage encryption does not protect source RAM, swap/pagefiles, crash dumps or a compromised kernel. Memory zeroization is not guaranteed.
- AEAD detects modifications but does not establish complete history or prevent restoration of an older valid checkpoint/deletion of the entire work directory. No external time/version authority is implied.
- Original sources remain in place. Existing plaintext is not automatically encrypted or securely erased. In-place staging conversion is rejected; start a new work directory.
- Checkpoint/file bounds still apply. AES-GCM copies increase peak memory; each 8 MiB part is buffered, rather than the entire package.
- Disk/output failures stop export and attempt to remove the incomplete new package while preserving chunks. SIGKILL/power loss can leave partial output; resume with a new output name.
- Physical USB/power and native Windows/macOS device checks remain untested. Process termination tests do not establish hardware behavior.
- Cryptography uses Go's standard library; this custom format/stream implementation has no independent cryptographic audit or certification claim.
- Complete old checkpoints with their producing binary. Earlier v1/v2 packages remain readable; reviews stay bound to their analyzer version.
