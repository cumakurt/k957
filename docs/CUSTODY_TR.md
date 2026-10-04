# Signed custody and transfer records — v0.7.0

`custody` creates signed declaration history for a verified evidence package. Each operation writes a new JSON file without modifying prior history or evidence. Every event retains its own Ed25519 signature. `custody-verify` checks all signatures, actor/key mappings, operation order and evidence bindings. The historical filename is retained; this document is in English.

These are digital declarations, not proof of physical handover, real identity, legal authorization or trusted time. File-based private keys, independently prepared trust policy and independently retained current heads are required.

## Trust list

Each actor uses a private key:

```sh
k957 keygen --out /secure/alice
k957 keygen --out /secure/bob
```

An administrator verifies public keys independently and places each `.pub` file's **64-character lowercase hexadecimal content** in `trust.json`:

```json
{"schema":"k957-custody-trust/1","keys":[
  {"actor":"Alice","public_key":"ALICE_PUBLIC_KEY_HEX"},
  {"actor":"Bob","public_key":"BOB_PUBLIC_KEY_HEX"}
]}
```

Actor names are case-sensitive and cannot have surrounding whitespace. One key identifies one actor. All historical signer mappings must appear in the external trust policy; an embedded list is not automatically trusted. The original v0.7 scope had no certificate authority, revocation service or historical authorization policy. Current lifecycle/witness extensions are documented in [EXAMINATION_WORKFLOWS.md](EXAMINATION_WORKFLOWS.md).

## Operation order

- `register`: initial holder signs the first event and establishes custody.
- `transfer`: current holder requests transfer to `--to`; custody does not yet change.
- `accept`: pending recipient signs acceptance and becomes the holder.
- `cancel`: current holder cancels the pending request.
- `note`: current holder adds a declaration when no request is pending.

A pending transfer must be accepted/cancelled before another transfer/note. The model has one current holder, rather than concurrent copies, group custody or two-person destruction approval.

```sh
k957 custody --in /evidence/case.k957 --trust /secure/trust.json \
  --action register --actor Alice --location "Evidence cabinet A" \
  --note "Verified package registered" --sign-key /secure/alice.key \
  --out /records/custody-001.json
```

Retain the returned 64-character `head` independently. Substitute that independently retained value for `PREVIOUS_HEAD`:

```sh
k957 custody --in /evidence/case.k957 --trust /secure/trust.json \
  --previous /records/custody-001.json --expected-head PREVIOUS_HEAD \
  --action transfer --actor Alice --to Bob --location "Laboratory intake" \
  --note "Requested examination transfer" --sign-key /secure/alice.key \
  --out /records/custody-002.json
```

Bob verifies the package/history in a trusted environment and signs acceptance. Here `PREVIOUS_HEAD` means custody-002's independently retained head:

```sh
k957 custody --in /evidence/case.k957 --trust /secure/trust.json \
  --previous /records/custody-002.json --expected-head PREVIOUS_HEAD \
  --action accept --actor Bob --location "Examination station B" \
  --note "Package checked and received" --sign-key /secure/bob.key \
  --out /records/custody-003.json
```

Optional `--at` supplies an RFC3339 declaration time, such as `2026-09-28T08:00:00+03:00`; otherwise recording time is used. Declared times cannot exceed recording time and history times cannot move backwards. An incorrect local clock can reject an operation. Times remain local/user declarations without TSA/NTP verification.

## Verify and report

Substitute custody-003's independently retained head for `FINAL_HEAD`:

```sh
k957 custody-verify --in /evidence/case.k957 \
  --ledger /records/custody-003.json --trust /secure/trust.json \
  --expected-head FINAL_HEAD
k957 analyze --in /evidence/case.k957 --out /reports/case-001 \
  --custody /records/custody-003.json --custody-trust /secure/trust.json \
  --custody-head FINAL_HEAD
```

Optional `--trusted-key /secure/acquisition.pub` authenticates evidence separately from custody actors. Verification JSON reports decoded history, `current_holder`, optional `pending_to`, `head` and trust digest. HTML, `analysis.json` and `custody.csv` project the same history with HTML escaping/CSV formula protection. Retain original custody JSON and trust policy for verification.

Without an expected head, an older valid signed prefix may be accepted. A hash chain alone cannot reveal removed tail events or another branch. Reading the expected head from the same file being verified is not independent verification. No centralized/distributed consensus service is provided.

## Evidence binding and limits

- All package objects and manifest hashes are verified first. History binds case, package ID and **SHA-256 of exact manifest bytes**, rather than the complete ZIP bytes. Repackaging identical manifest/objects may retain the same evidence binding.
- Commands require a plaintext `.k957`; unseal encrypted output in an authorized analysis environment first.
- Custody JSON/reports are unencrypted and expose actors, locations and notes. Base64 is not encryption; manage permissions separately.
- Bounds: 10,000 events/32 MiB ledger, 1,000 keys/1 MiB trust file, 256-byte actor, 1,024-byte location and 16,000-byte note. Lowercase field names, unknown/duplicate keys, nesting and signature encodings are checked.
- Existing files are never overwritten. Interrupted writes can leave a partial new file; verify before use and retain prior revisions.
- Custody format is independent of analyzer version and supports v1/v2 evidence. Checkpoints remain bound to the collector version; examiner reviews retain their analyzer basis.

## Independent format verification

`payload_base64` contains exact signed JSON bytes. Decode it without JSON reserialization. Signature input is `k957/custody/signature/v1` + a zero byte + payload. Event head is SHA-256 of `k957/custody/head/v1` + zero byte + 32-byte public key + 64-byte signature + payload. `previous` links the earlier head (empty initially). `signer_sha256` hashes the 32 raw public-key bytes.

`scripts/custody_integration.py` independently checks two signers, domain separation, chain and reports with Python cryptography. Historical results are retained in [TEST_REPORT.md](TEST_REPORT.md); current receipts are in [IMPLEMENTATION_PROGRESS.md](IMPLEMENTATION_PROGRESS.md).
