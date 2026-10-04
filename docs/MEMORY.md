# Physical memory acquisition and examination (0.15.0)

Full mode (`k957 collect` with no arguments, or `k957 collect --full`) acquires memory before filesystem artifacts. The image is a sibling of the evidence package, not an entry inside it, so other tools can open the file directly.

## LiME v1 layout

Each stored physical range is a 32-byte little-endian header followed by the raw pages:

Package file identification uses the same little-endian magic as the memory scanner. A renamed image does not need a `.lime` extension to enter memory analysis. Literal ASCII `LiME` is not the little-endian file signature.

| Offset | Type | Value |
|---|---|---|
| 0 | uint32 | magic `0x4C694D45` (`EMiL` on a little-endian machine) |
| 4 | uint32 | version `1` |
| 8 | uint64 | first physical address |
| 16 | uint64 | last physical address, inclusive |
| 24 | uint64 | reserved, zero |

The payload length is `last - first + 1`. Ranges do not overlap and are stored in ascending address order. This is the layout read by Volatility 3 `LimeLayer` and by Volatility 2's LiME address space. A raw image has no header; `memory.json` then records one range starting at address 0 and the addresses in reports are file offsets.

## Linux method

The collector reads `System RAM` ranges from `/proc/iomem` and intersects them with `/proc/kcore` `PT_LOAD` segments whose physical address is not all-bits-one. This is the same mapping used by AVML. Unmapped gaps are recorded in `memory.json` and omitted from the image. A page that cannot be read is stored as zeros and counted. The image is created once, hashed while it is written (SHA-256, plus SHA-1 and MD5 for tools that still expect them), then fsynced. It is not rewritten.

`/proc/iomem` hides addresses from unprivileged readers. Acquisition then fails with a privilege error, the rest of the triage continues, and the collection is `partial`.

## Other platforms

Windows uses one `winpmem*.exe` found next to the k957 executable or in `tools/`, invoked as `-o {output}`, or an explicit `--memory-tool` with repeatable `--memory-tool-arg`. One argument must contain `{output}`. The tool's SHA-256 is stored. macOS has no native method. The produced file is detected as LiME or raw.

## Record

`memory.json` uses `k957-memory/1`. It stores the case, operator, host, kernel release, method, source, tool hash, time range, ranges, gaps, byte count, image size and the three hashes. `collection.json` (`k957-collection/1`) binds this file, the image, `evidence.k957` and `signing.pub`. `collection.sig` is the raw 64-byte Ed25519 signature over the exact `collection.json` bytes. `SHA256SUMS` lists every file except itself and the derived `reports/` directory, in `sha256sum` text mode (`hash` + two spaces + slash-separated name).

## Analysis

`analyze` streams the image through one read-only file descriptor and computes SHA-256 over exactly the bytes consumed by the scanner. It accepts results only after matching the signed image hash and rechecking file identity, size and modification time. It neither loads the entire image into RAM nor creates an image-sized temporary copy. This also applies to `case` examination. Complete hashed private JSONL now retains:

- every case-insensitive ASCII/UTF-16LE literal-rule match, with its address and encoding;
- printable ASCII and UTF-16LE ASCII strings, in reconstructable 64 KiB segments;
- complete HTTP/HTTPS URL tokens, including tokens crossing scan windows, with address/encoding and continuation flags;
- executable headers, passwd-style accounts, `/proc/net` tcp/udp text rows, module vermagic, NUL-separated command lines, selected environment keys and PEM headers;
- the first plausible Linux banner and counts of zero/unreadable pages.

No image-size, LiME range-count or result-count ceiling truncates this scan. Repeated observations at different addresses are retained. Structured observations omit selected secret fields; complete printable strings can contain secrets. Result files have private permissions and must be reviewed before disclosure. A byte/header reading is not kernel reconstruction or proof of execution.

`analysis.json` and visual reports carry previews: 500 hits, 500 observations and 50 unique URL previews per image. Long URL previews can be shortened; complete tokens are reconstructable in JSONL. `memory.csv` records full result counts and file names. `memory-hits.csv` and `memory-observations.csv` stream complete applicable rows from the authenticated JSONL. The general 10,000-finding review projection and the case index have their own disclosed presentation/index capacities; these do not truncate the complete RAM results or stop later memory scans. Default PDF includes memory method status and complete result references. See [reporting](REPORTING.md).

Set `K957_VOLATILITY` to a trusted installed Volatility 3 executable and `K957_MEMORY_SYMBOLS` to a matching offline JSON/compressed symbol directory to run automatic kernel examination during `analyze` and `case`. `K957_MEMORY_WORK_DIR` optionally selects an existing staging filesystem. Package-contained LiME images are also authenticated, privately extracted and examined when configured. Automatic platform selection uses the memory acquisition record, or the package manifest OS for contained images. For imported images whose target differs from the collector OS, use explicit `memory-examine --platform` selection.

Store analysis (`k957 analyze` with no `--in`) verifies the collection before scanning. A failed verification is not analyzed.

A privileged Linux check acquired every host `System RAM` range into a complete LiME image. The first header's magic, version and physical address matched `memory.json`, and the file size was the payload plus 32 bytes per range. The image was deleted after that check. It was one machine, not a cross-platform or Volatility execution test.

## Offline kernel examination

```sh
k957 memory-examine --image ./memory.lime --sha256 <acquired-sha256> --tool /path/to/vol --symbols ./offline-symbols --platform linux --out ./kernel-results
```

The default `--plugin all` discovers every installed plugin for the image platform, plus global banner/YARA plugins. Each plugin is attempted independently with offline symbols. Advertised boolean `--dump` and `--threads` options are enabled; recovered files, help output, stderr and JSON records are retained with hashes. Missing optional modules and failures are explicit. Required PIDs/addresses, YARA rules or other selectors are not invented. A specific `--plugin linux.pslist.PsList` selects one method. Use `--work-dir /existing/disk-directory` when needed.

There is no automatic 8 GiB image ceiling, two-minute tool timeout, 32 MiB output limit, 64 KiB diagnostic limit, 100,000-row limit or symbol file-count/byte ceiling. Context cancellation, malformed output, changed input/symbols and disk exhaustion remain failures. Nested renderer objects are preserved; recorded row counts describe top-level records. Trusted external code can access its host: complete OS sandboxing and hashes of every interpreter dependency are not claimed.

A full private image/symbol copy is hash-checked before and after external execution. Staging first considers the system temporary directory, then the output filesystem if the temporary filesystem is too small. Only actual capacity is required; the former fixed 64 MiB reserve does not block RAM staging. Package examination needs both archive extraction and the private external-tool copy. Disk capacity for outputs/dumps must remain available throughout execution; no preflight can predict every plugin's eventual output size.

A real Volatility 3 2.28.2 invalid-image/missing-symbol check passed. No valid kernel reference image and exact matching symbols were available to measure process/socket enumeration accuracy. The separate >8 GiB synthetic suite check validates orchestration, full output retention and unchanged source bytes; it is not a kernel accuracy test. See [development plan and measurements](DEVELOPMENT_PLAN.md).

## Temporary storage and progress

Default store/case memory scanning works even when the system temporary filesystem cannot hold the acquired RAM image. Small private evidence-package copies and complex artifact workers may still require temporary storage. External Volatility enumeration retains its private-copy requirement and can use the output filesystem or an explicit work directory. Complete native scan results also require writable storage proportional to extracted observations/strings.

Verification progress labels its byte counter `read workload`: repeated hash/checksum/format passes are included, so it can exceed the unique image size. Four passes over a 31.4 GiB LiME image account for approximately 125.5 GiB of planned verification reads. The acquired image remains 31.4 GiB. A failed store verification/analysis is marked `failed`, with collection errors retained in its summary.

Regression tests cover zero reported staging capacity, an unavailable temporary directory, raw/LiME formats, original physical references, wrong hashes, same-metadata mutations, path replacement and cancellation. `scripts/memory_stream_integration.py` independently verifies a synthetic signed external image, runs `verify`, `analyze` and `case` with an unavailable temporary directory, and checks unchanged evidence files. These synthetic checks do not claim a repeat of the user's 31.4 GiB acquisition/analysis.
