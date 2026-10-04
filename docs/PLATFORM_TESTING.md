# Platform validation

The same command runs local and CI validation on Linux, Windows and macOS:

```sh
python -m pip install -r scripts/requirements-test.txt
python scripts/validate.py --out validation-results
```

Use Python 3.11 or newer (`python3` where appropriate), Go 1.26 or newer, and a native C compiler for the race detector. The release workflow pins Go 1.26.8 and Python 3.13. On Windows AMD64, the race detector needs GCC/MinGW available on `PATH`; Visual Studio alone is insufficient. On macOS, install the Xcode command line tools. Windows ARM64 does not support Go race detection; the receipt records that check as skipped.

The output directory must be new. The runner checks formatting, runs `go vet`, uncached Go tests with a coverage profile and race detection, builds the native executable, then runs the discovered independent integration scripts (including artifact/document comparisons and optional disk/RAM tools). By default it rebuilds `dist/k957-<os>-<arch>` (with `.exe` on Windows); `--binary` chooses another build destination. `K957_TEST_BINARY` selects an existing executable when running individual integration scripts. `--expect-target windows-arm64`, for example, fails early if host architecture detection does not match the intended target.

`validation.json` records the target, native/Wine environment, Python version/platform, executable SHA-256, command lines, durations, exit codes and explicit skips. Each command has its own log. A failed command or timeout fails the validation; a passed receipt with skipped checks does not imply those checks ran. Each command has a 300-second limit, adjustable with `--timeout`.

`--source-objects 100000` adds an explicit synthetic filesystem collection/case load check after the integrations and saves a nested `source-scale/scale.json` receipt. This step generates only temporary fixtures, disables memory/live system/OS profile collection and independently checks signatures, original/acquired bytes, hashes and export/index counts. It is omitted unless requested. The standalone command and measurement scope are documented in [SOURCE_SCALE.md](SOURCE_SCALE.md).

## CI

[platform-tests.yml](../.github/workflows/platform-tests.yml) runs on pushes, pull requests and manual dispatch in a GitHub repository with Actions enabled. It targets Linux AMD64/ARM64, Windows AMD64/ARM64 and macOS Intel/Apple Silicon, retains receipts and logs for 14 days, and pins actions to commit hashes. It neither publishes artifacts as a release nor signs binaries.

Windows ARM64 uses an x64 Python process for the independent cryptographic verifier because the pinned `cryptography` package does not publish Windows ARM64 wheels. The Go toolchain and tested application target native ARM64; the receipt identifies the Python platform separately and the job checks host target detection. Other jobs use native Python. These workflow definitions still require an actual successful CI run before claiming platform validation.

## Windows compatibility checks on Linux

When Windows test executables and the CLI are cross-compiled, a Windows Python interpreter can run the integration suite under Wine with:

```text
python scripts/validate.py --out validation-results --prebuilt-tests C:\tests
```

The directory must contain `core.test.exe` and `cli.test.exe`. This mode executes those tests and the integrations; it explicitly skips formatting, vet, coverage, race detection and building. The CLI is selected using `--binary` or the normal platform default. The receipt detects Wine and labels it separately from native Windows. Cross-compilation and Wine do not establish native Windows device, ACL, USB or system-command compatibility.

## Changes in 0.10.1

Collection uses `os.Lstat` rather than directory enumeration metadata for the source identity comparison. This avoids rejecting unchanged Windows files as replaced while preserving the identity check. A regression covers nested paths, Unicode characters, empty files and byte-for-byte acquired content.

Checkpoint replacement on Windows retries sharing/access conflicts for at most approximately one second. This allows short-lived `work-status` readers to finish. If replacement remains blocked, the command reports the error and preserves the previous checkpoint. It never deletes the previous checkpoint as a workaround. Tests cover plain and encrypted checkpoints, transient readers, persistent conflicts and temporary-file cleanup. This does not guarantee persistence through physical power loss.

Independent integration tests select the host binary, use explicit UTF-8 for reports and command output, use portable free-space measurement, and terminate child processes using the host mechanism. Both recovery tests retain stale-lock rejection, confirmed child exit before lock removal, part integrity and acquisition-epoch checks.

## Compatibility and execution status

Evidence schemas v1/v2 remain readable. Checkpoints and review histories remain bound to their producing version. Complete earlier work directories with their original binary; do not edit checkpoint versions to force migration. Preserve old signed review histories and create a new analysis with the current analyzer version for new review work. Packaged 0.9.0 example reports remain historical.

See [TEST_REPORT.md](TEST_REPORT.md) for the executed checks and their receipts. Native Windows and macOS runs require an accessible machine or connected CI runner. A ready workflow or a compiled executable is not a completed runtime test. Native OS permissions, signed application distribution, physical USB/power interruption and real device acquisition remain outside the local Wine/Linux results.

## Current source-bound developer preview

The retained 0.15.0 Linux AMD64 [receipt](validation/0.15.0/linux-amd64-scale/validation.json) passed 31 steps, including vet, race, the one-million-row index benchmark, release-metadata policy, a 100,000-source-object collection/case check and all integrations, including actual local model inference on synthetic scalar tasks. Unit statement coverage was 76.4%; standalone integration execution is not counted in that metric. Six targets passed cross compilation and static/platform library checks. RELEASE.json binds source and executable hashes; all other native targets and physical device scenarios remain unvalidated. The initial failed attempt is summarized separately, with its accidental host-acquisition output excluded from release files. Narrow model execution/citation measurements do not establish forensic model quality.

## Windows console acceptance

The console renderer enables ENABLE_PROCESSED_OUTPUT and ENABLE_VIRTUAL_TERMINAL_PROCESSING on the actual output handle before using escape sequences. Unsupported consoles receive plain progress, while terminal summaries remain human-readable. TERM=dumb requests plain output; NO_COLOR suppresses color only. Redirected output does not receive console escape sequences.

Native acceptance should cover Command Prompt and PowerShell in both Console Host and Windows Terminal, redirected stderr, TERM=dumb, NO_COLOR and Ctrl+C. Verify that no literal escape codes appear and that the cursor is visible after completion/interruption. Cross compilation alone does not certify these host behaviors.

## Native Windows AMD64 VM execution — 2026-10-04

The current [native Windows receipt](validation/0.15.0/windows-amd64-developer-20261004/validation.json) and [supplement](validation/0.15.0/windows-amd64-developer-20261004/supplement/result.json) cover source `41535d...`. Native Go build/vet/coverage/index checks passed; cross-compiled race executables were executed on Windows. Integration references include Xpdf text extraction, SQLite/EVTX/Registry fixtures, actual Windows Sleuth Kit deleted-file recovery and offline Volatility invalid-image handling. The optional local model was not configured. The [100,000-object scale check](validation/0.15.0/windows-amd64-scale-20261004/source-scale/scale.json) describes the immediately preceding `23b094...` source. Full details and failed attempts are in [TEST_REPORT.md](TEST_REPORT.md). These runs do not certify native Windows ARM64 or physical device/kernel accuracy.

`--timeout` controls validation commands. The synthetic source-scale test has three inner commands with their own deadlines; the runner allows four times that deadline for the overall scale step. This does not set an application memory-analysis timeout.

To bind multiple source-matching native receipts, repeat `scripts/release.py --no-build --validation <receipt>` for each target. Duplicate targets and mismatched source/executable hashes are rejected.
