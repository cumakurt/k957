# Repository and release preparation

The Git repository contains source code, documentation, dependency licenses, synthetic examples and deliberately retained validation receipts. Local executables in `dist/`, transient root coverage, private `.key` files, `output/`, `case/`, virtual environments and `validation-results/` are excluded from Git.

## Source checkouts

A fresh clone does not include compiled executables. Build with `scripts/build.sh` on Linux/macOS or `scripts/build.ps1` on Windows using the documented Go toolchain. The scripts create `dist/` locally. The start scripts require those binaries and do not download or compile them automatically.

`RELEASE.json` and `SHA256SUMS.txt` retain the identities of the prepared developer-preview artifacts. Their `dist/` entries describe separately distributed binaries, not files guaranteed to exist in a source checkout. A local rebuild must be validated on its own bytes before being advertised as the recorded tested executable.

## Before publishing a release

1. Inspect `git status --short` and the intended commit. Keep real acquired evidence, private keys and VM access information outside tracked paths.
2. Build the targets and run the intended platform validation using synthetic/reference inputs. Cross compilation alone does not establish native runtime success.
3. Retain selected, reviewed source-bound validation receipts under `docs/validation/`. This directory is intentional public test evidence; ordinary working logs remain in ignored `validation-results/`.
4. Use `scripts/release.py` to refresh release metadata, notices and artifact checksums. Its repeatable `--validation` arguments select passed native receipts for the exact source/binary bytes. Use `--no-build` only after source-matching builds already exist.
5. Distribute the reviewed executable files and relevant checksum/release metadata as release assets separately from the source commit. This guide does not assert that a GitHub release has been published.

Retained receipts and signed examples are marked `-text` in `.gitattributes`: Git must not normalize their line endings on Windows checkout. Original upstream licenses are also preserved byte-for-byte. Source files use LF consistently to keep source fingerprints stable.

## Local cleanup policy

Removing generated files from Git tracking does not delete their working copies or acquired evidence. An unrelated local setup script is not part of k957. Historical design notes are retained under `docs/history/` and must not be read as current capability claims. The current guides and release/test metadata describe present behavior.

Do not rewrite existing Git history or force-push as part of ordinary cleanup. Previously committed build files remain in historical revisions even after the current tree stops tracking them.
