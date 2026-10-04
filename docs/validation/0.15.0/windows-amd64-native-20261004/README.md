# Native Windows AMD64 validation

Source: `014179e7c5aaf6e07abc0aa5b4dbdbd6aae02a0f4d255d8e91ca17952fd9f822`.

The Windows VM runs Windows 10.0.26200 on AMD64 with Go 1.26.8 and Python 3.13.7. The supplemental checks were executed on October 2, 2026; their records were recovered after a VM restart on October 4. [result.json](result.json) records eight successful checks: native build, vet, unit coverage, coverage extraction, one-million-row case indexing, Go version and native execution of both race test executables. Race executables were cross compiled on Linux; execution was native Windows.

Corrections found by native execution:

- Absolute SQLite drive paths are now serialized as file URL paths instead of authorities. This fixes browser extraction, case indexing, queries and transaction-consistent SQLite acquisition.
- Case indexing owns transaction rollback synchronously so cancellation closes Windows SQLite handles before partial output cleanup.
- Windows console detection checks the console API and enables virtual terminal processing before cursor/color output. Redirected handles, TERM=dumb and NO_COLOR have regressions.
- Test fixtures preserve POSIX-only permission/FIFO/signal expectations on their applicable platforms. Windows replacement sharing protection is checked without weakening hash verification.
- Prebuilt test executables run from their package directories, preserving fixture lookup.
- PDF reference tools explicitly emit and decode UTF-8. SQLite reference test connections are explicitly closed before temporary-directory cleanup.
- Windows memory suite fixtures use a compiled Python launcher; the original large output/row/stderr assertions run on Windows. A generated ext2 image enables actual Windows Sleuth Kit enumeration and scoped deleted-file recovery.

These results do not certify Windows ARM64, driver-backed physical RAM capture, valid kernel-symbol corpus accuracy, physical USB interruption, enterprise security controls, code signing or native macOS operation. The local assistant requires an explicitly configured model and runtime; it is not silently installed.
