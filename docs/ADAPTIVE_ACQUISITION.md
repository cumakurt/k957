# Adaptive executable and library acquisition

Default full artifact collection supplements the operating-system profile with observed process executables and supported executable mappings/modules. An explicitly supplied profile retains its original scope. The signed `adaptive-executables.json` collection artifact records discovery times, method, process IDs, paths, status and later acquired evidence IDs/SHA-256 hashes.

## Linux executable mappings

For each observed process, the collector reads `/proc/<pid>/exe` and `/proc/<pid>/maps`. It selects absolute, file-backed mappings with execute permission, including shared libraries and executable files without a library suffix. Anonymous mappings and non-executable data mappings do not expand logical collection.

Each selected mapping retains its original line number, address range, permissions, file offset, device and inode. Address/identifier strings preserve 64-bit values in JSON readers. Repeated segments for the same process, path and filesystem identity share one file reference while retaining every executable range. File paths are deduplicated across processes for acquisition.

Before selection, the current regular file must match the observed device and inode. Deleted files, inaccessible processes/files, different filesystem identities and ambiguous `\012` pathname escapes remain unavailable references. A process in another mount namespace can therefore remain unavailable instead of selecting a different file at the same apparent path. The collector does not enter another mount namespace or recover deleted mapped bytes through this method.

The format and pathname ambiguities follow the [Linux process maps documentation](https://kernel.googlesource.com/pub/scm/docs/man-pages/man-pages/+/master/man/man5/proc_pid_maps.5).

## Windows loaded modules

Tool Help snapshots request both native and 32-bit module lists. Each module reference retains its name, load base address, image size and observed path. Module paths and process executable paths use the same regular-file selection and case-insensitive deduplication. Snapshot handles are closed after enumeration. Transient loader-list size failures are retried up to three times; persistent failures are explicit references. Cancellation stops enumeration.

This method does not expose every possible loaded byte: data-file loads, manually mapped code and unlinked modules are outside Tool Help enumeration. Protected/exited processes, loader changes, path truncation and architecture restrictions may prevent enumeration. See Microsoft's [snapshot contract](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) and [module enumeration](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-module-list).

## Interpretation and reporting

`observed_path` preserves the discovered path when a reference enters selection; `path` then identifies the resolved acquisition candidate. A successful acquisition binds the reference to the later package object. Discovery and acquisition are separate operations: these hashes do not prove that the process mapped those exact bytes. File replacement, PID reuse and process exit can occur between observations. Physical memory remains necessary to examine anonymous, modified, unlinked or deleted executable bytes.

HTML and PDF summaries distinguish process counts, selected/collected paths, unavailable executable paths, mapped-file/module references and mapping discovery/selection issues. Multiple mappings do not inflate the process count. A selected path absent from the acquired package becomes `not-collected`; inspect logical collection limits and package issues. Unavailable mapping references count discovery/selection failures and do not include every later acquisition failure.

Existing logical file/total/count budgets still apply; no new limit applies to memory analysis. macOS currently discovers process executables only. Recent-file selection is not implemented. Linux/Windows mapping additions have compilation assurance only until dedicated runtime/reference validation is recorded. Cross compilation does not establish native Windows/ARM64 behavior.
