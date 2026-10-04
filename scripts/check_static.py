#!/usr/bin/env python3
"""Reject release binaries that link a C library.

Linux has no dynamic imports; Windows permits platform DLLs without a C runtime.
macOS permits the Go runtime libraries and Go's native X.509 trust frameworks.
"""

import re
import struct
import sys


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_static.py BINARY...")
    for path in sys.argv[1:]:
        data = open(path, "rb").read()
        kind, libs = linked_libraries(data)
        forbidden = [lib for lib in libs if not allowed(kind, lib)]
        missing_kernel = kind == "pe" and "kernel32.dll" not in {lib.lower() for lib in libs}
        darwin_ok = kind != "mach-o" or set(libs) in (DARWIN_RUNTIME, DARWIN_RUNTIME | DARWIN_TRUST)
        if forbidden or missing_kernel or not darwin_ok:
            raise SystemExit(f"{path}: unexpected dynamic libraries for {kind}: {libs or ['none']}")
        print(f"{path}: {kind} static check passed ({len(libs)} platform libraries)")


_CRT = re.compile(
    r"^(msvcr\d+|msvcrt|ucrtbase|vcruntime\d+|msvcp\d+|libgcc_s_.+|libstdc\+\+.*|"
    r"libwinpthread.+|cygwin1|msys-.+|api-ms-win-crt-.+)$",
    re.IGNORECASE,
)

DARWIN_RUNTIME = {"/usr/lib/libSystem.B.dylib", "/usr/lib/libresolv.9.dylib"}
# crypto/x509/internal/macos uses these exact system paths with cgo disabled.
# No third-party dylib or alternate framework path is permitted.
DARWIN_TRUST = {"/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                "/System/Library/Frameworks/Security.framework/Versions/A/Security"}


def allowed(kind: str, lib: str) -> bool:
    if kind == "elf":
        return False
    if kind == "pe":
        name = lib.replace('\\', '/').rsplit('/', 1)[-1]
        if name.lower().endswith('.dll'):
            name = name[:-4]
        return _CRT.match(name) is None
    # Go's runtime and native trust verifier use these exact platform paths.
    return lib in DARWIN_RUNTIME | DARWIN_TRUST


def linked_libraries(data: bytes) -> tuple[str, list[str]]:
    if data.startswith(b"\x7fELF"):
        return "elf", elf_needed(data)
    if data.startswith(b"MZ"):
        return "pe", pe_imports(data)
    if len(data) >= 4 and struct.unpack_from("<I", data)[0] in {0xFEEDFACF, 0xCEFAEDFE}:
        return "mach-o", macho_dylibs(data)
    raise SystemExit("unrecognized executable format")


def elf_needed(data: bytes) -> list[str]:
    if data[4] != 2 or data[5] != 1:
        raise SystemExit("only little-endian ELF64 is supported")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    for index in range(phnum):
        if struct.unpack_from("<I", data, phoff + index * phentsize)[0] == 3:  # PT_INTERP
            raise SystemExit("ELF interpreter is present; the binary is dynamically linked")
    section_off = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    needed: list[str] = []
    for index in range(section_count):
        entry = section_off + index * section_size
        _, kind, _, _, offset, size, link, _, _, _ = struct.unpack_from("<IIQQQQIIQQ", data, entry)
        if kind != 6:  # SHT_DYNAMIC
            continue
        str_off = struct.unpack_from("<Q", data, section_off + link * section_size + 24)[0]
        pos = offset
        while pos + 16 <= offset + size:
            tag, value = struct.unpack_from("<QQ", data, pos)
            pos += 16
            if tag == 0:
                break
            if tag == 1:  # DT_NEEDED
                end = data.index(b"\x00", str_off + value)
                needed.append(data[str_off + value:end].decode("ascii"))
    return needed


def pe_imports(data: bytes) -> list[str]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise SystemExit("invalid PE signature")
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    section_count = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    if magic == 0x20B:
        import_rva, import_size = struct.unpack_from("<II", data, e_lfanew + 24 + 112 + 8)
        section_off = e_lfanew + 24 + 240
    elif magic == 0x10B:
        import_rva, import_size = struct.unpack_from("<II", data, e_lfanew + 24 + 96 + 8)
        section_off = e_lfanew + 24 + 224
    else:
        raise SystemExit(f"unknown PE optional header {magic:#x}")
    if import_rva == 0 or import_size == 0:
        return []
    names: list[str] = []
    pos = rva_to_offset(data, import_rva, section_off, section_count)
    while True:
        _, _, _, name_rva, _ = struct.unpack_from("<IIIII", data, pos)
        pos += 20
        if name_rva == 0:
            break
        name_off = rva_to_offset(data, name_rva, section_off, section_count)
        end = data.index(b"\x00", name_off)
        names.append(data[name_off:end].decode("ascii"))
    return names


def rva_to_offset(data: bytes, rva: int, section_off: int, section_count: int) -> int:
    for index in range(section_count):
        entry = section_off + index * 40
        virtual_size, virtual, raw_size, raw = struct.unpack_from("<IIII", data, entry + 8)
        span = max(virtual_size, raw_size)
        if virtual <= rva < virtual + span:
            return raw + (rva - virtual)
    raise SystemExit(f"RVA {rva:#x} is outside the PE sections")


def macho_dylibs(data: bytes) -> list[str]:
    if struct.unpack_from(">I", data)[0] == 0xCAFEBABE:
        raise SystemExit("fat Mach-O binaries are not produced by this build")
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", data, 0)
    pos = 32
    libs: list[str] = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, pos)
        if cmd & 0x7FFFFFFF in {0xC, 0x18}:  # LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB
            name_off = struct.unpack_from("<I", data, pos + 8)[0]
            end = data.index(b"\x00", pos + name_off)
            libs.append(data[pos + name_off:end].decode("utf-8"))
        pos += size
    return libs


if __name__ == "__main__":
    main()
