#!/usr/bin/env python3
"""Regression checks for permitted platform libraries and forbidden C runtimes."""
import unittest

from check_static import allowed, DARWIN_RUNTIME, DARWIN_TRUST


class PlatformLibraryTests(unittest.TestCase):
    def test_native_macos_trust_framework_paths(self):
        for path in DARWIN_RUNTIME | DARWIN_TRUST:
            self.assertTrue(allowed('mach-o', path))
        for path in ('/tmp/evil/Security.framework', '/usr/local/lib/libsqlite3.dylib'):
            self.assertFalse(allowed('mach-o', path))

    def test_windows_runtime_suffix_and_case(self):
        for name in ('ucrtbase.dll', 'UCRTBASE.DLL', 'msvcrt.dll', 'vcruntime140.dll',
                     'MSVCP140.dll', 'libwinpthread-1.dll', 'api-ms-win-crt-runtime-l1-1-0.dll',
                     'C:\\Windows\\System32\\ucrtbase.dll'):
            self.assertFalse(allowed('pe', name), name)
        self.assertTrue(allowed('pe', 'kernel32.dll'))

    def test_linux_no_dynamic_libraries(self):
        self.assertFalse(allowed('elf', 'libc.so.6'))


if __name__ == '__main__':
    unittest.main()
