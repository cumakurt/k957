"""Shared native-platform selection for the independent CLI integration tests."""
import os
import pathlib
import platform
import sys


def native_target():
    operating_system = {'linux': 'linux', 'win32': 'windows', 'darwin': 'darwin'}.get(sys.platform)
    architecture = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    if not operating_system or not architecture:
        raise RuntimeError(f'Unsupported test platform: {sys.platform}/{platform.machine()}')
    return operating_system, architecture


def default_binary():
    override = os.environ.get('K957_TEST_BINARY')
    if override:
        return pathlib.Path(override).resolve()
    operating_system, architecture = native_target()
    suffix = '.exe' if operating_system == 'windows' else ''
    return pathlib.Path(__file__).resolve().parents[1] / 'dist' / f'k957-{operating_system}-{architecture}{suffix}'


def execution_environment():
    if sys.platform == 'win32':
        import ctypes
        try:
            get_version = ctypes.WinDLL('ntdll').wine_get_version
        except AttributeError:
            pass
        else:
            get_version.restype = ctypes.c_char_p
            return {'kind': 'wine', 'version': get_version().decode('ascii')}
    return {'kind': 'native', 'version': platform.version()}

