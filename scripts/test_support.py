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



def report_text(path):
    """Read report text; independently extract binary PDFs when available."""
    if path.suffix.lower() != '.pdf':
        return path.read_text(encoding='utf-8')
    import shutil
    import subprocess
    tool = shutil.which('pdftotext')
    if not tool:
        print('PDF privacy text extraction not run: pdftotext unavailable; ordinary report checks continue.')
        return None
    result = subprocess.run([tool, '-enc', 'UTF-8', str(path), '-'], capture_output=True, text=True, encoding='utf-8',
                            timeout=60, check=True)
    return ' '.join(result.stdout.split())


def executable_python_fixture(path, body):
    """Create a test-only executable Python fixture, including a Windows launcher."""
    import json
    import subprocess
    if os.name != 'nt':
        path.write_text('#!' + sys.executable + '\n' + body, encoding='utf-8')
        path.chmod(0o700)
        return path
    script = path.with_suffix('.py')
    script.write_text(body, encoding='utf-8')
    launcher = path.with_suffix('.go')
    launcher.write_text('package main\nimport("os";"os/exec")\nfunc main(){\n'
                        'args:=append([]string{' + json.dumps(str(script), ensure_ascii=False) + '},os.Args[1:]...)\n'
                        'cmd:=exec.Command(' + json.dumps(sys.executable, ensure_ascii=False) + ',args...)\n'
                        'cmd.Stdin=os.Stdin;cmd.Stdout=os.Stdout;cmd.Stderr=os.Stderr\n'
                        'if err:=cmd.Run();err!=nil {if e,ok:=err.(*exec.ExitError);ok{os.Exit(e.ExitCode())};os.Exit(127)}\n}\n', encoding='utf-8')
    executable = path.with_suffix('.exe')
    subprocess.run(['go', 'build', '-o', str(executable), str(launcher)],
                   env=dict(os.environ, CGO_ENABLED='0'), check=True, capture_output=True, timeout=180)
    return executable
