#!/usr/bin/env python3
"""Run platform validation and retain command logs plus a machine-readable receipt."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import sysconfig
import time

from test_support import default_binary, execution_environment, native_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True, help='new directory for validation results')
    parser.add_argument('--binary', type=pathlib.Path, default=default_binary())
    parser.add_argument('--prebuilt-tests', type=pathlib.Path,
                        help='run core.test.exe and cli.test.exe without a Go installation (records skipped build/vet/race checks)')
    parser.add_argument('--timeout', type=int, default=300, help='maximum seconds for each command')
    parser.add_argument('--expect-target', help='fail if the native OS/architecture differs, e.g. windows-arm64')
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error('--timeout must be positive')
    root = pathlib.Path(__file__).resolve().parents[1]
    target_os, target_arch = native_target()
    if args.expect_target and args.expect_target != f'{target_os}-{target_arch}':
        parser.error(f'expected {args.expect_target}; detected {target_os}-{target_arch}')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    env = dict(os.environ, K957_TEST_BINARY=str(binary), PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1',
               GOOS=target_os, GOARCH=target_arch)
    receipt = {
        'schema': 'k957-validation/1',
        'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'target': f'{target_os}/{target_arch}',
        'environment': execution_environment(),
        'python': platform.python_version(),
        'python_platform': sysconfig.get_platform(),
        'binary': str(binary),
        'result': 'running',
        'steps': [],
    }

    def save():
        (out / 'validation.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')

    def skip(name, reason):
        receipt['steps'].append({'name': name, 'status': 'skipped', 'reason': reason})
        save()

    def run(name, command, require_empty=False, extra_env=None):
        command = [str(arg) for arg in command]
        step = {'name': name, 'command': command, 'status': 'running', 'log': f'{name}.log'}
        receipt['steps'].append(step)
        save()
        started = time.monotonic()
        print(f'RUN {name}', flush=True)
        log_path = out / step['log']
        with log_path.open('wb') as log:
            try:
                result = subprocess.run(command, cwd=root, env=env | (extra_env or {}),
                                        stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
                step['exit_code'] = result.returncode
                step['status'] = 'passed' if result.returncode == 0 else 'failed'
            except (OSError, subprocess.TimeoutExpired) as error:
                step['status'] = 'failed'
                step['error'] = str(error)
                log.write((str(error) + '\n').encode('utf-8'))
        step['duration_seconds'] = round(time.monotonic() - started, 3)
        if require_empty and log_path.stat().st_size:
            step['status'] = 'failed'
            step['error'] = 'Formatting changes are required; see the log.'
        save()
        print(f'{step["status"].upper()} {name}', flush=True)
        return step['status'] == 'passed'

    save()
    try:
        if args.prebuilt_tests:
            if target_os != 'windows':
                raise ValueError('--prebuilt-tests currently requires Windows test executables')
            for name in ('format', 'vet', 'coverage', 'race', 'build'):
                skip(name, 'Prebuilt mode: Go toolchain checks must be run separately on source.')
            for package in ('core', 'cli'):
                run(f'unit-{package}', [args.prebuilt_tests.resolve() / f'{package}.test.exe', '-test.v', '-test.timeout=3m'])
        else:
            run('go-version', ['go', 'version'])
            go_files = sorted(p for directory in ('cmd', 'internal') for p in (root / directory).rglob('*.go'))
            run('format', ['gofmt', '-l', *go_files], require_empty=True)
            run('vet', ['go', 'vet', './...'])
            if run('unit', ['go', 'test', '-count=1', '-json', f'-coverprofile={out / "coverage.out"}', './...']):
                run('coverage', ['go', 'tool', 'cover', f'-func={out / "coverage.out"}'])
            if (target_os, target_arch) == ('windows', 'arm64'):
                skip('race', 'The Go race detector does not support windows/arm64.')
            else:
                run('race', ['go', 'test', '-race', '-count=1', './...'], extra_env={'CGO_ENABLED': '1'})
            binary.parent.mkdir(parents=True, exist_ok=True)
            if not run('build', ['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', binary, './cmd/k957'],
                       extra_env={'CGO_ENABLED': '0'}):
                raise RuntimeError('Native build failed; integration tests were not started.')
        if not binary.is_file():
            raise FileNotFoundError(f'Test executable does not exist: {binary}')
        with binary.open('rb') as executable:
            receipt['binary_sha256'] = hashlib.file_digest(executable, 'sha256').hexdigest()
        run('version', [binary, 'version'])
        scripts = sorted((root / 'scripts').glob('*integration.py')) + [root / 'scripts/crypto_interop.py']
        for script in scripts:
            run(script.stem, [sys.executable, script])
        receipt['result'] = 'failed' if any(s['status'] == 'failed' for s in receipt['steps']) else 'passed'
    except (OSError, ValueError, RuntimeError) as error:
        receipt['result'] = 'failed'
        receipt['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(f'{receipt["result"].upper()}: {receipt["target"]} ({receipt["environment"]["kind"]}); {out}', flush=True)
    return 0 if receipt['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
