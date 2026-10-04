#!/usr/bin/env python3
"""Check full memory suite orchestration and former caps with a synthetic tool.

This validates k957's I/O and receipts, not Volatility/kernel interpretation.
"""
import argparse
import datetime
import time
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from test_support import default_binary, executable_python_fixture


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--large-image-bytes', type=int, default=0)
    parser.add_argument('--out', type=pathlib.Path)
    parser.add_argument('--timeout', type=int, default=300, help='test harness deadline; external tool records remain uncapped')
    args = parser.parse_args()
    if args.timeout < 1 or args.large_image_bytes < 0:
        parser.error('--timeout must be positive and --large-image-bytes nonnegative')
    if os.name == 'nt' and not shutil.which('go'):
        print('SKIP: Windows synthetic executable fixture requires Go')
        return 77
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    tick = time.monotonic()
    binary = default_binary()
    build = json.loads(subprocess.check_output([str(binary), "build-info"], text=True))
    repo = pathlib.Path(__file__).resolve().parents[1]
    # An explicit large-image exercise uses the disk filesystem, not /tmp tmpfs.
    with tempfile.TemporaryDirectory(prefix='.k957-memory-suite-check-', dir=repo if args.large_image_bytes else None) as tmp:
        work = pathlib.Path(tmp)
        image = work / 'memory.raw'
        with image.open('wb') as output:
            output.write(b'Synthetic memory staging fixture\n')
            if args.large_image_bytes:
                output.truncate(args.large_image_bytes)
        before = digest(image)
        symbols = work / 'symbols'
        symbols.mkdir()
        (symbols / 'fixture.json').write_text('{}')
        tool = work / 'fixture-vol'
        tool = executable_python_fixture(tool, r'''
import json, pathlib, sys
if '--help' in sys.argv:
    if 'linux.pslist.PsList' in sys.argv:
        print('  --dump           Extract listed processes\n  --threads        Include threads')
    else:
        print('Plugins:\n    linux.pslist.PsList  fixture\n    linux.sockstat.Sockstat  fixture\n    linux.fail.Fail  fixture\n    windows.pslist.PsList  excluded')
    raise SystemExit(0)
name = next(arg for arg in sys.argv if arg.startswith(('linux.', 'windows.', 'banners.')))
assert '--offline' in sys.argv
assert pathlib.Path(sys.argv[sys.argv.index('-f')+1]).stat().st_size > 0
sys.stderr.write('diagnostic\n' * 9000)
if name == 'linux.fail.Fail':
    print('[]')
    raise SystemExit(3)
if name == 'linux.pslist.PsList':
    assert '--dump' in sys.argv and '--threads' in sys.argv
    pathlib.Path(sys.argv[sys.argv.index('-o')+1], 'recovered.bin').write_bytes(b'Synthetic recovered bytes')
    count = 100002
    row = json.dumps({'PID':7, 'fixture': 'x' * 350, '__children':[]})
    sys.stdout.write('[')
    for i in range(count):
        if i: sys.stdout.write(',')
        sys.stdout.write(row)
    sys.stdout.write(']')
else:
    print('[{"PID":8,"__children":[{"PID":9}]}]')
''')
        out = work / 'suite'
        command = [str(default_binary()), 'memory-examine', '--image', str(image), '--out', str(out),
                   '--sha256', before, '--tool', str(tool), '--symbols', str(symbols), '--platform', 'linux']
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        assert result.returncode == 1, result.stderr
        receipt = json.loads((out / 'memory-suite.json').read_text(encoding='utf-8'))
        assert receipt['status'] == 'partial' and len(receipt['examinations']) == 3
        by_name = {r['plugin']: r for r in receipt['examinations']}
        assert by_name['linux.pslist.PsList']['rows'] == 100002
        assert by_name['linux.sockstat.Sockstat']['status'] == 'interpreted'
        assert by_name['linux.fail.Fail']['status'] == 'failed'
        for name, run in by_name.items():
            assert run['tool']['timeout_seconds'] == 0
            folder = out / name
            assert (folder / 'tool.stderr').stat().st_size > 65536
            assert digest(folder / 'objects.json') == run['tool']['stdout_sha256']
            assert digest(folder / 'tool.stderr') == run['tool']['stderr_sha256']
        assert (out / 'linux.pslist.PsList/objects.json').stat().st_size > 32 << 20
        assert digest(image) == before
        for file in receipt['files']:
            assert digest(out / file['name']) == file['sha256']
        record = {'schema': 'k957-memory-suite-check/1', 'result': 'passed',
                  'started': started, 'duration_seconds': round(time.monotonic()-tick, 3),
                  'source_sha256': build['source_sha256'], 'target': build['target'],
                  'binary_sha256': digest(binary),
                  'dump_and_threads_enabled': True,
                  'staging_outside_system_tmp': not by_name['linux.pslist.PsList']['tool']['args'][by_name['linux.pslist.PsList']['tool']['args'].index('-f')+1].startswith(tempfile.gettempdir() + os.sep),
                  'image_bytes': image.stat().st_size, 'image_sha256': before,
                  'tool_kind': 'synthetic orchestration fixture; no kernel-object accuracy claim',
                  'plugin_attempts': 3, 'retained_partial_failure': True,
                  'largest_object_file_bytes': (out / 'linux.pslist.PsList/objects.json').stat().st_size,
                  'largest_row_count': 100002, 'automatic_timeout_seconds': 0,
                  'source_unchanged': True}
        if args.out:
            args.out.write_text(json.dumps(record, indent=2) + '\n')
    print('PASS: full suite, >32 MiB output, >100k rows, >64 KiB diagnostics, partial failure, no automatic timeout, unchanged source')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
