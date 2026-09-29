#!/usr/bin/env python3
"""Read-only planning and gated collection through the native CLI."""
from test_support import default_binary
import hashlib
import json
import shutil
import pathlib
import subprocess
import tempfile
import zipfile

base = pathlib.Path(__file__).resolve().parents[1]
exe = str(default_binary())
with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory)
    root = p / 'source'
    root.mkdir()
    source = root / 'data.txt'
    source.write_bytes(b'Synthetic source\n' * 100)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    out, work = p / 'case.k957', p / 'work'

    def run(*args, code=0):
        result = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, encoding="utf-8")
        assert result.returncode == code, (args, result.stderr, result.stdout)
        return result

    args = ['preflight', '--root', root, '--out', out, '--work', work, '--reserve', '0']
    result = json.loads(run(*args).stdout)
    assert result['outcome'] == 'warning'  # This fixture shares one filesystem.
    assert result['eligible_files'] == 1 and result['eligible_bytes'] == source.stat().st_size
    assert len(result['storage']) == 1
    budget = result['storage'][0]
    assert budget['roles'] == ['output', 'work']
    assert budget['estimated_with_reserve_bytes'] == result['estimated_output_bytes'] + result['estimated_work_bytes']
    native = shutil.disk_usage(p)
    assert abs(budget['available_bytes'] - native.free) < 64 * 1024 * 1024
    encrypted = json.loads(run(*args, '--encrypted').stdout)
    assert encrypted['estimated_output_bytes'] > result['estimated_output_bytes']
    assert encrypted['estimated_work_bytes'] > result['estimated_work_bytes']
    limited = json.loads(run(*args, '--max-file', '1').stdout)
    assert limited['eligible_files'] == 0 and limited['inventory_issues']
    blocked = json.loads(run('preflight', '--root', root, '--out', root / 'bad', code=1).stdout)
    assert blocked['outcome'] == 'blocked'
    run('collect', '--root', root, '--out', root / 'bad', '--work', work,
        '--case', 'TEST', '--operator', 'Tester', '--scope', 'Synthetic', '--check-space', code=1)
    assert not out.exists() and not work.exists() and not (root / 'bad').exists()
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    run('collect', '--root', root, '--out', out, '--work', work, '--case', 'TEST',
        '--operator', 'Tester', '--scope', 'Synthetic', '--check-space', '--reserve', '0')
    run('verify', '--in', out)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    checkpoint = (work / 'state.json').read_bytes()
    resumed_out = p / 'resumed.k957'
    resume_args = ['preflight', '--resume', '--root', root, '--out', resumed_out, '--work', work, '--reserve', '0']
    completed = json.loads(run(*resume_args).stdout)
    assert completed['resume'] and completed['completed_files'] == 1
    assert completed['acquired_bytes'] == source.stat().st_size
    assert completed['remaining_bytes'] == 0 and completed['remaining_parts'] == 0
    assert completed['estimated_work_bytes'] < result['estimated_work_bytes']
    assert completed['estimated_output_bytes'] == result['estimated_output_bytes']
    assert checkpoint == (work / 'state.json').read_bytes() and not resumed_out.exists()
    (work / 'active.lock').write_text('owned test lock', encoding='utf-8')
    locked = json.loads(run(*resume_args, code=1).stdout)
    assert locked['outcome'] == 'blocked' and any(c['code'] == 'WORK_LOCK_PRESENT' for c in locked['checks'])
    collect_args = ['collect', '--resume', '--root', root, '--out', resumed_out, '--work', work,
                    '--case', 'TEST', '--operator', 'Tester', '--scope', 'Synthetic', '--check-space', '--reserve', '0']
    run(*collect_args, code=1)
    assert checkpoint == (work / 'state.json').read_bytes() and not resumed_out.exists()
    (work / 'active.lock').unlink()  # This fixture created the lock without a collector.
    source.unlink()
    (root / 'later.txt').write_text('outside the frozen inventory', encoding='utf-8')
    frozen = json.loads(run(*resume_args).stdout)
    assert frozen['eligible_files'] == 1 and frozen['acquired_bytes'] == completed['acquired_bytes']
    run(*collect_args)
    run('verify', '--in', resumed_out)
    with zipfile.ZipFile(resumed_out) as package:
        manifest = json.loads(package.read('manifest.json'))
        assert len(manifest['items']) == 1 and len(manifest['epochs']) == 2
        assert hashlib.sha256(package.read(manifest['items'][0]['object'])).hexdigest() == before
    print('PASS: metadata-only plan, native free space, combined budget, encrypted allowance, exclusions, overlap gate, remaining-space estimate, lock gate, completed frozen inventory reuse, verified collection')
