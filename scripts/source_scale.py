#!/usr/bin/env python3
"""Explicit synthetic source collection/case load check; never collects the host."""
import argparse
import csv
import datetime
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import time
import zipfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from test_support import default_binary, execution_environment


def payload(index):
    # Two byte-identical objects exercise duplicate grouping without huge reports.
    return ('synthetic source object %06d\n' % max(index, 1)).encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, default=default_binary())
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--objects', type=int, default=100000)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if not 2 <= args.objects <= 100000 or args.timeout < 1:
        parser.error('--objects must be 2..100000 and --timeout must be positive')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    receipt = {'schema': 'k957-source-scale/1', 'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'environment': execution_environment(), 'objects': args.objects, 'result': 'running', 'steps': [],
               'scope': 'Synthetic small regular files; full-mode filesystem collection, independent signatures/hashes, verification, case exports/index. No RAM, live system, OS profile or device acquisition.',
               'rss_method': 'Sampled Linux /proc/<pid>/status VmRSS every 50ms for the command process only; not exact peak, child processes or Go heap.'}
    with binary.open('rb') as stream:
        receipt['binary_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    receipt['build'] = json.loads(subprocess.check_output([binary, 'build-info']))
    receipt['script_sha256'] = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()

    def save():
        (out / 'scale.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')

    def run(name, command, cwd):
        step = {'name': name, 'status': 'running', 'stdout': name + '.json', 'stderr': name + '.log'}
        receipt['steps'].append(step)
        save()
        started = time.monotonic()
        print('RUN ' + name, flush=True)
        with (out / step['stdout']).open('wb') as stdout, (out / step['stderr']).open('wb') as stderr:
            with subprocess.Popen([str(binary), *map(str, command)], cwd=cwd, stdout=stdout, stderr=stderr) as process:
                peak = None
                while process.poll() is None:
                    try:
                        lines = pathlib.Path('/proc/%d/status' % process.pid).read_text(encoding='utf-8').splitlines()
                        for line in lines:
                            if line.startswith('VmRSS:'):
                                peak = max(peak or 0, int(line.split()[1]) * 1024)
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        pass
                    if time.monotonic() - started > args.timeout:
                        process.kill()
                        process.wait()
                        step['error'] = 'Command timeout'
                        break
                    time.sleep(0.05)
                step.update(exit_code=process.returncode, duration_seconds=round(time.monotonic() - started, 3),
                            sampled_rss_bytes=peak, status='passed' if process.returncode == 0 else 'failed')
        save()
        if step['status'] != 'passed':
            if name == 'collect':
                partial = json.loads((out / step['stdout']).read_text(encoding='utf-8'))
                receipt['collection_failure_issues'] = partial.get('issues', [])
                save()
            raise ValueError('%s failed; see retained log' % name)
        return json.loads((out / step['stdout']).read_text(encoding='utf-8'))

    save()
    try:
        with tempfile.TemporaryDirectory(prefix='k957-source-scale-') as temporary:
            root = pathlib.Path(temporary)
            source = root / 'source'
            source.mkdir()
            started = time.monotonic()
            for index in range(args.objects):
                directory = source / ('%03d' % (index // 1000))
                directory.mkdir(exist_ok=True)
                path = directory / ('object-%06d.bin' % index)
                path.write_bytes(payload(index))
                # Mix whole and fractional timestamps; export must sort numerically.
                stamp = 1704067200000000000 + index * 100000001
                os.utime(path, ns=(stamp, stamp))
            receipt['fixture_seconds'] = round(time.monotonic() - started, 3)
            record = run('collect', ['collect', '--full', '--root', source, '--output-dir', root / 'store',
                                     '--system=false', '--artifacts=false', '--memory=false', '--case', 'SYNTHETIC-SCALE',
                                     '--operator', 'Scale test', '--scope', 'Generated fixtures only', '--max-files', args.objects], root)
            if record['status'] != 'complete':
                raise ValueError('Collection was not complete')
            collection = pathlib.Path(record['directory'])
            signed = (collection / 'collection.json').read_bytes()
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(record['public_key'])).verify((collection / 'collection.sig').read_bytes(), signed)
            with zipfile.ZipFile(collection / 'evidence.k957') as archive:
                body = archive.read('manifest.json')
                manifest = json.loads(body)
                receipt['manifest_bytes'] = len(body)
                receipt['package_bytes'] = (collection / 'evidence.k957').stat().st_size
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(record['public_key'])).verify(archive.read('manifest.sig'), body)
                if manifest['status'] != 'complete' or len(manifest['items']) != args.objects:
                    raise ValueError('Signed manifest count/status mismatch')
                for item in manifest['items']:
                    index = int(pathlib.Path(item['source']).stem.split('-')[1])
                    expected = payload(index)
                    if archive.read(item['object']) != expected or pathlib.Path(item['source']).read_bytes() != expected:
                        raise ValueError('Acquired or original bytes differ from generated fixture')
                    if item['sha256'] != hashlib.sha256(expected).hexdigest() or item['size'] != len(expected):
                        raise ValueError('Signed content hash/size mismatch')
                digest = hashlib.sha256(body).hexdigest()
            verified = run('verify', ['verify', '--in', collection / 'evidence.k957', '--trusted-key', collection / 'signing.pub'], root)
            if (verified['integrity'] != 'verified' or verified['collection_status'] != 'complete' or
                    verified['items'] != args.objects or verified['signature'] != 'verified against supplied trusted key'):
                raise ValueError('Package verification failed')
            summary = run('case', ['case', '--store', root / 'store', '--out', root / 'case', '--trusted-key', collection / 'signing.pub'], root)
            if summary['items'] != args.objects or summary['verified'] != 1 or summary['failed'] != 0:
                raise ValueError('Case inventory/verification count mismatch')
            case = root / 'case'
            dossier = json.loads((case / 'case.json').read_text(encoding='utf-8'))
            if any(dossier[field] != summary[field] for field in ('items', 'verified', 'failed', 'collections')):
                raise ValueError('Case dossier and CLI counters disagree')
            for name, expected in [('inventory.csv', args.objects), ('timeline.csv', args.objects + 2)]:
                with (case / name).open(newline='', encoding='utf-8') as stream:
                    reader = csv.DictReader(stream)
                    count = 0
                    previous = None
                    for row in reader:
                        count += 1
                        if name == 'inventory.csv':
                            item = manifest['items'][count - 1]
                            if any(row[field] != str(item[key]) for field, key in
                                   [('evidence_id', 'id'), ('source', 'source'), ('size', 'size'), ('sha256', 'sha256')]):
                                raise ValueError('Inventory CSV content/source differs from signed manifest')
                        if name == 'timeline.csv':
                            date, _, fraction = row['time_utc'].removesuffix('Z').partition('.')
                            stamp = (datetime.datetime.fromisoformat(date), int((fraction + '000000000')[:9]))
                            if previous and stamp < previous:
                                raise ValueError('Timeline order is not chronological')
                            previous = stamp
                    if count != expected:
                        raise ValueError('%s row count differs: %d != %d' % (name, count, expected))
            with (case / 'bodyfile.txt').open() as stream:
                if sum(1 for _ in stream) != args.objects:
                    raise ValueError('Bodyfile row count mismatch')
            db = sqlite3.connect((case / 'case-index.sqlite').as_uri() + '?mode=ro', uri=True)
            try:
                if db.execute("SELECT count(*) FROM entries WHERE kind='inventory'").fetchone()[0] != args.objects:
                    raise ValueError('Derived inventory index count mismatch')
                receipt['index_rows'] = db.execute('SELECT count(*) FROM entries').fetchone()[0]
                if receipt['index_rows'] != args.objects * 3 + 2:
                    raise ValueError('Derived event/inventory/boundary count mismatch')
                row = db.execute("SELECT payload FROM entries WHERE kind='inventory' ORDER BY id DESC LIMIT 1").fetchone()
                if json.loads(row[0])['source'] != manifest['items'][-1]['source']:
                    raise ValueError('Last index source reference mismatch')
            finally:
                db.close()
            if len(dossier['duplicates']) != 1 or dossier['duplicates'][0]['count'] != 2:
                raise ValueError('Duplicate grouping mismatch')
            receipt['independent_checks'] = ['collection/manifest Ed25519 signatures', 'every acquired/source byte and signed SHA-256/size',
                                             'manifest, CSV, bodyfile and SQLite counts', 'chronological timeline', 'last inventory source reference', 'duplicate count']
            receipt['manifest_sha256'] = digest
            receipt['index_bytes'] = (case / 'case-index.sqlite').stat().st_size
            receipt['export_bytes'] = {name: (case / name).stat().st_size for name in
                                       ('inventory.csv', 'timeline.csv', 'examination.csv', 'bodyfile.txt')}
            receipt['result'] = 'passed'
    except (OSError, ValueError, KeyError, InvalidSignature, subprocess.SubprocessError, sqlite3.Error) as error:
        receipt['result'] = 'failed'
        receipt['error'] = str(error)
    finally:
        receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for step in receipt['steps']:
            for field in ('stdout', 'stderr'):
                path = out / step[field]
                if path.exists():
                    step[field + '_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        save()
    print(receipt['result'].upper() + ': ' + str(out), flush=True)
    return 0 if receipt['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
