#!/usr/bin/env python3
"""Compare a generated ext2 deleted-file recovery against independently saved bytes."""
import argparse
import os
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

from test_support import default_binary


def prepare_fixture(root, tools):
    image = root / 'reference.raw'
    with image.open('wb') as stream:
        stream.truncate(16 << 20)
    subprocess.run([tools['mke2fs'], '-q', '-F', '-t', 'ext2', str(image)], check=True, capture_output=True)
    payload = b'Synthetic deleted-file reference\n' * 40
    original = root / 'original.txt'
    original.write_bytes(payload)
    command = f'write {original} deleted.txt'
    subprocess.run([tools['debugfs'], '-w', '-R', command, str(image)], check=True, capture_output=True)
    stat = subprocess.run([tools['debugfs'], '-R', 'stat deleted.txt', str(image)], check=True, capture_output=True, text=True)
    inode = re.search(r'Inode:\s+(\d+)', stat.stdout).group(1)
    subprocess.run([tools['debugfs'], '-w', '-R', 'rm deleted.txt', str(image)], check=True, capture_output=True)
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    (root / 'fixture.json').write_text(json.dumps({'sha256': digest, 'inode': inode,
        'payload_sha256': hashlib.sha256(payload).hexdigest()}), encoding='utf-8')
    return image, payload, inode, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-fixture', type=pathlib.Path)
    args = parser.parse_args()

    tools = {name: shutil.which(name) for name in ('mke2fs', 'debugfs', 'fls', 'icat')}
    if args.prepare_fixture:
        if not tools['mke2fs'] or not tools['debugfs']:
            raise RuntimeError('Fixture preparation requires mke2fs and debugfs')
        args.prepare_fixture.mkdir(parents=True, exist_ok=False)
        prepare_fixture(args.prepare_fixture, tools)
        print('Prepared synthetic ext2 fixture with independent bytes and hashes')
        return 0
    required = ('fls', 'icat') if os.environ.get('K957_DISK_FIXTURE') else tuple(tools)
    if not all(tools[name] for name in required):
        print('SKIP: native ext2/Sleuth Kit tools unavailable')
        return 77
    exe = str(default_binary())
    with tempfile.TemporaryDirectory(prefix='k957-disk-reference-') as tmp:
        root = pathlib.Path(tmp)
        image = root / 'reference.raw'
        external = os.environ.get('K957_DISK_FIXTURE')
        if external:
            fixture = pathlib.Path(external)
            metadata = json.loads((fixture / 'fixture.json').read_text(encoding='utf-8'))
            shutil.copyfile(fixture / 'reference.raw', image)
            payload = (fixture / 'original.txt').read_bytes()
            inode, digest = metadata['inode'], metadata['sha256']
            assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
            assert hashlib.sha256(payload).hexdigest() == metadata['payload_sha256']
        else:
            image, payload, inode, digest = prepare_fixture(root, tools)
        def run(*args):
            return subprocess.run([exe, *map(str, args)], check=True, capture_output=True, text=True, timeout=150)
        report = root / 'examination'
        run('disk-examine', '--image', image, '--sha256', digest, '--out', report, '--tool', tools['fls'])
        result = json.loads((report / 'disk.json').read_text(encoding='utf-8'))
        assert result['status'] == 'interpreted'
        deleted = [row for row in result['entries'] if row['name'] == 'deleted.txt']
        assert len(deleted) == 1 and deleted[0]['deleted_directory_entry'] and deleted[0]['inode'] == inode
        assert result['tool']['stdout_sha256'] == hashlib.sha256((report / 'listing.txt').read_bytes()).hexdigest()
        recovery = root / 'recovery'
        run('disk-recover', '--image', image, '--sha256', digest, '--out', recovery, '--inode', inode, '--tool', tools['icat'])
        receipt = json.loads((recovery / 'recovery.json').read_text(encoding='utf-8'))
        assert receipt['status'] == 'interpreted'
        assert (recovery / 'recovered.bin').read_bytes() == payload
        assert receipt['recovered_sha256'] == hashlib.sha256(payload).hexdigest()
        assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        bad = subprocess.run([exe, 'disk-recover', '--image', str(image), '--sha256', 'a' * 64, '--out', str(root / 'bad'), '--inode', inode], capture_output=True)
        assert bad.returncode and not (root / 'bad').exists()
        failed_out = root / 'invalid-inode'
        failed = subprocess.run([exe, 'disk-recover', '--image', str(image), '--sha256', digest,
                                 '--out', str(failed_out), '--inode', '999999999', '--tool', tools['icat']], capture_output=True)
        assert failed.returncode and not (failed_out / 'recovered.bin').exists()
        failure = json.loads((failed_out / 'recovery.json').read_text(encoding='utf-8'))
        assert failure['status'] == 'failed' and failure['tool']['exit_code'] != 0
        assert failure['recovered_sha256'] == '' and failure['recovered_bytes'] == 0
        assert failure['tool']['stdout_sha256'] == hashlib.sha256((failed_out / 'recovered.partial.bin').read_bytes()).hexdigest()
        assert failure['tool']['stderr_sha256'] == hashlib.sha256((failed_out / 'tool.stderr').read_bytes()).hexdigest()
    print('PASS: generated ext2 directory/deleted inode, exact recovery and unchanged image; no physical device assurance')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
