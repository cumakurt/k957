#!/usr/bin/env python3
"""Independent checks for full-mode layout, signatures, hashes and LiME v1."""
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from test_support import default_binary

exe = str(default_binary())
LIME_MAGIC = 0x4C694D45


def run(args, cwd, expect=0):
    result = subprocess.run([exe, *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode != expect:
        raise SystemExit(f'{args} exit {result.returncode}, expected {expect}\n{result.stdout}\n{result.stderr}')
    return result


def parse_lime(data):
    ranges = []
    offset = 0
    while offset < len(data):
        if offset + 32 > len(data):
            raise SystemExit('truncated LiME header')
        magic, version, start, last, _reserved = struct.unpack_from('<IIQQQ', data, offset)
        if magic != LIME_MAGIC or version != 1 or last < start:
            raise SystemExit(f'bad LiME header at {offset}')
        size = last - start + 1
        offset += 32
        if offset + size > len(data):
            raise SystemExit('truncated LiME range')
        ranges.append((start, data[offset:offset + size]))
        offset += size
    if offset != len(data) or not ranges:
        raise SystemExit('LiME trailing bytes or empty image')
    return ranges


def check_sums(directory):
    listed = {}
    for line in (directory / 'SHA256SUMS').read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ', 1)
        listed[name] = digest
    present = {}
    for path in directory.rglob('*'):
        if not path.is_file():
            continue
        rel = path.relative_to(directory).as_posix()
        if rel == 'SHA256SUMS' or rel == 'reports' or rel.startswith('reports/'):
            continue
        present[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    if present != listed:
        raise SystemExit(f'SHA256SUMS mismatch\nlisted {sorted(listed)}\npresent {sorted(present)}')


def verify_signature(directory):
    body = (directory / 'collection.json').read_bytes()
    signature = (directory / 'collection.sig').read_bytes()
    record = json.loads(body)
    public = bytes.fromhex(record['public_key'])
    published = bytes.fromhex((directory / 'signing.pub').read_text(encoding='utf-8').strip())
    if public != published or len(signature) != 64:
        raise SystemExit('signing.pub does not match the collection record')
    Ed25519PublicKey.from_public_bytes(public).verify(signature, body)
    return record


def main():
    with tempfile.TemporaryDirectory(prefix='k957-full-') as tmp:
        root = pathlib.Path(tmp)
        source = root / 'source'
        source.mkdir()
        marker = b'failed password for integration'
        payload = b'Linux version 1.2.3-integration\n' + marker + b'\n'
        payload += b'\0' * (4096 - len(payload))
        image = struct.pack('<IIQQQ', LIME_MAGIC, 1, 0x100000, 0x100000 + len(payload) - 1, 0) + payload
        (source / 'memory.lime').write_bytes(image)
        (source / 'auth.log').write_bytes(b'2026-09-29T00:00:00Z failed password for integration\n')
        run(['collect', '--full', '--root', str(source), '--output-dir', 'output', '--system=false', '--artifacts=false', '--memory=false', '--case', 'INT', '--operator', 'INT', '--scope', 'INT'], root)
        hosts = [p for p in (root / 'output').iterdir() if p.is_dir()]
        stamps = [p for p in hosts[0].iterdir() if p.is_dir()]
        if len(hosts) != 1 or len(stamps) != 1:
            raise SystemExit(f'expected one collection, found {hosts} {stamps}')
        collection = stamps[0]
        record = verify_signature(collection)
        if record['schema'] != 'k957-collection/1' or record['status'] != 'complete' or record['full'] is not True:
            raise SystemExit(f'unexpected collection record {record["schema"]} {record["status"]}')
        if len(record.get('collector_sha256', '')) != 64:
            raise SystemExit('collector_sha256 missing from collection record')
        check_sums(collection)
        run(['verify'], root)
        run(['analyze'], root)
        check_sums(collection)
        reports = list((collection / 'reports').iterdir())
        analysis = json.loads((reports[0] / 'analysis.json').read_text(encoding='utf-8'))
        memories = analysis['memories']
        if len(memories) != 1 or memories[0]['kernel_banner'] != 'Linux version 1.2.3-integration':
            raise SystemExit(f'unexpected memory analysis {memories}')
        hits = [h for h in memories[0]['hits'] if h['rule'] == 'failed-password' and h['encoding'] == 'ascii']
        if not hits or hits[0]['physical'] != 0x100000 + payload.index(marker):
            raise SystemExit(f'LiME hit was not reported at the physical address: {hits}')
        for name in ('report.html', 'findings.csv', 'timeline.csv', 'correlations.csv', 'memory.csv', 'memory-hits.csv', 'memory-observations.csv', 'rules.json', 'verification.json', 'filetypes.csv', 'hash-matches.csv', 'bodyfile.txt', 'persistence.csv', 'activity.csv'):
            if not (reports[0] / name).is_file():
                raise SystemExit(f'missing report file {name}')
        if not (reports[0] / 'shared' / 'shared.json').is_file():
            raise SystemExit('missing shared report')
        # A second pass re-parses the acquired object from the zip through the CLI verify.
        run(['verify', '--in', str(collection / 'evidence.k957'), '--trusted-key', str(collection / 'signing.pub')], root)
        signature = collection / 'collection.sig'
        signature.write_bytes(b'\0' * 64)
        run(['verify'], root, expect=1)
    print('PASS: full-mode layout, Ed25519 collection signature, SHA256SUMS, LiME physical hit, reports, tamper rejection')


if __name__ == '__main__':
    main()
