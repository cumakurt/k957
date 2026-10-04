#!/usr/bin/env python3
"""Verify signed external RAM analysis/case export without temporary storage."""
import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from test_support import default_binary


def main():
    binary = str(default_binary())
    with tempfile.TemporaryDirectory(prefix='k957-memory-stream-') as directory:
        root = pathlib.Path(directory)
        payload = b'Linux version 1.2.3-synthetic\nfailed password\n'
        payload += b'\0' * (4096 - len(payload))
        image = struct.pack('<IIQQQ', 0x4C694D45, 1, 0x100000, 0x100fff, 0) + payload
        source = root / 'synthetic.lime'
        source.write_bytes(image)
        tool = root / 'acquire.py'
        tool.write_text('import pathlib, sys\npathlib.Path(sys.argv[2]).write_bytes(pathlib.Path(sys.argv[1]).read_bytes())\n', encoding='utf-8')

        def run(*args, env=None):
            result = subprocess.run([binary, *map(str, args)], cwd=root, env=env,
                                    capture_output=True, text=True, encoding='utf-8', timeout=120)
            assert result.returncode == 0, (args, result.stderr)
            return json.loads(result.stdout)

        store = root / 'store'
        collected = run('collect', '--full', '--output-dir', store, '--system=false', '--artifacts=false',
                        '--memory-tool', sys.executable, '--memory-tool-arg', tool,
                        '--memory-tool-arg', source, '--memory-tool-arg', '{output}',
                        '--memory-limit', 1 << 20, '--reserve', 0,
                        '--case', 'SYNTHETIC', '--operator', 'Test', '--scope', 'Synthetic memory stream only')
        collection = pathlib.Path(collected['directory'])
        body = (collection / 'collection.json').read_bytes()
        record = json.loads(body)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(record['public_key'])).verify(
            (collection / 'collection.sig').read_bytes(), body)
        assert record['status'] == 'complete' and not record.get('evidence')
        memory = collection / record['memory']['image']
        expected = hashlib.sha256(image).hexdigest()
        assert record['memory']['sha256'] == expected and memory.read_bytes() == image
        originals = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in collection.iterdir() if p.is_file()}
        unavailable = str(root / 'unavailable-temp')
        environment = dict(os.environ, TMPDIR=unavailable, TEMP=unavailable, TMP=unavailable)
        assert run('verify', '--store', store, env=environment)['verified'] == 1
        result = run('analyze', '--store', store, env=environment)
        assert result['analyzed'] == 1 and result['failed'] == 0
        report = pathlib.Path(result['collections'][0]['report'])
        analysis = json.loads((report / 'analysis.json').read_text(encoding='utf-8'))
        scanned = analysis['memories'][0]
        assert scanned['sha256'] == expected and scanned['bytes'] == len(payload) and scanned['format'] == 'lime'
        assert any(hit['rule'] == 'failed-password' and hit['physical'] == 0x100000 + payload.index(b'failed password')
                   for hit in scanned['hits'])
        assert any('no temporary image copy' in note for note in scanned['notes'])
        case = root / 'case'
        run('case', '--store', store, '--out', case, env=environment)
        assert (case / 'case-index.sqlite').is_file() and (case / 'report.html').is_file()
        assert all(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p, digest in originals.items())
        assert not pathlib.Path(unavailable).exists()
    print('PASS: signed external LiME, unavailable temp directory, store analysis/case export, exact hash/physical references and unchanged evidence')


if __name__ == '__main__':
    main()
