#!/usr/bin/env python3
"""Synthetic USN byte fixtures through acquisition, reports, case queries and signed selections."""
import csv
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess
import tempfile
from test_support import default_binary


def main():
    exe = str(default_binary())
    def run(*args):
        p = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        return p.stdout

    with tempfile.TemporaryDirectory(prefix='k957-usn-') as tmp:
        root = pathlib.Path(tmp)
        source = root / 'source'
        source.mkdir()
        records = []
        for version in (2, 3):
            offset = 24 if version == 2 else 40
            header = offset + 36
            name = f'fixture-v{version}.txt'.encode('utf-16-le')
            body = bytearray((header + len(name) + 7) & ~7)
            struct.pack_into('<IHH', body, 0, len(body), version, 0)
            body[8] = 0xab
            struct.pack_into('<QQI', body, offset, 4096 + version, 13348540800000000, 0x100)
            struct.pack_into('<HH', body, offset + 32, len(name), header)
            body[header:header + len(name)] = name
            records.append(body)
        original = b''.join(records)
        journal = source / 'fixture.usn'
        journal.write_bytes(original)
        store, report, case = root / 'store', root / 'report', root / 'case'
        run('collect', '--full', '--root', source, '--output-dir', store,
            '--system=false', '--artifacts=false', '--memory=false', '--case', 'Synthetic USN', '--operator', 'Test', '--scope', 'Synthetic only')
        collection = next(store.rglob('evidence.k957'))
        run('analyze', '--in', collection, '--out', report)
        analysis = json.loads((report / 'analysis.json').read_text(encoding='utf-8'))
        events = [e for e in analysis['timeline'] if e.get('usn')]
        assert len(events) == 2, events
        assert {e['native']['record'] for e in events} == {'4098', '4099'}
        groups = json.loads((report / 'usn-files.json').read_text(encoding='utf-8'))
        assert len(groups['groups']) == 2
        assert groups['source_analysis_digest'] == hashlib.sha256((report / 'analysis.json').read_bytes()).hexdigest()
        with (report / 'usn-files.csv').open() as f:
            assert len(list(csv.DictReader(f))) == 2
        assert 'fixture-v2.txt' in (report / 'report.html').read_text(encoding='utf-8')
        assert (report / 'report.pdf').read_bytes().startswith(b'%PDF')
        if shutil.which('pdftotext'):
            text = subprocess.check_output(['pdftotext', '-enc', 'UTF-8', str(report / 'report.pdf'), '-'], text=True, encoding='utf-8')
            assert 'fixture-v2.txt' in text and 'fixture-v3.txt' in text
        run('case', '--store', store, '--out', case)
        page = json.loads(run('case-query', '--case', case, '--native-parser', 'USN', '--native-record', '4098'))
        assert len(page['rows']) == 1, page
        row = page['rows'][0]
        file_id = row['payload']['usn']['file_id_le_hex']
        args = ['--native-parser', 'USN', '--native-record', '4098', '--usn-file-id', file_id.upper(),
                '--digest', row['collection_digest'], '--evidence', row['evidence']]
        scoped = json.loads(run('case-query', '--case', case, *args))
        assert len(scoped['rows']) == 1
        run('keygen', '--out', root / 'key')
        run('case-bookmark', '--case', case, '--out', root / 'selection', '--title', 'USN fixture', '--analyst', 'Test',
            '--note', 'Exact synthetic record', '--sign-key', root / 'key.key', *args)
        run('report-verify', '--report', root / 'selection', '--trusted-key', root / 'key.pub')
        assert journal.read_bytes() == original
    print('PASS: synthetic USN v2/v3 collection, worker analysis, JSON/CSV/HTML/PDF, exact case filters, signed selection; original bytes unchanged')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
