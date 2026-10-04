#!/usr/bin/env python3
"""Independent SQLite/WAL, EVTX, plist and Registry checks against parser workers."""
import hashlib
import datetime
import json
import pathlib
import plistlib
import shutil
import sqlite3
import subprocess
import struct
import sys
import tempfile
import xml.etree.ElementTree as ET

from Evtx.Evtx import Evtx
from Registry import Registry
from test_support import default_binary

EXE = str(default_binary())
ROOT = pathlib.Path(__file__).resolve().parents[1]


def registry_fixture():
    """Generated clean primary REGF hive containing a synthetic string value."""
    body = bytearray(8192)
    body[:4] = b'regf'
    for offset, value in {4: 1, 8: 1, 20: 1, 24: 5, 32: 1, 36: 32, 40: 4096, 44: 1}.items():
        struct.pack_into('<I', body, offset, value)
    body[4096:4100] = b'hbin'
    struct.pack_into('<I', body, 4104, 4096)
    cursor = 32

    def cell(payload):
        nonlocal cursor
        offset = cursor
        size = (len(payload) + 11) & ~7
        struct.pack_into('<i', body, 4096 + offset, -size)
        body[4100 + offset:4100 + offset + len(payload)] = payload
        cursor += size
        return offset

    nk = bytearray(80)
    nk[:2] = b'nk'
    struct.pack_into('<H', nk, 2, 0x2c)
    struct.pack_into('<Q', nk, 4, 133485408001234567)
    for offset, value in {16: 0xffffffff, 28: 0xffffffff, 32: 0xffffffff, 36: 1}.items():
        struct.pack_into('<I', nk, offset, value)
    struct.pack_into('<H', nk, 72, 4)
    nk[76:] = b'TEST'
    root = cell(nk)
    raw = 'synthetic\0'.encode('utf-16-le')
    vk = bytearray(23)
    vk[:2] = b'vk'
    struct.pack_into('<H', vk, 2, 3)
    struct.pack_into('<I', vk, 4, len(raw))
    struct.pack_into('<I', vk, 12, 1)
    struct.pack_into('<H', vk, 16, 1)
    vk[20:] = b'Run'
    value = cell(vk)
    values = cell(struct.pack('<I', value))
    data = cell(raw)
    struct.pack_into('<I', body, 4100 + root + 40, values)
    struct.pack_into('<I', body, 4100 + value + 8, data)
    struct.pack_into('<i', body, 4096 + cursor, 4096 - cursor)
    checksum = 0
    for offset in range(0, 508, 4):
        checksum ^= struct.unpack_from('<I', body, offset)[0]
    checksum = 1 if checksum == 0 else 0xfffffffe if checksum == 0xffffffff else checksum
    struct.pack_into('<I', body, 508, checksum)
    return bytes(body)


def run(*args):
    result = subprocess.run([EXE, *map(str, args)], capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise AssertionError(f'{args}: {result.stderr}')
    return result.stdout


def main():
    fixture = ROOT / 'internal/core/testdata/Security_1_record.evtx'
    with Evtx(str(fixture)) as log:
        records = list(log.records())
        assert len(records) == 1
        original = records[0]
        reference = ET.fromstring(original.xml())
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        event_id = int(reference.find('e:System/e:EventID', ns).text)
        record_id = reference.find('e:System/e:EventRecordID', ns).text
        offset = original.offset()
    with tempfile.TemporaryDirectory(prefix='k957-native-') as tmp:
        work = pathlib.Path(tmp)
        source = work / 'source'
        source.mkdir()
        path = source / 'History'
        db = sqlite3.connect(path)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA wal_autocheckpoint=0')
            db.executescript('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER);'
                             'CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);')
            db.execute('INSERT INTO urls VALUES(1,?,?,?)', ('https://example.test/visited', 'Synthetic visit', 13348540800000000))
            db.execute('INSERT INTO visits VALUES(7,1,13348540800000000)')
            db.commit()
            # No concurrent writes occur here. This tests WAL use, not atomic
            # acquisition of an actively changing database.
            shutil.copyfile(fixture, source / 'Security.evtx')
            bad = bytearray(fixture.read_bytes())
            bad[4608] ^= 1
            (source / 'corrupt.evtx').write_bytes(bad)
            launchd = {'Label': 'test.synthetic', 'ProgramArguments': ['/bin/echo', 'Café'],
                       'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False}}
            (source / 'synthetic.plist').write_bytes(plistlib.dumps(launchd, fmt=plistlib.FMT_BINARY))
            assert plistlib.loads((source / 'synthetic.plist').read_bytes()) == launchd
            hive_path = source / 'synthetic.hive'
            hive_path.write_bytes(registry_fixture())
            oracle = Registry.Registry(str(hive_path)).root()
            assert oracle.name() == 'TEST' and oracle.values()[0].name() == 'Run'
            assert oracle.values()[0].value() == 'synthetic'
            originals = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()}
            package = work / 'evidence.k957'
            run('collect', '--root', source, '--out', package, '--case', 'REFERENCE', '--operator', 'Test', '--scope', 'Synthetic fixtures')
            report = work / 'report'
            run('analyze', '--in', package, '--out', report)
            analysis = json.loads((report / 'analysis.json').read_text(encoding='utf-8'))
            visits = [e for e in analysis['timeline'] if e['type'] == 'browser_visit']
            assert len(visits) == 1 and visits[0]['native']['record'] == '7'
            assert visits[0]['time'] == '2024-01-01T00:00:00Z'
            assert visits[0]['original_time'] == '13348540800000000'
            events = [e for e in analysis['timeline'] if e['type'] == 'windows_event']
            assert len(events) == 1, analysis.get('parser_runs')
            assert events[0]['windows']['event_id'] == event_id
            assert events[0]['windows']['record_id'] == record_id
            assert events[0]['byte_offset'] == offset
            plist_events = [e for e in analysis['timeline'] if e.get('native', {}).get('parser') == 'binaryplist']
            assert len(plist_events) == 1, analysis.get('parser_runs')
            assert plist_events[0]['launchd']['arguments'] == launchd['ProgramArguments']
            assert plist_events[0]['launchd']['omitted_properties'] == 1
            registry_events = [e for e in analysis['timeline'] if e['type'] == 'registry_key_modified']
            assert len(registry_events) == 1, analysis.get('parser_runs')
            registry = registry_events[0]
            assert registry['registry']['key'] == oracle.name()
            assert registry['registry']['values'][0]['text'] == oracle.values()[0].value()
            # The independent library uses floating-point microseconds. Compare
            # within that precision and separately assert the fixture's exact ticks.
            projected = datetime.datetime.fromisoformat(registry['time'].replace('Z', '+00:00')).replace(tzinfo=None)
            assert abs((projected - oracle.timestamp()).total_seconds()) <= 0.000001
            assert registry['time'] == '2024-01-01T00:00:00.1234567Z'
            assert registry['original_time'] == '133485408001234567'
            assert registry['byte_offset'] == 4132
            parsers = analysis['parser_runs']
            browser = next(p for p in parsers if p['format'] == 'SQLite')
            assert any(p['role'] == '-wal' for p in browser['inputs'])
            assert all(p['security']['process_isolation'] for p in parsers if not p.get('error'))
            if sys.platform == 'linux':
                assert browser['security']['network_blocked'] and browser['security']['cpu_limit']
            corrupt = next(p for p in parsers if p['inputs'][0]['source'].endswith('corrupt.evtx'))
            assert 'checksum' in corrupt['error']
            coverage = next(p for p in analysis['coverage'] if p.get('format') == 'EVTX')
            assert coverage['status'] == 'partial' and not coverage['total_known']
            assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()} == originals
            logical_package = work / 'logical.k957'
            manifest = json.loads(run('sqlite-acquire', '--in', path, '--out', logical_package,
                                      '--case', 'REFERENCE', '--operator', 'Test', '--scope', 'Synthetic SQLite backup'))
            guarantee = manifest['acquisition']
            assert guarantee['origin'] == 'logical_backup' and guarantee['sqlite_transaction_consistent']
            assert not guarantee['filesystem_snapshot'] and not guarantee['multi_file_atomic']
            logical_report = work / 'logical-report'
            run('analyze', '--in', logical_package, '--out', logical_report)
            logical = json.loads((logical_report / 'analysis.json').read_text(encoding='utf-8'))
            assert len([e for e in logical['timeline'] if e['type'] == 'browser_visit']) == 1
        finally:
            db.close()
    print('PASS: WAL, independent EVTX/plist/Registry projections, corruption, immutable source, logical backup')


if __name__ == '__main__':
    main()
