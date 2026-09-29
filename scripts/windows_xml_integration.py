#!/usr/bin/env python3
"""Independently check XML event metadata, original byte offsets and redaction."""
import csv
import hashlib
import json
import pathlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from test_support import default_binary

exe = str(default_binary())
namespace = 'http://schemas.microsoft.com/win/2004/08/events/event'
event = f'''<Event xmlns="{namespace}"><System><Provider Name="=PrivateProvider957" Guid="PrivateGUID957"/><EventID Qualifiers="32768">4624</EventID><Version>0</Version><Level>4</Level><TimeCreated SystemTime="2026-09-29T14:02:03.1234567+03:00"/><EventRecordID>18446744073709551615</EventRecordID><Channel>PrivateChannel957</Channel><Computer>PrivateHost957.</Computer><Security UserID="S-1-5-21-987654321"/></System><EventData><Data Name="Repeated">PrivateData957</Data><Data Name="Repeated">İstanbul 😀</Data></EventData><RenderingInfo><Message>&lt;script&gt;PrivateMessage957&lt;/script&gt;</Message></RenderingInfo><UserData><Ignored>PrivateIgnored957</Ignored></UserData></Event>'''
# A separate XML implementation provides the field oracle. It is used only on
# these fixed synthetic fixtures, never on untrusted evidence.
parsed = ET.fromstring(event)
expected_data = [{'name': item.attrib.get('Name', ''), 'value': item.text or ''}
                 for item in parsed.findall(f'{{{namespace}}}EventData/{{{namespace}}}Data')]

with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory)
    root = p / 'source'
    root.mkdir()
    offsets = {}
    contents = {}
    for name, encoding, bom, declaration in [
        ('utf8.xml', 'utf-8', b'\xef\xbb\xbf', 'UTF-8'),
        ('utf16le.XML', 'utf-16le', b'\xff\xfe', 'UTF-16'),
        ('utf16be.xml', 'utf-16be', b'\xfe\xff', 'UTF-16BE'),
    ]:
        prefix = f'<?xml version="1.0" encoding="{declaration}"?>\n<Events>\n<!--' + '😀ö' * 1100 + '-->\n'
        raw = bom + (prefix + event + '\n</Events>').encode(encoding)
        (root / name).write_bytes(raw)
        contents[name] = raw
        offsets[name] = len(bom + prefix.encode(encoding))
    invalid = event.replace('2026-09-29T14:02:03.1234567+03:00', '2026-09-29T14:02:03')
    # Explicit bytes keep the independent offset oracle portable across shells/OSes.
    fragment_prefix = (invalid + '\r\n').encode('utf-8')
    (root / 'fragments.xml').write_bytes(fragment_prefix + event.encode('utf-8'))
    (root / 'truncated.xml').write_text(event + f'<Event xmlns="{namespace}"><System>', encoding='utf-8')
    (root / 'doctype.xml').write_text('<!DOCTYPE Event [<!ENTITY secret SYSTEM "file:///not-read">]>' + event, encoding='utf-8')
    (root / 'native.evtx').write_bytes(b'ElfFile\x00\x00synthetic binary marker')
    (root / 'peer.jsonl').write_text(json.dumps({'timestamp': '2026-09-29T11:02:03Z',
        'user': 'S-1-5-21-987654321', 'host': 'privatehost957'}), encoding='utf-8')
    rules = p / 'rules.json'
    rules.write_text(json.dumps([{'id': 'unicode', 'contains': 'İstanbul'}]), encoding='utf-8')

    def run(*args):
        return subprocess.run([exe, *map(str, args)], check=True, capture_output=True, text=True, encoding='utf-8')

    package = p / 'case.k957'
    run('collect', '--root', root, '--out', package, '--case', 'XML', '--operator', 'Test', '--scope', 'Synthetic XML')
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    report = p / 'report'
    run('analyze', '--in', package, '--rules', rules, '--out', report)
    analysis = json.loads((report / 'analysis.json').read_text(encoding='utf-8'))
    events = [e for e in analysis['timeline'] if e['type'] == 'windows_event']
    assert len(events) == 5, events
    for e in events:
        w = e['windows']
        assert w['data'] == expected_data
        assert w['event_id'] == 4624 and w['qualifiers'] == 32768
        assert w['record_id'] == '18446744073709551615'
        assert w['level'] == 4 and w['version'] == 0 and w['payload_omitted']
        assert e['time'] == '2026-09-29T11:02:03.1234567Z'
        assert e['host'] == 'privatehost957' and e['user'] == 'S-1-5-21-987654321'
        assert e['detail'] == '<script>PrivateMessage957</script>'
        name = pathlib.Path(e['source']).name
        if name in offsets:
            assert e['byte_offset'] == offsets[name] and e['line'] == 4
        elif name == 'fragments.xml':
            assert e['byte_offset'] == len(fragment_prefix) and e['line'] == 2
        else:
            assert name == 'truncated.xml' and e.get('byte_offset', 0) == 0
    item_names = {i['id']: pathlib.Path(i['source']).name for i in analysis['manifest']['items']}
    summaries = {item_names[s['evidence']]: s for s in analysis['parse_summaries']}
    assert summaries['fragments.xml']['skip_reasons'] == {'unsupported_timestamp': 1}
    assert summaries['fragments.xml']['parsed'] == 1 and summaries['fragments.xml']['skipped'] == 1
    assert summaries['truncated.xml']['parsed'] == 1 and summaries['truncated.xml']['skipped'] == 1
    assert summaries['truncated.xml']['error'] and summaries['doctype.xml']['error']
    assert 'native.evtx' not in summaries
    assert len(analysis['correlations']) == 2
    assert all(c['sources'] == 6 and c['events'] == 6 for c in analysis['correlations'])
    found_sources = {pathlib.Path(f['source']).name for f in analysis['findings']}
    assert all(name in found_sources for name in offsets), found_sources
    with (report / 'windows-events.csv').open(encoding='utf-8', newline='') as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 5
    assert all(row['provider'] == "'=PrivateProvider957" for row in rows)
    assert all(json.loads(row['event_data_json']) == expected_data for row in rows)
    html = (report / 'report.html').read_text(encoding='utf-8')
    assert '&lt;script&gt;PrivateMessage957&lt;/script&gt;' in html and '<script>PrivateMessage957' not in html
    assert 'Windows olay XML kayıtları' in html and 'unsupported_timestamp: 1' in html

    shared_dir = p / 'shared'
    run('share', '--in', package, '--rules', rules, '--out', shared_dir)
    secrets = ['PrivateProvider957', 'PrivateGUID957', 'PrivateChannel957', 'PrivateData957',
               'İstanbul', 'PrivateMessage957', 'PrivateIgnored957', '18446744073709551615',
               'privatehost957', 'S-1-5-21-987654321']
    for artifact in shared_dir.iterdir():
        text = artifact.read_text(encoding='utf-8')
        assert all(secret not in text for secret in secrets), artifact.name
    shared = json.loads((shared_dir / 'shared.json').read_text(encoding='utf-8'))
    assert sum(e['type'] == 'windows_event' for e in shared['timeline']) == 5
    assert hashlib.sha256(package.read_bytes()).hexdigest() == digest
    assert all((root / name).read_bytes() == raw for name, raw in contents.items())
    print('PASS: UTF-8/UTF-16 LE/BE; independent XML field oracle; original encoded byte offsets; uint64 record IDs; UTC/host/SID correlations; semantic skips and truncated-prefix recovery; DTD rejection; native EVTX excluded; Unicode rules; CSV/HTML escaping; all shared artifacts omit private context; evidence unchanged')
