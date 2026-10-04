#!/usr/bin/env python3
"""Independently check default PDF, offline indicators, portable exports and explicit technique mappings."""
from contextlib import closing
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile
from test_support import default_binary


def main():
    pdf_tool = shutil.which('pdftotext')
    if not pdf_tool:
        print('SKIP: independent default PDF checks require pdftotext')
        return 77
    exe = str(default_binary())
    def run(*args):
        result = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
        return result.stdout
    with tempfile.TemporaryDirectory(prefix='k957-report-upgrade-') as tmp:
        work = pathlib.Path(tmp)
        source = work / 'source'
        source.mkdir()
        # Real SQLite browser history, with a native row identifier and timestamp.
        with closing(sqlite3.connect(source / 'History')) as db:
            db.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)')
            db.execute('INSERT INTO urls VALUES(7,?,?,?)', ('https://fixture.example.test/path', 'Synthetic browser visit', 13348540800000000))
            db.commit()
        for i in range(60):
            (source / f'event-{i:03}.jsonl').write_text(json.dumps({'time': '2024-01-01T00:00:00Z', 'message': f'fixture-marker {i}', 'user': 'Synthetic'}) + '\n')
        run('collect', '--root', source, '--out', work / 'evidence.k957', '--case', 'Reporting fixture', '--operator', 'Test', '--scope', 'Synthetic')
        rules = work / 'rules.json'
        rules.write_text(json.dumps([{'id':'fixture', 'description':'Synthetic predicate', 'contains':'fixture-marker', 'techniques':['T1059.001']}]))
        iocs = work / 'iocs.json'
        iocs.write_text(json.dumps({'schema':'k957-indicators/1', 'name':'Fixture list', 'source':'Synthetic examiner fixture', 'indicators':[{'id':'domain-1','kind':'domain','value':'FIXTURE.EXAMPLE.TEST.'}]}))
        report = work / 'report'
        run('analyze', '--in', work / 'evidence.k957', '--out', report, '--rules', rules, '--iocs', iocs)
        a = json.loads((report / 'analysis.json').read_text(encoding='utf-8'))
        assert len(a['findings']) == 60
        matches = json.loads((report / 'indicators.json').read_text(encoding='utf-8'))['matches']
        assert len(matches) == 1 and matches[0]['event']['table'] == 'urls' and matches[0]['event']['record'] == '7'
        assert matches[0]['value'] == 'fixture.example.test'
        layer = json.loads((report / 'attack-navigator.json').read_text(encoding='utf-8'))
        assert layer['versions']['layer'] == '4.5' and layer['techniques'][0]['score'] == 60
        assert len(json.loads((report / 'attack-mappings.json').read_text(encoding='utf-8'))['rows']) == 60
        timeline = [json.loads(line) for line in (report / 'timeline.jsonl').read_text(encoding='utf-8').splitlines()]
        assert len(timeline) == len([e for e in a['timeline'] if not e['time'].startswith('0001-')])
        assert all({'datetime','message','timestamp_desc'} <= row.keys() for row in timeline)
        queue = json.loads((report / 'review-queue.json').read_text(encoding='utf-8'))
        assert len(queue['rows']) == 60 and all(r['priority'] == 4 for r in queue['rows'])
        text = subprocess.run([pdf_tool, '-enc', 'UTF-8', '-layout', report / 'report.pdf', '-'], check=True, capture_output=True, text=True, encoding='utf-8').stdout
        text = ' '.join(text.split())
        for value in ('Examination record', 'Reporting fixture', 'Offline indicator matches', 'fixture.example.test', 'E000001'):
            assert value in text, value
        receipt = json.loads((report / 'documents.json').read_text(encoding='utf-8'))
        assert receipt['formats'] == ['pdf'] and receipt['pdf_pages'] > 1
        html = (report / 'report.html').read_text(encoding='utf-8')
        assert 'beforeprint' in html and 'afterprint' in html and 'gradient(' not in html
        assert 'fixture.example.test' in html and 'report.pdf' in html
        shared = work / 'shared'
        run('share', '--in', work / 'evidence.k957', '--out', shared, '--rules', rules, '--iocs', iocs)
        safe_pdf = subprocess.run([pdf_tool, '-enc', 'UTF-8', shared / 'report.pdf', '-'], check=True, capture_output=True, text=True, encoding='utf-8').stdout
        assert 'fixture.example.test' not in safe_pdf and str(source) not in safe_pdf and 'fixture-marker' not in safe_pdf
        # The default PDF participates in the existing independently verified seal contract.
        run('keygen', '--out', work / 'key')
        seal = json.loads(run('report-seal', '--report', report, '--key', work / 'key.key'))
        pdf_entry = next(f for f in seal['files'] if f['name'] == 'report.pdf')
        assert hashlib.sha256((report / 'report.pdf').read_bytes()).hexdigest() == pdf_entry['sha256']
        run('report-verify', '--report', report, '--trusted-key', work / 'key.pub')
    print('PASS: default PDF and coverage, source-linked offline IOC, explicit ATT&CK counts, Timesketch JSONL, review order, safe shared PDF, sealed default PDF')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
