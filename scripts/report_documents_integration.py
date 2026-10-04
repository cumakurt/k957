#!/usr/bin/env python3
"""Check document Unicode/reference fidelity and report signatures independently."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from test_support import default_binary


def main():
    exe = str(default_binary())
    pdf_tool = shutil.which('pdftotext')
    if not pdf_tool:
        print('SKIP: independent PDF text extraction requires pdftotext')
        return 77

    def run(*args):
        result = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stderr
        return result.stdout

    with tempfile.TemporaryDirectory(prefix='k957-documents-') as tmp:
        work = pathlib.Path(tmp)
        source = work / 'source'
        source.mkdir()
        (source / 'events.jsonl').write_text(json.dumps({'time': '2024-01-01T00:00:00Z',
              'message': 'Café Synthetic record', 'user': 'Zoë'}, ensure_ascii=False) + '\n', encoding='utf-8')
        run('keygen', '--out', work / 'sign')
        package = work / 'evidence.k957'
        run('collect', '--root', source, '--out', package, '--case', 'Café', '--operator', 'Test', '--scope', 'Synthetic')
        report = work / 'analysis'
        run('analyze', '--in', package, '--out', report)
        documents = work / 'documents'
        receipt = json.loads(run('report-documents', '--analysis', report / 'analysis.json', '--out', documents))
        assert all(c['status'] == 'complete' for c in receipt['coverage'])
        extracted = subprocess.run([pdf_tool, '-enc', 'UTF-8', '-layout', str(documents / 'report.pdf'), '-'],
                                   capture_output=True, text=True, encoding='utf-8', timeout=30, check=True).stdout
        extracted = ' '.join(extracted.split())
        with zipfile.ZipFile(documents / 'report.docx') as word:
            root = ET.fromstring(word.read('word/document.xml'))
            text = '\n'.join(n.text or '' for n in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'))
        for value in ('Café', 'Synthetic record', 'E000001', 'Cuma Kurt', 'cumakurt@gmail.com',
                      'https://github.com/cumakurt/k957', 'https://www.linkedin.com/in/cuma-kurt-34414917/'):
            assert value in extracted and value in text, (value, extracted, text)
        credits = json.loads(run('build-info'))['developer']
        assert credits['name'] == 'Cuma Kurt' and credits['email'] == 'cumakurt@gmail.com'
        html = (report / 'report.html').read_text(encoding='utf-8')
        assert all(value in html for value in credits.values())
        seal = json.loads(run('report-seal', '--report', documents, '--key', work / 'sign.key'))
        body = (documents / 'report.seal.json').read_bytes()
        signature = (documents / 'report.seal.sig').read_bytes()
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex((work / 'sign.pub').read_text(encoding='utf-8')))
        # Signature domain must agree with the documented report bundle contract.
        public.verify(signature, b'k957-report-seal/1\x00' + body)
        for item in seal['files']:
            blob = (documents / item['name']).read_bytes()
            assert hashlib.sha256(blob).hexdigest() == item['sha256'] and len(blob) == item['size']
        run('report-verify', '--report', documents, '--trusted-key', work / 'sign.pub')
        with (documents / 'report.pdf').open('ab') as output:
            output.write(b'changed')
        rejected = subprocess.run([exe, 'report-verify', '--report', str(documents), '--trusted-key', str(work / 'sign.pub')],
                                  capture_output=True, text=True, timeout=30)
        assert rejected.returncode != 0
    print('PASS: independent PDF/DOCX Unicode and references, Ed25519 bundle signature, file hashes, tamper rejection')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
