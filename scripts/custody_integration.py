#!/usr/bin/env python3
"""Independent per-event Ed25519/hash verification and native custody CLI flow."""
from test_support import default_binary
import base64
import csv
import hashlib
import json
import pathlib
import subprocess
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

base = pathlib.Path(__file__).resolve().parents[1]
exe = str(default_binary())
with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory)
    def run(*args, code=0):
        result = subprocess.run([exe, *map(str, args)], text=True, capture_output=True, encoding="utf-8")
        assert result.returncode == code, (args, result.stderr, result.stdout)
        return result
    root = p / 'source'
    root.mkdir()
    (root / 'data.txt').write_text('Synthetic evidence\n', encoding="utf-8")
    for who in ('Alice', 'Bob'):
        run('keygen', '--out', p / who)
    trust = {'schema': 'k957-custody-trust/1', 'keys': [
        {'actor': who, 'public_key': (p / (who + '.pub')).read_text(encoding="utf-8").strip()}
        for who in ('Alice', 'Bob')]}
    (p / 'trust.json').write_text(json.dumps(trust), encoding="utf-8")
    package = p / 'case.k957'
    run('collect', '--root', root, '--out', package, '--case', 'SYNTHETIC',
        '--operator', 'Alice', '--scope', 'Fixture', '--sign-key', p / 'Alice.key')
    before = hashlib.sha256(package.read_bytes()).hexdigest()
    snapshots, head, previous = [], '', None
    for action, actor, to in [('register', 'Alice', ''), ('transfer', 'Alice', 'Bob'), ('accept', 'Bob', '')]:
        out = p / (action + '.json')
        args = ['custody', '--in', package, '--trusted-key', p / 'Alice.pub',
                '--trust', p / 'trust.json', '--action', action, '--actor', actor,
                '--location', '=SUM(A1)', '--note', '<script>synthetic</script>',
                '--sign-key', p / (actor + '.key'), '--out', out]
        if previous:
            args += ['--previous', previous, '--expected-head', head]
        if to:
            args += ['--to', to]
        result = json.loads(run(*args).stdout)
        head, previous = result['head'], out
        snapshots.append((out, out.read_bytes()))
    ledger = json.loads(previous.read_text(encoding="utf-8"))
    last = ''
    for i, entry in enumerate(ledger['events'], 1):
        payload = base64.b64decode(entry['payload_base64'], validate=True)
        pub, sig = bytes.fromhex(entry['public_key']), bytes.fromhex(entry['signature'])
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, b'k957/custody/signature/v1\0' + payload)
        event_hash = hashlib.sha256(b'k957/custody/head/v1\0' + pub + sig + payload).hexdigest()
        assert event_hash == entry['hash']
        claim = json.loads(payload)
        assert claim['sequence'] == i and claim['previous'] == last
        assert claim['signer_sha256'] == hashlib.sha256(pub).hexdigest()
        assert claim['evidence_digest'] == ledger['evidence_digest']
        assert claim['evidence_id'] == ledger['evidence_id'] and claim['case'] == ledger['case']
        assert next(k['actor'] for k in trust['keys'] if k['public_key'] == entry['public_key']) == claim['actor']
        last = entry['hash']
    assert last == head
    verify = ['custody-verify', '--in', package, '--trust', p / 'trust.json', '--expected-head', head]
    status = json.loads(run(*verify, '--ledger', previous).stdout)
    assert status['current_holder'] == 'Bob' and 'pending_to' not in status
    run(*verify, '--ledger', snapshots[0][0], code=1)  # Valid older history is not the anchored head.
    damaged = json.loads(previous.read_text(encoding="utf-8"))
    entry = damaged['events'][0]
    payload = base64.b64decode(entry['payload_base64']).replace(b'synthetic', b'fabricated')
    entry['payload_base64'] = base64.b64encode(payload).decode()
    entry['hash'] = hashlib.sha256(b'k957/custody/head/v1\0' + bytes.fromhex(entry['public_key']) + bytes.fromhex(entry['signature']) + payload).hexdigest()
    (p / 'tampered.json').write_text(json.dumps(damaged), encoding="utf-8")
    run(*verify, '--ledger', p / 'tampered.json', code=1)
    run('analyze', '--in', package, '--custody', previous, '--custody-trust', p / 'trust.json',
        '--custody-head', head, '--out', p / 'report')
    a = json.loads((p / 'report/analysis.json').read_text(encoding="utf-8"))
    assert a['custody']['head'] == head and len(a['custody']['events']) == 3
    html = (p / 'report/report.html').read_text(encoding="utf-8")
    assert '<script>synthetic</script>' not in html and '&lt;script&gt;synthetic&lt;/script&gt;' in html
    with (p / 'report/custody.csv').open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == 3 and rows[0]['location'] == "'=SUM(A1)"
    assert hashlib.sha256(package.read_bytes()).hexdigest() == before
    assert all(path.read_bytes() == contents for path, contents in snapshots)
    print('PASS: two signer keys, preserved event signatures, independent Ed25519/domain/hash verification, acceptance state, external-head rollback rejection, tamper rejection, safe HTML/CSV, unchanged package/history')
