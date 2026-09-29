#!/usr/bin/env python3
"""Scan every shared artifact, with verified review/custody inputs and keep policy."""
from test_support import default_binary
import csv
import hashlib
import json
import pathlib
import subprocess
import tempfile

base = pathlib.Path(__file__).resolve().parents[1]
exe = str(default_binary())
with tempfile.TemporaryDirectory() as directory:
    p = pathlib.Path(directory)
    def run(*args, code=0):
        r = subprocess.run([exe, *map(str, args)], capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == code, (args, r.stderr, r.stdout)
        return r
    user, host, actor, ip = 'PrivateUser927', 'privatehost927', 'PrivateActor927', '198.51.100.75'
    root = p / 'PrivatePath927'
    root.mkdir()
    record = {'timestamp': '2008-02-03T04:05:06Z', 'user': user, 'host': host,
              'src_ip': ip, 'message': 'InvisibleFreeSecret927'}
    for name in ('first.jsonl', 'second.jsonl'):
        (root / name).write_text(json.dumps(record) + '\n', encoding="utf-8")
    rules = p / 'rules.json'
    rules.write_text(json.dumps([{'id': 'PrivateRule927', 'description': 'PrivateDescription927', 'contains': 'InvisibleFreeSecret927'}]), encoding="utf-8")
    run('keygen', '--out', p / 'actor')
    package = p / 'evidence.k957'
    run('collect', '--root', root, '--out', package, '--case', 'PrivateCase927', '--operator', actor,
        '--scope', 'PrivateScope927', '--sign-key', p / 'actor.key')
    run('analyze', '--in', package, '--trusted-key', p / 'actor.pub', '--rules', rules, '--out', p / 'original')
    original = json.loads((p / 'original/analysis.json').read_text(encoding="utf-8"))
    review = p / 'reviews.json'
    run('review', '--analysis', p / 'original/analysis.json', '--finding', original['findings'][0]['id'],
        '--decision', 'confirmed', '--analyst', actor, '--note', 'PrivateReviewNote927',
        '--sign-key', p / 'actor.key', '--out', review)
    trust = p / 'trust.json'
    trust.write_text(json.dumps({'schema': 'k957-custody-trust/1', 'keys': [
        {'actor': actor, 'public_key': (p / 'actor.pub').read_text(encoding="utf-8").strip()}]}), encoding="utf-8")
    custody = p / 'custody.json'
    head = json.loads(run('custody', '--in', package, '--trust', trust, '--action', 'register',
                         '--actor', actor, '--location', 'PrivateLocation927', '--note', 'PrivateCustodyNote927',
                         '--sign-key', p / 'actor.key', '--out', custody).stdout)['head']
    originals = [package, review, custody, p / 'original/analysis.json']
    hashes = {x: hashlib.sha256(x.read_bytes()).hexdigest() for x in originals}
    args = ['share', '--in', package, '--trusted-key', p / 'actor.pub', '--rules', rules,
            '--reviews', review, '--review-key', p / 'actor.pub', '--custody', custody,
            '--custody-trust', trust, '--custody-head', head]
    run(*args, '--out', p / 'shared')
    secrets = [user, host, actor, ip, 'PrivatePath927', 'PrivateRule927', 'PrivateDescription927',
               'InvisibleFreeSecret927', 'PrivateCase927', 'PrivateScope927', 'PrivateReviewNote927',
               'PrivateLocation927', 'PrivateCustodyNote927', '2008-02-03', original['evidence_digest'],
               original['findings'][0]['id'], head, (p / 'actor.pub').read_text(encoding="utf-8").strip()]
    files = list((p / 'shared').iterdir())
    assert len(files) == 8
    for file in files:
        data = file.read_text(encoding="utf-8")
        assert all(secret not in data for secret in secrets), file.name
    shared = json.loads((p / 'shared/shared.json').read_text(encoding="utf-8"))
    assert shared['schema'] == 'k957-shared-report/1'
    assert len(shared['items']) == 2 and len(shared['findings']) == 2 and len(shared['correlations']) == 3
    assert shared['findings'][0]['review'] == 'confirmed' and len(shared['reviews']) == 1
    assert shared['current_holder'] == shared['custody'][0]['actor']
    assert shared['operator'] == shared['custody'][0]['actor']
    assert shared['items'][0]['source'] == next(x['source'] for x in shared['timeline'] if x['evidence'] == 'E000001')
    with (p / 'shared/findings.csv').open(encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 2
    policy = p / 'policy.json'
    policy.write_text(json.dumps({'schema': 'k957-share-policy/1', 'keep': ['users', 'timestamps']}), encoding="utf-8")
    run(*args, '--policy', policy, '--out', p / 'selective')
    selective = (p / 'selective/shared.json').read_text(encoding="utf-8")
    assert user in selective and '2008-02-03' in selective and host not in selective and actor not in selective
    # Invalid policy and unverified history must fail before exporting anything.
    changed_review = json.loads(review.read_text(encoding="utf-8"))
    changed_review['events'][0]['note'] = 'Forged decision note'
    damaged = p / 'damaged-review.json'
    damaged.write_text(json.dumps(changed_review), encoding="utf-8")
    bad_args = list(args)
    bad_args[bad_args.index('--reviews') + 1] = damaged
    run(*bad_args, '--out', p / 'bad-history', code=1)
    assert not (p / 'bad-history').exists()
    policy.write_text('{"schema":"k957-share-policy/1","keep":[],"keep":["paths"]}', encoding="utf-8")
    run(*args, '--policy', policy, '--out', p / 'bad', code=1)
    assert not (p / 'bad').exists()
    run('review', '--analysis', p / 'shared/shared.json', '--finding', 'F000001', '--decision', 'confirmed',
        '--analyst', actor, '--note', 'Must fail', '--out', p / 'bad-review.json', code=1)
    assert not (p / 'bad-review.json').exists()
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == digest for path, digest in hashes.items())
    print('PASS: all 8 artifacts scanned for 18 sensitive values; signed reviews/custody projected safely; counts and aliases preserved; explicit keep policy; tampered history/ambiguous policy/authoritative reuse rejected; source package/history/analysis unchanged')
