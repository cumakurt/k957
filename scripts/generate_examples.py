#!/usr/bin/env python3
"""Regenerate English reports and signed examples without rewriting evidence."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

from test_support import default_binary


def main():
    examples = pathlib.Path(__file__).resolve().parents[1] / 'examples'
    binary = default_binary()
    packages = sorted(examples.glob('*.k957'))
    hashes = {}
    for package in packages:
        with package.open('rb') as stream:
            hashes[package] = hashlib.file_digest(stream, 'sha256').hexdigest()
    with tempfile.TemporaryDirectory(prefix='k957-english-examples-') as directory:
        work = pathlib.Path(directory)
        generated = work / 'generated'
        generated.mkdir()

        def run(*args):
            result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                                    text=True, encoding='utf-8', timeout=120)
            if result.returncode:
                raise RuntimeError(f'{args[0]} failed: {result.stderr}')
            return result.stdout

        for package in packages:
            run('verify', '--in', package)
        rules = examples / 'rules.json'
        for name, package, options in (
                ('demo-report', 'demo.k957', ['--rules', rules]),
                ('demo-resumable-report', 'demo-resumable.k957', ['--rules', rules]),
                ('structured-report', 'structured.k957', []),
                ('network-report', 'network.k957', [])):
            run('analyze', '--in', examples / package, '--out', generated / name, *options)

        for actor in ('review', 'Alice', 'Bob'):
            run('keygen', '--out', work / actor)
        analysis = generated / 'demo-report/analysis.json'
        finding = json.loads(analysis.read_text(encoding='utf-8'))['findings'][0]['id']
        run('review', '--analysis', analysis, '--finding', finding,
            '--decision', 'needs-review', '--analyst', 'Alice', '--note', 'Initial synthetic review',
            '--sign-key', work / 'review.key', '--out', generated / 'reviews-v1.json')
        run('review', '--analysis', analysis, '--finding', finding,
            '--previous', generated / 'reviews-v1.json', '--previous-key', work / 'review.pub',
            '--decision', 'rejected', '--analyst', 'Bob',
            '--note', 'Synthetic test data; not a real incident finding.',
            '--sign-key', work / 'review.key', '--out', generated / 'reviews-v2.json')
        shutil.copyfile(work / 'review.pub', generated / 'demo-review.pub')
        review_options = ['--rules', rules, '--reviews', generated / 'reviews-v2.json',
                          '--review-key', generated / 'demo-review.pub']
        run('analyze', '--in', examples / 'demo.k957', '--out', generated / 'demo-reviewed-report',
            *review_options)

        trust = {'schema': 'k957-custody-trust/1', 'keys': [
            {'actor': actor, 'public_key': (work / f'{actor}.pub').read_text(encoding='utf-8').strip()}
            for actor in ('Alice', 'Bob')]}
        (generated / 'custody-trust.json').write_text(json.dumps(trust, indent=2) + '\n', encoding='utf-8')
        head, previous = '', None
        for sequence, (action, actor, recipient) in enumerate(
                [('register', 'Alice', ''), ('transfer', 'Alice', 'Bob'), ('accept', 'Bob', '')], 1):
            output = generated / f'custody-{sequence:03}.json'
            options = []
            if previous:
                options += ['--previous', previous, '--expected-head', head]
            if recipient:
                options += ['--to', recipient]
            status = json.loads(run('custody', '--in', examples / 'demo.k957',
                                    '--trust', generated / 'custody-trust.json', '--action', action,
                                    '--actor', actor, '--location', 'Synthetic laboratory',
                                    '--note', 'Demonstration record; not a physical transfer declaration.',
                                    '--sign-key', work / f'{actor}.key', '--out', output, *options))
            head, previous = status['head'], output
        (generated / 'custody-head.txt').write_text(head + '\n', encoding='utf-8')
        run('custody-verify', '--in', examples / 'demo.k957', '--ledger', previous,
            '--trust', generated / 'custody-trust.json', '--expected-head', head)
        custody_options = ['--custody', previous, '--custody-trust', generated / 'custody-trust.json',
                           '--custody-head', head]
        run('analyze', '--in', examples / 'demo.k957', '--out', generated / 'demo-custody-report',
            '--rules', rules, *custody_options)
        run('share', '--in', examples / 'demo.k957', '--out', generated / 'demo-shared-report',
            *review_options, *custody_options)
        run('share', '--in', examples / 'structured.k957', '--policy', examples / 'share-policy.json',
            '--out', generated / 'structured-shared-report')
        run('share', '--in', examples / 'network.k957', '--out', generated / 'network-shared-report')
        for package, expected in hashes.items():
            with package.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                    raise RuntimeError(f'Evidence changed: {package.name}')

        # Keep the previous outputs available until every replacement succeeds.
        backup = work / 'previous'
        backup.mkdir()
        published = []
        try:
            for output in sorted(generated.iterdir()):
                destination = examples / output.name
                if destination.exists():
                    shutil.move(str(destination), backup / output.name)
                published.append(destination)
                shutil.move(str(output), destination)
        except OSError:
            for destination in reversed(published):
                if destination.is_dir():
                    shutil.rmtree(destination)
                elif destination.exists():
                    destination.unlink()
                original = backup / destination.name
                if original.exists():
                    shutil.move(str(original), destination)
            raise
    print('PASS: English reports, signed review/custody examples, verified histories and unchanged evidence packages')


if __name__ == '__main__':
    main()
