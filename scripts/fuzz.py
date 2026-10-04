#!/usr/bin/env python3
"""Retain bounded native Go fuzz campaigns against the current source identity."""
import argparse
import datetime
import json
import os
import pathlib
import re
import subprocess
import time

from source_identity import ROOT, source_identity
from test_support import native_target

TARGETS = ('FuzzRules', 'FuzzEnvelope', 'FuzzStructuredLogs', 'FuzzPCAP', 'FuzzPCAPNG', 'FuzzWindowsXML',
           'FuzzRegistry', 'FuzzBinaryPlist', 'FuzzExternalJSON')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--target', choices=TARGETS, action='append', help='repeat selected targets; default is all')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 60:
        parser.error('--seconds must be 1..60 per target')
    args.out.mkdir(parents=True, exist_ok=False)
    identity = source_identity()['sha256']
    receipt = {'schema': 'k957-fuzz/1', 'source_sha256': identity, 'target': '/'.join(native_target()),
               'started': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'result': 'running', 'steps': []}

    def save():
        (args.out / 'fuzz.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')

    save()
    for target in dict.fromkeys(args.target or TARGETS):
        command = ['go', 'test', './internal/core', '-run=^$', f'-fuzz=^{target}$', f'-fuzztime={args.seconds}s',
                   '-fuzzminimizetime=1s', '-parallel=2']
        start = time.monotonic()
        step = {'name': target, 'command': command, 'status': 'running', 'log': f'{target}.log'}
        receipt['steps'].append(step)
        save()
        print(f'RUN {target}', flush=True)
        try:
            result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, GOMAXPROCS='2', CGO_ENABLED='0'),
                                    capture_output=True, text=True, timeout=args.seconds + 90)
            output = result.stdout + result.stderr
            step.update(exit_code=result.returncode, status='passed' if result.returncode == 0 else 'failed')
        except (OSError, subprocess.TimeoutExpired) as error:
            def decoded(value):
                return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
            output = decoded(getattr(error, 'stdout', None)) + decoded(getattr(error, 'stderr', None)) + str(error) + '\n'
            step.update(status='failed', error=str(error))
        (args.out / step['log']).write_text(output, encoding='utf-8')
        counts = re.findall(r'execs:\s+(\d+)', output)
        step.update(executions=int(counts[-1]) if counts else None, duration_seconds=round(time.monotonic() - start, 3))
        save()
        print(f'{step["status"].upper()} {target}', flush=True)
    receipt['source_unchanged'] = source_identity()['sha256'] == identity
    receipt['result'] = 'passed' if receipt['source_unchanged'] and all(s['status'] == 'passed' for s in receipt['steps']) else 'failed'
    receipt['finished'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    return 0 if receipt['result'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
