#!/usr/bin/env python3
"""Build a source-bound developer preview and refresh licenses/checksums together."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess

from source_identity import ROOT, source_identity
from test_support import native_target

TARGETS = ('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64')


def command(*args):
    return subprocess.run(list(map(str, args)), cwd=ROOT, check=True, capture_output=True, text=True).stdout


def json_stream(content):
    decoder = json.JSONDecoder()
    offset = 0
    while offset < len(content):
        while offset < len(content) and content[offset].isspace():
            offset += 1
        if offset == len(content):
            break
        item, offset = decoder.raw_decode(content, offset)
        yield item


def sha256(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def assistant_evaluation(receipt_path, receipt):
    """Retain narrow inference measurements without certifying model quality."""
    steps = [step for step in receipt['steps'] if step['name'] == 'assistant_model_integration']
    if not steps or steps[0]['status'] == 'skipped':
        return None
    if len(steps) != 1 or steps[0]['status'] != 'passed':
        raise ValueError('A passed local assistant protocol receipt is required')
    log_name = steps[0]['log']
    if pathlib.Path(log_name).name != log_name:
        raise ValueError('Assistant evaluation log must be in the validation directory')
    path = receipt_path.parent / log_name
    result = json.loads(path.read_text(encoding='utf-8'))
    cases = result['cases']
    if (result.get('schema') != 'k957-assistant-evaluation/1' or not cases or
            any(case.get('citation_contract') != 'passed' or type(case.get('task_success')) is not bool for case in cases) or
            result.get('signed_review') != 'passed' or result.get('index_unchanged') is not True):
        raise ValueError('Incomplete local assistant protocol measurements')
    successes = sum(case['task_success'] for case in cases)
    quality = 'passed' if successes == len(cases) else 'failed'
    if (result['task_successes'] != successes or result['task_total'] != len(cases) or
            result['task_quality_result'] != quality):
        raise ValueError('Assistant task counters disagree with retained cases')
    return {'name': path.relative_to(ROOT).as_posix(), 'sha256': sha256(path),
            'model': result['model'], 'model_digest': result['model_digest'], 'runtime': result['runtime'],
            'citation_contract_cases_passed': len(cases), 'task_successes': successes,
            'task_total': len(cases), 'task_quality_result': quality,
            'scope': result['scope'], 'forensic_quality_validated': False}


def dependencies():
    modules = {p['Module']['Path'] for p in json_stream(command('go', 'list', '-deps', '-json', './cmd/k957'))
               if p.get('Module') and p['Module']['Path'] != 'k957'}
    records = []
    for module in json_stream(command('go', 'list', '-m', '-json', 'all')):
        if module['Path'] not in modules:
            continue
        if module.get('Replace'):
            raise ValueError('Local module replacements cannot be published by this release workflow')
        directory = pathlib.Path(module['Dir'])
        licenses = sorted(p for p in directory.iterdir() if p.is_file() and
                          (p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'COPYRIGHT'))))
        if not any(p.name.upper().startswith(('LICENSE', 'COPYING')) for p in licenses):
            raise ValueError(f'Missing license text: {module["Path"]}; inspect before release')
        destination = ROOT / 'licenses' / (module['Path'].replace('/', '__') + '@' + module['Version'])
        destination.mkdir(parents=True, exist_ok=True)
        notices = []
        for original in licenses:
            target = destination / original.name
            target.write_bytes(original.read_bytes())
            notices.append(target.relative_to(ROOT).as_posix())
        records.append({'path': module['Path'], 'version': module['Version'], 'sum': module.get('Sum'), 'notices': notices})
    return sorted(records, key=lambda m: m['path'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='refresh metadata after prior source-matching builds')
    parser.add_argument('--validation', type=pathlib.Path, action='append', default=[],
                        help='retained native validation.json for these exact inputs; repeat for multiple targets')
    args = parser.parse_args()
    identity = source_identity()
    version = re.search(r'const Version = "([^"]+)"', (ROOT / 'internal/core/model.go').read_text(encoding='utf-8')).group(1)
    if not args.no_build:
        invocation = ['powershell', '-NoProfile', '-File', 'scripts/build.ps1'] if os.name == 'nt' else ['bash', 'scripts/build.sh']
        subprocess.run(invocation, cwd=ROOT, check=True)
    if source_identity()['sha256'] != identity['sha256']:
        raise ValueError('Source changed during builds')
    artifacts = []
    for target in TARGETS:
        name = 'dist/k957-' + target.replace('/', '-') + ('.exe' if target.startswith('windows/') else '')
        path = ROOT / name
        static = command('python' if os.name == 'nt' else 'python3', 'scripts/check_static.py', path).strip()
        info = command('go', 'version', '-m', path)
        # -trimpath intentionally omits linker flags from Go's build settings.
        # Check the embedded fingerprint bytes; native runtime validation also
        # checks the value returned by build-info.
        if identity['sha256'].encode('ascii') not in path.read_bytes():
            raise ValueError(f'Binary does not bind the current source: {name}')
        target_os, target_arch = target.split('/')
        if f'\tbuild\tGOOS={target_os}' not in info or f'\tbuild\tGOARCH={target_arch}' not in info:
            raise ValueError(f'Executable target differs from its release name: {name}')
        if '\tbuild\tCGO_ENABLED=0' not in info:
            raise ValueError(f'Binary was built with cgo: {name}')
        artifacts.append({'target': target, 'name': name, 'bytes': path.stat().st_size,
                          'sha256': sha256(path), 'static_check': static, 'native_runtime': 'unvalidated',
                          'platform_signature': 'unsigned'})
    deps = dependencies()
    runtime = []
    validation = None
    coverage = None
    model_evaluation = None
    validations = []
    coverage_by_target = {}
    for validation_path in args.validation:
        receipt_path = validation_path.resolve()
        receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
        target = next(a for a in artifacts if a['target'] == receipt['target'])
        if receipt.get('result') != 'passed' or receipt.get('source_sha256') != identity['sha256'] or receipt.get('binary_sha256') != target['sha256'] or receipt.get('environment', {}).get('kind') != 'native':
            raise ValueError('Validation receipt does not describe a passed native run of these exact source/binary bytes')
        if receipt['target'] in runtime:
            raise ValueError('Duplicate validation target')
        runtime.append(receipt['target'])
        target['native_runtime'] = 'passed retained validation; device scenarios not validated'
        entry = {'name': receipt_path.relative_to(ROOT).as_posix(), 'sha256': sha256(receipt_path), 'target': receipt['target']}
        validations.append(entry)
        if validation is None:
            validation = entry
        evaluation = assistant_evaluation(receipt_path, receipt)
        if evaluation is not None:
            model_evaluation = evaluation
        coverage_log = receipt_path.parent / 'coverage.log'
        if coverage_log.is_file():
            match = re.search(r'total:\s+\(statements\)\s+([\d.]+)%', coverage_log.read_text(encoding='utf-8'))
            if match:
                coverage_by_target[receipt['target']] = float(match.group(1))
                if coverage is None:
                    coverage = float(match.group(1))
    release = {'schema': 'k957-release/1', 'name': 'k957', 'version': version, 'license': 'AGPL-3.0-or-later',
               'status': 'developer-preview', 'production_validated': False,
               'developer': json.loads(command(ROOT / ('dist/k957-' + '-'.join(native_target()) + ('.exe' if os.name == 'nt' else '')), 'build-info'))['developer'],
               'generated': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'build_toolchain': command('go', 'version').strip(), 'source_manifest': 'SOURCE.json',
               'source_sha256': identity['sha256'], 'cross_compiled': list(TARGETS), 'runtime_tested': runtime,
               'native_platform_tests_pending': [t for t in TARGETS if t not in runtime],
               'validation': validation, 'validations': validations,
               'test_coverage_total_percent': coverage, 'test_coverage_by_target': coverage_by_target,
               'local_assistant_evaluation': model_evaluation,
               'go_module_dependencies': deps, 'artifacts': artifacts,
               'documentation': 'docs/EXAMINATION_WORKFLOWS.md',
               'supported_native_parsers': ['selected SQLite/WAL browser visits', 'EVTX system metadata',
                                            'clean primary Registry keys/selected values', 'binary launchd plist fields',
                                            'offline USN v2/v3 journal records'],
               'external_tools': ['optional offline Volatility 3', 'optional Sleuth Kit fls/icat', 'optional loopback Ollama'],
               'external_assurance': {'physical_usb_disconnect_tested': False, 'physical_device_separation_verified': False,
                                      'trusted_timestamp_authority': False, 'hardware_signing': False,
                                      'real_model_inference_validated': False,
                                      'real_model_inference_protocol_tested': model_evaluation is not None,
                                      'real_model_forensic_quality_validated': False, 'valid_kernel_ram_corpus_validated': False,
                                      'ci_workflow_executed': False, 'notarized': False},
               'accepted_evidence_schemas': ['k957-evidence/1', 'k957-evidence/2'],
               'default_report_formats': ['html', 'pdf', 'json', 'csv'],
               'complete_memory_results': 'private JSONL; no automatic image/result/tool-output/runtime cap',
               'kernel_memory_scope': 'installed platform/global Volatility plugins, offline symbols, retained failed/unavailable methods',
               'packaged_example_report_version': json.loads((ROOT / 'examples/demo-report/analysis.json').read_text(encoding='utf-8'))['version']}
    (ROOT / 'SOURCE.json').write_text(json.dumps(identity, indent=2) + '\n')
    (ROOT / 'RELEASE.json').write_text(json.dumps(release, indent=2) + '\n')
    notice = '# Third-party notices\n\nPinned modules linked by the Go CLI are listed in RELEASE.json. '
    notice += 'Their original license/notice texts are retained under licenses/. '
    notice += 'The embedded DejaVu Sans, Sans Bold and Serif font license is at internal/core/fonts/LICENSE.txt. '
    notice += 'The EVTX reference fixture has its own attribution at internal/core/testdata/EVTX_LICENSE.txt. '
    notice += 'Test-only Python packages and optional external tools are separate installations.\n'
    (ROOT / 'THIRD_PARTY_NOTICES.md').write_text(notice)
    go_root = pathlib.Path(command('go', 'env', 'GOROOT').strip())
    go_license = go_root / 'LICENSE'
    if not go_license.is_file():
        # Debian splits the toolchain and retains its complete original
        # notices in the package copyright file instead of GOROOT/LICENSE.
        major_minor = re.search(r'go(\d+\.\d+)', command('go', 'version')).group(1)
        go_license = pathlib.Path('/usr/share/doc') / f'golang-{major_minor}-go' / 'copyright'
    (ROOT / 'licenses' / 'Go-LICENSE').write_bytes(go_license.read_bytes())
    # Include only project release files, never local secrets, case outputs or arbitrary untracked executables.
    selected = []
    for name in ('.github', 'cmd', 'internal', 'docs', 'scripts', 'examples', 'licenses'):
        selected += [p for p in (ROOT / name).rglob('*') if p.is_file() and not p.is_symlink() and
                     not any(part in ('__pycache__', 'output', 'reports') for part in p.relative_to(ROOT).parts) and
                     p.suffix not in ('.pyc', '.pyo')]
    selected += [ROOT / a['name'] for a in artifacts]
    selected += [ROOT / name for name in ('go.mod', 'go.sum', 'README.md', 'README_TR.md', 'CHANGELOG.md',
                 'LICENSE', 'RELEASE.json', 'SOURCE.json', 'THIRD_PARTY_NOTICES.md', 'start-unix.sh', 'start-windows.cmd')]
    rows = [f'{sha256(p)}  {p.relative_to(ROOT).as_posix()}' for p in sorted(set(selected)) if p.is_file()]
    (ROOT / 'SHA256SUMS.txt').write_text('\n'.join(rows) + '\n')
    print(f'Prepared {version}, source {identity["sha256"]}, {len(artifacts)} targets; native validated: {runtime}')


if __name__ == '__main__':
    main()
