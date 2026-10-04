#!/usr/bin/env python3
"""Fingerprint exact compile inputs, including tests, fixtures and embedded assets."""
import argparse
import hashlib
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def source_identity():
    files = [p for name in ('cmd', 'internal') for p in (ROOT / name).rglob('*.go') if p.is_file() and
             not any(part in ('output', 'reports', '__pycache__') for part in p.relative_to(ROOT).parts)]
    for name in ('internal/core/fonts', 'internal/core/testdata'):
        files += [p for p in (ROOT / name).rglob('*') if p.is_file()]
    files = sorted(files + [ROOT / 'go.mod', ROOT / 'go.sum'])
    records = []
    for path in files:
        if path.is_symlink():
            raise ValueError(f'Source symlink is not supported: {path.relative_to(ROOT)}')
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        records.append({'name': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size, 'sha256': digest})
    canonical = json.dumps(records, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('ascii')
    return {'schema': 'k957-source/1', 'sha256': hashlib.sha256(canonical).hexdigest(), 'files': records,
            'scope': 'cmd/internal Go sources, core fonts/testdata, go.mod, go.sum; excludes generated outputs, documentation and scripts'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path)
    args = parser.parse_args()
    identity = source_identity()
    if args.out:
        args.out.write_text(json.dumps(identity, indent=2) + '\n', encoding='utf-8')
    print(identity['sha256'])


if __name__ == '__main__':
    main()
