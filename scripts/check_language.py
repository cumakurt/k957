#!/usr/bin/env python3
"""Check owned application text; preserve original evidence and raw test receipts."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUFFIXES = {'.go', '.py', '.md', '.html', '.json', '.csv', '.txt', '.sh', '.ps1', '.cmd',
            '.yaml', '.yml', '.js', '.jsx', '.ts', '.tsx', '.css'}
LOCALIZED = re.compile(r'[\u00e7\u011f\u0131\u0130\u00f6\u015f\u00fc\u00c7\u011e\u00d6\u015e\u00dc]|lang=[\"\x27]tr[\"\x27]')


def main():
    checked, failures = 0, []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if (not path.is_file() or path.suffix not in SUFFIXES or path.is_symlink() or
                any(part.startswith('.') or part == '__pycache__' for part in relative.parts) or
                relative.parts[0] in ('dist', 'licenses') or
                relative.parts[:2] == ('docs', 'validation') or relative == pathlib.Path('README_TR.md')):
            continue
        checked += 1
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if LOCALIZED.search(line):
                failures.append(f'{relative}:{number}')
    if failures:
        print('Localized application text found:\n' + '\n'.join(failures), file=sys.stderr)
        return 1
    print(f'PASS: English application text in {checked} owned files; root README_TR.md remains localized')
    return 0


if __name__ == '__main__':
    sys.exit(main())
