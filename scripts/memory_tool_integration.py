#!/usr/bin/env python3
"""Check explicit real Volatility failure for an invalid image/missing symbols."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

from test_support import default_binary


def main():
    candidate = pathlib.Path(sys.executable).parent / ('vol.exe' if os.name == 'nt' else 'vol')
    tool = os.environ.get('K957_VOLATILITY_TOOL') or shutil.which('vol') or (str(candidate) if candidate.is_file() else None)
    if not tool:
        print('SKIP: Volatility 3 executable unavailable')
        return 77
    with tempfile.TemporaryDirectory(prefix='k957-memory-negative-') as tmp:
        root = pathlib.Path(tmp)
        image = root / 'invalid.raw'
        image.write_bytes(b'Not a supported kernel RAM image\n' * 1024)
        symbols = root / 'symbols'
        symbols.mkdir()
        digest = hashlib.sha256(image.read_bytes()).hexdigest()
        out = root / 'examination'
        result = subprocess.run([str(default_binary()), 'memory-examine', '--image', str(image), '--sha256', digest,
                                 '--out', str(out), '--symbols', str(symbols), '--tool', tool, '--plugin', 'linux.pslist.PsList'], capture_output=True, text=True, timeout=150)
        assert result.returncode, 'Invalid image/missing symbols were accepted'
        receipt = json.loads((out / 'memory-examination.json').read_text(encoding='utf-8'))
        assert receipt['status'] == 'failed' and receipt['error'] and receipt['tool']['exit_code'] != 0
        assert '--offline' in receipt['tool']['args'] and receipt['image_sha256'] == digest
        assert hashlib.sha256(image.read_bytes()).hexdigest() == digest
        assert hashlib.sha256((out / 'objects.json').read_bytes()).hexdigest() == receipt['tool']['stdout_sha256']
    print('PASS: actual Volatility rejects invalid image/missing symbols with retained failure; valid-image accuracy untested')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
