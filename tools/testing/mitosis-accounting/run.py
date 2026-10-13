#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build both callback snapshots and check their expected regression results."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
REGRESSIONS = [
    'remote-context', 'remote-clock', 'remote-subcell', 'queued-clock',
    'sleep-clock', 'error-running-cell', 'error-running-pack',
    'error-running-map', 'error-stopping-map', 'error-quiescent-pack',
    'error-quiescent-map', 'error-running-queued',
]
CONTROLS = ['no-wait', 'shared-accounting']
results = {}
ok = True
with tempfile.TemporaryDirectory(prefix='mitosis-accounting-') as tmp:
    for version in ['unfixed', 'fixed']:
        binary = str(Path(tmp) / version)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=gnu11', '-O2', '-Wall', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable',
            str(ROOT / (version + '.c')), '-o', binary,
        ], check=True)
        results[version] = {}
        for case in REGRESSIONS + CONTROLS:
            result = subprocess.run([binary, case], capture_output=True, text=True)
            expected = 0 if version == 'fixed' or case in CONTROLS else 1
            matched = result.returncode == expected
            results[version][case] = {
                'passed': result.returncode == 0,
                'expected_result': matched,
            }
            ok &= matched
            if not matched:
                print(f'{version}/{case}: expected exit {expected}, '
                      f'got {result.returncode}\n{result.stderr}', file=sys.stderr)
print(json.dumps(results, indent=2))
sys.exit(0 if ok else 1)
