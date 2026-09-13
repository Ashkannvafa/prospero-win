#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Run the bounded Wine ntdll entry gate when a runtime is staged.

The genuine acceptance evidence needs the staged i386 Wine runtime, which is
a build artifact (`tools/build_wine_runtime.sh`) and never a repository file.
When it is absent this test reports that it skipped; a developer who has
staged a runtime gets the real end-to-end run as part of `make test`, and CI
still exercises the evidence contract through
tests/test_wine_ntdll_evidence.py.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "build/host/wine_ntdll_entry"
DISTRIBUTION = ROOT / ".deps/wine-runtime"
MANIFEST = DISTRIBUTION / "wine-runtime-manifest.json"
VALIDATOR = ROOT / "tools/validate_wine_ntdll_evidence.py"


def main() -> int:
    if not RUNNER.exists() or not MANIFEST.exists():
        print("wine ntdll gate: skipped (no staged runtime)")
        return 0
    completed = subprocess.run(
        [str(RUNNER), "--runtime", str(DISTRIBUTION / "lib/i386-windows")],
        check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        raise SystemExit("wine ntdll gate: the runner rejected its own run")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(completed.stdout)
        transcript = Path(handle.name)
    try:
        check = subprocess.run(
            [sys.executable, str(VALIDATOR), str(transcript),
             "--manifest", str(MANIFEST), "--expect-entry", "NtClose"],
            check=False, capture_output=True, text=True)
    finally:
        transcript.unlink()
    if check.returncode != 0:
        print(check.stdout, file=sys.stderr)
        print(check.stderr, file=sys.stderr)
        raise SystemExit("wine ntdll gate: evidence validation failed")
    print(check.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
