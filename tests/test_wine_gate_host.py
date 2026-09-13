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
MODES = ("1,1,1", "0,0,0", "1,0,1", "0,1,0")


def run_gate(*arguments: str, expect_acceptance: bool = True) -> str:
    completed = subprocess.run(
        [str(RUNNER), "--runtime", str(DISTRIBUTION / "lib/i386-windows"),
         *arguments],
        check=False, capture_output=True, text=True)
    # A run that stops somewhere other than the Unix-call boundary is still
    # valid evidence about that stop, so only the acceptance run must pass.
    if expect_acceptance and completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        raise SystemExit("wine ntdll gate: the runner rejected its own run")
    return completed.stdout


def field(text: str, kind: str, name: str) -> str:
    for line in text.splitlines():
        if f"kind=host-wine-{kind} " not in line:
            continue
        for token in line.split():
            key, separator, value = token.partition("=")
            if separator and key == name:
                return value
    raise SystemExit(f"wine ntdll gate: {kind} record has no {name}")


def main() -> int:
    if not RUNNER.exists() or not MANIFEST.exists():
        print("wine ntdll gate: skipped (no staged runtime)")
        return 0
    output = run_gate()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(output)
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

    # The same real code must behave identically with chaining, register
    # residency and lazy flags on and off: a mode difference here is a defect
    # in the dispatcher, not a nuance of the evidence.
    reference: tuple[str, str, str] | None = None
    for mode in MODES:
        text = run_gate("--entry-symbol", "LdrInitializeThunk", "--budget",
                        "800", "--modes", mode, expect_acceptance=False)
        observed = (field(text, "run", "stop"),
                    field(text, "run", "retired"),
                    field(text, "run", "stop_address"))
        if reference is None:
            reference = observed
            if observed[0] == "wine-unix-call-boundary":
                raise SystemExit("wine ntdll gate: unexpected syscall-only run")
        elif observed != reference:
            raise SystemExit("wine ntdll gate: engine modes disagree: "
                             f"{observed} != {reference}")
    print("wine ntdll gate: mode parity confirmed "
          f"({len(MODES)} configurations, {reference[1]} retired "
          f"instructions, stop {reference[0]} at {reference[2]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
