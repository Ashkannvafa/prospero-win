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
INITIALIZATION_BUDGET = "1500"


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


def validate_transcript(text: str, expect_entry: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.write(text)
        transcript = Path(handle.name)
    try:
        check = subprocess.run(
            [sys.executable, str(VALIDATOR), str(transcript),
             "--manifest", str(MANIFEST), "--expect-entry", expect_entry],
            check=False, capture_output=True, text=True)
    finally:
        transcript.unlink()
    if check.returncode != 0:
        print(check.stdout, file=sys.stderr)
        print(check.stderr, file=sys.stderr)
        raise SystemExit("wine ntdll gate: evidence validation failed")
    return check.stdout.strip()


def main() -> int:
    if not RUNNER.exists() or not MANIFEST.exists():
        print("wine ntdll gate: skipped (no staged runtime)")
        return 0
    output = run_gate()
    print(validate_transcript(output, "NtClose"))

    # Real ntdll initialization must reach its first Unix call, and the same
    # code must behave identically with chaining, register residency and lazy
    # flags on and off: a mode difference here is a dispatcher defect.
    reference: tuple[str, str, str] | None = None
    observed_syscall = None
    for mode in MODES:
        text = run_gate("--entry-symbol", "LdrInitializeThunk", "--budget",
                        INITIALIZATION_BUDGET, "--modes", mode,
                        expect_acceptance=False)
        observed = (field(text, "run", "stop"),
                    field(text, "run", "retired"),
                    field(text, "run", "stop_address"))
        call = (field(text, "run", "syscall"), field(text, "call", "caller_id"),
                field(text, "call", "in_module"))
        if call[0] != call[1] or call[2] != "1":
            raise SystemExit("wine ntdll gate: the boundary call is not bound "
                             f"to its issuing stub: {call}")
        if observed_syscall is None:
            observed_syscall = call[0]
        elif call[0] != observed_syscall:
            raise SystemExit("wine ntdll gate: modes disagree on the syscall "
                             f"number: {call[0]} != {observed_syscall}")
        if reference is None:
            reference = observed
            if observed[0] != "wine-unix-call-boundary":
                raise SystemExit("wine ntdll gate: ntdll initialization did "
                                 f"not reach the boundary: {observed[0]}")
            print(validate_transcript(text, "LdrInitializeThunk"))
        elif observed != reference:
            raise SystemExit("wine ntdll gate: engine modes disagree: "
                             f"{observed} != {reference}")
    print("wine ntdll gate: mode parity confirmed "
          f"({len(MODES)} configurations, {reference[1]} retired "
          f"instructions, stop {reference[0]} at {reference[2]}, "
          f"syscall {observed_syscall})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
