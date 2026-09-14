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

import json
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

# The pinned checkpoint: the exact frontier and handler coverage of the run
# this branch has reached, measured on one exact staged distribution.
#
# These numbers are evidence, not a contract of the dispatcher, so they are
# *meant* to be edited - deliberately, in the same commit that moves them. A
# failure here means one of three things and the message says which value moved:
# the bridge advanced, the staged runtime changed identity, or something
# regressed. The generic acceptance below still runs on its own terms; this
# block is what makes "we got further" and "we quietly got less far" different
# outcomes instead of both passing.
#
# The measured frontier after the last serviced call (NtQueryInformationProcess
# for the process image) is the classified null jump the validator accepts:
# the loader's own debug message calls __wine_unix_call_dispatcher, the unix
# -call dispatcher this gate does not publish yet, so the run ends with
# returned-to-caller at address zero.
PINNED_DISTRIBUTION = (
    "e88025bbc00a1195ebdfd76589ae0fdeab3265158ea7e8af40fd398c1ec0673d")
PINNED_RUN = {
    "stop": "returned-to-caller",
    "stop_address": "0x00000000",
    # Moved deliberately in the commit that names the process's own image, its
    # current directory and its DLL search path in the root that image came
    # from: this control's root is a system module, so its parameters name the
    # Windows directory and the search path starts there. The loader reaches
    # the same stop through the same 19 calls and the same handler coverage
    # below, with the length of the search accounted for here.
    "retired": "33118",
    "dispatches": "7065",
    "blocks": "961",
    "host_calls": "0",
    "syscall": "0x00000019",
}
PINNED_CALLS = {
    "serviced": "19", "handled": "19", "unimplemented": "0", "unknown": "0",
    "rejected": "0", "refusals": "0", "allocations": "2", "releases": "1",
    "regions": "2", "files": "1", "directories": "1", "registry": "1",
    "objects": "1", "tokens": "1", "processes": "1",
}
PINNED_CLEANUP = {"modules": "2", "mappings": "7", "translations": "1",
                  "status": "ok"}
# Ordered handler coverage: the call ids in the order the run issued them, with
# repeats, because the order is part of what makes this a record of a loader
# run rather than a set of implemented functions.
PINNED_SEQUENCE = (0x18, 0x18, 0x18, 0x33, 0x49, 0x1e, 0x12, 0x17, 0x17,
                   0x0f, 0x36, 0x21, 0x1d, 0x12, 0x0f, 0x12, 0x12, 0x58,
                   0x19)


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


def call_records(text: str) -> list[dict[str, str]]:
    """Every `host-wine-call-seq` record, ordered by its own index."""
    records = []
    for line in text.splitlines():
        if "kind=host-wine-call-seq " not in line:
            continue
        records.append(dict(token.split("=", 1)
                            for token in line.split() if "=" in token))
    return sorted(records, key=lambda record: int(record["index"]))


def compare(observed: dict[str, str], expected: dict[str, str], label: str,
            problems: list[str]) -> None:
    for name, value in expected.items():
        if observed.get(name) != value:
            problems.append(f"{label}.{name}: checkpoint says {value}, "
                            f"this run measured {observed.get(name)}")


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


# The application-root scenario: the same bounded gate with a generated PE32
# application as the process image, reading the runtime's own DLLs. Its frontier
# is pinned here for the same reason the control's is - so that "we got further"
# and "we quietly got less far" are different outcomes - and because the two
# configurations disagree: with register residency on, the run stops at the
# engine defect recorded in the private report (a memory-bounds stop inside
# dlls/ntdll's rb-tree fixup); with residency off it runs to the gate's own step
# budget. Either number moving is a decision, not an accident.
#
# The fixture is generated, not committed: tools/make_test_pe.py writes the
# application, its two DLLs and the dependency diamond into a temporary
# directory the run is pointed at.
APPLICATION_PINNED = {
    # Moved deliberately in the commit that serves NtAreMappedFilesTheSame and
    # raises the call budget to the measured requirement: residency off now
    # stops at the service after it, NtGetNextThread (i386 syscall 0x00a0, the
    # call ntdll's LdrpAllocateTls makes while it gives every running thread a
    # TLS block for the two modules that carry a TLS directory). The fault
    # address with residency on is unchanged while the faulting block stays the
    # same (0x105c1aa7, 9 instructions, resident mask 0x43), which is the
    # signature the private report records for it.
    "residency_on": {"stop": "memory-bounds", "fault": "0x61905fd0",
                     "retired": "56825", "blocks": "1223"},
    "residency_off": {"stop": "unix-call-unimplemented", "retired": "495501",
                      "blocks": "1797"},
}


def run_application(modes: str) -> str:
    with tempfile.TemporaryDirectory() as directory:
        built = subprocess.run(
            [sys.executable, str(ROOT / "tools/make_test_pe.py"), "--application",
             "--out-dir", directory], check=True, capture_output=True, text=True)
        assert built.returncode == 0, built.stderr
        return run_gate("--runtime", str(DISTRIBUTION / "lib/i386-windows"),
                        "--application", directory, "--root-application", "1",
                        "--root", "app.exe", "--entry-module", "ntdll.dll",
                        "--entry-symbol", "LdrInitializeThunk",
                        "--modules",
                        "app.exe,ntdll.dll,kernelbase.dll,a.dll,b.dll",
                        "--bridge", "1", "--unixlib", "1", "--modes", modes,
                        expect_acceptance=False)


def check_application_frontier() -> None:
    on = run_application("1,1,1")
    off = run_application("0,0,1")
    problems = []
    for label, text in (("residency_on", on), ("residency_off", off)):
        expected = APPLICATION_PINNED[label]
        stop = field(text, "run", "stop")
        if stop != expected["stop"]:
            problems.append(f"{label}: stop {stop} != {expected['stop']}")
        for name in ("retired", "blocks"):
            observed = field(text, "run", name)
            if observed != expected[name]:
                problems.append(f"{label}: {name} {observed} != "
                                f"{expected[name]}")
        if "fault" in expected:
            address = field(text, "fault", "address")
            if address != expected["fault"]:
                problems.append(f"{label}: fault address {address} != "
                                f"{expected['fault']}")
    if problems:
        raise SystemExit(
            "wine ntdll gate: the application-root frontier moved, and moving "
            "it must be a decision recorded in the same commit:\n  " +
            "\n  ".join(problems))
    print("wine ntdll gate: application-root frontier confirmed "
          f"(residency on {APPLICATION_PINNED['residency_on']['stop']}, "
          f"residency off {APPLICATION_PINNED['residency_off']['stop']})")


def main() -> int:
    if not RUNNER.exists() or not MANIFEST.exists():
        print("wine ntdll gate: skipped (no staged runtime)")
        return 0
    output = run_gate()
    print(validate_transcript(output, "NtClose"))
    # The run's evidence names the pipeline stage it reached: a failure has to
    # say where it stopped, and a run that gets as far as executing guest code
    # says so with its last stage.
    assert "stage=" in output, "the run evidence does not name its stage"

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

    # With the Unix-call bridge enabled the run must service real calls and
    # continue; how far it gets afterwards depends on instruction coverage,
    # so the contract is about the calls, not about the final stop. The run
    # uses the gate's own budget: real ntdll initialization needs thousands of
    # dispatches to reach the next stop, and a budget that cuts it short would
    # stop with "step-budget", which is not evidence about anything.
    bridged = run_gate("--entry-symbol", "LdrInitializeThunk", "--bridge", "1",
                       expect_acceptance=False)
    print(validate_transcript(bridged, "LdrInitializeThunk"))
    tallies = (field(bridged, "calls", "handled"),
               field(bridged, "calls", "rejected"),
               field(bridged, "calls", "allocations"))
    if int(tallies[0]) < 1 or int(tallies[1]) != 0 or int(tallies[2]) < 1:
        raise SystemExit("wine ntdll gate: the bridge did not service a call "
                         f"cleanly: handled={tallies[0]} rejected={tallies[1]} "
                         f"allocations={tallies[2]}")
    print("wine ntdll gate: bridge serviced "
          f"{tallies[0]} calls and mapped {tallies[2]} guest region(s); "
          f"final stop {field(bridged, 'run', 'stop')}")

    # The pinned checkpoint. The measurements describe one exact distribution,
    # so a differently built runtime is not comparable and must be re-measured
    # rather than silently compared.
    staged = json.loads(MANIFEST.read_text(encoding="utf-8")).get(
        "distribution_sha256")
    if staged != PINNED_DISTRIBUTION:
        raise SystemExit(
            "wine ntdll gate: the pinned checkpoint in this test describes "
            f"distribution {PINNED_DISTRIBUTION}, but the staged runtime is "
            f"{staged}. Stage the pinned distribution, or re-measure the "
            "checkpoint in the same commit as the change that moved it.")
    problems: list[str] = []
    compare({name: field(bridged, "run", name) for name in PINNED_RUN},
            PINNED_RUN, "run", problems)
    compare({name: field(bridged, "calls", name) for name in PINNED_CALLS},
            PINNED_CALLS, "calls", problems)
    compare({name: field(bridged, "cleanup", name) for name in PINNED_CLEANUP},
            PINNED_CLEANUP, "cleanup", problems)
    sequence = [int(record["id"], 16) for record in call_records(bridged)]
    if sequence != list(PINNED_SEQUENCE):
        problems.append(
            "handler sequence: checkpoint says " +
            " ".join(f"{value:#04x}" for value in PINNED_SEQUENCE) +
            ", this run measured " +
            " ".join(f"{value:#04x}" for value in sequence))
    if problems:
        raise SystemExit(
            "wine ntdll gate: the pinned checkpoint moved, and moving it must "
            "be a decision recorded in the same commit:\n  " +
            "\n  ".join(problems))
    check_application_frontier()
    print("wine ntdll gate: pinned checkpoint confirmed "
          f"({len(sequence)} calls, {PINNED_RUN['retired']} retired "
          f"instructions, stop {PINNED_RUN['stop']} at "
          f"{PINNED_RUN['stop_address']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
