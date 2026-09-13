#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Adversarial tests for the Wine ntdll entry evidence contract.

The transcript is the only proof that the milestone happened, so each rule
that could be satisfied by a fake, a wrong module or a partial run has to
fail closed here.
"""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "wine_ntdll_validator", ROOT / "tools/validate_wine_ntdll_evidence.py")
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

NTDLL_BASE = 0x10404000
NTDLL_SHA = "228f0cbc6b52f8e94c760b636a3d68909eb3618183cb6cb1d2604784201195a6"
KERNELBASE_SHA = "8171a6b10c9b3acdfae29ec3ae9c30052266eda711d1fe69cdd89f78e8e3f770"
SLOT_RVA = 0xAF030
THUNK_RVA = 0xE344
ENTRY_RVA = 0xD354


def base_records() -> dict[str, list[dict[str, str]]]:
    return {
        "gate": [{"runtime": ".deps/wine-runtime/lib/i386-windows",
                  "root": "kernelbase.dll", "entry": "ntdll.dll!NtClose",
                  "modules": "2"}],
        "module": [
            {"name": "ntdll.dll", "sha256": NTDLL_SHA, "size": "3747857",
             "machine": "0x014c", "base": hex(NTDLL_BASE),
             "image_bytes": "4194304", "loaded": "1", "runtime": "1",
             "imports": "0", "tls": "0",
             "path": ".deps/wine-runtime/lib/i386-windows/ntdll.dll"},
            {"name": "kernelbase.dll", "sha256": KERNELBASE_SHA,
             "size": "4806318", "machine": "0x014c", "base": "0x10000000",
             "image_bytes": "5242880", "loaded": "1", "runtime": "1",
             "imports": "428", "tls": "0",
             "path": ".deps/wine-runtime/lib/i386-windows/kernelbase.dll"},
        ],
        "bind": [{"modules": "1", "functions": "428", "data": "0",
                  "failures": "0"}],
        "tls": [{"modules": "0"}],
        "boundary": [{"slot_rva": hex(SLOT_RVA), "slot_va": hex(NTDLL_BASE + SLOT_RVA),
                      "thunks": "1", "thunk_rva": hex(THUNK_RVA),
                      "thunk_va": hex(NTDLL_BASE + THUNK_RVA)}],
        "entry": [{"module": "ntdll.dll", "symbol": "NtClose",
                   "rva": hex(ENTRY_RVA), "eip": hex(NTDLL_BASE + ENTRY_RVA),
                   "pe_entry_rva": "0x00010c60", "stub_id": "0x0000000f"}],
        "modes": [{"chaining": "1", "residency": "1", "lazy_flags": "1"}],
        "run": [{"first_eip": hex(NTDLL_BASE + ENTRY_RVA),
                 "last_eip": hex(NTDLL_BASE + THUNK_RVA), "retired": "3",
                 "dispatches": "1", "blocks": "1", "bytes": "160",
                 "stop_address": hex(NTDLL_BASE + THUNK_RVA),
                 "stop": VALIDATOR.ACCEPTED_STOP, "syscall": "0x0000000f",
                 "host_calls": "0"}],
        "cleanup": [{"modules": "2", "mappings": "3", "translations": "1",
                     "status": "ok"}],
        "verdict": [{"accepted": "1", "stop": VALIDATOR.ACCEPTED_STOP,
                     "entry_id": "0x0000000f", "syscall": "0x0000000f",
                     "retired": "3"}],
    }


def render(records: dict[str, list[dict[str, str]]]) -> str:
    lines = ["HELLO ps5log/1 title=PPSA99994 app=prospero-win boot=0x1 tag=test"]
    for kind in ("gate", "module", "bind", "tls", "boundary", "entry", "run",
                 "modes", "cleanup", "verdict"):
        for index, record in enumerate(records.get(kind, [])):
            fields = " ".join(f"{key}={value}" for key, value in record.items())
            lines.append(f"{index}\t0\tINFO\tkind=host-wine-{kind} {fields}")
    lines.append("BYE seq=9 reason=evidence")
    return "\n".join(lines) + "\n"


def manifest() -> dict:
    return {
        "schema": "prospero-win-wine-runtime-manifest/1",
        "modules": [
            {"name": "ntdll.dll", "sha256": NTDLL_SHA, "size": 3747857},
            {"name": "kernelbase.dll", "sha256": KERNELBASE_SHA,
             "size": 4806318},
        ],
        "distribution_sha256": "0" * 64,
    }


class Case(unittest.TestCase):
    def run_validation(self, records, expect_entry: str | None = None,
                       with_manifest: bool = False) -> list[str]:
        return VALIDATOR.validate(records, manifest() if with_manifest else None,
                                  expect_entry)

    def expect_failure(self, message: str, mutate, with_manifest: bool = False,
                       expect_entry: str | None = None) -> None:
        records = base_records()
        mutate(records)
        with self.assertRaises(SystemExit) as caught:
            self.run_validation(records, expect_entry, with_manifest)
        self.assertIn(message, str(caught.exception))

    def test_accepts_a_complete_transcript(self) -> None:
        notes = self.run_validation(base_records())
        self.assertTrue(any("retired 3" in note for note in notes))

    def test_accepts_with_a_matching_manifest(self) -> None:
        self.run_validation(base_records(), with_manifest=True)

    def test_manifest_disagreement(self) -> None:
        def mutate(records):
            records["module"][0]["sha256"] = "4" * 64
        self.expect_failure("does not match the manifest", mutate,
                            with_manifest=True)

    def test_manifest_unknown_module(self) -> None:
        def mutate(records):
            records["module"][1]["name"] = "kernel32.dll"
        self.expect_failure("is not in the manifest", mutate,
                            with_manifest=True)

    def test_duplicate_module(self) -> None:
        def mutate(records):
            records["module"].append(dict(records["module"][0]))
        self.expect_failure("duplicate module record", mutate)

    def test_missing_ntdll(self) -> None:
        def mutate(records):
            records["module"] = [records["module"][1]]
        self.expect_failure("at least two module", mutate)

    def test_wrong_machine(self) -> None:
        def mutate(records):
            records["module"][0]["machine"] = "0x8664"
        self.expect_failure("not an i386 PE image", mutate)

    def test_module_never_mapped(self) -> None:
        def mutate(records):
            records["module"][0]["loaded"] = "0"
        self.expect_failure("was never mapped", mutate)

    def test_host_module_instead_of_runtime(self) -> None:
        def mutate(records):
            records["module"][0]["runtime"] = "0"
        self.expect_failure("not loaded from the runtime namespace", mutate)

    def test_empty_hash(self) -> None:
        def mutate(records):
            records["module"][0]["sha256"] = ""
        self.expect_failure("has no SHA-256", mutate)

    def test_binding_failure(self) -> None:
        def mutate(records):
            records["bind"][0]["failures"] = "1"
        self.expect_failure("import binding reported failures", mutate)

    def test_binding_did_nothing(self) -> None:
        def mutate(records):
            records["bind"][0]["functions"] = "0"
        self.expect_failure("no runtime-to-runtime import was bound", mutate)

    def test_missing_boundary(self) -> None:
        def mutate(records):
            records["boundary"][0]["thunks"] = "0"
        self.expect_failure("no __wine_syscall dispatcher thunk", mutate)

    def test_boundary_outside_ntdll(self) -> None:
        def mutate(records):
            records["boundary"][0]["thunk_va"] = hex(NTDLL_BASE + THUNK_RVA + 4)
        self.expect_failure("not inside mapped ntdll", mutate)

    def test_entry_outside_ntdll(self) -> None:
        def mutate(records):
            records["entry"][0]["eip"] = "0x00100000"
        self.expect_failure("initial guest EIP is not inside mapped ntdll",
                            mutate)

    def test_wrong_entry_symbol(self) -> None:
        self.expect_failure(
            "entry symbol is NtClose, expected LdrInitializeThunk",
            lambda r: None, expect_entry="LdrInitializeThunk")

    def test_stub_without_syscall_id(self) -> None:
        def mutate(records):
            records["entry"][0]["stub_id"] = "0x00000000"
        self.expect_failure("does not encode a syscall number", mutate)

    def test_zero_retired(self) -> None:
        def mutate(records):
            records["run"][0]["retired"] = "0"
        self.expect_failure("no guest instruction was retired", mutate)

    def test_host_call(self) -> None:
        def mutate(records):
            records["run"][0]["host_calls"] = "1"
        self.expect_failure("a host Wine function was called", mutate)

    def test_wrong_stop(self) -> None:
        def mutate(records):
            records["run"][0]["stop"] = "unsupported-instruction"
        self.expect_failure("the gate stopped with unsupported-instruction",
                            mutate)

    def test_stop_not_on_the_thunk(self) -> None:
        def mutate(records):
            records["run"][0]["stop_address"] = hex(NTDLL_BASE + ENTRY_RVA)
        self.expect_failure("did not stop exactly on the dispatcher thunk",
                            mutate)

    def test_syscall_mismatch(self) -> None:
        def mutate(records):
            records["run"][0]["syscall"] = "0x00000010"
        self.expect_failure("does not match the stub id", mutate)

    def test_wrong_start(self) -> None:
        def mutate(records):
            records["run"][0]["first_eip"] = hex(NTDLL_BASE + THUNK_RVA)
        self.expect_failure("did not start at the entry point", mutate)

    def test_leaked_mappings(self) -> None:
        def mutate(records):
            records["cleanup"][0]["modules"] = "1"
        self.expect_failure("not every mapped module was released", mutate)

    def test_leaked_translations(self) -> None:
        def mutate(records):
            records["cleanup"][0]["translations"] = "0"
        self.expect_failure("translated code was not destroyed", mutate)

    def test_cleanup_status(self) -> None:
        def mutate(records):
            records["cleanup"][0]["status"] = "vm"
        self.expect_failure("ended with status vm", mutate)

    def test_verdict_not_accepted(self) -> None:
        def mutate(records):
            records["verdict"][0]["accepted"] = "0"
        self.expect_failure("did not accept its own evidence", mutate)

    def test_verdict_disagrees(self) -> None:
        def mutate(records):
            records["verdict"][0]["retired"] = "4"
        self.expect_failure("verdict retired count disagrees", mutate)

    def test_missing_record(self) -> None:
        def mutate(records):
            del records["run"]
        self.expect_failure("expected exactly one run record", mutate)

    def test_missing_modes_record(self) -> None:
        def mutate(records):
            del records["modes"]
        self.expect_failure("expected exactly one modes record", mutate)

    def test_parse_rejects_malformed_field(self) -> None:
        text = render(base_records()).replace("stop=wine-unix-call-boundary",
                                              "stop", 1)
        with self.assertRaises(SystemExit) as caught:
            VALIDATOR.parse_transcript(text)
        self.assertIn("malformed field", str(caught.exception))

    def test_round_trip_through_the_parser(self) -> None:
        records = VALIDATOR.parse_transcript(render(base_records()))
        self.assertEqual(len(records["module"]), 2)
        self.run_validation(copy.deepcopy(records))


if __name__ == "__main__":
    unittest.main()
