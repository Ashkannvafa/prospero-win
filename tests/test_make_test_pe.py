#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Cross-check the Python PE encoder against the C parser and mapper.

Two independent encoders exist on purpose: the C fixture header used by the
unit tests and `tools/make_test_pe.py`, which stages the on-disk samples the
hardware gate loads. This test feeds the Python output to the C
implementation through `inspect_pe`, so a defect in either encoder shows up
as a disagreement instead of certifying itself.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSPECT = ROOT / "build" / "host" / "inspect_pe"

sys.path.insert(0, str(ROOT / "tools"))

import make_test_pe  # noqa: E402


def run_inspect(*arguments: str) -> str:
    if not INSPECT.exists():
        raise unittest.SkipTest(f"{INSPECT} is not built")
    completed = subprocess.run([str(INSPECT), *arguments], check=False,
                               capture_output=True, text=True)
    if completed.returncode != 0:
        raise AssertionError(
            f"inspect_pe failed: {completed.returncode}\n"
            f"{completed.stdout}\n{completed.stderr}")
    return completed.stdout


def field(output: str, key: str) -> str:
    match = re.search(rf"\b{re.escape(key)}=(\S+)", output)
    if not match:
        raise AssertionError(f"{key} missing from:\n{output}")
    return match.group(1)


def graph_field(output: str, key: str) -> str:
    """Reads a field from the graph summary line specifically.

    `modules=` also appears in the import listing, so an unscoped search
    would silently read the wrong number.
    """
    for line in output.splitlines():
        if line.startswith("graph "):
            return field(line, key)
    raise AssertionError(f"no graph line in:\n{output}")


class SampleChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def stage(self, pe32plus: bool = True) -> None:
        for name, data in make_test_pe.sample_chain(pe32plus=pe32plus).items():
            (self.path / name).write_bytes(data)

    def test_amd64_chain_maps_and_resolves(self) -> None:
        self.stage()
        output = run_inspect(str(self.path / "sample.exe"), "--dir",
                             str(self.path))

        self.assertEqual(field(output, "machine"), "amd64")
        self.assertEqual(field(output, "bits"), "64")
        self.assertEqual(field(output, "preferred_base"), "0x140000000")
        self.assertEqual(field(output, "relocatable"), "1")
        self.assertEqual(field(output, "dynamic_base"), "1")
        self.assertIn("native_execution=yes", output)

        # Three declared sections plus the generated .idata and .reloc.
        self.assertEqual(field(output, "sections"), "5")  # 3 declared + 2 generated
        for name in (".text", ".data", ".bss", ".idata", ".reloc"):
            self.assertIn(name, output)
        self.assertRegex(output, r"section \.text\s+rva=0x00001000.*r-x")
        self.assertRegex(output, r"section \.bss\s+.*raw=0\s+.*bss")

        # binkw32 is third-party and mapped; kernel32 is a host binding.
        self.assertRegex(output, r"binkw32\.dll\s+named=2\s+ordinal=0\s+local")
        self.assertRegex(output, r"KERNEL32\.dll\s+named=1\s+ordinal=1\s+host")

        # game -> binkw32 -> msvcrt, plus kernel32 from the root.
        self.assertEqual(graph_field(output, "modules"), "4")
        self.assertEqual(graph_field(output, "local"), "1")
        self.assertEqual(graph_field(output, "host"), "2")
        self.assertEqual(graph_field(output, "cycles"), "0")
        self.assertEqual(graph_field(output, "depth"), "2")

        # The root is loaded last: every dependency precedes it.
        order = re.findall(r"^  \d+ (\S+)\s+(\S+)", output, re.M)
        self.assertEqual(order[-1], ("root.exe", "root"))
        self.assertIn(("binkw32.dll", "local"), order)
        self.assertLess(order.index(("binkw32.dll", "local")),
                        order.index(("root.exe", "root")))

        # Every mapped module was rebased away from its preferred base.
        for line in output.splitlines():
            if " local " in line or " root " in line:
                self.assertRegex(line, r"relocs=[1-9]")
        self.assertEqual(field(output, "opens"), "2")
        self.assertEqual(field(output, "closes"), "2")

    def test_i386_chain_parses_but_is_not_natively_executable(self) -> None:
        self.stage(pe32plus=False)
        output = run_inspect(str(self.path / "sample.exe"), "--no-map")

        self.assertEqual(field(output, "machine"), "i386")
        self.assertEqual(field(output, "bits"), "32")
        self.assertEqual(field(output, "preferred_base"), "0x400000")
        # The console runs 64-bit user code only; see docs/EXECUTION_MODEL.md.
        self.assertIn("native_execution=no", output)
        self.assertRegex(output, r"binkw32\.dll\s+named=2")

    def test_encoder_output_is_deterministic(self) -> None:
        first = make_test_pe.sample_chain()
        second = make_test_pe.sample_chain()
        self.assertEqual(first, second)
        # A reproducible artifact is a precondition for hashed evidence.
        self.assertEqual(sorted(first), ["binkw32.dll", "sample.exe"])

    def test_encoder_rejects_bad_specs(self) -> None:
        with self.assertRaises(ValueError):
            make_test_pe.build_pe(make_test_pe.Spec(name="empty.exe"))
        with self.assertRaises(ValueError):
            make_test_pe.build_pe(make_test_pe.Spec(
                name="misaligned.exe",
                image_base=0x140000800,
                sections=[make_test_pe.Section(
                    ".text", make_test_pe.SCN_MEM_READ, b"\xc3")],
            ))


if __name__ == "__main__":
    unittest.main()
