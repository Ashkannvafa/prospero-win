#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""The coverage classifier must use the translator's exact acceptance."""
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from survey_x86_coverage import parse_root, reachable, x87_form

assert reachable({"a": {"b", "c"}, "b": {"c"}}, "a") == {"a", "b", "c"}
parsed = parse_root("01020f95=entry")
assert (parsed.address, parsed.label) == ("01020f95", "entry")
result = subprocess.run(
    [str(root / "build/host/classify_x86")],
    input="8bff\n55\nd9e8\nzz\n\n", text=True, capture_output=True, check=True)
statuses = [int(line) for line in result.stdout.splitlines()]
assert statuses[:2] == [0, 0], statuses
assert statuses[2] != 0, statuses
assert statuses[3:] == [-1, -1], statuses
print("x86 instruction classifier passed: exact supported and rejected forms")

assert x87_form(bytes.fromhex("d9e8"), "FLD1") == "FLD1:op1/reg/g5/r0"
assert x87_form(bytes.fromhex("9bdbe3"), "FINIT") == "FINIT:op3/reg/g4/r3"
assert x87_form(bytes.fromhex("d945fc"), "FLD") == "FLD:op1/mem/g0"
assert x87_form(bytes.fromhex("f3d945fc"), "FLD") == "FLD:op1/mem/g0"
assert x87_form(bytes.fromhex("90"), "NOP") is None
print("x87 form classifier passed")
