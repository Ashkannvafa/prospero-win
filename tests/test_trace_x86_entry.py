#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Synthetic PE execution/stop tests; no original game is required."""
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from make_test_pe import Spec, Section, build_pe, SCN_CNT_CODE, SCN_MEM_READ, SCN_MEM_EXECUTE

with tempfile.TemporaryDirectory(prefix="pw-entry-") as directory:
    path = Path(directory) / "synthetic.exe"
    for instructions, steps, reason in [
        (bytes.fromhex("6aff 58 cc"), 2, "unsupported"),
        (bytes.fromhex("ebfe"), 256, "budget"),
        (bytes.fromhex("bc00000000 50"), 1, "memory-bounds"),
        (bytes.fromhex("64a100000000 50 59 cc"), 3, "unsupported"),
    ]:
        path.write_bytes(build_pe(Spec(name="synthetic.exe", pe32plus=False,
            image_base=0x01000000, relocate_data_pointer=False,
            sections=[Section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE,
                              instructions)])))
        result = subprocess.run([str(root / "build/host/trace_x86_entry"), str(path)],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 2, result.stderr
        assert f"steps={steps} stop={reason} " in result.stdout, result.stdout
print("host entry tracer passed: synthetic execution and bounded classified stops")
