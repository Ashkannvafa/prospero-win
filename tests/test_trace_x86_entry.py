#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Synthetic PE execution/stop tests; no original game is required."""
import subprocess
import json
import struct
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from make_test_pe import Spec, Section, Import, build_pe, SCN_CNT_CODE, SCN_MEM_READ, SCN_MEM_EXECUTE

with tempfile.TemporaryDirectory(prefix="pw-entry-") as directory:
    path = Path(directory) / "synthetic.exe"
    for instructions, steps, reason in [
        (bytes.fromhex("6aff 58 cc"), 2, "unsupported"),
        (bytes.fromhex("ebfe"), 256, "budget"),
        (bytes.fromhex("bc00000000 50"), 1, "memory-bounds"),
        (bytes.fromhex("64a100000000 50 59 cc"), 3, "unsupported"),
        (bytes.fromhex("8b0500000001 cc"), 1, "unsupported"),
        (bytes.fromhex("c7050000000178563412"), 0, "memory-bounds"),
    ]:
        path.write_bytes(build_pe(Spec(name="synthetic.exe", pe32plus=False,
            image_base=0x01000000, relocate_data_pointer=False,
            sections=[Section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE,
                              instructions)])))
        result = subprocess.run([str(root / "build/host/trace_x86_entry"), str(path)],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 2, result.stderr
        assert f"steps={steps} stop={reason} " in result.stdout, result.stdout
        assert "kind=host-heap-summary blocks=1 live=0 requested=0 arena=8388608 valid=1" in result.stdout
        assert "kind=host-dbt-cache " in result.stdout
        assert "kind=host-gdi-summary dcs=0 window_dcs=0 memory_dcs=0 surfaces=0 " \
               "targets=0 bitmaps=0 pixels=0 valid=1" in result.stdout
        assert "kind=host-gdi-cleanup dcs=0 surfaces=0 bitmaps=0 pixels=0 valid=1" in result.stdout
        if reason == "budget":
            limited = subprocess.run([str(root / "build/host/trace_x86_entry"), str(path), "8", "01001000"],
                                     capture_output=True, text=True, timeout=5)
            assert limited.returncode == 2 and "steps=8 stop=budget " in limited.stdout
            assert "dispatches=8 hits=7 misses=1 publishes=1 retired=8 " in limited.stdout
            assert "kind=host-pc-milestone pc=0x01001000" in limited.stdout
            assert "kind=host-pc-milestone-summary pc=0x01001000 seen=1" in limited.stdout
            for invalid in ("0", "65537", "no", "12bad", "-1", ""):
                rejected = subprocess.run([str(root / "build/host/trace_x86_entry"), str(path), invalid],
                                          capture_output=True, text=True, timeout=5)
                assert rejected.returncode == 1 and not rejected.stdout
    # Full synthetic PE -> IAT binding -> translated call -> Win32 return.
    for api, reason in [("GetModuleHandleA", "unsupported"), ("SetThreadPriority", "unimplemented-api")]:
        code=bytearray.fromhex("6a00 ff1500000000 cc")
        spec=Spec(name="synthetic.exe",pe32plus=False,image_base=0x01000000,
                  relocate_data_pointer=False,
                  sections=[Section(".text",SCN_CNT_CODE|SCN_MEM_READ|SCN_MEM_EXECUTE,bytes(code))],
                  imports=[Import("KERNEL32.dll",(api,))])
        path.write_bytes(build_pe(spec))
        inspected=subprocess.run([str(root/"build/host/inspect_pe"),str(path),"--imports-json"],
                                 check=True,capture_output=True,text=True)
        slot=json.loads(inspected.stdout)["modules"][0]["imports"][0]["iat_rva"]
        struct.pack_into("<I",code,4,0x01000000+slot)
        spec.sections[0].data=bytes(code);path.write_bytes(build_pe(spec))
        result=subprocess.run([str(root/"build/host/trace_x86_entry"),str(path)],
                              capture_output=True,text=True,timeout=5)
        assert result.returncode==2, result.stderr
        assert f"steps=2 stop={reason} " in result.stdout,result.stdout
        assert "total=1 functions=1 data=0" in result.stdout
        if api=="GetModuleHandleA":
            assert "name=GetModuleHandleA result=0x01000000" in result.stdout
        else:
            assert "name=SetThreadPriority status=-5 caller=0x01001008" in result.stdout
print("host entry tracer passed: synthetic execution and bounded classified stops")
