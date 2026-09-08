#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tools"))
from make_test_pe import Spec, Import, Section, build_pe, SCN_CNT_CODE, SCN_MEM_READ, SCN_MEM_EXECUTE
from inventory_imports import inventory, wine_export

with tempfile.TemporaryDirectory(prefix="pw-inventory-") as directory:
    path = Path(directory)
    image = path / "synthetic.exe"
    image.write_bytes(build_pe(Spec(name="synthetic.exe", pe32plus=False,
        sections=[Section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE, b"\xc3")],
        imports=[Import("KERNEL32.dll", ("GetModuleHandleA", 'Quote"Name'), (42,))])))
    data = inventory(image)
    assert data["module_count"] == 1 and data["import_count"] == 3
    assert data["imports"][1]["name"] == 'Quote"Name'
    assert data["imports"][2]["ordinal"] == 42
    assert len({row["iat_rva"] for row in data["imports"]}) == 3
    assert all(row["implementation"] == "pending" for row in data["imports"])
    spec = path / "dlls/kernel32/kernel32.spec"
    spec.parent.mkdir(parents=True)
    spec.write_text("@ stdcall -import GetModuleHandleA(str)\n42 stub Example\n"
                    "@ stdcall Different() Missing\n")
    assert wine_export(path, "KERNEL32.dll", "GetModuleHandleA", None)["status"] == "declaration-found"
    assert wine_export(path, "KERNEL32.dll", None, 42)["matches"][0]["line"] == 2
    assert wine_export(path, "KERNEL32.dll", "Missing", None)["status"] == "export-not-found"
print("import inventory passed: names, ordinals, JSON escaping and Wine spec lookup")
