#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_wine_imports import WineAudit

with tempfile.TemporaryDirectory(prefix="pw-wine-audit-") as directory:
    root = Path(directory)
    for module, spec, deps in [
        ("outer", "@ stdcall -import Entry(ptr)\n@ cdecl Alias() implementation\n@ extern Data storage\n@ stdcall Bridged(ptr) Entry\n", "inner"),
        ("inner", "@ stdcall Entry(ptr)\n@ stdcall Loop() inner.Loop\n", ""),
    ]:
        path = root / "dlls" / module
        path.mkdir(parents=True)
        (path / (module + ".spec")).write_text(spec)
        (path / "Makefile.in").write_text("IMPORTS = " + deps + "\n")
        (path / "code.c").write_text("int implementation(void) { return 1; }\nint storage;\n")
    audit = WineAudit(root)
    assert audit.follow("outer.dll", "Entry")["variants"][0]["import_candidates"][0]["module"] == "inner"
    assert audit.follow("outer.dll", "Alias")["variants"][0]["source_references"][0]["first_line"] == 1
    assert audit.follow("outer.dll", "Data")["variants"][0]["kind"] == "extern"
    assert audit.follow("outer.dll", "Bridged")["variants"][0]["external_alias_candidates"][0]["module"] == "inner"
    assert audit.follow("inner.dll", "Loop")["variants"][0]["forward"]["status"] == "cycle-or-depth-limit"
    assert audit.follow("outer.dll", "Missing")["status"] == "export-not-found"
print("Wine audit passed: import routing, aliases, data exports and cycle limits")
