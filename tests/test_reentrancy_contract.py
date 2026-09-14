#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""The gate path must hold no process-static state.

An earlier review asked for the gate's state to move out of process statics or,
until that happened, for a single-instance contract to be documented and
enforced. The state does live in the run's own context - the config, the
per-run loader, engine, cache and the units - so what is left is to *keep* it
that way. This test is that contract: it scans every source on the gate's
compilation path and fails when a mutable file-scope object appears, because
the next one is exactly what would make two runs interfere.

Read-only tables (`static const`), forward declarations and functions are of
course fine; the check is about a mutable object with a name.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every source the gate binary is built from, minus the console/platform
# adapters (which the host build does not compile) and minus the runner, whose
# report buffer is process-level on purpose: it is a tool that runs once.
GATE_SOURCES = [
    "src/pw_wine_gate.c",
    "src/pw_guest_vm.c",
    "src/pw_guest_process.c",
    "src/pw_nt_handle.c",
    "src/pw_unix_call.c",
    "src/pe_export.c",
    "src/pe_image.c",
    "src/pe_import.c",
    "src/pe_layout.c",
    "src/pe_reloc.c",
    "src/pe_tls.c",
    "src/pw_compat32.c",
    "src/pw_export.c",
    "src/pw_guest_call.c",
    "src/pw_guest_fp.c",
    "src/pw_import_bind.c",
    "src/pw_loader.c",
    "src/pw_map.c",
    "src/pw_module_name.c",
    "src/pw_result.c",
    "src/pw_segment.c",
    "src/pw_sha256.c",
    "src/pw_tls.c",
    "src/pw_vm.c",
    "src/pw_vm_posix.c",
    "src/pw_x86_block.c",
    "src/pw_x86_cache.c",
    "src/pw_x86_engine.c",
    "src/pw_x87.c",
]

# A file-scope definition: "static <something> <name>...;" with no parentheses
# before the semicolon, so function declarations and definitions do not match.
STATIC_OBJECT = re.compile(
    r'^static\s+(?!const\b)(?![A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\))'
    r'[A-Za-z_][A-Za-z0-9_]*(?:\s+|\s*\*\s*)'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;',
    re.M)


def main() -> int:
    offenders: list[str] = []
    for relative in GATE_SOURCES:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for match in STATIC_OBJECT.finditer(text):
            declaration = match.group(0).strip()
            # A prototype is not an object: "static int f(void);" has the
            # parentheses the pattern already excludes, but a function pointer
            # table spelled as a prototype keeps them too.
            if "(" in declaration:
                continue
            offenders.append(f"{relative}: {declaration}")
    if offenders:
        raise SystemExit("mutable file-scope state on the gate path:\n  " +
                         "\n  ".join(offenders))
    print("reentrancy contract passed: no mutable file-scope state in "
          f"{len(GATE_SOURCES)} gate-path sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
