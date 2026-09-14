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

The list of sources is the Makefile's own `WINE_GATE`, not a copy of it: the
service adapters were split out of the gate in one commit, and a hardcoded list
would have gone on scanning the old file while the moved code was never
checked. A gate source that is added to the build is covered here by
construction.

Read-only tables (`static const`), forward declarations and functions are of
course fine; the check is about a mutable object with a name.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Shared headers on the same path. Nothing in them is an object today, and a
# table added to one of them is exactly as much per-process state as one added
# to a source file.
SHARED_HEADERS = [
    "src/pw_wine_context.h",
    "src/pw_wine_gate.h",
    "src/pw_nt_dispatch.h",
    "src/pw_nt_handle.h",
]


def gate_sources() -> list[str]:
    """The Makefile's `WINE_GATE` variable, following continuations."""
    lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("WINE_GATE :="):
            continue
        value: list[str] = []

        while True:
            value.append(lines[index].split(":=", 1)[-1].rstrip("\\"))
            if not lines[index].rstrip().endswith("\\"):
                break
            index += 1
        return [source for source in " ".join(value).split() if not source.startswith("$")]
    raise SystemExit("the Makefile has no WINE_GATE variable to scan")

# A file-scope definition: "static <something> <name>...;" with no parentheses
# before the semicolon, so function declarations and definitions do not match.
STATIC_OBJECT = re.compile(
    r'^static\s+(?!const\b)(?![A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\))'
    r'[A-Za-z_][A-Za-z0-9_]*(?:\s+|\s*\*\s*)'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;',
    re.M)


def main() -> int:
    offenders: list[str] = []
    sources = gate_sources() + SHARED_HEADERS

    for relative in sources:
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
          f"{len(sources)} gate-path sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
