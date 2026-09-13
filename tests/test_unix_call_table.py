#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Cross-check the built-in Unix-call table against the pinned Wine source.

The bridge answers a call number by looking it up in a table, so that table
is versioned data, not folklore: every entry must match
`dlls/ntdll/ntsyscalls.h` at the pinned revision, including the stdcall
argument width the dispatcher has to pop. The test skips when no Wine
checkout is available, and fails closed when one is.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "src/pw_unix_call.c"
HEADER = ROOT / "src/pw_unix_call.h"
ENTRY_RE = re.compile(
    r'\{\s*0x([0-9a-f]+)u,\s*"([A-Za-z0-9_]+)",\s*(\d+)u\s*\}')
WINE_ENTRY_RE = re.compile(
    r"SYSCALL_ENTRY(?:_[A-Za-z0-9_]+)?\(\s*(0x[0-9a-f]+),\s*(\w+),\s*(\d+)\s*\)")
COMMIT_RE = re.compile(r'PW_UNIX_CALL_WINE_COMMIT "([0-9a-f]{40})"')


def wine_source() -> Path | None:
    candidates = []
    if os.environ.get("PROSPERO_WINE_SOURCE"):
        candidates.append(Path(os.environ["PROSPERO_WINE_SOURCE"]))
    candidates.append(ROOT / ".deps/wine/source")
    for candidate in candidates:
        if (candidate / "dlls/ntdll/ntsyscalls.h").is_file():
            return candidate
    return None


def our_table() -> dict[int, tuple[str, int]]:
    text = TABLE.read_text(encoding="utf-8")
    body = text[text.index("static const PwUnixCallInfo table[]"):]
    return {int(match.group(1), 16): (match.group(2), int(match.group(3)))
            for match in ENTRY_RE.finditer(body)}


def wine_table(source: Path) -> dict[int, tuple[str, int]]:
    text = (source / "dlls/ntdll/ntsyscalls.h").read_text(encoding="utf-8")
    block = text.split("#define ALL_SYSCALLS32", 1)[1].split("#ifdef _WIN64", 1)[0]
    return {int(match.group(1), 16): (match.group(2), int(match.group(3)))
            for match in WINE_ENTRY_RE.finditer(block)}


def main() -> int:
    entries = our_table()
    if not entries:
        raise SystemExit("unix call table: the built-in table is empty")
    for identifier, (name, args) in entries.items():
        if args % 4 != 0 or args > 64:
            raise SystemExit(f"unix call table: {name} has {args} argument bytes")
        if identifier > 0xFFFF:
            raise SystemExit(f"unix call table: {name} has an out-of-range id")
    source = wine_source()
    if source is None:
        print(f"unix call table: {len(entries)} entries checked structurally; "
              "skipped the pinned-source cross-check (no Wine checkout)")
        return 0
    pinned = wine_table(source)
    for identifier, entry in sorted(entries.items()):
        if identifier not in pinned:
            raise SystemExit(f"unix call table: id {identifier:#06x} is not in "
                             "the pinned 32-bit table")
        if pinned[identifier] != entry:
            raise SystemExit(
                f"unix call table: id {identifier:#06x} is {entry} here and "
                f"{pinned[identifier]} in the pinned source")
    declared = COMMIT_RE.search(HEADER.read_text(encoding="utf-8"))
    if not declared:
        raise SystemExit("unix call table: the header does not name a revision")
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                          check=False, capture_output=True, text=True)
    if head.returncode != 0:
        raise SystemExit("unix call table: the Wine checkout has no HEAD")
    if head.stdout.strip() != declared.group(1):
        raise SystemExit("unix call table: the table is checked against "
                         f"{declared.group(1)} but the checkout is "
                         f"{head.stdout.strip()}")
    print(f"unix call table: {len(entries)} entries match the pinned Wine "
          f"revision {declared.group(1)[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
