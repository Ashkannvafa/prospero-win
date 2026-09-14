#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Cross-check the second-dispatcher table against the pinned Wine source.

The PE side reaches the Unix side through `__wine_unix_call_dispatcher(handle,
code, args)`, so the code space is versioned data: it is the order of
`enum ntdll_unix_funcs` in `dlls/ntdll/unixlib.h`, which is also the order of
`unix_call_funcs[]` in `dlls/ntdll/unix/loader.c`. Both are re-parsed here and
compared with the C table, and the `wine_dbg_write_params` layout the first
handler depends on is checked field by field rather than assumed.

The structural checks always run; only the comparison against the pinned
checkout is skipped when no checkout is present (with a clear message), so a CI
without Wine still validates the table's own invariants.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "src/pw_unixlib.c"
HEADER = ROOT / "src/pw_unixlib.h"
COMMIT_RE = re.compile(r'PW_UNIXLIB_WINE_COMMIT "([0-9a-f]{40})"')
ENTRY_RE = re.compile(
    r'\{\s*PW_UNIXLIB_CODE_[A-Z0-9_]+,\s*"([a-z0-9_]+)"\s*\}')
ENUM_RE = re.compile(r"enum ntdll_unix_funcs\s*\{(.*?)\};", re.S)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PARAMS_RE = re.compile(
    r"struct wine_dbg_write_params\s*\{(.*?)\};", re.S)
LOADER_FUNCS_RE = re.compile(
    r"static const unixlib_entry_t unix_call_funcs\[\]\s*=\s*\{(.*?)\};", re.S)


def wine_source() -> Path | None:
    candidates = []
    if os.environ.get("PROSPERO_WINE_SOURCE"):
        candidates.append(Path(os.environ["PROSPERO_WINE_SOURCE"]))
    candidates.append(ROOT / ".deps/wine/source")
    for candidate in candidates:
        if (candidate / "dlls/ntdll/unixlib.h").is_file():
            return candidate
    return None


def our_table() -> list[str]:
    text = TABLE.read_text(encoding="utf-8")
    body = text[text.index("static const PwUnixlibFunc table"):]
    return ENTRY_RE.findall(body)


def pinned_enum(source: Path) -> list[str]:
    text = (source / "dlls/ntdll/unixlib.h").read_text(encoding="utf-8")
    match = ENUM_RE.search(text)
    assert match, "enum ntdll_unix_funcs not found in the pinned source"
    return IDENT_RE.findall(match.group(1))


def loader_order(source: Path) -> list[str]:
    text = (source / "dlls/ntdll/unix/loader.c").read_text(encoding="utf-8")
    match = LOADER_FUNCS_RE.search(text)
    assert match, "unix_call_funcs[] not found in the pinned source"
    return IDENT_RE.findall(match.group(1))


def normalize(name: str) -> str:
    """Both spellings of an entry reduce to the same suffix."""
    for prefix in ("unixcall_", "unix_"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def dbg_write_params(source: Path) -> list[str]:
    text = (source / "dlls/ntdll/unixlib.h").read_text(encoding="utf-8")
    match = PARAMS_RE.search(text)
    assert match, "wine_dbg_write_params not found in the pinned source"
    return [line.strip().rstrip(";") for line in match.group(1).splitlines()
            if line.strip()]


def main() -> int:
    entries = our_table()
    header = HEADER.read_text(encoding="utf-8")

    # Structural checks: they hold with or without a Wine checkout.
    if len(entries) != 8:
        raise SystemExit(f"unixlib table: {len(entries)} entries, expected 8")
    if len(set(entries)) != len(entries):
        raise SystemExit("unixlib table: a code name appears twice")
    if "PW_UNIXLIB_MAX_FUNCS = 8" not in header:
        raise SystemExit("unixlib header: PW_UNIXLIB_MAX_FUNCS is not 8")
    if not COMMIT_RE.search(header):
        raise SystemExit("unixlib header: the Wine commit pin is missing")
    # The first handler's contract: the params struct is a guest pointer and a
    # length, in that order, at the offsets the header declares.
    for token in ("PW_UNIXLIB_DBG_WRITE_PARAMS_BYTES = 8",
                  "PW_UNIXLIB_DBG_WRITE_STR_OFFSET = 0",
                  "PW_UNIXLIB_DBG_WRITE_LEN_OFFSET = 4"):
        if token not in header:
            raise SystemExit(f"unixlib header: missing {token}")

    source = wine_source()
    if source is None:
        print("unixlib table: structural checks passed; pinned-source "
              "comparison skipped (no Wine checkout)")
        return 0

    declared = pinned_enum(source)
    if declared != entries:
        raise SystemExit("unixlib table disagrees with enum ntdll_unix_funcs:\n"
                         f"  ours:    {entries}\n  pinned:  {declared}")
    order = [normalize(name) for name in loader_order(source)]
    if [normalize(name) for name in entries] != order:
        raise SystemExit("unixlib table disagrees with unix_call_funcs[] order:"
                         f"\n  ours:    {order}\n  pinned:  {order}")
    fields = dbg_write_params(source)
    if len(fields) != 2 or "str" not in fields[0] or "len" not in fields[1]:
        raise SystemExit("wine_dbg_write_params is not {str, len}: "
                         f"{fields}")
    if "unsigned int" not in fields[1] or "*" not in fields[0]:
        raise SystemExit("wine_dbg_write_params field types changed: "
                         f"{fields}")
    print("unixlib table: 8 entries match enum ntdll_unix_funcs, the "
          "unix_call_funcs[] order and the wine_dbg_write_params layout at "
          "the pinned Wine revision")
    return 0


if __name__ == "__main__":
    sys.exit(main())
