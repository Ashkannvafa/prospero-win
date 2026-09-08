#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Generate code/data classifications, never API implementations or ABI guesses."""
import argparse
import json
from pathlib import Path

def generate(data):
    if data.get("schema") != "pw-import-plan/1" or not data.get("wine_worktree_clean"):
        raise ValueError("a Wine-indexed clean inventory is required")
    rows = {}
    for row in data["imports"]:
        if row["ordinal"] is not None:
            raise ValueError("ordinal catalogs require explicit manual identity review")
        kinds = {match["kind"] for match in row["wine"].get("matches", [])}
        if kinds == {"extern"}:
            kind = "PW_IMPORT_DATA"
        elif kinds and kinds <= {"stdcall", "cdecl", "varargs", "thiscall"}:
            kind = "PW_IMPORT_FUNCTION"
        else:
            raise ValueError("unresolved or conflicting export kind")
        key = (row["dll"].lower(), row["name"])
        if key in rows and rows[key] != kind:
            raise ValueError("conflicting duplicate")
        rows[key] = kind
    output = ["/* SPDX-License-Identifier: LGPL-2.1-or-later */",
              "/* Generated factual export classifications, not Wine implementations.",
              " * Wine commit: " + data["wine_commit"] + " */",
              "static const struct { const char *dll,*name; PwImportKind kind; } pw_catalog[] = {"]
    for (dll, name), kind in sorted(rows.items()):
        output.append("    {" + json.dumps(dll) + "," + json.dumps(name) + "," + kind + "},")
    return "\n".join(output + ["};", ""])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(generate(json.loads(args.inventory.read_text())))
