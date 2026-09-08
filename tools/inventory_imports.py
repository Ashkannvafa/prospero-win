#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Inventory a private PE through the canonical C parser, without execution."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUBSYSTEMS = {
    "kernel32.dll": "process-memory-files-loader",
    "msvcrt.dll": "crt",
    "user32.dll": "windows-messages-input",
    "gdi32.dll": "gdi-palettes-blits",
    "winmm.dll": "audio-timers-midi",
    "advapi32.dll": "registry-security",
    "shell32.dll": "shell-ui",
    "comctl32.dll": "controls",
}


def wine_export(source, dll, name, ordinal):
    """Report spec declarations, not a claim that code can be copied alone."""
    stem = dll.lower().removesuffix(".dll")
    if not re.fullmatch(r"[a-z0-9_.-]+", stem):
        return {"status": "unresolved-module"}
    relative = Path("dlls") / stem / (stem + ".spec")
    result = {"status": "not-indexed", "candidate_spec": relative.as_posix()}
    if source is None:
        return result
    path = source / relative
    if not path.is_file():
        return {**result, "status": "spec-missing"}
    matches = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        export = re.match(r"(@|\d+)\s+(\S+)\s+(?:-\S+\s+)*([^\s(]+)", text)
        if export and ((name is not None and export[3] == name) or
                       (name is None and export[1] == str(ordinal))):
            matches.append({"line": line_number, "kind": export[2], "declaration": text})
    return {**result, "status": "declaration-found" if matches else "export-not-found",
            "matches": matches}


def inventory(path, wine_source=None):
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    result = subprocess.run([str(ROOT / "build/host/inspect_pe"), str(path),
                             "--imports-json"], check=True, capture_output=True, text=True)
    data = json.loads(result.stdout)
    if hashlib.sha256(path.read_bytes()).hexdigest() != before:
        raise RuntimeError("input changed during inspection")
    if data["schema"] != "pw-imports/1":
        raise ValueError("unexpected inspector schema")
    rows = []
    for module in data["modules"]:
        for symbol in module["imports"]:
            rows.append({"dll": module["dll"], **symbol, "bound": module["bound"],
                         "subsystem": SUBSYSTEMS.get(module["dll"].lower(), "unclassified"),
                         "implementation": "pending", "abi": "not-audited",
                         "wine": wine_export(wine_source, module["dll"],
                                             symbol["name"], symbol["ordinal"])})
    commit = None
    if wine_source:
        commit = subprocess.run(["git", "-C", str(wine_source), "rev-parse", "HEAD"],
                                check=True, capture_output=True, text=True).stdout.strip()
    return {"schema": "pw-import-plan/1", "input_sha256": before,
            "machine": data["machine"], "image_base": data["image_base"],
            "module_count": len(data["modules"]), "import_count": len(rows),
            "scope": "normal static import directory only",
            "delay_import_directory_present": data["delay_import_directory_present"],
            "dynamic_imports": "unknown until runtime or further analysis",
            "wine_commit": commit, "wine_worktree_clean": None if not wine_source else
                not subprocess.run(["git", "-C", str(wine_source), "status", "--porcelain"],
                                   check=True, capture_output=True, text=True).stdout.strip(),
            "imports": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--wine-source", type=Path)
    parser.add_argument("--output", type=Path, help="new JSON report; refuses to overwrite")
    args = parser.parse_args()
    report = json.dumps(inventory(args.image.resolve(), args.wine_source), indent=2) + "\n"
    if args.output:
        with args.output.open("x") as file:
            file.write(report)
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
