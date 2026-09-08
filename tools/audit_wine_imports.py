#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Follow Wine export declarations; report source leads, not extraction closure."""
import argparse
from functools import lru_cache
import json
from pathlib import Path
import re
import subprocess
from inventory_imports import wine_export


class WineAudit:
    def __init__(self, source):
        self.source = source

    @lru_cache(None)
    def dependencies(self, module):
        path = self.source / "dlls" / module / "Makefile.in"
        if not path.is_file():
            return []
        text = path.read_text().replace("\\\n", " ")
        match = re.search(r"^IMPORTS\s*=\s*(.*)$", text, re.M)
        return [token for token in match[1].split() if re.fullmatch(r"[a-z0-9_]+", token)] if match else []

    @lru_cache(None)
    def sources(self, module):
        directory = self.source / "dlls" / module
        return [(path, path.read_text(errors="replace")) for path in sorted(directory.rglob("*"))
                if path.suffix in (".c", ".h", ".S", ".s") and "tests" not in path.relative_to(directory).parts]

    def references(self, module, symbol):
        if not symbol or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
            return []
        expression = re.compile(r"\b" + re.escape(symbol) + r"\b")
        result = []
        for path, text in self.sources(module):
            hits = [text.count("\n", 0, match.start()) + 1 for match in expression.finditer(text)]
            if hits:
                result.append({"file": path.relative_to(self.source).as_posix(),
                               "first_line": hits[0], "occurrences": len(hits)})
        return result

    def follow(self, dll, name, ordinal=None, seen=()):
        module = dll.lower().removesuffix(".dll")
        if not re.fullmatch(r"[a-z0-9_]+", module):
            return {"status": "unsupported-module"}
        key = (module, name, ordinal)
        if key in seen or len(seen) >= 8:
            return {"status": "cycle-or-depth-limit"}
        exported = wine_export(self.source, dll, name, ordinal)
        node = {"module": module, "name": name, "ordinal": ordinal,
                "status": exported["status"], "module_imports": self.dependencies(module),
                "variants": []}
        for match in exported.get("matches", []):
            declaration = match["declaration"]
            signature = re.match(r"(?:@|\d+)\s+\S+\s+((?:-\S+\s+)*)([^\s(]+)(?:\(([^)]*)\))?(?:\s+(\S+))?", declaration)
            if not signature:
                node["variants"].append({"status": "unparsed-declaration"})
                continue
            flags, exported_name, parameters, alias = signature.groups()
            variant = {"kind": match["kind"], "flags": flags.split(),
                       "spec_line": match["line"], "parameters": parameters,
                       "implementation_symbol": alias or exported_name,
                       "dependency_closure": "not-established"}
            symbol = alias or exported_name
            if alias and "." in alias:
                target_module, target = alias.rsplit(".", 1)
                variant["forward"] = self.follow(target_module, target, seen=seen+(key,))
            elif "-import" in flags.split():
                variant["import_candidates"] = []
                for dependency in self.dependencies(module):
                    found = wine_export(self.source, dependency, symbol, None)
                    if found["status"] == "declaration-found":
                        variant["import_candidates"].append(self.follow(dependency, symbol, seen=seen+(key,)))
                variant["resolution"] = "candidate" if variant["import_candidates"] else "unresolved-import"
            else:
                variant["source_references"] = self.references(module, symbol)
                if alias and not variant["source_references"]:
                    variant["external_alias_candidates"] = [
                        self.follow(dependency, symbol, seen=seen+(key,))
                        for dependency in self.dependencies(module)
                        if wine_export(self.source, dependency, symbol, None)["status"] == "declaration-found"]
            node["variants"].append(variant)
        return node


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--wine-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if inventory.get("schema") != "pw-import-plan/1":
        raise ValueError("expected pw-import-plan/1")
    commit = subprocess.run(["git", "-C", str(args.wine_source), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(args.wine_source), "status", "--porcelain"],
                           check=True, capture_output=True, text=True).stdout.strip()
    if dirty or commit != inventory.get("wine_commit"):
        raise ValueError("Wine checkout must be clean and match the inventory commit")
    audit = WineAudit(args.wine_source)
    report = {"schema": "pw-wine-audit/1", "wine_commit": commit,
              "input_sha256": inventory["input_sha256"],
              "scope": "export routing and lexical source references; not a C call graph",
              "imports": [{"dll": row["dll"], "name": row["name"], "ordinal": row["ordinal"],
                           "audit": audit.follow(row["dll"], row["name"], row["ordinal"])}
                          for row in inventory["imports"]]}
    with args.output.open("x") as file:
        json.dump(report, file, indent=2)
        file.write("\n")


if __name__ == "__main__":
    main()
