#!/usr/bin/env python3
"""Validate the public Wine foundation ledger and its dependency graph."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "WINE_FOUNDATION.json"
VALID_STATUSES = {"validated", "implemented", "partial", "planned", "external-wip"}
REQUIRED = {
    "pe-loader", "runtime-module-policy", "ia32-dbt", "pe64-abi",
    "wine-pe-runtime", "unix-call-bridge", "nt-process-thread",
    "nt-objects-waits", "virtual-memory", "exceptions-seh",
    "filesystem-paths", "registry-environment-nls", "audio-input",
    "networking", "dxvk", "ps5-vulkan", "observability-lifecycle",
}


data = json.loads(LEDGER.read_text(encoding="utf-8"))
assert data["schema"] == "prospero-win-wine-foundation/1"
assert len(data["wine_reference"]) == 40
assert data["architecture"] == {
    "pe32_cpu": "prospero-win-dbt",
    "pe64_cpu": "native-x86-64-with-abi-bridge",
    "windows_subsystem": "wine",
    "direct3d": "dxvk",
    "vulkan": "ps5-vulkan",
    "native_gpu": "agc-gfx1013",
}

components = data["components"]
by_id = {component["id"]: component for component in components}
assert len(by_id) == len(components), "duplicate component id"
assert set(by_id) == REQUIRED, "foundation component inventory drift"

for component in components:
    assert component["status"] in VALID_STATUSES
    assert component["evidence"].strip()
    assert component["exit_criteria"]
    assert len(component["exit_criteria"]) == len(set(component["exit_criteria"]))
    for dependency in component["depends_on"]:
        assert dependency in by_id, f"unknown dependency {dependency}"
        assert dependency != component["id"], "self dependency"

visiting: set[str] = set()
visited: set[str] = set()


def visit(component_id: str) -> None:
    assert component_id not in visiting, f"dependency cycle at {component_id}"
    if component_id in visited:
        return
    visiting.add(component_id)
    for dependency in by_id[component_id]["depends_on"]:
        visit(dependency)
    visiting.remove(component_id)
    visited.add(component_id)


for identifier in by_id:
    visit(identifier)

assert by_id["dxvk"]["depends_on"] == [
    "wine-pe-runtime", "nt-objects-waits", "ps5-vulkan"
]
assert by_id["runtime-module-policy"]["status"] == "implemented"
assert by_id["wine-pe-runtime"]["status"] == "partial"
assert by_id["ps5-vulkan"]["status"] == "external-wip"

print(f"Wine foundation ledger passed: {len(components)} components")
