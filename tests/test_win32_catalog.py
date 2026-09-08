#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from make_win32_catalog import generate
sample={"schema":"pw-import-plan/1","wine_commit":"reference","wine_worktree_clean":True,
        "imports":[{"dll":"SAMPLE.dll","name":"Function","ordinal":None,
                    "wine":{"matches":[{"kind":"stdcall"}]}}]}
assert '{"sample.dll","Function",PW_IMPORT_FUNCTION}' in generate(sample)
sample["imports"][0]["wine"]["matches"][0]["kind"]="extern"
assert "PW_IMPORT_DATA" in generate(sample)
sample["imports"][0]["ordinal"]=1
try: generate(sample)
except ValueError: pass
else: raise AssertionError("ordinal needs review")
print("Win32 catalog generator passed: function/data classification and explicit review")
