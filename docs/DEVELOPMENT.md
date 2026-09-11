# Development workflow

## Stable tree

`main` is reviewable, not a scratch area. The portable loader lives in
`src/` behind the contracts in `include/`; the console adapter lives in
`native/`. Every change keeps `make all` green.

## Isolated experiments

Each risky change gets a sibling worktree, so it has its own build directory
while sharing history:

```sh
git switch main
git worktree add ../prospero-win-exp-<topic> -b exp/<topic>
cd ../prospero-win-exp-<topic>
make all
```

Commit small steps on `exp/<topic>`, validate them independently, and merge
only reviewed commits. When finished, confirm nothing uncommitted remains,
then remove the worktree from the primary checkout.

## Required gates

```sh
make test        # C contracts and Python integration suites
make sanitize    # clean Clang ASan/UBSan rebuild, including leak detection
make audit       # fail-closed publication audit
git diff --check
git status --short
```

Native changes additionally require a clean `make native-release`, the
artifact hashes it prints, and one hardware launch whose `ps5log/1` manifest
the matching validator accepts: `validate_pe_map_evidence.py` for the mapping
gate or `validate_runtime_evidence.py` for the game runner. A change to the memory contract,
the mapping order or the protection logic requires a longer run before it is
called done.

For an orderly resource-release gate without changing production behavior:

```sh
PW_TEST_EXIT_AFTER_MS=18000 PW_FOUNDATION_READY=1 \
PW_STAGE_INPUT=/private/path/pinball_xp PW_ROOT_MODULE=pinball.exe \
tools/build_native.sh
```

The default is zero (continuous). A finite test artifact must never be
mistaken for the production candidate; record both hashes and the runtime
mode in hardware evidence.

## Working with real binaries

Windows binaries are private build inputs. `.exe` and `.dll` are ignored
repository-wide, the publication audit refuses any tracked file that starts
with a DOS header, and it refuses a tracked `win/` directory outright,
because that is the name the builder stages images under.

To study a binary you own without copying anything into the tree:

```sh
make inspect PE_INPUT=/private/path/game.exe PE_DIR=/private/path
make inspect-only PE_INPUT=/private/path/PINBALL.EXE
```

That prints the machine, layout, per-section protections, the full import
table with each module classified local or host, and — when the whole chain
resolves — the mapped graph with load order, per-module checksums and the
page-protection outcome. It is the fastest way to size a title's Win32
surface before implementing any of it.

For Pinball, clone the public SpaceCadetPinball reference outside this
repository and reproduce the checked identity/source/PDB crosswalk:

```sh
python3 tools/build_source_oracle.py \
  --config references/spacecadet_pinball.json \
  --reference-dir /external/SpaceCadetPinball \
  --image /private/PINBALL.EXE \
  --output docs/PINBALL_SOURCE_ORACLE.json
```

The command rejects an unpinned commit, mismatched image hash, PDB identity or
public-symbol address. The Ghidra coverage command in `STARTUP_ANALYSIS.md`
regenerates `PINBALL_X86_COVERAGE.json`; raw bytes/assembly remain transient.

To run a gate with no proprietary input at all:

```sh
make sample OUT_DIR=/tmp/pw-sample
make native PS5LOG_DEV_CONF=/private/path/dev.conf
```

## Adding to the loader core

- Keep `src/` free of platform imports. The allowed headers are
  `<stddef.h>`, `<stdint.h>` and `<string.h>`; `tests/test_native_contract.py`
  enforces it and also enforces that every core source is compiled into the
  title.
- Take memory only from the injected `PwVmBackend` and bytes only from the
  injected `PwFileProvider`.
- Give every new capacity a compiled-in bound and a fail-closed overflow.
- Add the unit test in the same commit, and prefer asserting exact values
  over presence. The suites here assert byte-level mapping results,
  relocated pointer values and page-protection counts, not just success.
- When a new record joins the telemetry vocabulary, extend
  `tools/validate_pe_map_evidence.py` and its test in the same commit.
  Evidence the validator does not check is decoration.
