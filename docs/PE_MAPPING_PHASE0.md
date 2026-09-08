# Phase 0 gate 1 — the console reads a raw Windows executable

**Objective.** Make the PS5's Zen 2 cores read and understand a raw Windows
executable: parse it without an operating system, place its sections in owned
memory, and resolve its third-party dependency chain.

**Status: host-complete, hardware pending.** Every contract in `make test`
passes. No console run has happened, so nothing below is claimed as proven on
FW 12.02. When the gate runs, this document records the accepted run.

## What is built

| Part | Source | Contract |
| --- | --- | --- |
| PE reader | `src/pe_image.c` | DOS/NT headers, optional header for both PE32 shapes, up to 16 data directories, up to 96 sections; every field bounds-checked; RVA to file-offset translation that refuses ranges crossing a section or landing in an uninitialised tail |
| Layout planner | `src/pe_layout.c` | Reservation size, per-section copy and zero spans, protections from characteristics; refuses sub-page section alignment, misaligned or unordered or overlapping sections, sections past `SizeOfImage`, headers larger than the file |
| Relocation | `src/pe_reloc.c` | `HIGHLOW`, `DIR64`, `HIGH`, `LOW`, `ABSOLUTE` padding; `HIGHADJ` and unknown types fail closed rather than desynchronise the entry stream |
| Import reader | `src/pe_import.c` | Descriptors, named and ordinal thunks for both thunk widths, `OriginalFirstThunk` preferred and bound images handled; names only, nothing is bound |
| Mapper | `src/pw_map.c` | Reserve, commit read-write, copy, explicit zero fill, relocate, verify, then protect at the backend's page granularity |
| Loader | `src/pw_loader.c` | Breadth-first dependency resolution, canonical dedupe, cycle tolerance, machine consistency, post-order load order, all-or-nothing release |
| Gate report | `src/pw_gate.c` | The `ps5log/1` record set, formatted without importing a platform formatter |

## What the host contracts prove

`make test` runs nine C suites and four Python suites. The load they exercise
end to end is the shape a real game has:

```text
game.exe  -> binkw32.dll -> msvcrt.dll   (host binding)
          -> kernel32.dll                (host binding)
             helper.dll  -> kernel32.dll  (already registered: one edge added)
```

Four modules, two mapped, two host bindings, one file opened per local
dependency and every span closed. Specific properties asserted:

- a `.bss` section with no bytes on disk is fully zero after mapping, and the
  zero fill is verified rather than assumed;
- a rebased image's relocated pointer equals `exec_base + rva` exactly, so
  the alias arithmetic is pinned by test and not by comment;
- an image mapped at its preferred base is byte-identical to its file across
  every section, checked by comparison, not by checksum alone;
- a mapping granularity coarser than the section alignment merges section
  protections into one page, and the resulting writable-executable page is
  counted;
- a PE32 image whose reservation lands above 4 GiB is refused instead of
  relocated with truncated addends;
- a rebase with no relocation directory is refused;
- a graph mixing `i386` and `amd64` modules is refused;
- a mutual import is loaded successfully and reported as a cycle;
- a missing third-party module fails with its name, and the failed load
  leaves no reservation behind.

Two encoders exist on purpose. `tests/pe_fixture.h` builds images in C for
the unit tests; `tools/make_test_pe.py` builds them independently in Python
for the staged samples. `tests/test_make_test_pe.py` feeds the Python output
to the C parser through `inspect_pe`, so a defect in either encoder shows up
as a disagreement instead of certifying itself.

## Building the title

```sh
# Synthetic images: a hardware run that needs no proprietary input.
make native PS5LOG_DEV_CONF=/private/path/dev.conf

# A private game directory, staged under lowercase names.
make native-release PW_STAGE_INPUT=/private/path/game \
  PW_ROOT_MODULE=game.exe PS5LOG_DEV_CONF=/private/path/dev.conf
```

The builder pins the public native foundation by commit and verifies it,
compiles every core source, links, signs, packages `dist/PPSA99995/`, stages
the images under `dist/PPSA99995/win/` and writes the linked ELF's complete
undefined-dynamic-symbol list to `build/native/PW_DYNAMIC_IMPORTS.txt`. A
reintroduced `strcasestr` import fails the build.

## What the runtime does, in order

1. `ps5log/1` starts and `PW_BEGIN` records the identity, the stage
   directory, the root module and the registry size.
2. **Filesystem pre-flight.** `PW_FS_SMOKE` calls `sceKernelStat`,
   `sceKernelOpen`, `read`, `lseek` and `sceKernelClose` on the staged root
   and reports each result plus the first two bytes. This runs before any
   parsing, so a platform call that is exported but not working is reported
   as itself instead of surfacing later as a mysterious parse error.
3. The loader registry and report come from anonymous mappings, never the
   libc heap, which is roughly 8 MiB here and cannot be grown from a title.
4. The gate runs and every report line is emitted verbatim.
5. `PW_FILES` reports the provider's open, close and failure counts.
6. Every span is closed and every reservation released, then `ps5log_close`
   and `_exit(0)`. The runtime never returns from `main()`: the CRT exit path
   leaves a failure dialog on this firmware.

## Hardware acceptance

A run passes when `tools/validate_pe_map_evidence.py <manifest>` accepts it.
That requires, beyond a clean transport:

- exactly one `PW_BOOT` with `schema=1 slice=pe-map`, a non-empty root and a
  reported protection granularity;
- one `PW_MODULE` per module with dense indices agreeing with `PW_GRAPH`;
- every non-host module mapped, with `headers=1`, zero verification
  mismatches, zero zero-tail violations, zero alias mismatches, a verified
  section count equal to its planned section count and a non-zero base;
- relocation consistency in both directions: rebased implies relocations
  applied, and mapped at the preferred base implies none applied;
- every host module unmapped, with no base and no machine;
- one instruction set across the graph, and `native=1` for every mapped
  module unless `--allow-i386` is given;
- `PW_PROTECT` covering exactly the mapped modules, with zero
  writable-executable pages unless `--allow-wx` is given;
- a load order that is a permutation of the module set, in which every
  `PW_DEP` edge points to an earlier position unless `PW_GRAPH` admits a
  cycle — re-derived by the validator from the edges, not taken from the
  runtime's own conclusion;
- `PW_EXIT result=0 status=ok missing=none truncated=0`, with released equal
  to mapped.

Suggested first run, pinning what was staged:

```sh
python3 tools/validate_pe_map_evidence.py <manifest> \
  --root sample.exe --expect-modules 4 --expect-local 1 --expect-host 2
```

## Deliberately out of scope

No import is bound, no `DllMain` runs, no TLS directory is processed, no
delay-load descriptor is read, no exception directory is registered and
nothing is executed. Those belong to later gates, and gate 1 is the thing
they will all stand on.

## Open questions for the first run

1. What is the console's actual protection granularity for these mappings?
   `PW_BOOT page_bytes` answers it, and `PW_PROTECT merged`/`wx` say what it
   costs a 4 KiB-aligned PE.
2. Does `read`/`lseek` on a `sceKernelOpen` descriptor behave for a
   multi-megabyte image as it does for the small files already measured?
   `PW_FS_SMOKE` plus `PW_FILES bytes` answer it.
3. How large a reservation is comfortable? `PW_GRAPH reserved_bytes` against
   the laboratory's measured direct-memory and anonymous-heap budgets.
