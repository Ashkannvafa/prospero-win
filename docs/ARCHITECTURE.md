# Architecture

Three layers, with the dependency direction fixed. Nothing in `src/` knows
what platform it is on; `native/` knows the console and nothing about PE.

```text
include/           the contracts a host implements
  prospero_win.h      result codes, protection flags, limits
  prospero_win_vm.h   reserve / commit / protect / release, two aliases
  prospero_win_file.h canonical module name -> read-only byte span

src/               the portable loader core
  pe_image      DOS/NT headers, directories, section table   (read only)
  pe_layout     reservation, copy/zero spans, page protection
  pe_reloc      base relocation against the executing address
  pe_import     import descriptors: which modules, which symbols
  pw_module_name canonical names; the local / host split
  pw_map        reserve, copy, zero, relocate, verify, protect
  pw_loader     recursive dependency graph and load order
  pw_gate       the structured report one load produces
  pw_registry   fixed-capacity guest keys, values and opaque handles
  pw_x86_block  bounded x86-to-x86-64 translation
  pw_x86_cache  mapping-generation-scoped translated-block lifecycle
  pw_guest_fp   isolated x87/SSE control and raw 80-bit stack state
  pw_vm_posix   anonymous-mapping backend (host and console)
  pw_file_posix directory backend (host tools and tests only)

native/            the PS5 adapter
  main.c        ps5log init, pre-flight, gate run, teardown
  pw_file_ps5   sceKernelOpen/Close/Stat plus read/lseek, mmap'd buffers
  ps5log/       vendored `ps5log/1` client, pinned by digest
```

## Why the core imports almost nothing

`src/` includes only `<stddef.h>`, `<stdint.h>` and `<string.h>`. It has no
allocator, no formatter and no case-folding helper from the platform.

That is a direct response to the laboratory's porting playbook: on this
firmware a system library exports many symbols that are placeholders or
subtly wrong, and treating "provided by `libSceLibcInternal`" as a green
check has already cost a full session once. The cheapest way to not inherit
that class of bug is to not import the symbol. So:

- module names are compared with an in-tree ASCII fold, not `strcasecmp`,
  which is also the locale-correct choice for names that are ASCII by spec;
- the gate formats its own records with bounded integer and hex helpers
  rather than `snprintf`;
- memory comes from the injected `PwVmBackend`, never from `malloc`.

`tests/test_native_contract.py` enforces this: it fails if a core source
includes an unexpected header or references a forbidden symbol, and it fails
if `tools/build_native.sh` stops compiling a core source, so a new module
cannot be silently left out of the title.

## The two memory aliases

`PwVmRegion` carries a `write_base` and an `exec_base`. On a POSIX host they
are the same pointer. On the console, publishing executable pages goes
through a second mapping of the same memory, so they differ.

The rule that follows is the important one: **a relocation delta is computed
against `exec_base`, and the patched bytes are written through
`write_base`.` `pw_map_image()` does this in one place, and
`pw_map_verify()` compares the two aliases over every executable section so
a mismatch is caught as itself rather than as a wild jump later.

## Order of operations, and why it is fixed

```text
reserve(image_bytes, section_alignment)
  -> commit everything read-write
  -> copy headers, copy each section's raw bytes
  -> zero the uninitialised remainder explicitly
  -> apply base relocations
  -> verify against the file
  -> install final page protections
```

Protections come last because the read-write window is where relocation and,
later, import binding happen: installing a read-only `.text` first would
fault on the first thunk write. Verification comes before protections
because afterwards some pages are deliberately unreadable;
`pw_map_verify()` returns `PW_ERR_STATE` if called too late, so the
ordering is a contract rather than a convention.

The explicit zero fill is not redundant with a fresh anonymous mapping. A
recycled reservation would otherwise leak previous contents into a `.bss`
that the program is entitled to see as zero.

## The local / host split

Every import is classified by canonical name:

- a **host** module (`kernel32.dll`, `msvcrt.dll`, `ddraw.dll`, …) is an
  interface prospero-win implements natively. It is registered in the graph,
  never opened, never mapped. There is no Windows on the console to load it
  from, and a stub silently standing in for it would be the worst possible
  failure mode.
- anything else is **local**: real third-party code, resolved through the
  file provider next to the executable and manually mapped. `binkw32.dll` is
  the canonical case.

The classification table in `pw_module_name.c` is sorted and searched by
binary search, so its order is a correctness property; a test asserts it
stays sorted, and asserts that known third-party names are absent. A name
missing from the table is treated as local; an unresolved file produces
`PW_ERR_NOT_FOUND`. This is provisional mapping-gate policy, not Windows
DLL search-order conformance. Familiar names such as d3d9.dll and dinput8.dll
can be application-local wrappers. Before execution/import binding, replace
this classification with explicit core-host, API-set, local-override and
fallback rules, covered by resolver fixtures. See ROADMAP.md gate 0.3.

## Bounds, cycles and failure

Every capacity is compiled in — 96 sections, 64 import descriptors, 32
modules, 16 levels of depth — and every overflow fails closed. A corrupt or
hostile import table cannot make the loader allocate or recurse without
bound.

Import cycles are normal in PE (`kernel32` and `ntdll` import each other), so
they are not errors: a module is registered once under its canonical name,
a repeat edge only adds a link, and the depth-first ordering counts back
edges into `cycle_edges` and keeps going. What *is* an error: a dependency
that cannot be found, a graph mixing instruction sets, a rebase with no
relocation table, an unknown relocation type, and a verification mismatch.

A failed load releases every reservation it had already made and closes every
span it had opened, so `PW_EXIT` on a failing run is as trustworthy as on a
passing one.
