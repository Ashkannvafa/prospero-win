# Import-first implementation plan

Export routing and reviewed CRT/platform dependencies: see WINE_REUSE_AUDIT.md.

Use a complete normal-import inventory to understand an application before it
runs. It remains valuable for compatibility reporting and selecting tests, but
it is no longer a queue of functions to reimplement directly: Wine PE modules
provide the Windows API surface, and prospero-win adapts Wine's bounded native
platform dependencies.

## Reproduce for another game

```sh
make build/host/inspect_pe
python3 tools/inventory_imports.py "$GAME_EXE" --wine-source "$WINE_SOURCE" \
    --output /private/new-import-plan.json
```

The read-only inspector uses the same C PE/import parser as the loader.
The JSON includes input SHA-256, machine, DLL, name or ordinal, IAT RVA,
bound-table state, subsystem, implementation/ABI audit status and Wine spec
locations. No executable is staged or executed. Output refuses overwrites.
The Wine commit and worktree cleanliness accompany declaration lookups.
Without a Wine checkout, paths are candidates marked `not-indexed`.

Scope is the normal static import directory. Delay-import presence is
flagged but not decoded; dynamically resolved APIs remain unknown. Do not
call this a complete runtime dependency closure. Implementation status is
currently initialized to `pending`: this generated inventory is not a live
coverage database and must not overwrite future reviewed API coverage.

## Pinball baseline (2026-09-08)

Input SHA-256:
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`.
Wine reference: `490f6d5dcbb2a5047345b8af88d114bbcaad69a8`, clean checkout.
All 207 imports have matching declarations in that reference. That proves
export discovery, not functional completeness, PS5 compatibility or safe
standalone extraction. No Wine implementation has been copied yet.

| DLL | Imports | Work package |
|---|---:|---|
| KERNEL32 | 46 | Module/process state, memory, files, resources, clocks |
| msvcrt | 42 | CRT initialization, strings, allocation, exceptions |
| USER32 | 67 | Window lifecycle, messages, input, dialogs |
| GDI32 | 24 | DIBs, palettes, clipping and blits |
| WINMM | 19 | Timers, MMIO, PCM and MCI/music |
| ADVAPI32 | 7 | Registry and observed security behavior |
| SHELL32 | 1 | Shell UI behavior |
| COMCTL32 | 1 | Common-control initialization |

Wine declaration kinds: 164 stdcall, 38 cdecl, three varargs and two extern
data exports. These are declarations, not yet audited argument layouts.

- `_acmdln` and `_adjust_fdiv` are data imports: bind live guest storage,
  not call tokens. Audit initialization, width and pointer indirection.
- `wsprintfA`, `sprintf` and `sscanf` are variadic: a fixed-argument stdcall
  adapter is wrong. Audit guest stack traversal and format semantics.
- The first observed call is `KERNEL32!GetModuleHandleA(NULL)`. Wine's
  kernel32 spec imports it; its implementation is in kernelbase/loader.c
  and delegates to GetModuleHandleExA. Follow dependencies rather than
  copying the small wrapper in isolation.

## Integration order

1. Build and pin the selected i386 Wine PE module set outside the repository;
   record hashes, architecture and source revision in a runtime manifest.
2. Map application and runtime namespaces independently. Complete exports,
   forwarders, TLS and API-set/override policy before executing module entry.
3. Create PE32 PEB/TEB/process state, enter Wine `ntdll` under the DBT and
   intercept its versioned Unix-call boundary.
4. Implement the platform side as reusable VM, object/wait, file/path,
   registry, exception, audio, input and networking services. Use Wine tests
   and synthetic multi-application fixtures as the behavioral oracle.
5. Validate each integrated batch with structured telemetry and exact artifact
   identity. Use application imports and traces to prioritize coverage, not to
   define application-specific runtime semantics.

Wine's Makefile imports show why isolated wrapper copying does not scale:
kernel32 pulls kernelbase/ntdll; user32 and gdi32 involve win32u and further
modules; winmm includes ole32/msacm32 dependencies. The module graph is the
reusable Windows subsystem. Wine's Unix libraries still assume host services
that PS5 does not provide unchanged, so that boundary must be adapted and
tested deliberately; Wine is not treated as PS5-ready by compilation alone.

Keep LGPL-2.1-or-later for the project. Preserve Wine authorship, license
notices and pinned provenance for every reused file. A proposed license
migration elsewhere is not evidence that third-party GPL code can be
relicensed. No proprietary game resources enter the public source tree.
