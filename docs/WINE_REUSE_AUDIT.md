# Wine reuse audit and integration boundary

Reference: Wine `490f6d5dcbb2a5047345b8af88d114bbcaad69a8`.
No Wine implementation is vendored into this project by this audit.

## Architecture decision

The direct Win32/CRT handlers audited below enabled the first playable target
and remain valuable as focused behavioral references. They are not the path to
broad compatibility. prospero-win will execute Wine's PE DLLs and intercept
the defined ntdll Unix-call/syscall boundary; native PS5 code will implement
platform services below that boundary. See [WINE_INTEGRATION.md](WINE_INTEGRATION.md).

This changes the unit of reuse from an individual imported function to a
coherent Wine module plus its tests. The inventory and source navigator remain
useful for prioritization, provenance and debugging, but they must not generate
another application-specific dispatcher.

## Repeatable source navigation

```sh
python3 tools/audit_wine_imports.py /private/import-plan.json \
    --wine-source "$WINE_SOURCE" --output /private/new-wine-audit.json
```

The tool requires the clean Wine commit recorded by the inventory. It
follows explicit DLL forwards, `-import` declarations through module imports
and external implementation aliases. It preserves calling-convention and
architecture flags and handles data exports separately. Cycles and excessive
depth stop explicitly. Reports refuse overwrite.

Source results are **lexical references**, not proven definitions or a C
call graph. Comments, macros and calls may all match. Module dependencies
are navigation leads, not minimal function-level dependencies. Missing
sparse-checkout files and unresolved references do not prove Wine lacks an
implementation. Conditional build expressions and ABI variants still need
review. No result here authorizes automatic extraction of a source file.

## Reviewed integration requirements

| Imports / subsystem | Reviewed Wine location | Required guest contract |
|---|---|---|
| GetModuleHandleA | kernelbase/loader.c; kernel32 imports kernelbase | Guest module registry, handles and last-error behavior; no native host module handles |
| GetStartupInfoA | kernel32/kernel_main.c, copy_startup_info; include/processthreadsapi.h | Serialize the PE32 structure from guest launch policy, not host pointers. Initial GUI show profile implemented; inherited handles, desktop/title/geometry overrides remain outside the current profile |
| __set_app_type, __p__fmode, __p__commode | msvcrt/data.c; include/msvcrt/fcntl.h | cdecl void state setter and stable writable guest pointers; fmode initializes to _O_TEXT (0x4000), commode to zero. Initial handlers and host regressions now implemented; file semantics remain pending |
| __getmainargs, _acmdln | msvcrt/data.c | Guest argument/environment packer and non-wildcard handler implemented. Five cdecl arguments: argc/argv/env output pointers, wildcard-expansion flag, optional pointer to new_mode. Outputs validated before mutation; initial environment explicitly empty, never host environ. Wildcards/code-page conversion and registered new-handler behavior remain pending; the default absent-handler allocator profile is implemented |
| malloc/calloc/realloc/free | msvcrt/heap.c; tests/heap.c test_malloc/test_calloc | Reusable guest heap and cdecl adapters implemented, including zero sizes, checked calloc product, preserved data on resize and logical guest ENOMEM. Default handler absent; handler registration/callbacks and errno pointer export remain pending. Host original malloc returns guest address 0x03400000; the other three have synthetic ABI evidence |
| RegCreate/Open/Query/Set/Close A subset | kernelbase/registry.c; advapi32/registry.c; advapi32/tests/registry.c | Fixed-capacity HKCU service and all seven target adapters implemented. Tests preserve buffers on `MORE_DATA`, return required size, support default values and keep LastError separate. Target keys/values persist in a versioned checksummed atomic store. Security descriptors, volatile/link/WOW64 views and broad types remain explicit gaps; this is not the complete Wine registry |
| _initterm | msvcrt/data.c | Checked guest table walker and nested callback dispatch implemented; translated synthetic callbacks tested. First original-game call needs no callback; the second now completes its original callback in host. Never call guest addresses as host function pointers |
| _except_handler3 | msvcrt/except_i386.c | Guest exception records, scope tables, frame registers and unwind callbacks; native host stack unwinding is not equivalent |
| _CIacos | msvcrt/math.c, CREATE_FPU_FUNC1 | Argument/result in guest x87 state despite an empty .spec parameter list |
| _controlfp | msvcrt/math.c, _control87 and __control87_2 | cdecl two unsigned arguments, unsigned return; filters _EM_DENORMAL out of the update mask. i386 path combines x87/SSE control state and reports _EM_AMBIGUOUS for differing exception/rounding modes. Guest control-state and startup binary80 families are implemented with integer-only state; complete trap delivery and SSE remain pending. No host _controlfp call |
| _ftol | msvcrt/math.c, assembly implementation | Guest x87 conversion/control behavior and split 64-bit integer return in EDX:EAX; preserve the relevant FP environment |
| SetSystemPaletteUse | gdi32 alias to win32u/palette.c | GDI palette/device state and a platform presentation boundary, not just a function rename |
| GetDC/ReleaseDC, compatible DC/bitmap, SelectObject/DeleteObject/DeleteDC | win32u DC and bitmap object paths | Process-owned typed handles, DC/bitmap selection exclusivity, balanced release/delete and transactional failure. The initial fixed-capacity model is implemented and tested; it is not Wine's complete GDI object manager |
| BitBlt, GetDeviceCaps, Get/SetLayout, GetObjectA | win32u drawing/DC paths | Checked surface geometry, clipping, raster-op semantics and exact PE32 structures. The splash path supports `SRCCOPY`, `BLACKNESS` and a deterministic true-color profile; other raster operations and device profiles stop explicitly |
| CreatePalette, SetPaletteEntries, SelectPalette, RealizePalette | win32u palette paths | Fixed-capacity logical palettes, checked entry mutation, selection ownership and deterministic true-color realization are implemented and tested |
| MessageBeep | user32 alias to win32u/sysparams.c | User/audio service integration; do not assume the alias is implemented inside user32 |
| DefWindowProcA | user32 forward to ntdll; ntdll/rtl.c macros | Registered user-procedure dispatch; source name is constructed by token-pasting macros |

The last example is a concrete limitation of text indexing: the complete
`NtdllDefWindowProc_A` symbol is absent from ntdll C text but is generated
by `USER_FUNC`/`DEFINE_USER_FUNC` macros in rtl.c. It must not be
classified as missing functionality just because lexical lookup is empty.

## Reuse decisions

The shared integer call/callback foundation is implemented and host-tested;
see GUEST_ABI.md for its exact scope. It supports both the bootstrap path and
future Wine crossings, but is not a completed Wine runtime.

1. Complete loader exports/forwarders/TLS and the application/runtime namespace
   contract, then boot the pinned i386 Wine `ntdll` rather than binding another
   batch of individual APIs.
2. Implement PEB/TEB, callbacks, FP/SSE state and exception delivery as CPU and
   process contracts shared by all Wine modules.
3. Define a versioned Unix-call dispatch table whose arguments are guest-
   validated and whose failures are atomic. Do not expose raw PS5 pointers or
   an assumed `dlopen` ABI to PE code.
4. Reuse Wine's Windows semantics above the boundary. Implement or adapt only
   the native VM, thread, object/wait, path, audio, input and network services
   below it, retaining relevant Wine regression tests.
5. Keep the direct handlers as a bootstrap/reference suite until equivalent
   Wine paths pass; retire them by demonstrated subsystem, not all at once.

Per-file licensing and authorship review precedes vendoring. Preserve Wine
LGPL notices and record source commit plus local changes. Generated Wine PE
binaries remain external build artifacts. This audit is implementation
planning, not a completed compatibility claim.
