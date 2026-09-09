# Wine reuse audit: Pinball bootstrap and CRT

Reference: Wine `490f6d5dcbb2a5047345b8af88d114bbcaad69a8`.
No Wine implementation is vendored into this project by this audit.

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
| RegCreate/Open/Query/Set/Close A subset | kernelbase/registry.c; advapi32/registry.c; advapi32/tests/registry.c | Fixed-capacity process-local HKCU service and all seven target adapters implemented. Tests preserve buffers on `MORE_DATA`, return required size, support default values and keep LastError separate. Security descriptors, volatile/link/WOW64 views, broad types and persistence remain explicit gaps; this is not the complete Wine registry |
| _initterm | msvcrt/data.c | Checked guest table walker and nested callback dispatch implemented; translated synthetic callbacks tested. First original-game call needs no callback; the second now completes its original callback in host. Never call guest addresses as host function pointers |
| _except_handler3 | msvcrt/except_i386.c | Guest exception records, scope tables, frame registers and unwind callbacks; native host stack unwinding is not equivalent |
| _CIacos | msvcrt/math.c, CREATE_FPU_FUNC1 | Argument/result in guest x87 state despite an empty .spec parameter list |
| _controlfp | msvcrt/math.c, _control87 and __control87_2 | cdecl two unsigned arguments, unsigned return; filters _EM_DENORMAL out of the update mask. i386 path combines x87/SSE control state and reports _EM_AMBIGUOUS for differing exception/rounding modes. Guest control-state handler implemented in pw_guest_fp.c; x87 arithmetic remains pending. No host _controlfp call |
| _ftol | msvcrt/math.c, assembly implementation | Guest x87 conversion/control behavior and split 64-bit integer return in EDX:EAX; preserve the relevant FP environment |
| SetSystemPaletteUse | gdi32 alias to win32u/palette.c | GDI palette/device state and a platform presentation boundary, not just a function rename |
| MessageBeep | user32 alias to win32u/sysparams.c | User/audio service integration; do not assume the alias is implemented inside user32 |
| DefWindowProcA | user32 forward to ntdll; ntdll/rtl.c macros | Registered user-procedure dispatch; source name is constructed by token-pasting macros |

The last example is a concrete limitation of text indexing: the complete
`NtdllDefWindowProc_A` symbol is absent from ntdll C text but is generated
by `USER_FUNC`/`DEFINE_USER_FUNC` macros in rtl.c. It must not be
classified as missing functionality just because lexical lookup is empty.

## Extraction decisions

The shared integer call/callback foundation is now implemented and host-
tested; see GUEST_ABI.md for its exact scope. This is not Wine extraction
or completed API coverage.

1. Implement the common guest ABI services first: pointer validation,
   code/data import distinction, calling conventions, guest callbacks,
   module/TEB state and FP-state access. Do this from the whole inventory,
   not from whichever API happens to fail on the next execution.
2. Evaluate coherent CRT string/conversion/allocation groups for reuse.
   Adapt their guest memory, Windows type widths, locale and allocation
   ownership. A host libc function is not automatically ABI-compatible.
3. Treat startup, exceptions and x87 helpers as an execution-engine contract,
   not standalone C wrappers. Retain Wine regression cases where applicable
   and add synthetic guest callbacks, unwind and FP tests.
4. Extract GDI/window and audio logic only after selecting the platform
   boundary. Wine's Unix/driver layers must be replaced or ported deliberately;
   copying an entire DLL pulls substantially more dependencies than Pinball's
   import list alone reveals.

Per-file licensing and authorship review precedes vendoring. Preserve Wine
LGPL notices and record source commit plus local changes. The project's
LGPL declaration and a planned license migration in another project do not
override third-party rights. This audit is implementation planning, not a
completed compatibility claim.
