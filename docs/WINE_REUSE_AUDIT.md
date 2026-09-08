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
| __getmainargs, _acmdln | msvcrt/data.c | Guest argv/env storage, 32-bit pointer arrays, command-line initialization and allocation lifetime |
| _initterm | msvcrt/data.c | Walk guest 32-bit function-pointer tables and reenter the guest execution engine; never call guest addresses as host function pointers |
| _except_handler3 | msvcrt/except_i386.c | Guest exception records, scope tables, frame registers and unwind callbacks; native host stack unwinding is not equivalent |
| _CIacos | msvcrt/math.c, CREATE_FPU_FUNC1 | Argument/result in guest x87 state despite an empty .spec parameter list |
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
