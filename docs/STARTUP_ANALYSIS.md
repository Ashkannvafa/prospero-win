# Pinball startup: Ghidra-guided work packages

## Evidence and limits

Read-only analysis of the private PE identified by SHA-256
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`.
Ghidra reports x86:LE:32, Windows compiler, image base 0x01000000 and 852
functions. The on-disk hash was checked; 280636 file-backed bytes from headers,
.text, .data and .rsrc were compared with Ghidra memory and matched exactly.
This comparison excludes file padding/overlay and zero-filled virtual tails;
it is not a claim that the Ghidra database itself has the file SHA-256.

The full graph endpoint returned 2058 edges from 502 caller nodes. A graph
walk over recorded edges found the following reachable sets (root included):

| Root | Internal nodes | External symbol names |
| --- | ---: | ---: |
| Entry 0x01020f95 | 151 | 132 |
| Application startup 0x0100833a | 145 | 123 |
| Main window procedure 0x01007a3e | 350 | 136 |
| Message pump 0x010082a9 | 1 | 4 |

These are static graph observations, not executed paths, unique DLL-qualified
API coverage or a complete dependency closure. In particular the registered
window procedure reaches substantially more code than the entry-root walk.
Callbacks and computed calls must be included explicitly. Ghidra inferred
types/names are hypotheses unless separately checked against assembly/API
contracts. No decompiled implementation or original resource text is included.

The server's inline-script endpoint was disabled. It was not enabled or
bypassed; ordinary read-only program, memory, graph, disassembly and decompiler
endpoints were sufficient for this pass.

## Static instruction coverage baseline

On 2026-09-08, `tools/survey_x86_coverage.py` walked the union of Ghidra's
recorded direct graph from entry, application startup and the registered main
window procedure. It passed every exact instruction byte sequence to
`pw_x86_translate`; the result therefore measures accepted encodings and
operand forms, rather than assuming that every instruction sharing a mnemonic
is supported.

| Root | Reachable functions | Static instructions | Accepted | Unique x87 forms |
| --- | ---: | ---: | ---: | ---: |
| Entry | 151 | 8,082 | 7,558 (93.52%) | 36 |
| Application startup | 145 | 7,905 | 7,382 (93.38%) | 36 |
| Main window procedure | 350 | 23,338 | 20,661 (88.53%) | 54 |
| Union of all three | 393 | 25,538 | 22,839 (89.43%) | 54 |

All 393 function bodies were read successfully. Of 2,699 rejected static
instructions, 2,300 are x87 occurrences (85.22%) comprising only 54 unique
semantic encoding forms; none executes yet. The startup graph needs 36 forms.
The remaining 399 include unsupported MOV forms, string
operations shown by Ghidra as MOVSD, IMUL, CDQ and less frequent integer forms.
The largest x87 groups are FSTP (781), FLD (583), FLDZ (279), FNSTSW (129) and
FMUL (125). If every observed x87 form alone were implemented, the arithmetic
upper bound would become 98.35%; that is prioritisation guidance, not a forecast
that an x87 implementation automatically makes the program run.

The surveyed instructions include 926 indirect-call encodings and 10
indirect-jump encodings. Those are occurrences, not unique unresolved targets;
many are import-table calls that static analysis can identify. Conversely,
computed targets and callbacks absent from recorded edges remain outside the
reachable union. This baseline is static and unweighted: it neither says which
paths execute nor replaces dynamic coverage, API contracts, exception behavior
or PS5 execution evidence.

Reproduce while the private program is open in the local Ghidra server:

```sh
make build/host/classify_x86
python3 tools/survey_x86_coverage.py --program Pinball.exe \
  --root 01020f95=entry --root 0100833a=startup \
  --root 01007a3e=wndproc --classifier build/host/classify_x86 --json
```

The survey never writes raw instructions or assembly. Its output contains only
aggregate counts, and the classifier calls the production translator so future
instruction support changes are reflected without maintaining a duplicate
opcode allowlist.

The checked `PINBALL_X86_COVERAGE.json` is the sanitized aggregate result; it
contains no bytes or assembly. Form identifiers retain mnemonic, opcode class,
ModR/M group and register operand only, enough to distinguish semantics without
publishing proprietary instructions.

## Source/PDB/binary crosswalk

`tools/build_source_oracle.py` independently verifies the private image hashes,
the two pinned public source commits, MIT license, public PDB GUID/age and ten
symbol addresses. The PDB's segment-1 offsets map through `.text` RVA 0x1000:
`_WinMainCRTStartup` becomes 0x01020f95, `_WinMain@16` 0x0100833a and
`_message_handler@16` 0x01007a3e, matching the existing Ghidra roots exactly.
The resulting `PINBALL_SOURCE_ORACLE.json` records only public provenance,
addresses and aggregate API references. The pre-SDL revision is used for Win32
flow; current source is useful for maintained game logic. Neither replaces
compiled ABI/disassembly checks.

## Startup structure

The entry graph calls 0x0100833a, whose decompilation contains resource and
registry setup, a single-instance check, class registration, splash setup,
main-window creation, ShowWindow/UpdateWindow, a timed message-processing
interval, the game/message loop and teardown. Treat it as the application
startup function, not as proof of a recovered original source-level name.

The main class registers 0x01007a3e as its window procedure. Its message-1
branch performs display/palette-related setup, invokes sound and music setup,
and calls the table-initialization path at 0x01015424. Its key-down/up branches
reach 0x01015072 and 0x010152e4; paint reaches 0x01003f98. Close/destruction
paths request quit and cleanup. Callback handling therefore cannot wait until
after a fabricated successful CreateWindowExA return.

The message pump at 0x010082a9 contains both GetMessageA and PeekMessageA
paths with TranslateMessage/DispatchMessageA and a quit-message check. Its
caller also invokes the update path at 0x01014bf9 using elapsed time.
The startup function's 515 disassembled instructions include FILD, FADD,
FMUL, FDIVR and FSTP in a statistics-related path. This establishes a real
x87 dependency, not the complete floating-point requirements of gameplay.

## Implementation packages

1. **Guest heap and CRT ownership.** Implement malloc/calloc/realloc/free as
   one guest-addressable allocator family. Assembly at 0x010054c2 confirms a
   game wrapper requests four extra bytes, writes its own header, returns the
   pointer plus four and uses callee cleanup for its own argument. That wrapper
   is not the cdecl CRT ABI. Decompilation at 0x01005541 and 0x01005579 shows
   free/realloc recovering the underlying pointer. Preserve the game's header;
   do not confuse the adjusted game pointer with the CRT allocation pointer.
   The allocation-failure path has a conditional indirect callback through
   0x01024f08. Test callback reentry, zero sizes, calloc multiplication overflow,
   alignment, realloc preservation/failure, coalescing and final heap release.
2. **Process, strings, resources and registry.** Startup already uses these
   before class creation. Cover bounded string operations and varargs, module
   paths, resource handles beyond RT_STRING, registry defaults/read/write and
   persistence, last-error state and single-instance behavior as coherent
   contracts. Do not treat different registry/default branches as executed
   evidence or silently launch an external process to satisfy a branch.
3. **Window lifecycle and callback ABI.** Cover class registration, the real
   window procedure, nested callbacks during creation, message queues, focus,
   painting, quit and teardown together. Validate PE32 WNDCLASS/MSG/PAINTSTRUCT
   layouts and return values; decompiler-inferred void return is not an ABI
   declaration. Include splash and audio-related helper windows found in
   callers 0x01007308 and 0x01006973, not only the main HWND.
4. **DIB/palette presentation.** Static callers of StretchDIBits are at
   0x0100469c, 0x01004705 and 0x01004787; BitBlt callers include 0x01007103,
   0x010071a5 and 0x01007264. Follow these and the paint path to establish
   pixel formats, palette ownership, clipping and presentation to AGC. This
   pass has not yet recovered the complete image/bitmap data contracts.
5. **PCM/music/input and game loop.** MCI call sites cluster at 0x0100af1f,
   0x0100af8e, 0x0100afb9, 0x0100afdc and 0x0100b035. waveOutOpen callers
   include 0x0101d7b1 and 0x0101eb23. Audio is reached during window creation,
   so investigate its initialization/callback requirements alongside package
   3. Wire validated platform PCM/input only after reviewing provenance;
   Windows keyboard messages and guest audio callbacks remain guest contracts.
6. **Execution coverage and measured DBT.** Survey opcode families across the
   callback-inclusive graph, including x87 and unresolved indirect targets.
   Expand and test groups and measure dispatch cost. The host runner now uses
   generation-scoped cached multi-instruction blocks with explicit control-flow
   boundaries and RW-to-RX publication. This is correctness and integration
   evidence, not a performance benchmark.

## Wine comparison for the first package

Reviewed pinned Wine `490f6d5dcbb2a5047345b8af88d114bbcaad69a8`,
`dlls/msvcrt/heap.c`: malloc calls the internal heap allocator and can invoke
the new handler according to new_mode; failed allocation sets errno.
realloc(NULL,n) delegates to malloc; realloc(p,0) frees and returns NULL.
The allocator must preserve the old allocation on failed nonzero resize.
The guest allocator family and cdecl adapters now support the default absent
new-handler with logical errno. Registered handlers remain pending. Do not copy the Wine wrapper without its heap,
errno and callback dependencies. Relevant Wine tests and the underlying heap
implementation still require a fuller review before claiming compatibility.

## Reproduce and next evidence

Use the local Ghidra server's advertised schema, always selecting the program
explicitly: get_current_program_info, read_memory, get_full_call_graph with
format=json_edges and limit=0, get_function_call_graph, disassemble_function
and decompile_function. Raw responses containing proprietary code stay private.
Do not infer function-level execution order from unordered graph edges.

The source-confirmed registry package now implements all seven imported Advapi
entry points over fixed owner-supplied storage. A bounded exact-binary host run
reaches the public-PDB-verified `WinMain` address and then retires 1,823
instructions while completing 105 calls across 30 distinct APIs. It records
417 DBT dispatches, 270 cache hits, 147 misses/publications and 45,488 emitted
code bytes for generation 1. The classified stop is `LoadIconA`, before
`RegisterClassA` and window creation. This requires a resource-backed icon
handle and object-lifetime contract; returning a fabricated handle would not
advance the implementation. This is host integration evidence, not a window,
gameplay or translated PS5 execution claim.
