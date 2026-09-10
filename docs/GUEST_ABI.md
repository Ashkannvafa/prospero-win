# Shared guest call and callback services

`src/pw_guest_call.c` provides integer-stack marshalling for Win32 adapters.
It does not resolve imports or implement a Win32 API. These services are
shared prerequisites identified by the complete Pinball import inventory.

## Function/data IAT binding

`pw_import_bind32` is a shared PE32 binding operation. It parses preserved
name/ordinal lookups, asks an injected resolver for explicitly typed guest
destinations, and validates every slot before writing any IAT entry. Unknown
imports, zero/oversized targets, invalid kinds or overlapping slots fail
without changing the mapped image. A report separates functions from data.
This lets the reviewed catalog bind `_acmdln` as storage rather than a
function trampoline. It does not allocate or initialize that storage itself.

Binding must happen before final mapping protections. PE64 and delay imports
are refused; the workspace currently caps one image at 512 imports. Resolver
side effects are not rolled back by the binder and must be managed by the
owner. The resolver must not modify mappings or the IAT while planning.
It must supply live guest storage or dispatcher-owned function destinations,
not unresolved Windows addresses. The binder does not implement forwarders,
load external DLLs, infer API signatures or turn pending APIs into success
stubs. The canonical artifact verification precedes binding; runtime
evidence must account for subsequent deliberate IAT modifications.

Synthetic tests cover named/ordinal imports, function/data classification,
late resolver failure without partial writes, invalid targets, overlapping
IATs and refusal after final protections. The service compiles for PS5 but
is now integrated into the host original-game trace, but not the console runner.

## Guest calls into an adapter

Start a zero-initialized `PwGuestCall` with the guest state, calling
convention and fixed argument byte count (including 64-bit stack words).
The entry stack contains a 4-byte return PC followed by arguments.
`pw_guest_call_u32/u64` read by byte offset without assuming host pointer
width or alignment. Reads outside the declared fixed arguments fail; cdecl
variadic frames permit additional reads within the live guest stack.
A format parser must still determine the types and extent of varargs.
The service neither forwards a guest va_list nor implements printf/scanf.

Finish with a void, 32-bit EAX or 64-bit EDX:EAX integer return. Cdecl removes
only the return address; stdcall removes it and the declared argument bytes.
Invalid widths, changed frame identity or corrupted EBX/EBP/ESI/EDI reject
completion without consuming the frame or changing the guest state.
The adapter must handle its own rollback on failure. A second finish fails.
Guest EFLAGS are preserved by these host services.

## Host adapter calls back into guest code

`pw_guest_callback_enter` constructs a guest stack frame and changes guest
EIP/ESP. It does not invoke a host function pointer. The dispatcher must run
the execution engine and intercept its reserved return token before fetching
code. `pw_guest_callback_leave` verifies the returned EIP, convention-specific
ESP and nonvolatile registers, captures the integer result and restores the
calling adapter's saved registers, PC and flags. Each nested callback needs
separate zero-initialized storage. Guest memory side effects are retained.

The caller owns live mappings, accessible host argument buffers and return-
token allocation. Mappings must remain valid while a frame is active. This
API is not a process sandbox, scheduler, stack allocator or exception
unwinder. Floating-point, aggregate returns, thiscall/fastcall and x87 helper
ABIs remain unsupported. In particular, `_CIacos` and `_ftol` need additional
guest FP-state services, not a claim of generic cdecl compatibility.

## Evidence

- Unit tests exercise cdecl/stdcall cleanup, 32/64-bit arguments and returns,
  void returns, varargs bounds, double completion and register corruption.
- Callback state tests cover both cleanup conventions. A separate integrated
  test enters an actual translated synthetic cdecl callback that returns 42,
  verifies its result and restores the caller. A second translated callback
  returns 42 using RET 8, exercising stdcall argument cleanup and caller-state
  restoration through the real generated-code boundary.
- Host tests pass under ASan/UBSan. The shared C service compiles with the
  PS5 target toolchain. No hardware callback evidence is claimed yet.

## Initial runtime integration

`pw_win32.c` uses the generated factual code/data catalog for Pinball's 207
imports. Unknown names/ordinals are refused. All 205 function imports bind
to unique dispatcher tokens, not host addresses. Initial handlers cover
`GetModuleHandleA(NULL)`, `__set_app_type`, `__p__fmode`, `__p__commode`, `_controlfp`, `_initterm` and `__getmainargs`.
Six time/identity handlers and GetStartupInfoA are also available as described below.
Named-module arguments and other API calls stop explicitly without guest-state mutation or a false
success. A bound function is not necessarily an implemented function.

The two CRT data imports bind to separate guest words: `_acmdln` points to
the guest command-line string and `_adjust_fdiv` starts at zero, matching
the reviewed Wine CRT initialization. The owner supplies a live mapped CRT
region; this is not yet the full CRT startup/environment implementation.
The tracer uses a virtual `C:\\game\\<input basename>` command line; no
filesystem adapter is implied by that namespace.

CRT bootstrap contracts are implemented independently from the reviewed Wine
`msvcrt/data.c` behavior (pinned revision in WINE_REUSE_AUDIT.md):
`__set_app_type(int)` stores process-local state and returns void via cdecl;
the two zero-argument pointer getters return writable guest words at CRT
offsets 8 and 12. File mode starts at `_O_TEXT` (0x4000), as after Wine CRT
initialization, and commit mode starts at zero. Repeated calls preserve guest
writes. This does not implement file I/O or commit semantics yet. Tests cover
cdecl stack cleanup, void return, persistent pointer identity, defaults and
failure atomicity when the argument is outside the guest stack.

Translated indirect calls push a guest return PC and yield to the dispatcher.
The original Pinball trace binds 207 imports (205 function/2 data), invokes
GetModuleHandleA(NULL), returns its actual mapped base, then calls
`__set_app_type`, `__p__fmode`, `__p__commode`, `_controlfp`, `_initterm`, `__getmainargs`
and the time/identity calls plus GetStartupInfoA, LoadStringA, lstrlenA, malloc,
lstrcpyA and lstrcatA. The registry package then completes the source-confirmed
read-default and write-default sequences; the exact-binary trace reaches
`WinMain` and stops at `LoadIconA` after 1,823 instructions and 105 completed
calls, after an original-game initializer callback has returned.
The pointer getters now have original-game
host execution evidence as well as unit coverage.
Synthetic PE tests cover binding,
dispatch and return, plus a
named stop for a pending API. No PS5 execution of this integration is claimed.

## Guest heap core

`pw_guest_heap` implements alloc/calloc/realloc/free over owner-supplied live
RW identity-mapped memory below 4 GiB. Metadata is separate host-owned storage,
not headers in guest allocations; the game's four-byte wrapper header remains
untouched. The owner maps/registers the arena and releases it at teardown.
The core does not allocate virtual memory, synchronize threads or execute code.

First-fit blocks are 16-byte aligned. Splits reuse caller-provided metadata;
neighboring free blocks coalesce. If splitting needs an unavailable metadata
slot, the allocation retains the larger block. Realloc shrinks/grows in place
where possible, otherwise allocates, copies the requested prefix and frees the
old block. Failed resize preserves the old allocation and output argument.
Zero-size allocation returns a unique freeable block; realloc(NULL,0) does the
same, while realloc(p,0) frees p and returns zero. Calloc checks 32-bit product
overflow and clears exactly the requested bytes. Invalid/interior/double-free
pointers and damaged metadata are classified errors, not successful frees.
Exhaustion returns PW_ERR_LIMIT to the future CRT adapter, not a native pointer.

Original host tests cover zero sizes, alignment, coalescing, metadata exhaustion,
moving/in-place/shrinking realloc, ordinary and overflow allocation failure,
calloc sentinels, invalid pointers and 4000 deterministic fragmentation steps
with live-data pattern checks and partition validation after every operation.
The Wine reference's msvcrt/tests/heap.c test_malloc/test_calloc and heap.c
were reviewed for zero-size, overflow and realloc behavior. This is not an
executed differential comparison against Wine or a claim of full CRT fidelity.
The native forbidden-call gate now strips C comments/literals before scanning
call tokens; regression cases ensure documented function names do not fail the
gate while actual forbidden calls still do. This remains a lexical check,
not a full preprocessor or link-symbol audit.

The four CRT adapters now use cdecl guest frames and preflight the return on
a state copy before heap mutations. The arena must be registered RW and disjoint
from the guest stack. Exhaustion/size overflow returns NULL with logical guest
crt_errno=12 (ENOMEM); success retains errno. Free returns void, preserving EAX.
Invalid frees and invalid arena/frame state stop without reporting CRT success.
Tests cover all four adapters, cdecl stack cleanup, original header preservation,
zero/NULL behavior, overflow/exhaustion, guest flags and read-only arena rejection.

The default new-handler is absent; new_mode 0/1 therefore shares the allocation
failure result. Handler registration/invocation and an addressable _errno export
remain pending. The host tracer reserves an 8 MiB RW arena at 0x03400000 with
4096 metadata slots, registers it, and releases it even after a classified stop.
It reports live blocks/requested bytes before release; that is not evidence
that guest code freed every allocation or completed normal application teardown.
One original malloc now returns 0x03400000. PS5 runtime integration is pending.

## Guest string lengths

`lstrlenA` uses stdcall with one 32-bit guest pointer. NULL returns zero;
otherwise it checks read access for each byte before looking for NUL. Adjacent
readable regions can form one string; a gap or missing read permission stops
without changing the guest call state. The maximum scan is 1 MiB, including
the terminator; exhaustion returns an explicit runtime limit, not a false
length. No unchecked guest pointer reaches host strlen. Length counts bytes,
not Unicode codepoints. A valid return preserves guest flags and callee state.
Tests cover NULL/empty/extended bytes, region crossings, a last-byte terminator,
scan-limit exhaustion and inaccessible/unterminated input. The original host
trace returns 32 for the preceding resource string and next requests malloc.
Reference: [lstrlenA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrlena).

## Guest string copies and last-error state

`lstrcpyA`, `lstrcpynA` and `lstrcatA` use stdcall guest frames and preflight
all source and destination spans before writing. `lstrcpyA` preserves Wine's
overlap-safe memmove behavior. `lstrcpynA` implements the count-zero and
count-one cases without dereferencing an unused pointer, always terminates when
count is nonzero, and treats the signed count as the unsigned loop bound used by
the reviewed Wine implementation. Overlap other than an exact bounded self-copy
is deliberately rejected for the two APIs whose forward-copy behavior differs;
it is not silently promoted to memmove semantics.

Inaccessible pointers return NULL and set logical per-guest-thread last error
to `ERROR_INVALID_PARAMETER` (87), matching Wine's protected bad-pointer path.
Successful calls do not clear a previous error. `GetLastError` returns this
state independently from CRT errno. Tests cover truncation, zero/one counts,
large counts with an early terminator, high bytes, strcpy overlap, bounded
self-copy, rejected ambiguous overlap, invalid pointers, output canaries,
callee preservation and stack cleanup. The original host trace executes two
lstrcpyA and two lstrcatA calls; lstrcpynA and GetLastError currently have
synthetic evidence only.

## Resource strings

`pe_resource_find` reads numeric type/name/language entries from the original
immutable PE file. It bounds metadata by the resource directory and payloads by
file-backed RVA spans; tree cycles, wrong depths, unsorted/duplicate IDs,
oversized tables and truncated data are rejected. Language selection is an
explicit profile: requested language, neutral, then lowest numeric language.
This is not full Windows locale/MUI fallback. Named-key lookup is pending.
`pe_resource_string` validates all 16 counted UTF-16LE strings in an RT_STRING
block and returns a borrowed span, never a copied proprietary artifact.

The host tracer supplies the main module (or NULL), language 0x0409 and ANSI
codepage 1252 through `PwWin32Services`. LoadStringA uses stdcall with four
32-bit arguments and returns the number of bytes excluding the NUL. It supports
capacity 1..4096, truncation, empty/missing resources and exact CP1252 mappings.
Missing resources return zero without writing the destination; malformed
resources stop rather than masquerading as missing. Invalid output spans,
unsupported codepages/characters and invalid frames do not publish output.
Best-fit/default-character conversion, additional modules, larger capacities,
LastError reporting and PS5 resource-provider wiring remain pending.
The provider's UTF-16 span must remain live through dispatch; raw source bytes
remain live for the host trace. No Windows DLL is used for this service.

Synthetic regressions cover resource boundaries/cycles/language selection,
CP1252 accents/euro/dash, output truncation, NUL/sentinels, empty/missing strings,
unsupported input and failure atomicity. The original host run completes one
LoadStringA call returning 32 bytes; it does not prove window creation.
References: [PE resource layout](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section),
[LoadStringA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadstringa),
[CP1252 mapping](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT).

## Registry service

`pw_registry` is a process-local, fixed-capacity registry whose key/value
metadata and payload storage are supplied by the runtime owner. Handles are
opaque 32-bit values; paths and value names use locale-independent ASCII
case-folding. The core supports `REG_DWORD`, `REG_SZ` and `REG_BINARY`, default
values, create/open disposition, balanced opens/closes, size-only queries and
`ERROR_MORE_DATA` without overwriting a short destination.

The Win32 dispatcher implements all seven registry imports present in this
target: `RegCreateKeyExA`, both open variants, both query variants,
`RegSetValueExA` and `RegCloseKey`. Guest pointers and output spans are checked
before writes or registry mutation. Source-oracle evidence confirms the startup
read-default and write-default sequences; the 1,823-instruction host trace
executes both. Persistence is intentionally a later injected service—this core
does not use the host filesystem or claim Windows security/access semantics.

## Guest floating-point control

`PwX86State.fp` owns x87 control/status/tag/opcode/IP/DP, eight architectural
80-bit register slots and MXCSR. Initialize each guest
thread using `pw_guest_fp_init`: CRT defaults are 0x027f and 0x1f80.
`pw_guest_fp_control` implements the reviewed i386/SSE2 `_controlfp` control
mapping entirely with integer operations: mask filtering (including preserved
denormal exception mask), rounding, x87 precision/infinity control, SSE
denormal modes and ambiguous x87/SSE exception/rounding reports. Changes to
SSE controls clear its exception-status bits as in the pinned Wine reference;
queries preserve status. The cdecl adapter reads two 32-bit arguments and
commits FP changes only after successful ABI return.

Tests cover the field mappings, defaults, status handling, queries, ambiguous
state, raw 80-bit push/peek/pop, TOP wrap, zero/valid tags, overflow/underflow,
invalid/uninitialized calls, and unchanged host x87/MXCSR controls.
`pw_x87` adds integer-only binary80 load/store conversion, constants, register
stack operations, status transfer, add/subtract/multiply/divide, comparisons
and square root. The translator accepts all 36 source-reachable startup forms;
synthetic encoding and independently stated IEEE-bit golden vectors cover the
families. Complete unmasked trap delivery, later transcendental forms and SSE
execution remain pending. Every future handler must consume this same
per-thread state, not host defaults.

## Initializer callbacks

`_initterm(start,end)` uses a checked, half-open guest pointer table, skips null
entries and schedules cdecl callbacks through `pw_guest_callback_enter`.
It never invokes a guest address as a host function. A successful dispatch
with `callback_pending=1` is a yield to guest EIP, **not API completion**.
The dispatcher must intercept reserved return tokens at 0xe1000000 + depth*16
before fetching code. These tokens and the API-token range must remain unmapped.
Runtime storage is guest-thread-owned. Code execution permissions remain the
execution dispatcher's responsibility; each table read requires guest readability.

The initial bounds are 1,024 entries and eight nested initializer calls.
Misaligned/reversed tables, unavailable memory, excessive depth/length and
out-of-order or ABI-invalid returns stop explicitly. Completed callback side
effects are not rolled back on a later fault. Caller stack cleanup is cdecl;
the API is counted complete only after its table finishes.

`test_pw_initterm` executes synthetic translated callbacks with persistent
memory effects, null entries, nested empty and nonempty initializers, and
checks malformed tables, permissions/ranges, stale tokens and damaged
callee-saved register returns. Pinball's first observed `_initterm` returns
without scheduling callbacks, so actual-game callbacks are not yet proven.
The subsequent original-game initializer now schedules a callback, executes
its clock/identity calls and returns through the guest ABI bridge, allowing
the enclosing `_initterm` to finish. This is completed original-game callback
evidence on the host only; nested callback evidence remains synthetic.
Host telemetry labels scheduled work `host-callback-enter` separately from
the API-return records. No PS5 callback execution is claimed.

## Arguments and environment

`pw_guest_args_build` packs narrow strings and NULL-terminated 32-bit argv/env
tables using an explicit guest base, with no host pointers or inherited host
environment. It supports 128 arguments/environment entries and 4,096 string
bytes; runtime initialization must fit both the original command line and
packed data in its 4 KiB CRT region. Failures leave output unchanged.
Parsing follows the [Microsoft CRT command-line rules](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments):
pathname quoting for argv[0], space/tab separators, embedded quotes and
backslash/quote handling for later arguments. It does not perform Unicode
code-page conversion, shell interpretation or filesystem wildcard expansion.

The initial runtime deliberately provides an empty environment; the reusable
packer accepts explicit environment strings for future configuration.
`__getmainargs` validates all three output words and the optional new_mode
word before modifying guest state. It returns cdecl integer zero, stable
guest argc/argv/env pointers, and records new_mode 0/1. Nonzero wildcard
requests and unsupported mode values stop explicitly. Allocator behavior
for a registered new-handler remains pending; the current default has no handler.
Tests cover quoting/escaping, empty input/arguments, explicit environments,
pointer packing, storage/argument limits, and API failure atomicity.

## Clock and identity services

`PwWin32Services` injects three clock domains and two stable guest IDs. Missing
services stop explicitly; shared runtime code never assumes host process IDs.
The Linux tracer connects UTC to CLOCK_REALTIME, uptime to CLOCK_BOOTTIME
(including suspend), and the counter to CLOCK_MONOTONIC, with guest IDs 1/2.
PS5 clock bindings and a multi-process/thread ID registry remain pending.

- `GetSystemTimeAsFileTime`: stdcall pointer output, void return; converts
  nonnegative Unix nanoseconds to 100 ns ticks using the 1601 UTC epoch offset.
  Layout follows [FILETIME](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
- `GetTickCount` and `timeGetTime`: uptime milliseconds modulo 2^32, as specified
  by [GetTickCount](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount)
  and [timeGetTime](https://learn.microsoft.com/en-us/windows/win32/api/timeapi/nf-timeapi-timegettime).
- `QueryPerformanceCounter`: signed-range 64-bit monotonic nanosecond count
  in guest memory, BOOL true on success. This backend's counter frequency is
  1 GHz (units, not measured clock resolution); a future QueryPerformanceFrequency
  handler must return that same frequency. That export is not yet implemented.
- `GetCurrentProcessId` and `GetCurrentThreadId`: explicitly configured nonzero
  guest identifiers. These are not host handles or process enumeration support.

The 8-byte output range is fully checked before sampling or mutation, using
byte copies rather than alignment assumptions. Unavailable clocks, invalid
destinations and counter overflow are classified runtime stops; Windows
last-error/failure-return emulation remains future work. Tests use injected
clock values to verify epochs, units, wraparound, ABI returns and failure
atomicity. UTC, tick, counter and both IDs now have original-game host evidence;
timeGetTime remains unit-tested only.

## GUI startup profile

`GetStartupInfoA` serializes the 68-byte PE32 layout, not a host-sized struct.
The launcher profile specifies STARTF_USESHOWWINDOW and `startup_show`
(default SW_SHOWNORMAL=1), with no inherited console handles, title/desktop
override, geometry override or reserved CRT block. The supported show values
exclude SW_SHOWDEFAULT, as required by the
[STARTUPINFOA contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa).
Future ShowWindow handling must consume this same first-show policy; this
API by itself neither creates nor displays a window.

All 68 output bytes are validated before modification; the stdcall return is
void. Tests verify byte-exact PE32 fields, alternate show modes, unaligned
output, adjacent-byte preservation and failure atomicity for a truncated range.
The original CRT now reads this profile and continues past its startup call.
