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
  verifies its result and restores the caller. The stdcall callback unit test
  models the return state; it is not translated RET-immediate evidence.
- Host tests pass under ASan/UBSan. The shared C service compiles with the
  PS5 target toolchain. No hardware callback evidence is claimed yet.

## Initial runtime integration

`pw_win32.c` uses the generated factual code/data catalog for Pinball's 207
imports. Unknown names/ordinals are refused. All 205 function imports bind
to unique dispatcher tokens, not host addresses. Initial handlers cover
`GetModuleHandleA(NULL)`, `__set_app_type`, `__p__fmode` and `__p__commode`.
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
`__set_app_type`, `__p__fmode`, `__p__commode` and stops after 66 instructions
at the pending `_controlfp` API. The pointer getters now have original-game
host execution evidence as well as unit coverage.
Synthetic PE tests cover binding,
dispatch and return, plus a
named stop for a pending API. No PS5 execution of this integration is claimed.
