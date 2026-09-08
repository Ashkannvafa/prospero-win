# Shared guest call and callback services

`src/pw_guest_call.c` provides integer-stack marshalling for Win32 adapters.
It does not resolve imports or implement a Win32 API. These services are
shared prerequisites identified by the complete Pinball import inventory.

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

The existing Pinball host trace still stops at its first indirect import
call. Connecting a reviewed symbol catalog, separate data/function IAT
bindings and these services is the next integration step; no API has been
silently replaced by a success stub.
