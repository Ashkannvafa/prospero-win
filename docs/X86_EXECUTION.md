# x86 execution prototype

The first prototype in src/pw_x86_block.c translates a bounded sequence of
32-bit guest instructions into native x86-64 code. Its initial purpose is
to establish 4-byte guest stack semantics and dispatcher transitions needed
by Pinball's entry. It is not a complete decoder or CPU implementation.

Supported encodings: push imm8/imm32/r32 and r32/memory (FF /6), pop r32, mov r32/imm32,
mov r32/r32 and r32/memory (89/8B ModRM/SIB), LEA,
MOV immediate/r32 or memory (C7 /0), register ADD (01/03), SUB (29/2B), XOR (31/33),
Immediate ADD/OR/ADC/SBB/AND/SUB/XOR/CMP 16/32-bit (81/83 and accumulator
forms, optional 66 prefix), CMP r32/memory
(39/3B), MOVZX word (0F B7), all short/near Jcc and register-byte SETcc,
Absolute and FS-prefixed A1/A3 moffs32 loads/stores
through EAX, nop, direct call rel32, indirect near call/jump (FF /2,/4),
jmp rel8/rel32 and ret. Calls push a 32-bit guest return PC and yield the
target EIP to the caller. Ret reads that PC and yields again. Guest ESP
lives in the state structure, independently from native RSP. No guest stack
opcode is copied as a 64-bit push/pop/call/ret.

The caller supplies a live RW low-address guest stack and keeps it mapped
for the full execution lifetime. Generated bounds checks verify each 2- or 4-byte
access and preserve the faulting guest PC on failure. Prior completed guest
instructions remain committed. The translator emits into writable scratch;
only successful translations may be published RX. Unsupported or truncated
input and insufficient output capacity report failure.

FS accesses use `fs_base` and `fs_bytes` in guest state, never the native
thread's segment register. The caller owns the live RW low-address mapping.
Generated checks reject offsets outside that mapping, base/offset overflow,
and a dword crossing the 32-bit address limit before any memory access.
This is an addressing primitive, not a complete TEB or exception subsystem.

ModRM/SIB uses 32-bit effective-address arithmetic, including wraparound,
signed disp8 and absolute disp32 (never host RIP-relative). LEA only computes
an address. MOV accepts the live stack or up to eight additional identity-
mapped regions with independent read/write permissions. The caller owns
their lifetime and must register only real, accessible mappings. A SysV
helper validates each dword before access; generated blocks contain its
process-local address and are not serializable. Native RSP is aligned and
the context pointer preserved across that call. This registry is not a
virtual-memory allocator or a security boundary against a hostile host.
All three memory ModRM modes and every SIB byte are covered by host LEA
tests, including truncated encodings. These tests are not a full decoder
conformance suite; operand/address-size overrides are not supported.

SUB snapshots the six arithmetic flags (OF/SF/ZF/AF/PF/CF) after the native
32-bit subtraction, retaining all other guest EFLAGS bits in the state.
Guest control flags are never installed in native RFLAGS. Tests cover edge
values for borrow, signed overflow, auxiliary carry, parity, sign and zero;
MOV and failed memory accesses preserve the recorded guest flags.
XOR updates its five defined arithmetic flags, clears OF/CF, and preserves
the previous guest AF as a deterministic choice for that undefined flag.

## Host evidence

test_pw_x86_block.c executes generated code after RW-to-RX protection and
checks calls, ret, stack boundaries, sign extension and rejection paths.
Register stack tests cover all eight registers, old-ESP semantics for push,
loaded-ESP semantics for pop, and partial progress before a stack fault.
Register MOV tests cover both encodings and every source/destination pair.
FS tests cover a synthetic exception-chain sentinel read, a write, the last
valid dword, out-of-bounds offsets, undersized regions and address overflow.
Those are host contract tests, not differential i386 or PS5 FS evidence.
The generated-function invocation alone disables Clang's UBSan function-type
check: JIT code has no compiler metadata preceding its entry. AddressSanitizer
and the other undefined-behavior checks remain enabled for the host code;
they do not instrument generated machine instructions.
test_x86_differential.py assembles a separate i386 ELF from project-authored
assembly, runs it directly using the host Linux i386 execution support, and
compares its three stack words and a wrapping SIB address with the translated
program. The return PC, both pushed values and computed address match byte
for byte. GNU as/ld and host i386 execution
support are required; this check does not substitute an emulator silently.

The differential test covers only that instruction sequence, not the whole
supported subset, arbitrary guest blocks or PS5 execution. The generated
blocks still need hardware validation.

## Pinball dependency

The private executable's entry begins with two immediate pushes and a
direct call, which this subset represents. Its helper then accesses FS:0
and constructs an x86 exception-registration frame. We must implement a
guest TEB and exception chain; using the native thread's FS state is wrong.
The bounded host tracer now executes instructions directly from the private
file through this engine. Build `make build/host/trace_x86_entry`, then run
`build/host/trace_x86_entry /private/path/Pinball.exe`. Exit 2 is a classified
stop, not successful application startup; exit 1 is setup/cleanup failure.
The tracer owns a synthetic stack and FS region and initializes only the
exception-chain sentinel, not a complete Windows TEB. It fetches from
executable PE sections through the existing mapper and registers headers
and sections with their logical access permissions. A typed catalog binds
function tokens and CRT data, with unsupported APIs stopped by identity.
The current tracer requires mapping at the preferred base; it rejects an
alternate base instead of executing with inconsistent guest addresses.
It stops at 256 dispatch/instruction events, unsupported decoding/API behavior
or memory-bound failure. The printed steps count excludes API dispatch events.

On 2026-09-08, input SHA-256
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`
initially completed 22 translated instructions through the startup helper.
With import binding and indirect-call dispatch, the same input now completes
95 instructions and seven completed API calls after adding guest arguments,
operand PUSH, initializer dispatch, guest FP control, absolute MOV, immediate ALU
operations, conditional execution and initial CRT state services:

```
kind=host-import-bind total=207 functions=205 data=2
kind=host-api dll=kernel32.dll name=GetModuleHandleA result=0x01000000
kind=host-api dll=msvcrt.dll name=__set_app_type result=0x00000000
kind=host-api dll=msvcrt.dll name=__p__fmode result=0x03300008
kind=host-api dll=msvcrt.dll name=__p__commode result=0x0330000c
kind=host-api dll=msvcrt.dll name=_controlfp result=0x0009001f
kind=host-api dll=msvcrt.dll name=_initterm result=0x0009001f
kind=host-api dll=msvcrt.dll name=__getmainargs result=0x00000000
kind=host-callback-enter dll=msvcrt.dll name=_initterm target=0x0101cd2b depth=1
kind=host-entry-trace steps=95 stop=unsupported eip=0x0101cd38 esp=0x030fff2c ebp=0x030fff3c fs0=0x030fffe8 flags=0x00000202
```

The next stop is an unsupported instruction inside the second `_initterm`'s
guest callback. The first initializer call needed no callbacks; the second
has not completed. Synthetic tests separately exercise complete translated
and nested callbacks. `_controlfp` now
updates guest control state without modifying host FP controls; arithmetic
execution remains pending. Absolute MOV tests exercise independent read/write permissions,
last-valid and crossing-boundary addresses, unchanged flags and fault atomicity.
Operand PUSH tests cover old-ESP addressing, source and destination faults,
flag preservation and continuation into the next instruction. PUSH checks
the source before committing the destination or changing guest ESP.
The 95-instruction trace reproduces under ASan/UBSan. The argument packer and
Win32 adapter compile with the PS5 toolchain; this is not PS5 guest execution.
Immediate-ALU tests cover all eight operations, all three encoding forms,
16/32-bit operands, carry inputs, boundary values and memory/register results.
Read-modify-write requires both read and write permissions; rejected accesses
preserve memory and guest flags. ADC/SBB import only guest CF into the host
arithmetic operation, never guest control flags.
The tracer's `result` field reports EAX; `__set_app_type` returns void, so
that field is not a CRT return value (the same applies to `_initterm`). Regression tests cover all 16
conditions across 32 arithmetic-flag combinations, register-byte writes,
word-access boundaries, compare operand order and immediate sign extension.
This is host evidence only: seven narrow API cases have completed,
no gameplay has begun, and this tracer has
not been exercised on PS5. Synthetic PE tests independently cover normal
instruction progress, unsupported stops, memory faults and a looping budget
stop. Executable bytes remain private; no extracted routine is embedded here.

The IAT slot at RVA 0x10f0 resolves by its preserved import lookup table to
`KERNEL32!GetModuleHandleA`; the caller pushes a null argument. The bound
address in the original file belongs to the old Windows image, not this
host. The mapper's writable copy is now rebound; the original file remains
unchanged. The GetModuleHandleA(NULL) response uses the mapped main-module
base and the shared stdcall return service. Other API cases remain pending.

Next coverage: import binding and dispatch, more arithmetic and
guest EFLAGS, TEB initialization and broader FS encodings, indirect calls into import adapters,
x87/SSE state and fault semantics. There is no block cache, invalidation,
full memory model or scheduling yet. Before a broader decoder is adopted,
retain these semantic tests and extend differential coverage.
