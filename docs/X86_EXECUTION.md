# x86 execution prototype

The first prototype in src/pw_x86_block.c translates a bounded sequence of
32-bit guest instructions into native x86-64 code. Its initial purpose is
to establish 4-byte guest stack semantics and dispatcher transitions needed
by Pinball's entry. It is not a complete decoder or CPU implementation.

Supported encodings: push imm8/imm32/r32 and r32/memory (FF /6), pop r32, mov r32/imm32,
mov r32/r32 and r32/memory (89/8B ModRM/SIB), LEA,
MOV immediate/r32 or memory (C7 /0), register/memory ADD (01/03), SUB (29/2B), XOR (31/33),
NOT/NEG r32/memory (F7 /2,/3), LEAVE (C9),
byte MOV (88/8A, C6 /0, B0-B7), byte CMP (38/3A, 80 /7, 3C),
byte TEST (84, F6 /0, A8), register/memory INC/DEC (40-4F, FF /0,/1),
Immediate ADD/OR/ADC/SBB/AND/SUB/XOR/CMP 16/32-bit (81/83 and accumulator
forms, optional 66 prefix), CMP r32/memory
(39/3B), TEST 32-bit register/memory or immediate (85, A9, F7 /0),
MOVZX/MOVSX byte/word to 32-bit (0F B6/B7/BE/BF), all short/near Jcc and register-byte SETcc,
32-bit SHL/SHR/SAR with immediate, implicit-one or CL counts (C1/D1/D3),
Absolute and FS-prefixed A1/A3 moffs32 loads/stores
through EAX, nop, direct call rel32, indirect near call/jump (FF /2,/4),
jmp rel8/rel32 and ret/ret imm16 (C3/C2). Calls push a 32-bit guest return PC and yield the
target EIP to the caller. Ret reads that PC and yields again. Guest ESP
lives in the state structure, independently from native RSP. No guest stack
opcode is copied as a 64-bit push/pop/call/ret.

The caller supplies a live RW low-address guest stack and keeps it mapped
for the full execution lifetime. Generated bounds checks verify each 1-, 2- or 4-byte
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
It stops at 256 dispatch/instruction events by default, unsupported decoding/API behavior
or memory-bound failure. The printed steps count excludes API dispatch events.

On 2026-09-08, input SHA-256
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`
initially completed 22 translated instructions through the startup helper.
With import binding and indirect-call dispatch, the same input now completes
495 instructions and 24 completed API calls (eighteen distinct APIs),
using the optional 4096-event limit (`trace_x86_entry private.exe 4096`), after
adding memory arithmetic and initializer epilogue support, clock services, logical TEST, guest arguments,
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
kind=host-api dll=kernel32.dll name=GetSystemTimeAsFileTime result=0x030fff34
kind=host-api dll=kernel32.dll name=GetCurrentProcessId result=0x00000001
kind=host-api dll=kernel32.dll name=GetCurrentThreadId result=0x00000002
kind=host-api dll=kernel32.dll name=GetTickCount result=0x28d8442d
kind=host-api dll=kernel32.dll name=QueryPerformanceCounter result=0x00000001
kind=host-api dll=msvcrt.dll name=_initterm result=0x00000000
kind=host-api dll=kernel32.dll name=GetStartupInfoA result=0x030fff78
kind=host-api dll=kernel32.dll name=GetModuleHandleA result=0x01000000
kind=host-api dll=user32.dll name=LoadStringA result=0x00000020
kind=host-api dll=kernel32.dll name=lstrlenA result=0x00000020
kind=host-api dll=msvcrt.dll name=malloc result=0x03400000
kind=host-api dll=kernel32.dll name=lstrcpyA result=0x03400004
kind=host-api dll=user32.dll name=LoadStringA result=0x0000000a
kind=host-api dll=msvcrt.dll name=malloc result=0x03400030
kind=host-api dll=kernel32.dll name=lstrcpyA result=0x03400034
kind=host-api dll=kernel32.dll name=lstrcatA result=0x03400034
kind=host-api dll=kernel32.dll name=lstrcatA result=0x03400034
kind=host-api-stop dll=advapi32.dll name=RegCreateKeyExA status=-5
kind=host-entry-trace steps=495 stop=unimplemented-api eip=0xe0000010 esp=0x030ffdc4 ebp=0x030ffdf8 fs0=0x030fffe8 flags=0x00000202
kind=host-heap-summary blocks=3 live=2 requested=2041 arena=8388608 valid=1
```

The next stop is the RegCreateKeyExA dispatcher token. Before it, two malloc
calls allocate guest memory, two lstrcpyA and two lstrcatA calls construct
startup strings, and LoadStringA copies two private PE string resources. The CRT reads
the GUI startup profile, walks the command line and
the second `_initterm` returns. Its original-game callback has completed through the translator and
guest ABI bridge. Clock values (and derived flags) vary across live runs;
the transcript above is one observed run, not a fixed-value invariant.
Synthetic tests separately exercise nested callbacks. `_controlfp` now
updates guest control state without modifying host FP controls; arithmetic
execution remains pending. Absolute MOV tests exercise independent read/write permissions,
last-valid and crossing-boundary addresses, unchanged flags and fault atomicity.
Operand PUSH tests cover old-ESP addressing, source and destination faults,
flag preservation and continuation into the next instruction. PUSH checks
the source before committing the destination or changing guest ESP.
TEST regressions cover all five supported operand forms, sign/zero/parity
flags, cleared carry/overflow, preserved operands, and memory-boundary faults.
Undefined AF is retained deterministically, as with the other logical operations.
Memory-arithmetic tests cover operand order, aliasing of address/destination
registers, results/flags and bounds. NOT/NEG tests cover register/memory forms
and signed overflow; LEAVE/RET tests cover full frame teardown and invalid EBP.
Byte tests cover all low/high register MOV combinations, partial-register
preservation, comparison/test flags, last-byte memory access and crossing
faults. INC/DEC preserve guest CF while updating the other arithmetic flags.
The tracer accepts an optional maximum of 1..65536 events, validated before
opening the executable. Default-budget and explicit-budget regressions remain.
RET imm16 tests cover zero, odd and boundary cleanup sizes, oversized cleanup
rejection, unchanged flags, and an actual translated stdcall callback with
two arguments. Return-PC reads and final ESP validation precede state publication.
FF /0,/1 tests verify register/memory INC/DEC, carry preservation, overflow
and continuation into the next instruction.
MOVZX/MOVSX tests cover every source/destination register combination, including
high bytes, aliasing and negative byte/word values, with unchanged guest flags.
Memory forms check the exact source width and reject crossing-boundary reads
without publishing a destination register value.
Shift regressions compare SHL/SHR/SAR results and defined flags against native
x86 for all 256 count bytes, all three count forms and register/memory operands.
Counts are masked to five bits; zero preserves every guest flag, AF is retained,
and OF is updated only for count one. Tests cover ECX/CL aliasing, continuation
and rejected crossing-boundary accesses, including a zero-count memory operand.
Rotates and 8/16-bit shifts are not yet implemented.
The 495-instruction trace with a 4096-event limit reproduces under ASan/UBSan;
the translator compiles for PS5. Native guest execution is still not integrated.
Immediate-ALU tests cover all eight operations, all three encoding forms,
16/32-bit operands, carry inputs, boundary values and memory/register results.
Read-modify-write requires both read and write permissions; rejected accesses
preserve memory and guest flags. ADC/SBB import only guest CF into the host
arithmetic operation, never guest control flags.
The tracer's `result` field reports EAX; `__set_app_type` returns void, so
that field is not a CRT return value (the same applies to `_initterm` and
GetSystemTimeAsFileTime and GetStartupInfoA). Regression tests cover all 16
conditions across 32 arithmetic-flag combinations, register-byte writes,
word-access boundaries, compare operand order and immediate sign extension.
This is host evidence only: sixteen distinct API cases and one original callback have completed,
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
