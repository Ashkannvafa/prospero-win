# x86 execution prototype

The first prototype in src/pw_x86_block.c translates a bounded sequence of
32-bit guest instructions into native x86-64 code. Its initial purpose is
to establish 4-byte guest stack semantics and dispatcher transitions needed
by Pinball's entry. It is not a complete decoder or CPU implementation.

Supported encodings: push imm8/imm32/r32, pop r32, mov r32/imm32,
mov r32/r32 and r32/stack-memory (89/8B ModRM/SIB), LEA,
MOV immediate/r32 or stack-memory (C7 /0), register SUB (29/2B),
FS-prefixed A1/A3 moffs32 loads/stores
through EAX, nop, direct call rel32,
jmp rel8/rel32 and ret. Calls push a 32-bit guest return PC and yield the
target EIP to the caller. Ret reads that PC and yields again. Guest ESP
lives in the state structure, independently from native RSP. No guest stack
opcode is copied as a 64-bit push/pop/call/ret.

The caller supplies a live RW low-address guest stack and keeps it mapped
for the full execution lifetime. Generated bounds checks verify each 4-byte
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
an address. MOV currently accepts memory addresses within the live stack
range; PE data, heap and other regions still require a general memory map.
All three memory ModRM modes and every SIB byte are covered by host LEA
tests, including truncated encodings. These tests are not a full decoder
conformance suite; operand/address-size overrides are not supported.

SUB snapshots the six arithmetic flags (OF/SF/ZF/AF/PF/CF) after the native
32-bit subtraction, retaining all other guest EFLAGS bits in the state.
Guest control flags are never installed in native RFLAGS. Tests cover edge
values for borrow, signed overflow, auxiliary carry, parity, sign and zero;
MOV and failed memory accesses preserve the recorded guest flags.

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
executable PE sections but does not map or expose PE data to guest loads.
It stops at 256 instructions, unsupported decoding or memory-bound failure.

On 2026-09-08, input SHA-256
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`
completed 22 translated instructions, including the startup helper's return:

```
kind=host-entry-trace steps=22 stop=unsupported eip=0x01020fa1 esp=0x030fff6c ebp=0x030ffff8 fs0=0x030fffe8 flags=0x00000206
```

The next unsupported instruction is register XOR. This is host evidence
only: no Win32 imports have run, no gameplay has begun, and this tracer has
not been exercised on PS5. Synthetic PE tests independently cover normal
instruction progress, unsupported stops, memory faults and a looping budget
stop. Executable bytes remain private; no extracted routine is embedded here.

Next coverage: general guest memory regions, arithmetic and
guest EFLAGS, TEB initialization and broader FS encodings, indirect calls into import adapters,
x87/SSE state and fault semantics. There is no block cache, invalidation,
full memory model or scheduling yet. Before a broader decoder is adopted,
retain these semantic tests and extend differential coverage.
