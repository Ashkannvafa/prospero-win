# x86 execution prototype

The first prototype in src/pw_x86_block.c translates a bounded sequence of
32-bit guest instructions into native x86-64 code. Its initial purpose is
to establish 4-byte guest stack semantics and dispatcher transitions needed
by Pinball's entry. It is not a complete decoder or CPU implementation.

Supported encodings: push imm8/imm32/r32, pop r32, mov r32/imm32,
mov r32/r32 (89/8B register ModRM), FS-prefixed A1/A3 moffs32 loads/stores
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
compares its three stack words with the translated program. The return PC
and both pushed values match byte for byte. GNU as/ld and host i386 execution
support are required; this check does not substitute an emulator silently.

The differential test covers only that instruction sequence, not the whole
supported subset, arbitrary guest blocks or PS5 execution. The generated
blocks still need hardware validation.

## Pinball dependency

The private executable's entry begins with two immediate pushes and a
direct call, which this subset represents. Its helper then accesses FS:0
and constructs an x86 exception-registration frame. We must implement a
guest TEB and exception chain; using the native thread's FS state is wrong.
The original entry has been inspected, not yet executed through this engine.

Next coverage: memory ModRM/SIB addressing, arithmetic and
guest EFLAGS, TEB initialization and broader FS encodings, indirect calls into import adapters,
x87/SSE state and fault semantics. There is no block cache, invalidation,
full memory model or scheduling yet. Before a broader decoder is adopted,
retain these semantic tests and extend differential coverage.
