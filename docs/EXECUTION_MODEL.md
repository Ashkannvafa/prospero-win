# Execution model

PE32/i386 and PE32+/AMD64 applications are in scope; neither is currently a
demonstrated complete Windows application. Phase 0.1 validated mapping
synthetic images, not executing a game.

## Native AMD64 and ABI bridges

AMD64 guest instructions can execute on the PS5 CPU. Crossings into native
code still need an ABI bridge: Windows x64 uses RCX/RDX/R8/R9, 32 bytes of
caller-provided shadow space and different preserved registers from the
native System V convention. Floating arguments, aggregate returns, stack
alignment and callbacks need explicit tests.

Gate 0.2b starts with a mapped constant-return function, then validates
these crossings using explicit ms_abi functions or equivalent thunks.
Compiler acceptance is not hardware proof. No-argument leaf execution alone
does not establish a working Win32 import boundary.

Reference: [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).

## PE32 execution

The tested sysarch(I386_SET_LDT, ...) route returns EINVAL on FW 12.02.
Controls and repeated measurements remain in COMPAT32_PHASE0A.md. We plan a
software execution engine for x86 code; the tested compatibility-mode route
is closed. ABI marshalling is still needed.

Dynamic binary translation is a form of CPU emulation. It translates and
caches blocks rather than interpreting every instruction repeatedly.
Sharing the instruction family may help, but performance and instruction
coverage have not been established for this project.

Low addresses do not make arbitrary 32-bit instructions safe to copy into
long mode. Address size changes, absolute disp32 can become RIP-relative,
stack width changes, and guest ESP and FS/TLS need treatment. Prefixes,
flags, x87/SSE state, indirect control flow, exceptions and self-modifying
code also need coverage.

The prototype must compare known blocks against native 32-bit host
execution. Pinball determines initial coverage. cdecl/stdcall marshalling,
32-bit pointers/handles and host-to-guest callbacks remain required.

## Measured memory facts

The 2026-09-08 low-memory probe recorded:

| Observation | Meaning and limit |
| --- | --- |
| 256 MiB at 0x10000000 in a title | One low mapping; not proof the full low 4 GiB is allocatable |
| 1 GiB and larger title requests failed | Large single mappings unavailable in that context |
| mmap hint honoured; MAP_32BIT returned high memory | Check returned address and release unacceptable mappings; never overwrite existing mappings with MAP_FIXED |
| mprotect to RX and RWX succeeded | Single-mapping executable protection available on tested firmware |
| Title anonymous budget previously around 432 MiB | Sparse mappings do not remove working-set constraints |
| 16 KiB pages | Adjacent 4 KiB PE sections can share protection |

Payload results are not title guarantees. Reserve/commit/decommit, multiple
low mappings and alternative backing memory need separate tests before
promising a larger guest address space.

## Executable publication and ownership

The backend uses one mapping and mprotect; write_base equals exec_base.
Prefer RW during construction and RX before execution. Never modify or
release a block while another thread may execute it.

The contract retains optional write/execute aliases. Relocations use
exec_base and writes use write_base. Double mapping is not a requirement
established by FW 12.02 results; adopting it needs implementation and
concurrency validation.

The mapper unions protections on shared pages and reports merged/WX
counts. The validator requires --allow-wx to accept such pages.

pe_image_machine_is_native() identifies CPU architecture, not ABI
compatibility, resolved imports or readiness to execute. The validator
accepts mapping evidence only; PE32 requires --allow-i386 and still needs
an execution engine.
