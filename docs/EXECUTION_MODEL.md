# Execution model: what "zero emulation" means here

Most classic PC games are 32-bit, `binkw32.dll` included. A PS5 title runs
in 64-bit long mode. This document is about the gap between those two facts,
because it decides the project's scope and it is easy to describe wrongly.

## Three mechanisms, not one

Collapsing everything that isn't plain native execution into "emulation"
is the mistake this section exists to prevent. There are three distinct
mechanisms with very different cost and very different claims:

| Mechanism | What runs the game's arithmetic | Overhead | Is it emulation? |
| --- | --- | --- | --- |
| **Interpretation** (Bochs, a console emulator's CPU core) | A decode loop in C: fetch opcode, switch, update simulated registers and flags in RAM | Enormous — a silicon state machine simulated in software | Yes. This is what the word means |
| **Dynamic binary translation** (Rosetta 2, FEX-Emu, box86) | The silicon, executing 64-bit blocks a JIT recompiled from the original 32-bit blocks and cached | Modest, and amortised: x86-32 and x86-64 share endianness, memory ordering and most semantics, so the translation is near-transcription | No interpretation anywhere, but the instruction path is altered. JIT recompilation, not emulation |
| **ABI thunking** (WoW64) | The silicon, executing the game's original 32-bit opcodes in the CPU's hardware compatibility mode | Zero in the game's own code. Cost appears only at API boundaries, marshalling arguments | No. Nothing intercepts the game's logic at all |

Under ABI thunking, translation happens strictly at the operating-system
boundary. The 32-bit program calls `CreateFileA` or a Direct3D 9 entry
point, a 32-bit stub catches it, widens pointers and arguments into 64-bit
registers, and hands off to the native implementation. The game's math,
physics and logic are never touched. That is prospero-win's ideal
architecture, and it is what the project should aim at.

## What ABI thunking actually requires

Zen 2 supports 32-bit execution natively through compatibility mode, so the
hardware is not the constraint. The constraint is how a thread *enters* that
mode, and it is worth stating mechanically rather than loosely.

In long mode the current code segment is described by a segment descriptor.
Two bits in it select the mode: `L` (long) clear and `D/B` set give a 32-bit
ring-3 code segment. A thread enters compatibility mode by performing a far
transfer — a far `jmp` or `call` — to a selector whose descriptor has those
bits. It cannot flip a mode bit directly; there is no such instruction.

So the descriptor has to exist first, and a descriptor table is not
something user code can write:

- the GDT is kernel-only (`lgdt` is ring 0);
- the LDT is per-process, but installing entries into it is a syscall.

On FreeBSD amd64 that syscall is `sysarch(I386_SET_LDT, …)`, implemented by
`amd64_set_ldt`, which validates a `user_segment_descriptor` and installs
it. It exists in FreeBSD precisely to support 32-bit compatibility and
consumers like Wine. `I386_SET_FSBASE` is the companion a 32-bit thread
needs for `fs`-based TLS.

The pinned PS5 payload SDK ships those declarations:
`target/include/x86/sysarch.h` defines `I386_GET_LDT`, `I386_SET_LDT`,
`I386_SET_FSBASE` and `int sysarch(int, void *)`, and
`target/include/sys/syscall.h` gives `SYS_sysarch` as 165.

**A declaration is not a capability.** The laboratory's porting playbook is
explicit that an exported platform symbol is not a working one, and a header
declaration is weaker evidence still: this SDK is a FreeBSD-derived header
set, so it describes FreeBSD, not necessarily what Sony's kernel permits a
sandboxed title to do. Prospero may have removed LDT support, or may filter
`sysarch` down to the `fsbase`/`gsbase` operations a normal title needs.

**Measured on 2026-09-08: refused.** `sysarch(I386_SET_LDT, ...)` returns
`EINVAL` from a title on FW 12.02, so no local descriptor can be installed
and compatibility mode cannot be entered. The same probe completes a full
round trip on an ordinary x86-64 Linux host, which is what makes the console
result attributable to the platform rather than to the stub. See
`COMPAT32_PHASE0A.md`.

ABI thunking is therefore **not** available here. The remainder of this
section stays because it documents what was tried and why the answer is
credible, not because the route is still open.

## The probe that decides the scope

Gate 0.2 therefore opens with the cheapest experiment in the project:

1. Build a `user_segment_descriptor` for a ring-3 32-bit code segment:
   `L` clear, `D/B` set, type execute/read, DPL 3, present, page granular,
   base 0, limit `0xfffff`. Add a matching data segment.
2. Call `sysarch(I386_SET_LDT, …)` with `LDT_AUTO_ALLOC` and report the
   result and `errno` through `ps5log/1`.
3. If it succeeds, far-jump to the returned selector, execute a handful of
   32-bit instructions that produce a value only 32-bit semantics can
   produce, far-return to 64-bit, and report the value.

Three outcomes, each decisive:

- **`sysarch` refused.** ABI thunking is off the table on this firmware.
  The choice narrows to DBT or 64-bit-only scope, and the reason is
  recorded rather than assumed.
- **Descriptor installed, far transfer faults.** Something subtler is
  wrong — worth Ghidra time on the kernel's LDT and trap paths, exactly the
  inspection layer the playbook reserves for an ambiguous platform result.
- **Round trip returns the right value.** WoW64-style thunking is real
  here, the project's premise holds literally for 32-bit games, and Phase 1
  gains a whole second dimension: every Win32 entry point needs a 32-bit
  stub and a marshalling thunk.

This probe is small, bounded and answers a question that otherwise shapes
months of work on a guess. It runs before any scope decision.

## What thunking still costs if the probe passes

Compatibility mode is necessary, not sufficient. The remaining surface is
real and should be sized before committing:

- **Everything the 32-bit code can address must live below 4 GiB** — its
  images, its stacks, its heap. `pw_map_image()` already enforces the image
  half of this: a PE32 rebase is expressed as a 32-bit addend, so an image
  reserved above 4 GiB is refused with `PW_ERR_UNSUPPORTED` instead of
  being relocated with truncated pointers. The memory backend will need an
  address-limited reservation to satisfy it rather than merely detect it.
- **Every crossing needs hand-written assembly**, in both directions, with
  a stack switch: game to host on an API call, and host to game on every
  callback — window procedures, DirectSound mixing callbacks, comparison
  functions handed to `qsort`. The stack switch is not optional and not a
  detail: the host run of gate 0.2a showed that the 64-bit stack pointer
  does not survive a round trip, because compatibility mode leaves only
  `ESP` meaningful and `RSP` returns with its upper half zeroed. The
  transfer stub saves and restores it explicitly for that reason.
- **Signal and exception delivery while in compatibility mode** is the
  biggest unknown. FreeBSD builds 32-bit signal frames for i386
  *processes*; whether it does so for a 32-bit thread inside a 64-bit
  process is doubtful, and a fault delivered with the wrong frame shape is
  unrecoverable.
- **TLS** needs `I386_SET_FSBASE` and a 32-bit thread-information block.

## If the probe fails, DBT is not starting from zero

Should `sysarch` be refused, DBT becomes the only route to the 32-bit
catalogue — and it is closer to hand than it looks, because its hardest
platform prerequisite is already proven in this laboratory. Executable
memory on FW 12.02 goes through the `jitshm` double mapping, one alias
writable and one executable, with concurrent `mprotect` transitions
avoided. That is precisely a JIT's requirement, it is already measured, and
`include/prospero_win_vm.h` is built around that two-alias shape from the
start for exactly this reason.

A DBT still costs a translator, a block cache, a register allocator and a
self-modifying-code story, which is the main technical argument against it
and against static recompilation. But it is engineering on measured
foundations, not a research gamble.

## Scope, decided

**Both 32-bit and 64-bit programs are supported.** 64-bit ones execute
natively, with no interpretation, no translation and no thunking — the
premise holds literally. 32-bit ones go through the Phase 4 instruction
translator, because compatibility mode is refused here.

That is a decision about what the project builds, not a change to what any
of the above measured. It is worth being precise about what it costs, since
"we support 32-bit too" can be heard as cheaper than it is:

- **Instruction translation is not emulation**, in the sense that matters:
  the silicon executes 64-bit instructions a JIT produced and cached, with
  no decode loop anywhere. But the instruction path *is* altered, so the
  strict "zero emulation" claim applies to the 64-bit half only, and the
  README says so rather than blurring it.
- **A translator does not remove the thunking work.** It removes the
  hardware mode switch. Translated code is 64-bit instructions, but the
  guest ABI stays 32-bit: `cdecl`/`stdcall` arguments on a 4-byte stack,
  32-bit pointers, 32-bit handles. Every Win32 entry point still needs
  marshalling in both directions, callbacks included. That work was going
  to be needed on the ABI-thunking route too; it survives the change of
  route intact.
- **The measured prerequisites hold**, which is why this is a defensible
  choice rather than an aspiration: guest pointers below 4 GiB mean memory
  operands need no rewriting, a code cache can be `rwx`, and 256 MiB
  contiguous low is available in a title.

## The honest statement of scope, today

- 64-bit (PE32+/AMD64) programs: the premise holds literally. No
  interpretation, no translation, no thunking. The bytes run on Zen 2.
- 32-bit (PE32/i386) programs: parsed, laid out and relocated by the
  current gate, and **not yet executable** — in scope, but waiting on the
  Phase 4 translator. Compatibility mode is refused, so there is no native
  path. Note that the earlier concern about rebasing a PE32 image into the
  low 4 GiB is resolved: the default anonymous placement is high, but a low
  address is grantable on request, so a 32-bit image can be mapped where its
  32-bit relocations can express it.

The loader keeps refusing to overstate this. `pe_image_machine_is_native()`
is true only for AMD64, and the validator still requires `--allow-i386`
before accepting a run that mapped a 32-bit image — not because such images
are unwelcome, but because until Phase 4 exists a mapped one cannot run, and
a partial result should have to be acknowledged as one.

The loader reflects exactly this and claims nothing more.
`pe_image_machine_is_native()` is true only for AMD64;
`tools/validate_pe_map_evidence.py` rejects a run containing a non-native
module unless `--allow-i386` is passed, so accepting a parse-and-map-only
result of a 32-bit image is always a visible, deliberate decision.

## Page granularity, separately

PE images are laid out on 4 KiB section boundaries. Where the platform's
protection granularity is coarser, two sections with different protections
share one protectable page and the mapper applies the union — a `.text` and
`.data` page merging that way yields a page both writable and executable.

`pw_map_finalize_protections()` does that and counts it: `merged`, `wx` and
`no_access` totals appear in the `PW_PROTECT` record, and the validator
rejects any run with writable-executable pages unless `--allow-wx` is
given. The weakening is real, so it is measured and acknowledged rather
than discovered later.

## Measured: what the JIT route would have to work with

Compatibility mode is refused, so JIT recompilation is the only route to the
32-bit catalogue. Its two hard prerequisites were measured on 2026-09-08
rather than assumed, because a 32-bit guest can only avoid address
translation entirely if its whole address space sits below 4 GiB — writing a
32-bit register zeroes the upper half, so `[ebx]` and `[rbx]` then compute
the same address for free.

| Question | Answer | Source |
| --- | --- | --- |
| Is the low 4 GiB available? | Yes, and nearly empty: the image occupies about `0x400000`–`0x584000` and little else | `tools/lowmem-probe`, `KERN_PROC_VMMAP` |
| Are low addresses grantable? | Yes. A plain `mmap` **hint** is honoured exactly | Both payload and title |
| How much contiguous, in a title? | **256 MiB** at `0x10000000`. 1 GiB and above fail | `PW_LOWMEM` |
| How much in an `elfldr` payload? | 3 GiB contiguous | `lowmem-probe` |
| Writable and executable? | Yes, in a title: `mprotect` to `r-x` and to `rwx` both succeed | `PW_LOWMEM` |
| `MAP_32BIT`? | Ignored; returns high memory | `lowmem-probe` |

The title-versus-payload gap is the point of measuring in the right
context. It is not an address-range restriction: it matches the
laboratory's already-recorded anonymous ceiling for a title, 432 MiB
verified and 448 MiB refused. So the low address space is fully usable, but
a title can only commit a few hundred megabytes of it at once — which means
a guest address space has to be mapped on demand rather than reserved flat.
A real loader does that anyway.

Two consequences worth carrying forward:

- **The free address-computation property holds.** Guest pointers can live
  below 4 GiB, so a translator does not have to rewrite memory operands —
  the single largest saving available on this route, and the reason
  x86-32 to x86-64 is much cheaper than a cross-architecture translation.
- **A code cache can be `rwx` directly.** `mprotect` to read-write-execute
  succeeds from a title, so a JIT does not need the `jitshm` double mapping.
  The laboratory's preference for that double mapping was about avoiding
  *concurrent* protection transitions, which remains sound advice, but it is
  not a feasibility barrier.

Neither of these makes the route cheap. They bound it, which is what a
scope decision needs.
