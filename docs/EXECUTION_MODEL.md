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

## The honest statement of scope, today

- 64-bit (PE32+/AMD64) programs: the premise holds literally. No
  interpretation, no translation, no thunking. The bytes run on Zen 2.
- 32-bit (PE32/i386) programs: parsed, laid out and relocated by the
  current gate, and **not executable on this firmware**. Compatibility mode
  is refused, so ABI thunking is off the table; reaching them requires JIT
  recompilation, which is not emulation either but does alter the
  instruction path. That is a scope decision for the owner, and it is now
  informed by a measurement rather than an assumption. A further obstacle is
  already recorded: anonymous reservations land near `0x200080000`, so a
  PE32 image could not be rebased into the low 4 GiB even if it could run.

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
