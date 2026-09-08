# What "zero emulation" can and cannot mean here

This document exists because the project's stated goal — running classic PC
programs natively on Zen 2, with no emulation — is achievable for one class of
Windows binary and not for another. That boundary shapes every phase after
this one, so it is recorded before any code depends on it.

## The constraint

A PS5 title runs in 64-bit long mode. Executing 32-bit x86 code on the same
core is a hardware capability the CPU has (compatibility mode), but entering
it requires a code segment descriptor with the 32-bit default-operand bit
clear, installed in the GDT or LDT. A title cannot create one: descriptor
tables are kernel state, and the sandbox exposes no call that installs a
segment. There is no `far jmp` to a descriptor we are allowed to define.

So for an `i386` PE image:

- parsing works,
- mapping works,
- relocation works,
- **the mapped code cannot be entered.**

For an `amd64` (PE32+) image, all four work, and the project's premise holds
literally: the bytes execute on the console's own cores with no translation
layer in the instruction path.

## What the loader does about it

`pe_image_machine_is_native()` answers this question and nothing else. It is
true only for `IMAGE_FILE_MACHINE_AMD64`. The loader still parses, plans and
maps an `i386` image, because the structural work is identical and useful —
it is how the project will study real game binaries — but:

- the gate's telemetry records `native=0` for such a module, and
- `tools/validate_pe_map_evidence.py` **rejects** the run unless
  `--allow-i386` is passed, so accepting a parse-only result is always a
  deliberate, visible decision.

A second, related refusal lives in `pw_map_image()`. A PE32 image expresses
each relocation as a 32-bit addend, so it can only be rebased inside the low
4 GiB of the address space. When the memory backend hands back a higher base,
the mapper returns `PW_ERR_UNSUPPORTED` rather than writing truncated
pointers, which would fault later and far from their cause. Windows avoids
this by always mapping 32-bit images low; a future phase that needs to run
32-bit code would have to add an address-limited reservation to the backend
contract.

## The consequence for the project

Most classic PC games are 32-bit. `binkw32.dll`, the canonical vendor DLL
this loader was designed around, is 32-bit by its very name. Taking the
"no emulation" phrasing strictly would therefore exclude most of the intended
library. Three routes exist, and they are not equivalent:

| Route | What it costs | What it preserves |
| --- | --- | --- |
| Restrict scope to 64-bit Windows programs | A much smaller catalogue; no classic-era titles | "Zero emulation" holds literally, and every later phase stays simple |
| Static recompilation of 32-bit images to 64-bit code ahead of time | A recompiler, and per-title work; self-modifying or computed-flow code breaks | No interpreter at run time; the shipped code is native |
| An x86-32 to x86-64 translation layer at run time | This *is* emulation of the instruction path, and the project's premise changes | The whole 32-bit catalogue becomes reachable |

**This is an owner decision, not an implementation detail, and it is not
made here.** Gate 1 is deliberately useful under all three: parsing, layout,
relocation, protection and dependency resolution are needed whichever route
is chosen. The choice becomes unavoidable at gate 0.2, where something has to
actually be called.

Until then the honest statement of scope is: prospero-win maps any supported
PE image and executes only `amd64` ones.

## Executable memory, separately

Even for a 64-bit image, making mapped pages executable is not a plain
`mprotect`. The laboratory's measured position on this firmware is that a
read-write to read-execute transition is not a supported operation, and that
the working route is a double mapping of the same pages: one alias writable,
one executable.

The memory contract in `include/prospero_win_vm.h` is built around that from
the start. A region carries both a `write_base` and an `exec_base`, and the
mapper computes relocation deltas against `exec_base` — the address the code
will observe — while writing the patched bytes through `write_base`. Mixing
the two produces an image full of pointers into the wrong alias, which is
precisely the kind of defect that presents as an unexplained fault far from
its origin. The split exists so that mistake is hard to write.

Gate 1 does not need executable memory and does not request it. The aliased
backend is gate 0.2's work, with its own hardware smoke test, because an
exported platform symbol is not a working one until a run says it is.

## Page granularity

PE images are laid out on 4 KiB section boundaries. When the platform's
protection granularity is coarser, two sections with different protections
share one protectable page and the mapper must apply the union of their
protections; a `.text` and a `.data` page merging that way yields a page that
is writable and executable at once.

`pw_map_finalize_protections()` implements exactly that and counts it:
`merged`, `wx` and `no_access` page totals appear in the `PW_PROTECT` record.
The validator rejects any run with writable-executable pages unless
`--allow-wx` is passed. The weakening is real, so it is measured and
acknowledged rather than discovered later.
