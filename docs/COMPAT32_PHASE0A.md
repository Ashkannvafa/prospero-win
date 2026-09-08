# Gate 0.2a — can a title enter 32-bit compatibility mode?

**Objective.** Measure, rather than assume, whether a PS5 title can execute
32-bit x86 code on the console's own cores. The answer decides whether
classic 32-bit programs run through WoW64-style ABI thunking — their own
opcodes on the silicon, zero instruction emulation — or whether reaching
them needs JIT recompilation instead.

**Status: answered on FW 12.02 on 2026-09-08. Compatibility mode is
unavailable, and the reason is now understood rather than merely observed.**

The first answer to this gate was reached from a **malformed call** and its
evidence was worthless on its own. The probe asked
`sysarch(I386_SET_LDT, ...)` for two descriptors in one call with
`LDT_AUTO_ALLOC`. FreeBSD's amd64 `amd64_set_ldt` honours that sentinel only
for a single descriptor; with `num=2` it takes the range-check path instead,
where a `start` of `0xffffffff` is refused as `EINVAL` whatever the kernel's
policy happens to be. `EINVAL` means *invalid argument*, and the argument
really was invalid.

Re-measured properly, with every argument shape tried and a control, from an
`elfldr` payload that runs with more privilege than a title:

```text
AMD64_GET_FSBASE (control)          rc=0   errno=0   fsbase=0x8ff800080
machdep.max_ldt_segment             rc=-1  errno=2 (ENOENT)  value absent
I386_GET_LDT      start=0 num=1     rc=-1  errno=22 (EINVAL)
I386_SET_LDT auto        num=1      rc=-1  errno=22   <- the correct call
I386_SET_LDT auto        num=2      rc=-1  errno=22   <- the malformed one
I386_SET_LDT      start=0 num=1     rc=-1  errno=22
I386_SET_LDT      start=1 num=1     rc=-1  errno=22
I386_GET_LDT      start=0 num=4     rc=-1  errno=22
```

Four things follow, and together they are conclusive where the first
attempt was not:

1. **`sysarch` works.** The control operation returns a real FS base, so
   the syscall is present, reachable and dispatching. This is not a missing
   or stubbed syscall.
2. **The correct call fails identically.** Single-descriptor auto-allocation
   — the shape FreeBSD documents — is refused exactly like the malformed
   one, so the original `num=2` defect was real but not the cause.
3. **Reads fail too.** `I386_GET_LDT` is a pure read and also returns
   `EINVAL`. A uniform refusal across reads, writes, explicit indices and
   auto-allocation is the signature of a zero-sized descriptor table: every
   index is out of range, so every start value fails the same check.
4. **`machdep.max_ldt_segment` does not exist.** On stock FreeBSD amd64 that
   sysctl is declared in the same file as the LDT implementation, so its
   absence points at the support being compiled out rather than merely
   configured to zero. There is no knob here to turn on.

And the whole matrix was run from `elfldr`, which is more privileged than a
title, so this is **not a sandbox restriction on titles** — it is kernel
wide. The title reproduces it exactly, in run
`20260908T113831241Z_PPSA99995_prospero-win_0xf7861c1d7e16`, which records
each attempt as its own `PW_LDT_TRY` record with the control passing and
every LDT operation refused. Both halves of that run are in the evidence
trail: the matrix, and the pe-map gate passing alongside it.

The only route left in principle is installing a descriptor from kernel
context with the laboratory's kernel read/write primitives. That is a kernel
patch, not something a homebrew compatibility layer can rely on, and it is
out of scope for this project; it is recorded here so nobody has to
re-derive that it was considered.

So ABI thunking is unavailable, and reaching the 32-bit catalogue means JIT
recompilation or a 64-bit-only scope. That is an owner decision, and it is
now backed by a measurement that survives scrutiny.

The probe still completes a full round trip on an ordinary x86-64 Linux host
inside `make test`, which is what makes the console refusal attributable to
the platform rather than to the stub. Recorded for the record: the console's
user selectors are `cs=0x43` and `ds=0x3b`.

## Why this is a measurement and not a lookup

Reaching compatibility mode needs a code descriptor with `L` clear and
`D/B` set, entered by a far transfer. User code cannot write a descriptor
table, but it can ask the kernel to install one: on FreeBSD amd64 that is
`sysarch(I386_SET_LDT, ...)`, implemented by `amd64_set_ldt`, which exists
precisely to support 32-bit compatibility and consumers like Wine. The
pinned payload SDK declares it (`x86/sysarch.h`, `SYS_sysarch` 165), along
with `I386_SET_FSBASE` for 32-bit TLS.

A declaration is not a capability. That SDK is a FreeBSD-derived header set,
so it describes FreeBSD rather than what Sony's kernel permits a sandboxed
title to do — the porting playbook's first principle, applied to evidence
even weaker than an export. Prospero may have dropped LDT support, or
filtered `sysarch` to the `fsbase`/`gsbase` operations an ordinary title
needs.

## Reading an errno is not the same as answering the question

`EINVAL` is the weakest possible evidence of a platform limit, because it is
also what a wrong argument produces. The first pass through this gate made
exactly that mistake and published a conclusion from it. What turned the
observation into an answer was three additions, none of them expensive: a
**control** operation known to work, so a failure can be attributed to the
specific operation rather than to the syscall; the **full argument matrix**,
so a uniform refusal can be told apart from one malformed shape; and a
**privilege comparison**, so a sandbox restriction can be told apart from a
kernel-wide one. Any future probe of a refused platform call should carry
all three before its result is written down.

## Two stages, so a crash still tells you something

| Stage | What it does | Can it fault? |
| --- | --- | --- |
| One | Installs both descriptors, reserves the pages, writes the stub, seals it executable, reports everything | No |
| Two | Performs the far transfer into 32-bit code and back | Yes |

Stage one is the default (`PW_COMPAT32_TRANSFER=0`) and its record is
emitted before stage two is attempted. A run that installs the descriptor
and then dies still tells the operator which half failed, which is the whole
reason for the split.

## How the round trip works

Two pages, both in the low 2 GiB because 32-bit code addresses them with
32-bit operands and the far pointer back carries a 32-bit offset. They are
separate on purpose: the stub writes while it runs, and a page that is
writable and executable at once is exactly what this firmware makes hard to
get. The code page is written, then sealed read-execute, then run.

```text
64-bit launcher (code page)
    save rsp and rbp into the data page
    point rsp at a 32-bit stack inside the data page
    ljmp *[far_in]                    -> enters compatibility mode
32-bit entry (code page)
    load ds with the installed 32-bit data selector
    record cs as seen from inside 32-bit mode
    mov eax, 0 ; 0x40 0x40 0x40 ; store eax
    jmp far [far_back]                -> returns to 64-bit mode
64-bit landing (code page)
    restore ds, rsp and rbp
    jmp [saved_ret]                   -> back into ordinary C
```

The proof is those three `0x40` bytes. In 32-bit mode each is `inc eax`, so
`eax` becomes 3; in 64-bit mode they are REX prefixes and it stays 0. A
result of 3 cannot be produced by a CPU that did not decode the stub as
32-bit code. The observed `cs` must also equal the selector that was
installed, so arriving by some other route cannot pass either. Both slots
are seeded with `0xffffffff` beforehand, so an unwritten slot cannot read as
a success.

## What the host run already established

Running the same builder and the same transfer on an x86-64 Linux host, with
only descriptor installation and page reservation swapped:

- the descriptors install, and reading them back shows the kernel's own
  encoding matches `pw_segment_encode()` bit for bit apart from the AVL bit
  the host sets from `useable` — an independent check that the descriptor
  words this project hands to a kernel are right;
- the canonical values `0x00cffb000000ffff` (code) and
  `0x00cff3000000ffff` (data) are what every x86-64 kernel uses for its own
  32-bit ring-3 segments, and are asserted directly;
- the transfer enters compatibility mode under the installed selector,
  produces the value 3, and returns;
- the stub runs correctly from a page that is **not** writable.

And one finding that changed the design: **the 64-bit stack pointer does not
survive the round trip.** Compatibility mode leaves only `ESP` meaningful,
so `RSP` comes back with its upper half zeroed and the next `call` writes to
a truncated address. The launcher therefore saves `RSP`/`RBP` and the
landing restores them. A real thunk has to do this at every crossing, in
both directions — it is not a probe artefact.

## Running it

```sh
# Stage one only: cannot fault.
make native PS5LOG_DEV_CONF=/private/path/dev.conf

# Stage two: attempts the transfer.
PW_COMPAT32_TRANSFER=1 make native PS5LOG_DEV_CONF=/private/path/dev.conf
```

The probe rides along in the same title as the pe-map gate and runs after
telemetry and the filesystem are known good, so a failure cannot be confused
with a transport problem.

## Reading the result

The `PW_COMPAT32` record carries every step's status separately:
`install`, `install_errno`, `ldt_index`, the selectors, `reserve`,
`code_base`, `data_base`, `build`, `seal`, `seal_errno`, `transfer`,
`attempted`, `returned`, `result`, `cs_seen`, `expected` and `proven`.
`PW_COMPAT32_PLATFORM` adds how many candidate low addresses were tried and
which one was taken.

`tools/validate_pe_map_evidence.py` checks the record cannot claim more than
it demonstrated — no proof without an attempt, without a return, with the
wrong result, under a selector other than the installed one, or alongside a
failed step — and `--expect-compat32 proven|refused` lets the operator
assert the outcome explicitly. The validator deliberately does not prefer
either answer.

## The four outcomes and what each one means

| Observation | Meaning | Next step |
| --- | --- | --- |
| `install` failed | **This is what happened**, uniformly and at elevated privilege, with a working control alongside it. ABI thunking is out on this firmware | Scope narrows to 64-bit-only or JIT recompilation |
| `install=ok`, `seal` failed | Descriptors work; a read-write to read-execute transition does not | Gate 0.2b first: the `jitshm` double mapping, then retry |
| `install=ok`, transfer attempted, no return | The descriptor was accepted but the transfer or its fault path is broken | Ghidra on the kernel's LDT and trap paths — the inspection layer the playbook reserves for an ambiguous platform result |
| `proven=1` | 32-bit code executes natively on the console | Phase 1 gains a second dimension: a 32-bit stub and a marshalling thunk per Win32 entry point. Size it against `EXECUTION_MODEL.md` |

## Still unmeasured even if it passes

Compatibility mode is necessary, not sufficient. Signal and exception
delivery while a thread is in 32-bit mode is the largest remaining unknown:
FreeBSD builds 32-bit signal frames for i386 *processes*, and whether it
does so for a 32-bit thread inside a 64-bit process is doubtful. A fault
delivered with the wrong frame shape is unrecoverable, so the first
long-running thunked code needs its own gate for that. Also unmeasured: how
much of the low 2 GiB a title may actually claim, which bounds how many
32-bit images can be mapped at once.
