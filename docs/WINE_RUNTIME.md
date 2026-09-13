# Reproducible i386 Wine PE runtime

Wine PE modules are build inputs, not sources of this repository. This
document defines how they are produced, how their identity is recorded and
what a second developer has to reproduce to obtain the same bytes.

The pinned reference is:

```text
Wine 490f6d5dcbb2a5047345b8af88d114bbcaad69a8  (Wine version 11.17)
```

## What is staged

`tools/build_wine_runtime.sh` builds the selected i386 PE modules and stages
them, with a manifest, into an ignored directory:

```text
.deps/wine-runtime/
    lib/i386-windows/ntdll.dll
    lib/i386-windows/kernelbase.dll
    lib/i386-windows/kernel32.dll
    wine-runtime-manifest.json
```

`ntdll`, `kernelbase` and `kernel32` are the first boot attempt's module set:
`kernel32` forwards into `kernelbase`, `kernelbase` forwards into `ntdll`, and
`ntdll` owns the versioned Unix-call boundary named in
[WINE_INTEGRATION.md](WINE_INTEGRATION.md). Nothing else is selected yet, so
the staged runtime is deliberately not a complete Win32 surface.

The modules are PE32/i386 images. The Unix-side modules (`*.so`) are *not*
staged: they are not loadable objects on this target, and the whole point of
the DBT is that guest PE code runs natively translated instead.

## Reproducing the build

```sh
# A clean checkout of the pinned revision is required. The script clones one
# when PROSPERO_WINE_SOURCE does not exist.
export PROSPERO_WINE_SOURCE=/private/wine-11.17
export PROSPERO_WINE_ROOT=/private/wine-build
tools/build_wine_runtime.sh --check-reproducible
```

Requirements the script enforces rather than assumes:

- the checkout is clean and its `HEAD` is exactly the pinned commit;
- the build is out-of-tree, in `PROSPERO_WINE_ROOT/build`;
- the environment is normalised: `LC_ALL=C`, `TZ=UTC`,
  `SOURCE_DATE_EPOCH=1000000000`;
- the configure line is fixed:
  `--enable-archs=i386,x86_64 --disable-tests`.

`--check-reproducible` performs two clean builds and compares every staged
module byte for byte before writing the manifest. On this host the PE linker
is GNU `ld` (binutils) through `i686-w64-mingw32-gcc`; it honours
`SOURCE_DATE_EPOCH` for the PE timestamp, which is the only non-deterministic
field otherwise present. The observed difference between two builds without
that variable is exactly the file-header `TimeDateStamp` and the derived
optional-header `Checksum`; with it, two clean rebuilds are byte-identical.
No field is zeroed, masked or excluded from the digest.

Tool versions that can change the bytes are recorded in the manifest, because
an identical source revision plus a different linker is a different runtime.

## Manifest contract

`tools/validate_wine_runtime.py write` hashes the staged modules and writes
the manifest; `check` validates a manifest against a staged tree.

The manifest records, per module, the canonical lowercase name, the relative
path inside the distribution, the byte size, the SHA-256 and the PE machine
and magic; plus the Wine commit, the configure line, the normalised
environment, the tool versions and the aggregate digest. The JSON schema is
[WINE_RUNTIME_MANIFEST.schema.json](WINE_RUNTIME_MANIFEST.schema.json).

The aggregate digest is reproducible from the manifest alone:

```text
sha256( concat( sorted_by_name( "name<TAB>size<TAB>sha256\n" ) ) )
```

`check` fails closed on: an unknown schema, an unknown architecture, a second
entry for the same canonical name, a name that is not a lowercase `.dll`, an
absolute or `..`-traversing path, a missing file, a size drift, a hash drift,
a module whose PE machine is not i386, a module that is not PE32, a path that
is not inside the declared library, and an aggregate digest that disagrees
with the module list it is supposed to summarise. Every one of those cases is
exercised by `tests/test_wine_runtime_manifest.py`.

## Publication rules

- Generated PE modules and the build tree stay in ignored directories
  (`.deps/`, `build/`). `tools/audit_publication.py` refuses a Windows binary
  anywhere in the tree, so a staged runtime can never be committed by
  accident.
- No Wine source is vendored. The manifest and this document are the whole
  public footprint of the runtime, and Wine remains LGPL-2.1-or-later with its
  own authorship and notices.
- The runtime directory is configured explicitly on both the host and the PS5
  provider. There is no fallback that would silently load an application-local
  `ntdll.dll`.

## Bounded ntdll entry gate

`tools/wine_ntdll_entry.c` is the integration milestone: it loads the staged
runtime, binds the real module graph, enters one exported ntdll function
through the IA-32 DBT and stops at Wine's versioned Unix-call boundary.

```sh
make build/host/wine_ntdll_entry
build/host/wine_ntdll_entry --runtime .deps/wine-runtime/lib/i386-windows \
    > /private/wine-ntdll-entry.txt
python3 tools/validate_wine_ntdll_evidence.py /private/wine-ntdll-entry.txt \
    --manifest .deps/wine-runtime/wine-runtime-manifest.json \
    --expect-entry NtClose
```

What the gate proves, and what it does not:

- it maps `ntdll.dll` and `kernelbase.dll` from `PW_FILE_RUNTIME`, and binds
  the 428 imports `kernelbase` declares against `ntdll`'s exports with the
  same resolver every other caller uses;
- it identifies the boundary structurally. Wine's i386 PE syscall stubs end in
  `call <__wine_syscall>`, and `__wine_syscall` is the single
  `jmp dword ptr [__wine_syscall_dispatcher]` thunk that references the
  exported dispatcher slot. The gate locates the slot through the export
  directory and the thunk by scanning the mapped `.text`, so the stop address
  is one the manifest-hashed image really contains;
- it enters the exported `NtClose` stub, retires its real instructions and
  stops *before* the dispatcher jump, reporting the syscall number the stub
  encoded (0x0f) and the number observed in EAX;
- it never calls a host Wine function, and it refuses to accept a stop that is
  not the Unix-call boundary.

It does not implement the Unix call, does not create a PEB/TEB, does not run
ntdll's process initialization and is not wired into title startup. A
classified stop is evidence, not a compatibility claim.

### How far real ntdll execution currently gets

Two entry points are measured, each with the engine's chaining, register
residency and lazy-flag modes toggled (four configurations, identical stop
kind, retired count and stop address):

| Entry | Result |
|---|---|
| `NtClose` | stops on the dispatcher thunk after 3 retired instructions, syscall `0x000f` |
| `LdrInitializeThunk` | retires 266 instructions over 35 dispatches and reaches ntdll's **first Unix call**: syscall `0x0018` (`NtAllocateVirtualMemory`), again stopping before the dispatcher jump |

Reaching that point required four general instruction families and a minimal
guest thread block, all of which are now implemented and host-tested:

- **FS-prefixed absolute operands** (`mov r32, fs:[disp32]` and
  `mov fs:[disp32], r32`). Wine's ntdll reads `fs:[0x18]` (the TEB self
  pointer) on its first initialization instructions. The segment base is the
  guest's own FS base from `PwX86State`, never the host's, and the offset is
  bounded by the declared FS block before any dereference. GS and FS operands
  with a base or index stay refused.
- **LOCK-prefixed read-modify-write** for the group-1 memory forms
  (`lock add [mem], 1`, which Wine's critical sections use). The emitted host
  instruction carries the same prefix, so the host provides the atomicity; a
  register destination or a pure compare is not a legal LOCK form and stays
  refused.
- A **minimal guest TEB and PEB** owned by the gate: the TEB is what FS points
  at, with the documented NT offsets for `StackBase` (0x04), `StackLimit`
  (0x08), `Self` (0x18) and `ProcessEnvironmentBlock` (0x30), and the PEB is
  handed to ntdll's initialization entry as its first argument.
  `ThreadLocalStoragePointer` (0x2C) stays zero because no module of this
  distribution declares a TLS directory.
- **BT/BTS/BTR/BTC**, both the register-index encodings (`0f a3/ab/b3/bb`) and
  the immediate form (`0f ba /4../7`), for register and memory destinations
  and for the 16-bit forms. The host instruction is re-emitted on guest
  values, so bit-string addressing of a memory operand and the 4/5-bit index
  masking of a register operand come from the CPU. Only CF is written; the
  flags the ISA leaves undefined stay unchanged, which is deterministic
  rather than arbitrary. A register-destination BTS/BTR/BTC reads, modifies
  and writes back; a memory one needs write permission, while a memory BT
  only reads.
- **CMOVcc** (`0f 40..4f`, 32-bit forms) with the condition materialised from
  guest flags and the move skipped when it does not hold, so flags are never
  written and the destination keeps its value otherwise.

Every family has native i386 differential coverage: `make test` runs a
32-bit reference program that installs a real FS base with `set_thread_area`
and executes the same `mov edi, fs:[0x18]`, `lock addl $1, mem`,
`btsl %ecx, %eax` and `cmovel %esi, %edx` instructions on the host CPU, and
the translated engine's output must match it byte for byte. Each family is
also executed through residency and lazy-flag modes in the unit suite.

The syscall number itself is verified twice: from the entry stub when the
entry is a stub, and always from the **issuing stub inside the mapped image**
— the return address on the guest stack points into the stub that called the
dispatcher, and the `mov eax, id` immediately before its
`mov edx, <dispatcher thunk>` must name the number observed in EAX. A number
that cannot be re-read from the image is rejected by the evidence validator.

Mode parity is asserted on this real code: all eight combinations of
chaining, register residency and lazy flags retire 266 instructions and stop
on the same thunk with the same syscall. That check earned its place — it
exposed a real defect in the first CMOV emission, where the skip branch
covered three bytes and jumped into the middle of a two-byte `mov` whenever
the condition did not hold; register residency changed the following bytes
enough to turn the fault into a silent no-op, so only the mode matrix found
it. `tests/test_pw_x86_block.c` now runs the new families through all four
residency/lazy combinations, and the gate runs the real ntdll initialization
through all eight.

The next unimplemented behaviours on that path are the rest of Wine's loader
initialization — which needs a real `PEB_LDR_DATA` and process parameters
rather than the gate's zeroed page — and the Unix call itself. Neither is
claimed as working.

### Servicing the first Unix calls

`--bridge 1` turns the gate's boundary from a stopping point into a bridge:
the call is identified, its arguments are read out of validated guest memory,
a handler services it, and the guest continues exactly where the stub's own
`ret imm16` would have left it.

The call number is a position in a table that belongs to one Wine revision,
so `src/pw_unix_call.c` carries the first 64 entries of the pinned i386 table
with their exported names and stdcall argument widths, and
`tests/test_unix_call_table.py` re-derives that table from
`dlls/ntdll/ntsyscalls.h` at the revision named in the source and fails on any
difference. Numbers outside the table are reported as unknown, never guessed.

The frame has two levels, because a Wine stub reaches the dispatcher with a
call rather than a jump:

```text
[esp]      return address into the issuing stub   (provenance, and where the
                                                   syscall number is re-read)
[esp+4]    the caller's return address            (where the guest resumes)
[esp+8..]  the stdcall arguments
```

Servicing a call therefore means: `EAX = NTSTATUS`, `EIP = [esp+4]` and
`ESP += 8 + arg_bytes` — the state the stub's own `ret imm16` would have
produced.

The first handler is `NtAllocateVirtualMemory` for the profile a boot attempt
reaches: the current process handle, `ZeroBits == 0`, `MEM_RESERVE`,
`MEM_COMMIT` or both, `PAGE_READWRITE` (or the reserve-only value), a bounded
total per run, and guest pointers that must pass the dispatcher's own region
check before anything is read or written. Value errors are answered with an
NTSTATUS, because that is the guest's contract; a guest pointer the bridge
cannot safely touch is a refusal that names the argument index instead. Every
block it maps joins the dispatcher's declared regions, so the guest can
immediately use what it was given, and every block is released at cleanup.

A `MEM_COMMIT` that lands inside a block this run already mapped is treated as
the second half of "reserve then commit" rather than a new reservation, which
is what Wine's loader does.

Measured on the pinned runtime:

```text
LdrInitializeThunk, --bridge 1
  retires 315 instructions over 44 dispatches
  services  2 NtAllocateVirtualMemory calls, both STATUS_SUCCESS
  maps      1 guest region of 65536 bytes, addressable to the guest
  stops at  ntdll RVA 0x1cdd5 on "movd xmm0, eax" (SSE), the next family
            the translator does not cover
```

Honest limits: the reserve/commit distinction is not modelled (the dispatcher
knows one kind of guest region), `NtFreeVirtualMemory` and every other call
still has no handler, and a handler failing midway is not rolled back. None
of that is claimed as working.

### What ntdll initialization reaches now

Servicing the first calls pushed real ntdll code into the DBT that nothing had
executed before, and each stop then named the next missing family. Current
state of that path with `--bridge 1`:

```text
retired 8582 instructions over 1440 dispatches and 253 translated blocks
3 NtAllocateVirtualMemory calls serviced, 2 guest regions mapped (88 KiB)
stops at ntdll RVA 0x28ef7 with a classified memory bound: the guest read
2 bytes at 0x7ca, i.e. CurrentDirectory.Buffer was null
```

The families added for that path, each with architectural tests:

- **SSE data movement and lane shuffles**: `movd` both directions, `movdqa`/
  `movdqu` (`66`/`F3 0F 6F`/`7F`), `movups`/`movaps` (`0F 10/11/28/29`),
  `movq` store and load (`66 0F D6`, `F3 0F 7E`), `movss`/`movsd` memory
  forms, the `punpck`/`packss` lane family (`60`-`6D`), `pand`/`paddq`/
  `psubq`/`por`/`pxor`, `pshufd`/`pshufhw`/`pshuflw` (`66`/`F3`/`F2 0F 70`),
  `pextrw` and `pinsrw`. The i386 XMM register file lives in
  `PwGuestFp.xmm`, host XMM registers are scratch, and the host executes the
  same operation, so upper-bit zeroing (`movd`, `movss`, `movsd`, `movq`),
  lane order and the 16-byte granularity come from the CPU. MMX encodings of
  the same opcodes, the merging scalar register forms and anything outside
  the list stay refused.
- **BSF/BSR** (`0F BC/BD`, 32- and 16-bit, register and memory sources): the
  index comes from the host instruction, a zero source leaves the destination
  unchanged deterministically (the ISA leaves it undefined) while ZF still
  reports the zero, and only ZF is written.
- **The 16-bit shift group** (`66 D1`/`D3`/`C1` with the `shl`/`shr`/`sar`
  registers): the destination's upper 16 bits are untouched, the count is
  masked to four bits rather than five - which also changes which counts
  preserve the flags - and the flag policy matches the 32-bit path
  (`count == 0` preserves everything, `count == 1` sets OF, wider counts keep
  the deterministic subset).
- The memory guard accepts 16-byte accesses now, which is the width of the SSE
  loads and stores, and records the address, width and direction of a refused
  access, so a `memory-bounds` stop names the fault instead of only its kind.
- A REP prefix (`F3`) that does not introduce a string instruction falls
  through to the SSE slice instead of being refused as a malformed `REP`.

Two further gaps surfaced by the same path were closed in the gate: ntdll
reads `PEB->ProcessParameters` (PEB+0x10) during heap and loader
initialization, so the gate owns a zeroed process-parameters page and links
it, and the FS-segment work from the previous step is what makes the TEB
reads valid. The gate's PEB is still a zeroed page with two fields filled: it
is not a Windows process environment.

Testing note: the SSE slice is verified by explicit architectural
expectations (upper-bit zeroing, lane order, 16-byte guard behaviour, and the
same instructions through all four residency/lazy-flag combinations) rather
than by the native oracle, because the emitted host instruction *is* the
instruction the oracle would execute.

### Where the run now stops, and why that is not an opcode

The last stop is not another instruction family. `_RtlGetCurrentDirectory_U`
reads `PEB->ProcessParameters->CurrentDirectory` and dereferences `Buffer`;
the gate's process-parameters page is zeroed, so `Buffer` is null and the
dispatcher classifies the read as `memory-bounds` at address `0x7ca` with
width 2. In other words: real ntdll initialization now runs until it needs a
**populated process environment** - the system root, the current directory,
the environment block, the command line - which is the
`wine-process-startup` exit criterion in the foundation ledger, not a gap in
instruction coverage.

The evidence contract reflects that honestly. A `memory-bounds` stop is
accepted by the validator only when the calls record is present, every call
was handled, the `fault` record names a non-zero access of an allowed width,
the fault address lies outside every mapped module (so it is the guest
dereferencing something it was never given, not the guard refusing mapped
memory) and the stop address is inside ntdll. Nothing about it is reported as
acceptance: the verdict still says the run did not reach the Unix-call
boundary.

### A populated process environment, and the first I/O call

The null `CurrentDirectory.Buffer` was the binding constraint, so the gate now
builds a small but self-consistent `RTL_USER_PROCESS_PARAMETERS` in its page:
`MaximumLength`/`Length`, `CurrentDirectory.DosPath`, `DllPath`,
`ImagePathName`, `CommandLine` and an `Environment` block, all as UTF-16LE
strings (`C:\windows`, `C:\windows\system32`, the root module's path and
`SystemRoot=C:\windows`). `PEB->ProcessParameters` points at the page and
`PEB->ImageBaseAddress` at the root module. It is still not a Windows process
environment - no registry, no NLS data, no drive-letter table - but the fields
the loader asks for are present and self-consistent.

That closed the architectural gap: the run jumped from 8582 to 11 707 retired
instructions, and three more forms the compiler emits as padding or prefixing
were needed along the way:

- `66 90` (the 16-bit NOP) and `0F 1F /0` (the multi-byte NOP), which compilers
  emit for alignment;
- a **segment override on LEA** (`2E 8D B4 26 ...`), which is exact to ignore
  because LEA never accesses memory.

The gate's translated-code arena was also raised to 4 MiB: ntdll's loader path
translates far more code than a title's startup, and running out of the arena
now has its own classified stop (`cache-limit`) instead of surfacing as a
guest fault. The evidence validator accepts that stop under the same rule as
the others: the calls record must be present and nothing may have been
refused.

The result is the first **Unix call that has no handler**:

```text
retired 11707 instructions over 2252 dispatches and 404 translated blocks
3 NtAllocateVirtualMemory calls serviced, 2 guest regions mapped (88 KiB)
4th call: syscall 0x0033 = NtOpenFile, 24 argument bytes -> unimplemented
stop: unix-call-unimplemented, verdict not accepted
```

So the next work is concrete and architectural rather than an instruction
family: implement the file/open path (`NtOpenFile` and the calls that follow
it) behind the same table, with guest-pointer validation and a documented
mapping onto the gate's read-only runtime directory.

### The first platform service: files

`NtOpenFile` was the first Unix call with no handler, so the bridge now has a
file service below it. The gate owns a bounded handle table and translates the
guest path; the runner owns the host side through a small interface
(`PwWineFileService`: open, read, close), so the portable core still contains
no file-system call.

Handlers and their shape:

```text
NtOpenFile              (0x0033) OBJECT_ATTRIBUTES + UNICODE_STRING name,
                                 handle and IO_STATUS_BLOCK written back
NtReadFile              (0x0006) handle, IO status, buffer, length, offset
NtQueryInformationFile  (0x0011) FileStandardInformation only (sizes)
NtClose                 (0x000f) releases a gate-owned handle
```

Rules the gate enforces before the platform is ever asked:

- only `C:\windows\system32\<name>` and `C:\windows\<name>` are accepted,
  with an optional `\??\` prefix;
- the remainder must be a single path component, lower-cased, so `..`, a
  separator, a drive letter or an absolute host path cannot reach the service;
- every guest pointer (the OBJECT_ATTRIBUTES, the UNICODE_STRING, its buffer,
  the handle slot, the IO status block, the read buffer) is read or written
  through the dispatcher's validated accessor;
- reads are bounded per call, handles are gate-owned indices (`0x100 + slot`),
  and any handle the gate does not own answers `STATUS_INVALID_HANDLE`.

Everything else is answered with a real NTSTATUS - a name outside the runtime
namespace gives `STATUS_OBJECT_NAME_NOT_FOUND`, a value error gives
`STATUS_INVALID_PARAMETER`, an unsupported information class gives
`STATUS_INVALID_INFO_CLASS` - because that is the contract the guest expects.
Handles are released at cleanup, and the counters (`opens`, `reads`, `bytes`,
`closes`, `refusals`, `last`) are part of the evidence.

`tests/test_pw_wine_file_service.c` proves the whole path without a real file:
a synthetic module builds a UNICODE_STRING and an OBJECT_ATTRIBUTES for
`C:\windows\system32\test.dll` in its own data section (with the base
relocations a real image has), calls NtOpenFile, reads the file into a guest
buffer, closes the handle and then attempts
`C:\windows\system32\..\..\etc`. The first three calls succeed, the guest
observes the handle and the IO status blocks, and the escaping path is refused
*by the gate* - the platform service is never asked to open it.

On the real runtime the loader's first open is the Windows **directory**
itself:

```text
4th call: NtOpenFile "\??\C:\windows" -> STATUS_OBJECT_NAME_NOT_FOUND
retired 14918 instructions, 3041 dispatches, 580 translated blocks
stop: returned-to-caller at EIP 0 (the loader's failure path jumps to null)
```

So the next step is a directory object: accepting that open and answering
`FileStandardInformation` with `Directory = 1` is what should let the loader
continue past this point.
