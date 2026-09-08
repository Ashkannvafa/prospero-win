# Roadmap

One variable per hardware iteration; host gates green before the console is
touched; a phase closes only against a `ps5log/1` manifest its validator
accepts. Order inside a phase is the intended iteration order.

## Phase 0 — the image loader

- [x] **0.1 Read and understand a raw Windows executable — passed on
      FW 12.02.** Minimal PE parser, section mapping, base relocation, page
      protection and recursive third-party dependency resolution, proven on
      hardware: `sample.exe` and `binkw32.dll` mapped, rebased, relocated,
      verified and released, with `kernel32`/`msvcrt` recorded as host
      bindings and never read from disk. `PE_MAPPING_PHASE0.md`.
- [x] **0.2a The compatibility-mode probe — answered: refused.**
      `sysarch(I386_SET_LDT, ...)` returns `EINVAL` on FW 12.02, so a title
      cannot enter 32-bit mode and ABI thunking is unavailable. The same
      probe round-trips on an x86-64 host, so the result is the platform's,
      not the stub's. `COMPAT32_PHASE0A.md`.
- [ ] **0.2b Executable memory and the first call.** The aliased
      write/execute backend for this firmware, with its own smoke test,
      then calling one function in a mapped 64-bit image and returning
      from it.
- [ ] **0.3 Import binding.** Fill the address tables: local exports
      resolved through each module's export directory, host imports pointed
      at native implementations. Forwarders and ordinal-only exports
      included.
- [ ] **0.4 Module initialisation.** `DllMain` in dependency order, TLS
      directory, static initialisers, and a documented teardown order.

## Phase 1 — the Win32 core

- [ ] Process and error state: `GetLastError`, command line, environment,
      module handles, `GetProcAddress`/`GetModuleHandle` over the loader's
      own registry.
- [ ] Memory: `VirtualAlloc`/`VirtualFree`/`VirtualProtect` and a heap onto
      the measured anonymous-mapping budget, not the libc heap.
- [ ] Files: the `CreateFile`/`ReadFile` family over `sceKernel*`, with the
      case-insensitivity and directory-listing limits this firmware imposes.
- [ ] Time, synchronisation and threads: `QueryPerformanceCounter`,
      `CreateThread`, critical sections and events onto pthreads.
- [ ] `msvcrt` surface, preferring in-tree implementations for anything
      non-standard until a hardware smoke test accepts the platform's.

## Phase 2 — presentation and input

- [ ] A framebuffer path: GDI/DirectDraw blitting to VideoOut, reusing the
      laboratory's proven ownership model — fence, exact flip token, intact
      guards, clean teardown.
- [ ] Input: DirectInput and the Win32 message queue onto ScePad.
- [ ] Audio: DirectSound onto SceAudioOut.

## Phase 3 — one 64-bit program end to end

- [ ] A single 64-bit Windows program running from its own files. Chosen
      first because it needs no translation, so every other layer — loader,
      binding, Win32 surface, presentation — is validated against native
      execution before an instruction translator is added underneath.
- [ ] A soak long enough to expose leaks in the loader, the heap and the
      presentation path.
- [ ] A reproducible release with artifact hashes and a documented firmware
      boundary.

## Phase 4 — the 32-bit execution engine

Both 32-bit and 64-bit programs are in scope. 64-bit ones execute natively;
32-bit ones need an instruction translator, because compatibility mode is
refused on this firmware (gate 0.2a). This phase is deliberately last: it
plugs in underneath a stack that Phase 3 has already proven.

The platform constraints it has to work within are measured, not assumed
(see `EXECUTION_MODEL.md`):

- Guest pointers can live below 4 GiB, so **memory operands need no
  rewriting** — a 32-bit register used as an address is already correct,
  because writing a 32-bit register zeroes the upper half. This is the
  single largest saving on the route.
- A title gets **256 MiB contiguous** low, not the whole 4 GiB, so guest
  address space is mapped on demand.
- `mprotect` to `rwx` succeeds, so the **code cache can be writable and
  executable** without the `jitshm` double mapping.
- Pages are 16 KiB.

- [ ] **4.1 Same-ISA block translator.** Decode a basic block, pass through
      the instructions that are already valid in 64-bit mode — most of
      them — and rewrite only what must change: stack width
      (`push`/`pop`/`call`/`ret`/`enter`/`leave`/`pushf`, all 8 bytes in
      long mode against the guest's 4), the `0x40`–`0x4F` single-byte
      `inc`/`dec` that became REX prefixes, the opcodes long mode removed
      (`pusha`/`popa`, the BCD family, `into`, `bound`, `lds`/`les`/`lss`,
      far immediate transfers, `arpl`), and `fs:`-relative TEB access.
      Guest ESP lives in one of r8–r15, which 32-bit code cannot name.
- [ ] **4.2 Block cache and dispatch.** Indirect branches resolve through a
      translated-block map; direct branches chain. Invalidation on write for
      self-modifying code.
- [ ] **4.3 The 32-bit ABI boundary.** Note that choosing a translator does
      **not** remove the thunking work — it only removes the hardware mode
      switch. Translated code is 64-bit instructions, but the guest ABI is
      still 32-bit: `cdecl`/`stdcall` arguments on a 4-byte stack, 32-bit
      pointers, 32-bit `HANDLE`s. Every Win32 entry point still needs
      argument marshalling in both directions, including callbacks.
- [ ] **4.4 One 32-bit program end to end**, with a soak.

Prior art to mine rather than adopt: DynamoRIO's `x86_to_x64.c` and
`mangle.c` (BSD-3-Clause) for the mangling list, QEMU's i386 target
(GPL-2.0-only — see `LICENSING.md` on why this project's licence keeps that
usable) for instruction semantics. A lean decoder/encoder such as Zydis
(MIT) is the dependency to build on, not a whole emulator: box64 and FEX
spend their effort on an ARM backend this project does not need.

## Rules that carry through every phase

- Host gates green before the console is touched, one variable per run.
- A platform symbol that is merely exported is not a working one. Anything
  non-standard gets a boot-time smoke test that calls it on real input and
  reports through `ps5log/1`, before the code that depends on it.
- Every dynamic import of the linked ELF is reviewed after each link.
- Memory stays owned: every reservation released, every span closed, and a
  failed operation leaves nothing behind.
- A game or third-party binary is a private build input. It never enters the
  repository, an archive or a release artifact.
- Every hardware run is archived with its artifact hash and manifest,
  including the ones that fail.
- New work happens on a topic branch in a sibling worktree and lands through
  a pull request.

## Risks to watch

| Risk | Where it bites | Current position |
| --- | --- | --- |
| Whether 32-bit images can execute at all | Phase 4, and most of the intended catalogue | Not natively: compatibility mode is refused with `EINVAL`. **Scope decided — both 32-bit and 64-bit are supported**, so 32-bit goes through the Phase 4 translator. The memory prerequisites are measured and hold |
| Self-modifying and computed control flow | Phase 4.2 | Unaddressed, and the classic hard part of any translator. Write-invalidation of the block cache is the mitigation; some programs will still need per-title work |
| Coarse protection granularity versus 4 KiB PE sections | Every mapped image | **Measured: 16 KiB pages.** A 28 KiB image gets 2 protectable pages, merged protections and one writable-executable page. Counted per module and refused by the validator unless acknowledged |
| Signal delivery to a thread in 32-bit mode | The first long-running thunked code | Unmeasured, and the largest unknown even if 0.2a passes: FreeBSD builds 32-bit signal frames for i386 processes, not necessarily for a 32-bit thread in a 64-bit process |
| Thunk surface if the probe passes | Phase 1 | Every Win32 entry point would need a 32-bit stub and a marshalling thunk, plus a below-4-GiB reservation, far-transfer stubs both ways, and a signal-frame answer. Sized in `EXECUTION_MODEL.md` before committing |
| No read-write to read-execute transition | Gate 0.2 | The memory contract carries two aliases from the start and the mapper already relocates against the executing one |
| Coarse protection granularity versus 4 KiB PE sections | Gate 0.1 onwards | Union applied, merged and writable-executable pages counted, validator rejects them unless acknowledged |
| libc heap ceiling of roughly 8 MiB | Every phase | All large allocations go to anonymous mappings; the loader takes memory only from its injected backend |
| Case-insensitive names on a listable-only-by-index image | Gate 0.1 | Modules are staged lowercase and resolved by exact path; the host tool keeps a directory scan, the console provider does not |
| Import surface size of a real game | Phase 1 | `inspect_pe` reports the exact per-module named and ordinal counts for a private binary before any of it is implemented |
| Self-modifying or computed control flow | Gate 0.2 and beyond | Unaddressed. It is the main technical argument against the static-recompilation route |
