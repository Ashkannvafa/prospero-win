# Roadmap

One variable per hardware iteration; host gates green before the console is
touched; a phase closes only against a `ps5log/1` manifest its validator
accepts. Order inside a phase is the intended iteration order.

## Phase 0 — the image loader

- [x] **0.1 Read and understand a raw Windows executable.** Minimal PE
      parser, section mapping, base relocation, page protection, recursive
      third-party dependency resolution. Host-complete; the console gate is
      specified in `PE_MAPPING_PHASE0.md` and has not been run.
- [ ] **0.2a The compatibility-mode probe.** `sysarch(I386_SET_LDT, ...)`
      with a ring-3 32-bit code descriptor, then a far transfer into it and
      back. The smallest experiment in the project and the one that decides
      its architecture: if the kernel installs the descriptor and the round
      trip returns, 32-bit games run natively through ABI thunking with
      zero instruction emulation; if it refuses, the choice narrows to JIT
      recompilation or 64-bit-only scope. Runs before any scope decision.
      See `EXECUTION_MODEL.md`.
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

## Phase 3 — one program end to end

- [ ] A single classic program running from its own files.
- [ ] A soak long enough to expose leaks in the loader, the heap and the
      presentation path.
- [ ] A reproducible release with artifact hashes and a documented firmware
      boundary.

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
| Whether 32-bit images can execute at all | Gate 0.2a, and most of the intended catalogue | Open, and deliberately untested rather than assumed. The mechanism (`sysarch(I386_SET_LDT)`, declared by the pinned SDK) and the probe that settles it are in `EXECUTION_MODEL.md`. The loader refuses to pretend either way |
| Thunk surface if the probe passes | Phase 1 | Every Win32 entry point would need a 32-bit stub and a marshalling thunk, plus a below-4-GiB reservation, far-transfer stubs both ways, and a signal-frame answer. Sized in `EXECUTION_MODEL.md` before committing |
| No read-write to read-execute transition | Gate 0.2 | The memory contract carries two aliases from the start and the mapper already relocates against the executing one |
| Coarse protection granularity versus 4 KiB PE sections | Gate 0.1 onwards | Union applied, merged and writable-executable pages counted, validator rejects them unless acknowledged |
| libc heap ceiling of roughly 8 MiB | Every phase | All large allocations go to anonymous mappings; the loader takes memory only from its injected backend |
| Case-insensitive names on a listable-only-by-index image | Gate 0.1 | Modules are staged lowercase and resolved by exact path; the host tool keeps a directory scan, the console provider does not |
| Import surface size of a real game | Phase 1 | `inspect_pe` reports the exact per-module named and ordinal counts for a private binary before any of it is implemented |
| Self-modifying or computed control flow | Gate 0.2 and beyond | Unaddressed. It is the main technical argument against the static-recompilation route |
