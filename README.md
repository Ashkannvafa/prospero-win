# prospero-win

**prospero-win is a zero-emulation Win32 compatibility layer for the
PlayStation 5.** Classic PC programs are not interpreted or recompiled: their
machine code is manually mapped into the console's own address space and runs
directly on its Zen 2 cores, while the Windows API surface those programs call
is reimplemented natively on top of the platform.

The project grows in hardware-proven phases, the same way the laboratory's
renderer work does. This repository currently contains **Phase 0, gate 1**:
making the console read and understand a raw Windows executable.

## Where the port stands

| Phase | State | What it establishes |
| --- | --- | --- |
| 0.1 — Image loader | **Passed on FW 12.02** | Minimal PE reader, section mapping, base relocation, page protection and recursive third-party DLL resolution, proven on hardware |
| 0.2a — Compatibility mode | **Answered: refused** | A title cannot install an LDT descriptor (`EINVAL`), so 32-bit code cannot run natively here |
| 0.2b — Executable memory | Next | Read-execute publication through the console's double-mapping path, and the first call into mapped 64-bit code |
| 1 — Win32 core | Later | `kernel32`/`msvcrt` process, memory, file, time and threading surface; import binding; TLS; `DllMain` ordering |
| 2 — Presentation and input | Later | DirectDraw/GDI blitting to VideoOut, DirectInput/DirectSound onto ScePad and SceAudioOut |
| 3 — First program end to end | Later | One classic title running from its own files, with a soak and a reproducible release |

Phase 0.1 is proven on one PS5 on firmware 12.02, against an accepted
`ps5log/1` manifest; nothing beyond it is claimed. Gate 0.2a is answered in
the negative, which settles the project's scope question rather than
advancing it. Details, evidence and the two defects the hardware runs
exposed are in [`docs/PE_MAPPING_PHASE0.md`](docs/PE_MAPPING_PHASE0.md) and
[`docs/COMPAT32_PHASE0A.md`](docs/COMPAT32_PHASE0A.md).

## What gate 1 does

Given a Windows image and a directory of its dependencies, the loader:

1. parses the DOS and NT headers, the data directories and the section table
   out of a read-only byte span, bounds-checking every field before use;
2. plans the mapped layout: the reservation size, each section's copy and
   zero-fill spans, and the page protection derived from its characteristics;
3. reserves one contiguous span per image, copies the headers and sections,
   zeroes the uninitialised remainder and applies base relocations;
4. installs final page protections, reporting where the console's mapping
   granularity forced two sections to share one protectable page;
5. verifies the mapping byte by byte against the file and reports a checksum;
6. walks the import table and repeats all of the above for every third-party
   dependency it can resolve locally — `game.exe` → `binkw32.dll` →
   `msvcrt.dll` — tolerating import cycles and refusing, by name, anything it
   cannot find.

Windows modules such as `kernel32.dll` are never loaded from disk. They are
recorded as **host bindings**: interfaces prospero-win implements itself.
That split is the whole design, and `binkw32.dll` is its canonical example of
the other side — real vendor code that must actually be mapped.

## Build and test

```sh
make test        # every host contract, plus the two Python suites
make audit       # fail-closed publication audit
```

Inspect a Windows binary you own. It is read from a private path and nothing
is copied into the repository:

```sh
make inspect PE_INPUT=/private/path/game.exe PE_DIR=/private/path
```

Build the console gate. `PW_SAMPLE=1` stages synthetic images, so a hardware
run needs no proprietary input at all:

```sh
make native PS5LOG_DEV_CONF=/private/path/dev.conf
make native-release PW_STAGE_INPUT=/private/path/game \
  PW_ROOT_MODULE=game.exe PS5LOG_DEV_CONF=/private/path/dev.conf
```

## Scope and honesty

- **Zero emulation holds literally for 64-bit programs today.** For 32-bit
  ones it is an open question with a known answer shape: Zen 2 executes
  32-bit code natively in compatibility mode, so the target architecture is
  WoW64-style ABI thunking — the game's own opcodes on the silicon, with
  translation only at API boundaries and no interpretation anywhere.
  That route is now measured and **closed on this firmware**: the syscall
  that installs the required descriptor returns `EINVAL` to a title, though
  the same probe round-trips on an ordinary x86-64 host. Until then an `i386` image parses,
  maps and relocates here but is not executed, and the loader says exactly
  that rather than pretending either way.
  [`docs/EXECUTION_MODEL.md`](docs/EXECUTION_MODEL.md) has the mechanism,
  the probe and the fallbacks, including why JIT recompilation is not
  emulation.
- **No game or third-party binary is committed.** `.exe` and `.dll` files are
  ignored repository-wide and the publication audit refuses any tracked file
  that begins with a DOS header. Tests run against images the repository
  generates itself.
- This repository contains no proprietary SDK files, no dumps and no
  jailbreak or payload-delivery implementation. Hardware results, when they
  exist, will apply only to the console and firmware actually tested.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module structure and the contracts between layers
- [`docs/EXECUTION_MODEL.md`](docs/EXECUTION_MODEL.md) — what "zero emulation" can and cannot mean here
- [`docs/COMPAT32_PHASE0A.md`](docs/COMPAT32_PHASE0A.md) — gate 0.2a: the compatibility-mode probe, its stub, and how to read its four outcomes
- [`docs/PE_MAPPING_PHASE0.md`](docs/PE_MAPPING_PHASE0.md) — gate 1: what is built, what is proven, and the hardware acceptance criteria
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — phase order and the gates that close each one
- [`docs/TELEMETRY.md`](docs/TELEMETRY.md) — the `ps5log/1` record vocabulary and its validator
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — workflow, worktrees and required gates
- [`LICENSING.md`](LICENSING.md) — the licence decision, deliberately still open

Provenance and attribution are recorded in [`NOTICE.md`](NOTICE.md). The
application identity `PPSA99995` is a local development identifier, not an
official Sony assignment.
