# prospero-win

An experimental Windows compatibility runtime for the PlayStation 5 GPU
and CPU. PE64 execution is planned natively with Win64 ABI bridges;
PE32 execution requires an x86 translation engine.

The first game target is the original Windows Space Cadet **PINBALL.EXE**,
without recompilation, with DualSense input and AGC-backed presentation.
DRM, anti-cheat and kernel drivers are out of scope.

## Current status

- **Validated on FW 12.02:** synthetic PE parsing, mapping, relocation,
  protection, dependency classification, verification and release.
- **Measured:** the tested LDT route is refused; low allocations and
  mprotect RW-to-RX/RWX work in a title.
- **Host progress:** the exact Pinball binary reaches its public-PDB-verified
  `WinMain` address, completes the splash path and enters WaveMix setup:
  37,925 translated instructions and 241 completed adapter calls across 67
  distinct DLL/API pairs. The measured run records 3,807 DBT dispatches, 3,469
  cache hits and 338 published blocks. Keyboard scan-code discovery, main and
  nested helper-window creation, logical palettes, INI lookup and the complete
  splash blits now execute. The next classified stop is
  `winmm!waveOutGetNumDevs`, the first audio-device query.
- **Measured execution scope:** 25,092/25,538 reachable static instructions
  are accepted (98.25%). Integer-only binary80 helpers now translate 2,253 of
  2,300 x87 occurrences, including all 36 forms and all 384 occurrences in the
  startup graph. The remaining 47 x87 occurrences are later wndproc/gameplay
  forms; 399 rejected instructions are non-x87.
- **Verified oracle:** the target SHA-1, public PDB identity and ten public
  symbol addresses match the pinned MIT source reconstruction. The generated
  manifest groups source-confirmed startup, graphics, input and audio APIs.
- **Reusable PS5 baseline:** `ps5-xash3d` now runs Half-Life 1 gameplay on the
  same owned FW 12.02 console with native AGC rendering, DualSense input and
  live game audio. Its public Phase 7 still tracks fidelity, performance,
  longer soaks and release polish; prospero-win treats the proven platform
  components as reusable foundations rather than pending research.
- **Next:** implement the source-confirmed reusable WaveOut state machine and
  advance through audio initialization toward the message loop. Wine remains a contract
  and test reference, not a claim of implemented compatibility.
- **Not yet implemented:** a complete execution engine, Win32 API surface
  or a running Windows game.

Mapping evidence is documented in
[PE_MAPPING_PHASE0.md](docs/PE_MAPPING_PHASE0.md). Full application
compatibility is not established by mapping or by executable permissions.

## Build and inspect

```sh
make all          # host contracts and publication audit
make sanitize     # clean rebuild with Clang ASan, UBSan and leak detection
make inspect-only PE_INPUT=/private/path/PINBALL.EXE
make inspect PE_INPUT=/private/path/game.exe PE_DIR=/private/path
```

The inspector lists sections and static import names/ordinals.
`inspect-only` requires no dependencies and does not map or execute code.
Host/local classification is provisional until resolver policy is expanded.

Build the existing synthetic console mapping gate:

```sh
make native PS5LOG_DEV_CONF=/private/path/dev.conf
```

## Development

[Roadmap](docs/ROADMAP.md) · [Pinball target](docs/PINBALL_TARGET.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Execution model](docs/EXECUTION_MODEL.md) ·
[GDI contracts](docs/GDI.md) ·
[Source oracle](docs/PINBALL_SOURCE_ORACLE.json) ·
[x86 coverage](docs/PINBALL_X86_COVERAGE.json) ·
[Import plan](docs/IMPORT_PLAN.md) · [Wine reuse audit](docs/WINE_REUSE_AUDIT.md) ·
[Development workflow](docs/DEVELOPMENT.md) ·
[Telemetry](docs/TELEMETRY.md)

Windows binaries and game resources are private inputs kept outside the
public source tree. Tests generate synthetic images. The publication audit
rejects executable content, vendor DLLs and staged game directories.

Licensed LGPL-2.1-or-later. See [LICENSING.md](LICENSING.md) and
[NOTICE.md](NOTICE.md) for provenance and component obligations.
PPSA99995 is a local development identifier, not an official Sony assignment.
