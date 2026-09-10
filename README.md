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
  `WinMain` address through generation-scoped cached multi-instruction blocks:
  1,823 instructions and 105 completed calls (30 distinct APIs). The measured
  run records 417 dispatches, 270 cache hits and 147 published blocks. The next
  classified stop is `LoadIconA`, before window-class registration.
- **Measured execution scope:** 22,839/25,538 reachable static instructions
  are accepted. The 2,300 x87 occurrences reduce to 54 unique semantic forms
  (36 in the startup graph), not 2,300 separate implementation tasks.
- **Verified oracle:** the target SHA-1, public PDB identity and ten public
  symbol addresses match the pinned MIT source reconstruction. The generated
  manifest groups source-confirmed startup, graphics, input and audio APIs.
- **Next:** implement the 36 startup x87 forms and the resource/window ownership
  package beginning at `LoadIconA`. Wine remains a contract
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
