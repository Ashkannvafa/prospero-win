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
- **Host progress:** 66 translated instructions and four initial Win32/CRT calls
  from original Pinball startup; 207 imports bound as 205 functions/2 data.
  CRT mode-pointer getters have unit coverage; other handlers remain pending.
- **Next:** reviewed Win32 subsystem reuse, guest ABI services and broader
  execution-engine coverage. Wine references are not implemented APIs.
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
[Import plan](docs/IMPORT_PLAN.md) · [Wine reuse audit](docs/WINE_REUSE_AUDIT.md) ·
[Development workflow](docs/DEVELOPMENT.md) ·
[Telemetry](docs/TELEMETRY.md)

Windows binaries and game resources are private inputs kept outside the
public source tree. Tests generate synthetic images. The publication audit
rejects executable content, vendor DLLs and staged game directories.

Licensed LGPL-2.1-or-later. See [LICENSING.md](LICENSING.md) and
[NOTICE.md](NOTICE.md) for provenance and component obligations.
PPSA99995 is a local development identifier, not an official Sony assignment.
