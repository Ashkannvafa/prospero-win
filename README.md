# prospero-win

An experimental Windows compatibility runtime for PlayStation 5. It maps
Windows PE images, translates 32-bit x86 code to x86-64, supplies reviewed
Win32/CRT services and connects guest graphics and audio to native PS5
backends.

The first target is the owner's original Windows XP Space Cadet
`PINBALL.EXE`, executed without recompilation. DRM, anti-cheat and kernel
drivers are out of scope.

## Current milestone

The visible-and-audible milestone is validated on an owned PS5 running FW
12.02:

- the original PE32 image executes continuously through the x86 DBT;
- its main window and animated table are composed by the GDI compatibility
  layer and presented at 1920×1080 through AGC DMA and VideoOut;
- its MMIO/WaveMix/WinMM path submits original game PCM to SceAudioOut;
- `ps5log/1` records artifact identity, instruction/API progress, AGC flips,
  PCM bytes/frames/hash and any classified abort;
- Remote Play evidence contains 1080p60 H.264 video and captured AAC audio;
- close and relaunch work without rebooting the console.

The validated fSELF SHA-256 is
`b755b0bd5ded13e944b7fd2262c5b7e5004a7af9af102454d43603b4bc26a824`.
See [HARDWARE_VALIDATION.md](docs/HARDWARE_VALIDATION.md) for the correlated
run and its limitations.

This is not yet playable: DualSense input is deliberately deferred. GDI
fidelity also has known composition defects, and MIDI/MCI, broad Win32
compatibility and a general D3D backend remain future work.

## Build and inspect

```sh
make all          # host contracts plus publication audit
make sanitize     # clean ASan/UBSan rebuild
make inspect-only PE_INPUT=/private/path/PINBALL.EXE

# Native package; private game files are staged into ignored dist/ only.
PW_FOUNDATION_READY=1 \
PW_STAGE_INPUT=/private/path/pinball_xp \
PW_ROOT_MODULE=pinball.exe \
tools/build_native.sh
```

No Windows executable, resource, vendor SDK blob, telemetry transcript or
capture belongs in this repository. Tests generate synthetic PE fixtures,
and the fail-closed publication audit enforces that boundary.

## Documentation

[Roadmap](docs/ROADMAP.md) ·
[hardware validation](docs/HARDWARE_VALIDATION.md) ·
[architecture](docs/ARCHITECTURE.md) ·
[Pinball target](docs/PINBALL_TARGET.md) ·
[x86 execution](docs/X86_EXECUTION.md) ·
[guest ABI](docs/GUEST_ABI.md) ·
[GDI](docs/GDI.md) ·
[telemetry](docs/TELEMETRY.md) ·
[development](docs/DEVELOPMENT.md) ·
[Wine reuse audit](docs/WINE_REUSE_AUDIT.md)

Licensed LGPL-2.1-or-later. See [LICENSING.md](LICENSING.md) and
[NOTICE.md](NOTICE.md). `PPSA99995` is a local development identifier, not an
official Sony assignment.
