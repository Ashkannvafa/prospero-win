# prospero-win

An experimental Windows compatibility runtime for PlayStation 5. It maps
Windows PE images, translates 32-bit x86 code to x86-64, supplies reviewed
Win32/CRT services and connects guest graphics and audio to native PS5
backends.

The first target is the owner's original Windows XP Space Cadet
`PINBALL.EXE`, executed without recompilation. DRM, anti-cheat and kernel
drivers are out of scope.

## Current milestone

The P5/P6 gameplay candidate is running on an owned PS5 with FW 12.02:

- the original PE32 image executes continuously through the x86 DBT;
- its main window and animated table are composed by the GDI compatibility
  layer and presented at 1920×1080 through AGC DMA and VideoOut;
- its MMIO/WaveMix/WinMM path submits original game PCM to SceAudioOut;
- `ps5log/1` records artifact identity, instruction/API progress, AGC flips,
  PCM bytes/frames/hash and any classified abort;
- Remote Play evidence contains 1080p60 H.264 video and captured AAC audio;
- close and relaunch work without rebooting the console.
- the reusable ScePad adapter translates chronological DualSense samples into
  Win32 key-down/up messages and neutralizes held keys on disconnect, input
  interception, controller-generation changes and shutdown; `Create` posts an
  orderly `WM_QUIT` instead of masquerading as a guest keyboard key;
- versioned, checksummed registry state is atomically saved under the title's
  persistent `/download0` storage and has been reloaded on a later launch;
- the target's `wavemix.inf` is parsed through the confined file provider;
- a bounded validation build has demonstrated an orderly teardown of Pad,
  AudioOut, GDI, VideoOut, AGC direct memory, DBT, PE image and guest VM.

The current production fSELF SHA-256 is
`a71688d0c95ddb07fc2b86be16cbc5fb6705208e2df8078d5449843c3e972458`.
See [HARDWARE_VALIDATION.md](docs/HARDWARE_VALIDATION.md) for correlated
continuous and orderly-exit evidence and its limitations.

Automated and hardware-side implementation is complete for the current P5/P6
candidate. Physical gameplay has now confirmed plunger launch, both flippers,
scoring and ball loss without a runtime exit. Pause/resume and manual new-game
restart remain on the owner acceptance checklist.
The original game defaults music off; its single optional `MCI_OPEN` request is
reported honestly as no MIDI device, while its required WaveMix PCM effects
remain active. Broad Win32 compatibility and a general D3D backend are later
work.

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
