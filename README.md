# prospero-win

prospero-win is an experimental Windows compatibility runtime for PlayStation
5 homebrew. It maps Windows PE images, translates 32-bit x86 code to x86-64,
provides reviewed Win32 and CRT services, and connects guest graphics, audio
and input to native PS5 backends.

The first compatibility target is the original Windows Space Cadet Pinball
executable, running without recompilation. Pinball is a bring-up target for the
general runtime, not a project-specific architecture. DRM, anti-cheat, kernel
drivers and distribution of proprietary game files are out of scope.

## Current status

On an owned PS5 running firmware 12.02, Pinball is the first playable title:

- the PE32 image executes through the IA-32 dynamic binary translator;
- GDI output is composed and presented at 1920x1080 through AGC and VideoOut;
- WinMM and WaveMix PCM reaches SceAudioOut through an asynchronous worker;
- DualSense input is translated into Win32 key messages;
- registry state persists in title-owned storage;
- close and relaunch work without rebooting the console.

The DBT includes hashed block lookup, direct block chaining, cross-block guest
register residency, dead-flag elimination and real lazy arithmetic flags.
Exact eager/lazy host traces finish with identical guest CPU state. Bounded
hardware runs also reach video, audio and input teardown cleanly. These results
establish correctness and no observed regression; they do not yet establish a
percentage performance gain.

This is not broad Windows compatibility. The implemented surface is currently
PE32/IA-32 with the Win32, GDI and WinMM services required by the first target.
PE64 and Direct3D are not implemented.

## Build and test

```sh
make all
make sanitize
make inspect-only PE_INPUT=/private/path/APPLICATION.EXE
```

To build a native package, provide your own legally obtained Windows files
from an external directory:

```sh
PW_FOUNDATION_READY=1 \
PW_STAGE_INPUT=/private/path/application \
PW_ROOT_MODULE=application.exe \
tools/build_native.sh
```

Private applications are copied only into the ignored `dist/` build tree.
The fail-closed publication audit rejects Windows binaries, captures, telemetry
transcripts, private paths and unreviewed files from the repository.

## Documentation

Start with the [documentation index](docs/README.md), then see the
[architecture](docs/ARCHITECTURE.md), [compatibility roadmap](docs/ROADMAP.md),
[hardware evidence](docs/HARDWARE_VALIDATION.md) and
[development workflow](docs/DEVELOPMENT.md).

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a change.

prospero-win is licensed under LGPL-2.1-or-later. See
[LICENSING.md](LICENSING.md) and [NOTICE.md](NOTICE.md). `PPSA99995` is a
local development identifier, not an official Sony assignment.
