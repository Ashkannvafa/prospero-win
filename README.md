# prospero-win

prospero-win is an experimental Windows compatibility runtime for PlayStation
5 homebrew. Its target architecture runs Wine's Windows subsystem on PS5:
PE32 code uses the project's IA-32 dynamic translator, PE64 will use native
x86-64 plus ABI bridges, and platform services connect Wine to the console.
Direct3D will run through DXVK over the companion `ps5-vulkan` project.

The first compatibility target is the original Windows Space Cadet Pinball
executable, running without recompilation. Pinball is a bring-up target for the
general runtime, not a project-specific architecture. DRM, anti-cheat, kernel
drivers and distribution of proprietary game files are out of scope.

## Current status

On an owned PS5 running firmware 12.02, the direct Win32 bootstrap makes
Pinball the first playable title:

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

The reusable Wine path has progressed beyond static loading. A pinned i386
Wine runtime is built reproducibly and recorded in a validated manifest. The
loader maps its real `ntdll`/`kernelbase` graph, binds exports by name and
ordinal, resolves bounded forwarders, and constructs PE32 TLS plus minimal
process state. Under the DBT, real `ntdll` initialization now retires 32,544
guest instructions over 6,869 dispatches and 968 translated blocks while
servicing 19 NT calls. It stops at a defined frontier: Wine calls
`__wine_unix_call_dispatcher`, the second dispatcher that prospero-win has not
published yet. Cleanup is complete and validator-enforced.

This is not yet a booting Wine process or broad Windows compatibility. Pinball
still uses the direct bootstrap, PE64 application execution is incomplete, and
Direct3D awaits DXVK over `ps5-vulkan`.

## Isolation model

Each native PS5 build runs inside the console's title process and title-owned
filesystem boundary. That is a useful outer sandbox, but it is not an API for
creating arbitrary nested jails: applications hosted by one prospero-win title
would share that title boundary. The runtime therefore also validates guest
memory, publishes translated code W^X, uses typed non-reissued handles,
canonicalizes guest paths into explicit namespaces, and keeps deployment or
debug services outside the guest capability surface. PE64 native execution
will require an explicit trust model because it has less mediation than PE32
DBT execution. See [Architecture](docs/ARCHITECTURE.md#isolation-boundaries).

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
[Wine integration](docs/WINE_INTEGRATION.md),
[hardware evidence](docs/HARDWARE_VALIDATION.md) and
[development workflow](docs/DEVELOPMENT.md).

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a change.

prospero-win is licensed under LGPL-2.1-or-later. See
[LICENSING.md](LICENSING.md) and [NOTICE.md](NOTICE.md). `PPSA99995` is a
local development identifier, not an official Sony assignment.
