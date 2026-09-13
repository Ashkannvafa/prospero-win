# Compatibility roadmap

The roadmap describes public compatibility milestones. It is not a promise of
dates or a list of internal experiments.

## Status vocabulary

- **Bring-up**: all required PE images map, relocate and bind, and guest
  execution reaches application initialization.
- **First frame**: the application presents its first recognizable frame.
- **In-game**: changing application graphics and required audio are present.
- **First playable**: the primary interaction loop works with native input.
- **Validated**: a repeatable hardware run satisfies its documented evidence
  gate and cleanup contract.

## Current baseline

- PE32 image graph mapping, relocations and reviewed imports.
- IA-32 to x86-64 dynamic translation with bounded W^X publication.
- Hashed block lookup, direct chaining, register residency, dead-flag
  elimination and lazy arithmetic flags.
- Reusable Win32, User32, GDI, registry, WinMM, Pad and callback foundations.
- Native AGC/VideoOut presentation, asynchronous SceAudioOut and structured
  `ps5log/1` telemetry.
- Space Cadet Pinball: **First playable** and hardware-validated as the first
  target.

## Next compatibility release

1. Add a second independent PE32 GDI application to expose target-specific
   assumptions.
2. Introduce deterministic target-side DBT benchmarks for chaining, register
   residency, lazy flags and indirect branches.
3. Reduce reconciliation and spill traffic using measured workloads.
4. Expand User32, GDI, WinMM and CRT behavior only through reusable contracts
   with Wine-compatible semantics and application-independent tests.
5. Stabilize packaging, contributor documentation and release automation.

## 3D applications

The first 3D milestone is a reusable Direct3D 9 frontend targeting the native
PS5 graphics backend. Earlier Direct3D applications can later use established
D3D8-to-D3D9 translation where licensing and behavior permit. Work begins with
small synthetic API tests before attempting a complete game.

This milestone requires:

- resource and lifetime models independent of any single title;
- shader translation with explicit gfx1013 capability gates;
- render-state and synchronization tests;
- deterministic visual and telemetry evidence;
- no dependency on proprietary shaders or SDK blobs.

## Later work

- Broader multimedia and filesystem compatibility.
- More complete exception, thread and synchronization behavior.
- PE64/x86-64 loading and ABI support.
- Additional graphics APIs only after the D3D9 backend is stable.

## Non-goals

- DRM or anti-cheat bypass.
- Kernel drivers.
- Shipping proprietary executables, DLLs, shaders, captures or SDK material.
- Claiming compatibility from static imports or a single screenshot.
