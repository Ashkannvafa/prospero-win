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

1. Produce a reproducible, pinned i386 Wine PE runtime distribution and map it
   from the dedicated runtime namespace.
2. Complete PE exports/forwarders and TLS, then enter Wine `ntdll` under the
   IA-32 DBT with real PEB/TEB state.
3. Implement the versioned Wine Unix-call boundary and reusable NT
   object/handle/wait services on the PS5 platform layer.
4. Drive DBT instruction coverage and performance from Wine plus multiple
   applications: indirect-branch caches, SSE2, wider register allocation,
   traces and thread-safe immutable code reuse.
5. Add a second independent PE32 application and Wine test subsets so
   application-specific assumptions cannot become runtime contracts.

The exact dependency graph and exit criteria live in
[WINE_FOUNDATION.json](WINE_FOUNDATION.json).

## 3D applications

The Direct3D path is DXVK, not a new prospero-win D3D renderer. DXVK's
D3D8/9/10/11 and DXGI PE modules will execute inside the same Wine runtime and
use `ps5-vulkan`, which in turn owns AGC/VideoOut/gfx1013. Direct3D work begins
only when the companion backend satisfies its pinned DXVK consumer profile.

This milestone requires:

- Wine/DXGI loader, thread, object and presentation contracts;
- Vulkan resource, lifetime and synchronization behavior required by DXVK;
- shader/pipeline support exposed through the ps5-vulkan consumer gate;
- deterministic visual and telemetry evidence;
- no dependency on proprietary shaders or SDK blobs.

## Later work

- Broader multimedia and filesystem compatibility.
- Wine-compatible exception, multi-thread and synchronization behavior.
- PE64/x86-64 imports, callbacks and ABI/unwind support.
- Additional graphics APIs only after the D3D9 backend is stable.

## Non-goals

- DRM or anti-cheat bypass.
- Kernel drivers.
- Shipping proprietary executables, DLLs, shaders, captures or SDK material.
- Claiming compatibility from static imports or a single screenshot.
