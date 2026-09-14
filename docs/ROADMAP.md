# Compatibility roadmap

This roadmap records public compatibility milestones and their evidence. It is
not a promise of dates or a list of internal experiments.

## Status vocabulary

- **Bring-up**: all required PE images map, relocate and bind, and guest
  execution reaches application initialization.
- **First frame**: the application presents its first recognizable frame.
- **In-game**: changing application graphics and required audio are present.
- **First playable**: the primary interaction loop works with native input.
- **Validated**: a repeatable hardware run satisfies its documented evidence
  gate and cleanup contract.

## Current baseline

### Hardware bootstrap

- PE32 images execute through an IA-32-to-x86-64 DBT with bounded W^X
  publication, hashed lookup, direct chaining, cross-block register residency,
  dead-flag elimination and lazy arithmetic flags.
- Reusable Win32, User32, GDI, registry, WinMM, Pad and callback foundations
  drive native AGC/VideoOut presentation, asynchronous SceAudioOut and
  `ps5log/1` telemetry.
- Space Cadet Pinball is **First playable** and hardware-validated as the first
  unmodified Windows target. It is a bootstrap and regression target, not the
  architecture's compatibility boundary.

### Wine bring-up

- The pinned i386 Wine revision is built reproducibly and recorded in a
  validated runtime manifest.
- The loader maps the real runtime graph, resolves exports by name and ordinal,
  follows bounded forwarders, and owns PE32 TLS plus minimal PEB, TEB and
  process-parameter state.
- All 256 pinned i386 Wine syscall IDs are cross-checked against source.
- A versioned Unix-call registry currently services 19 dynamic NT calls with
  validated guest spans and typed, monotonic handles.
- Real `ntdll` initialization retires exactly 32,544 guest instructions over
  6,869 dispatches and 968 translated blocks, then returns cleanly to the host
  gate. Sanitizer and cleanup validators pass.

That Wine result is a bounded host checkpoint. It does not yet mean that a Wine
process boots inside the PS5 title or that Pinball has migrated away from the
direct Win32 bootstrap.

## Current frontier

Wine's loader debug path calls `__wine_unix_call_dispatcher`. This is distinct
from the syscall dispatcher already published through `TEB.WOW32Reserved`.
prospero-win deliberately stops at that unimplemented boundary instead of
inventing a return value or continuing with corrupt runtime state.

## Next compatibility release

1. Publish the pinned, versioned `__wine_unix_call_dispatcher` boundary and
   implement the first required unixlib calls with validated arguments,
   deterministic errors and rollback-safe ownership.
2. Complete loader process state: `PEB_LDR_DATA`, module lists, kernelbase
   initialization and Wine-compatible process/thread attach ordering.
3. Expand native process, thread, object and wait services: thread creation and
   exit, events, mutexes, semaphores, wait-any/wait-all, timeouts and abandoned
   ownership.
4. Complete the prefix-facing foundation: Unicode/NLS data, environment,
   registry views, DOS-device/NT path normalization, sharing and directory
   enumeration.
5. Stage the pinned Wine distribution in the native title, boot the first Wine
   process on hardware and require structured identity, lifecycle and cleanup
   evidence.
6. Add a second independent PE32 application and selected Wine test subsets so
   application-specific assumptions cannot become runtime contracts.

The exact dependency graph and exit criteria live in
[WINE_FOUNDATION.json](WINE_FOUNDATION.json).

## Performance line

Compatibility work and DBT performance advance together, but neither
substitutes for correctness. Wine and multiple applications will drive:

- indirect-branch inline caches and return prediction;
- broader SSE/SSE2 and integer instruction coverage;
- an intermediate representation with wider register allocation;
- bounded traces or superblocks with precise safepoints;
- thread-safe immutable translated-code reuse; and
- deterministic counters for dispatch, spills, exits, code size and frame
  pacing.

No native-performance percentage is claimed without matched PS5 measurements
and exact eager/control state parity.

## Isolation direction

The native package runs inside the PS5 title process and title-owned filesystem
boundary. This is the outer sandbox, not an API for arbitrary nested containers.
If one prospero-win title hosts several Windows applications, they share that
outer boundary.

The runtime therefore keeps an inner logical boundary: validated guest memory,
W^X publication, typed non-reissued handles, canonical application/runtime/
storage namespaces, quotas and capability-limited Unix-call services. PE32 is
mediated by the DBT. Future PE64 code can execute directly in the title process
and needs an explicit trust or stronger-containment policy before broad use.

## 3D applications

The Direct3D path is DXVK, not a new prospero-win D3D renderer. DXVK's
D3D8/9/10/11 and DXGI PE modules will execute inside the same Wine runtime and
use `ps5-vulkan`, which owns AGC/VideoOut/gfx1013. Direct3D work begins when the
companion backend satisfies its pinned DXVK consumer profile.

This milestone requires:

- Wine/DXGI loader, thread, object and presentation contracts;
- Vulkan resource, lifetime and synchronization behavior required by DXVK;
- shader/pipeline support exposed through the ps5-vulkan consumer gate;
- deterministic visual and telemetry evidence; and
- no dependency on proprietary shaders or SDK blobs.

## Later work

- Broader multimedia, networking and filesystem compatibility.
- Wine-compatible exceptions, multi-threading and synchronization.
- PE64/x86-64 imports, callbacks, ABI/unwind support and an isolation policy.
- Additional graphics APIs only after the D3D9 backend is stable.

## Non-goals

- DRM or anti-cheat bypass.
- Kernel drivers.
- Shipping proprietary executables, DLLs, shaders, captures or SDK material.
- Claiming compatibility from static imports or a single screenshot.
