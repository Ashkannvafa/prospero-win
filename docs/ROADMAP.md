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
- Wine's syscall and Unix-call dispatchers are published from versioned tables
  cross-checked against the pinned source. The gate services 32 NT call shapes
  with validated guest spans and typed, monotonic handles.
- A generated PE32 executable plus two DLLs loads from the application
  namespace through Wine's own `ntdll`, reaches its own entry point, returns
  `1`, and exits cleanly through `NtTerminateThread`. With register residency
  disabled, that host run retires 598,404 guest instructions over 2,981 blocks.
- The smaller ntdll control remains independently pinned at 33,118 retired
  instructions, 7,065 dispatches, 961 blocks and 19 serviced calls. Normal,
  sanitizer, pinned-source and cleanup gates pass.

Those Wine results are bounded host checkpoints. They do not yet mean that a
Wine process boots inside the PS5 title or that Pinball has migrated away from
the direct Win32 bootstrap.

## Current frontier

The successful application checkpoint deliberately disables cross-block
register residency. With residency enabled the same deterministic run stops in
Wine's module-tree insertion with a classified bounds fault caused by an
incorrect DBT entry-state contract. The loader graph and its load/memory/init
lists also still need to be read back and validated, and DllMain/TLS attach
ordering is not yet evidence. The current registry is run-local rather than a
persistent Wine prefix.

## Next compatibility release

1. Repair the DBT residency entry contract and require the generated Wine
   application to finish identically with optimization on and off.
2. Validate Wine-owned `PEB_LDR_DATA`, all loader lists and module identity,
   then prove dependency, DllMain and TLS attach/detach ordering.
3. Expand native process, thread, object and wait services: thread creation and
   exit, events, mutexes, semaphores, wait-any/wait-all, timeouts and abandoned
   ownership.
4. Complete the persistent prefix: `drive_c`, environment, registry views and
   crash-safe storage, DOS-device/NT path normalization, sharing and directory
   enumeration; prove two runs and two isolated prefixes.
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
