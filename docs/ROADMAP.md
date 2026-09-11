# Roadmap

prospero-win is an experimental Windows compatibility runtime for PS5. Its
milestones describe runtime capability, not a Pinball port. The owner's
original x86 Windows Space Cadet `PINBALL.EXE` is the first compatibility
target executed without recompilation; subsequent targets must exercise the
same reusable loader, DBT, Win32 and native-backend architecture.

Runtime iteration validates coherent subsystems discovered from static
inventory, public reference source and private local analysis; it is not
one-API-at-a-time scope discovery. Every hardware result requires an exact
artifact hash, `ps5log/1` telemetry and an independently checked result. Visual
capture alone is not renderer or audio proof.

## Compatibility status vocabulary

- **Bring-up:** enough loader, CPU and platform infrastructure exists to begin
  executing a Windows target reproducibly.
- **Boots:** the target reaches its application entry and sustained message
  loop without a classified runtime abort.
- **First frame:** output originating in the target reaches native PS5
  presentation with verified ownership and completion.
- **In-game:** the target produces changing graphics and its required audio
  path, but interaction or timing may still prevent meaningful play.
- **First playable:** core interaction and state transitions work with usable
  timing. This is neither a polished release nor broad compatibility.
- **Compatibility expansion:** additional independent targets expose and
  remove target-specific assumptions by subsystem.
- **3D API bring-up:** Direct3D frontends, shaders, descriptors, formats,
  synchronization and residency begin running over a PS5 GPU backend.

## Completed bring-up

- [x] **Target inventory.** Exact binary identity, PE32 layout, 207 static
  imports, resources and public-PDB/source-oracle correlation are recorded
  without publishing proprietary data.
- [x] **x86 execution foundation.** A generation-scoped x86-to-x86-64 DBT
  with bounded guest memory, isolated guest flags/x87 state, RW-to-RX
  publication, cache invalidation and differential/unit regressions executes
  the first target.
- [x] **First boot.** PE mapping, IAT binding, CRT/heap/registry/resource
  services and guest callbacks reach `WinMain` and sustain the original
  message loop.
- [x] **Window and message bring-up.** Transactional window creation, nested
  WndProc callbacks, queues, painting, timers/waits and deterministic synthetic
  key messages run on host and PS5.
- [x] **First frame.** The original GDI surface is composed on CPU, tiled for
  PS5 scanout, copied by AGC DMA and flipped through VideoOut. Fence
  completion, flips and changing frame hashes are observable.
- [x] **In-game / visible and audible.** The animated table and original
  WaveMix PCM path run together on FW 12.02. The audio adapter converts the
  requested 11025 Hz unsigned 8-bit mono stream to SceAudioOut's 48000 Hz
  signed 16-bit stereo blocks. Correlated 1080p60/AAC Remote Play evidence,
  artifact identity and telemetry are recorded in HARDWARE_VALIDATION.md.

## First playable title: Space Cadet Pinball

- [x] The ScePad/Win32 adapter maps plunger, both flippers, three nudges,
  pause/resume and new game with exact key transitions and neutralization.
  `Create` posts `WM_QUIT` directly for an orderly guest/runtime exit.
- [x] Physical play has confirmed Cross launch, both shoulder flippers,
  scoring, ball loss, Options pause/resume and Square new-game restart without
  an unintended runtime exit.
- [x] Bottom-up DIB subrects use the correct source origin, the focused
  top-level owner wins presentation and empty `PeekMessage` iterations yield
  rather than busy-spin.
- [x] Registry preferences and scores use a versioned checksummed format with
  atomic `/download0` replacement; a later hardware launch reloaded 473 bytes.
  `wavemix.inf` uses a bounded parser and confined file route.
- [x] Strict continuous validation passed beyond ten minutes with 8,733
  changing-frame flips and 901 audio blocks. Bounded runs prove orderly
  teardown of all owned subsystems.
- [ ] Intermittent motion/pacing and remaining presentation details need
  profiling and polish. They do not invalidate the first-playable result.

## Active: compatibility expansion

- [ ] Select a second independent Windows program or game using objective
  loader, CPU, import and graphics-API criteria.
- [ ] Run it through the same inventory and bring-up gates without title-name
  branches or hard-coded application behavior.
- [ ] Generalize only the CRT/User32/GDI/WinMM contracts exposed by evidence,
  with synthetic fixtures and cross-target regressions.
- [ ] Track per-title status using the vocabulary above so one successful title
  cannot be mistaken for project completion.

## Later: 3D API bring-up

- [ ] Evaluate DXVK's D3D8/9 frontends against either a Vulkan-on-AGC layer or
  a narrower direct backend. DXVK is not a call-name translation table:
  shaders, descriptors, formats, synchronization and resource residency remain
  substantial engineering work.
- [ ] Promote a D3D target through first frame, in-game and first playable only
  when hardware telemetry proves each boundary.

## Known boundaries

- The current frame path uses CPU GDI composition and PS5 tile conversion;
  AGC accelerates the final DMA/presentation step. It is not D3D acceleration.
- The current x86 engine is target-capable, not a complete IA-32 CPU or Windows
  process model. Exceptions, SSE breadth, TLS and dynamic module semantics are
  incomplete.
- `SOUND59.WAV`, requested by Pinball's plunger mapping, is absent from the
  owner's original asset set. Other original effects produce validated PCM;
  the runtime does not fabricate a replacement.
- Windows binaries/resources, decompiler output and raw captures stay private.
  Only project-authored source, synthetic fixtures and reviewed facts are
  publishable.

## Engineering gates

- `make test audit` before project commits and `make check` before lab commits.
- ASan/UBSan after loader, DBT, ABI, GDI or audio ownership changes.
- Exact stdcall/cdecl stack-balance tests for every adapter. The `mmioClose`
  regression is permanent because its two-argument ABI previously consumed a
  saved guest register and silently disconnected valid WaveMix buffers.
- Topic branches and pull requests only; never push directly to `main`.
