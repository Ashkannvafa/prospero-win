# Roadmap

The first target is the owner's original x86 Windows Space Cadet
`PINBALL.EXE`, executed without recompilation. Runtime iteration validates
coherent subsystems discovered from static inventory, public reference source
and private local analysis; it is not one-API-at-a-time scope discovery.

Every hardware milestone requires an exact artifact hash, `ps5log/1`
telemetry and an independently checked result. Visual capture alone is not
renderer or audio proof.

## Completed foundation

- [x] **P0 — target inventory.** Exact binary identity, PE32 layout, 207
  static imports, resources and public-PDB/source-oracle correlation are
  recorded without publishing proprietary data.
- [x] **P1 — x86 feasibility.** A generation-scoped x86-to-x86-64 DBT with
  bounded guest memory, isolated guest flags/x87 state, RW-to-RX publication,
  cache invalidation and differential/unit regressions executes the target.
- [x] **P2 — application entry and startup.** PE mapping, IAT binding,
  CRT/heap/registry/resource services and guest callbacks reach `WinMain` and
  complete startup through the original message loop.
- [x] **P3 — message and window foundation.** Transactional window creation,
  nested WndProc callbacks, queues, painting, timers/waits and deterministic
  synthetic key messages run on host and PS5. Real controller mapping is not
  implied.
- [x] **P4 — first hardware frame.** The original GDI surface is composed on
  CPU, tiled for PS5 scanout, copied by AGC DMA and flipped through VideoOut.
  Fence completion, flips and changing frame hashes are observable.
- [x] **P4.5 — visible and audible.** The animated table and the original
  WaveMix PCM path run together on FW 12.02. The audio adapter converts the
  requested 11025 Hz unsigned 8-bit mono stream to SceAudioOut's 48000 Hz
  signed 16-bit stereo blocks. A correlated 1080p60/AAC Remote Play capture,
  artifact hash and telemetry are recorded in HARDWARE_VALIDATION.md.

## Next milestones

- [ ] **P5 — playable.** Adapt the already proven PS5 pad lifecycle into
  reusable Win32 key/mouse messages. Launch a ball, operate both flippers,
  score, lose a ball and restart with correct transitions and timing.
- [ ] **P5.5 — presentation fidelity and pacing.** Correct remaining GDI
  composition defects, select the actual top-level presentation target by
  ownership rather than size, eliminate duplicated/stale regions and measure
  frame pacing without busy-looping the guest.
- [ ] **P6 — complete Pinball runtime.** Implement required persistence,
  preferences and score storage; classify optional missing assets; add only
  the MCI/MIDI behavior the target actually needs; perform repeated launch,
  close and long soaks with stable ownership and no unhandled APIs.
- [ ] **P7 — reusable compatibility expansion.** Select a second title and
  measure which CRT/User32/GDI/WinMM contracts generalize. Add compatibility
  by subsystem with fixtures, never by title-name hacks.
- [ ] **P8 — D3D8/9 investigation.** Evaluate DXVK's D3D8/9 frontend against
  a Vulkan-on-AGC layer or a narrower direct backend. DXVK is not a call-name
  translation table: shaders, descriptors, formats, synchronization and
  resource residency remain substantial engineering work.

## Known boundaries

- The current frame path uses CPU GDI composition and PS5 tile conversion;
  AGC accelerates the final DMA/presentation step. It is not D3D acceleration.
- The current x86 engine is target-capable, not a complete IA-32 CPU or Windows
  process model. Exceptions, SSE breadth, TLS and dynamic module semantics are
  incomplete.
- `SOUND59.WAV`, requested by the target's plunger mapping, is absent from the
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
