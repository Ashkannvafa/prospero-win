# Roadmap

The first game milestone is the original x86 Windows Space Cadet
PINBALL.EXE, running without recompilation. DRM, anti-cheat and kernel
drivers are out of scope. Each hardware milestone needs artifact identity,
structured ps5log/1 evidence and an independently checked result.

## Proven foundation

- [x] **0.1 PE mapping on FW 12.02.** Synthetic images parsed, mapped,
  rebased, relocated, protected, verified and released. Dependency names
  classified; import addresses are not yet bound. See PE_MAPPING_PHASE0.md.
- [x] **0.2a LDT route refused.** The tested title cannot install the required
  descriptor. This closes that compatibility-mode route on the tested
  firmware, not ABI marshalling. See COMPAT32_PHASE0A.md.
- [x] Low-address allocation and RW-to-RX/RWX protection measured in a title.
  These are allocation/protection results, not a completed execution engine.

## Next: target inventory and execution contracts

- [ ] **P0 Pinball inventory.** Owner-supplied binary identity (SHA-256,
  architecture and version), complete static import names/ordinals,
  resources, TLS, relocations, delay imports and dynamically resolved APIs.
  `make inspect-only` supplies initial layout and static imports; the rest
  needs separate inspection. The supplied binary's initial layout and 207
  static imports are recorded in PINBALL_TARGET.md; P0 remains incomplete.
- [ ] **0.2b PE64 execution and ABI bridge.** RW-to-RX publication, mapped
  leaf return, integer and floating arguments, more than four arguments,
  aggregate returns, shadow space, stack alignment, preserved registers and
  XMM state, guest-to-host imports and host-to-guest callbacks. Use explicit
  Win64 ABI functions/thunks. Each case has expected outputs and canaries;
  repeat on hardware before claiming the bridge works there.
  Host mapped-code integer/float/callback tests now pass; the six-integer
  assembly call bridge also compiles for PS5. The target rejects ms_abi,
  so native import/callback stubs must be explicit. See EXECUTION_MODEL.md.
- [ ] **P1 x86 feasibility prototype.** Decode and translate bounded blocks;
  compare registers, flags, memory and exceptions with native 32-bit host
  execution. Cover address-size changes, absolute versus RIP-relative
  addressing, stack width, indirect branches, segment/TLS references and
  floating-point instructions the target uses. Choose decoder and execution
  approach from measured coverage and performance.
- [ ] **Memory feasibility.** Test scattered low allocations, reserve versus
  commit/decommit and realistic working sets. A 256 MiB low mapping does not
  prove a 2 GiB guest address space or sufficient resident memory.

## Bind and start the target

- [ ] **0.3 Imports/exports.** Names, ordinals, forwarders and dynamically
  resolved functions. Replace broad system-DLL classification with an
  explicit policy: core host modules, API sets, application overrides and
  host fallback. Local d3d9.dll/dinput8.dll wrappers must not be silently
  bypassed. Add resolver conformance fixtures.
- [ ] **0.4 Initialisation.** Dependency ordering, TLS, CRT entry, DllMain
  and teardown required by the target. Track unsupported features.
- [ ] **P2 Pinball entry.** Expand x86 execution and cdecl/stdcall marshalling
  until the executable reaches application entry. Keep guest pointers and
  handles 32-bit; exercise callbacks in both directions.
- [ ] Implement the observed Win32 surface: process/error state, heap,
  virtual memory, files/resources, registry subset if needed, clocks and
  synchronisation. Unsupported calls identify themselves and stop with a
  classified error instead of returning fabricated success.

## First frame to playable Pinball

- [ ] **P3 Message loop.** Window procedures, messages, timers and input.
  Reuse Xash3D's validated ScePad lifecycle with a Win32 event adapter.
- [ ] **P4 First frame.** Implement observed graphics calls and present
  through the reusable AGC backend. Determine GDI/DirectDraw requirements
  from the binary; D3D9 is not a prerequisite. Preserve fence, flip-token,
  guard and cleanup telemetry. Capture the board.
- [ ] **P5 Playable.** Launch a ball, use both flippers with DualSense,
  score, lose a ball and restart. Check timing and physics against Windows.
  Run continuously until operator closure.
- [ ] **P6 Complete.** Required audio/music APIs, preferences and scores,
  adapting Xash3D's PCM backend to WinMM (MIDI/MCI remain separate work),
  repeated launch/close and a soak with stable memory and no unhandled APIs.
  Record binary/build hashes, telemetry and reviewed video evidence.

A native source port can be a reference, but does not close these binary
compatibility milestones. See [PINBALL_TARGET.md](PINBALL_TARGET.md).

## After Pinball

Select a second title to expand reusable APIs. Evaluate D3D8/9 to AGC
against DXVK plus a Vulkan backend with a representative workload before
choosing a fork strategy. DXVK's Vulkan backend is substantial; renaming
calls is insufficient. Shaders, formats, synchronization and graphics state
remain implementation work.

The 1995–2010 catalogue is long-term scope, not a compatibility claim.
Track individual versions, required APIs, working set and measured results.

## Engineering gates

- Host contracts and ASan/UBSan pass before loader/execution changes advance.
- Add toolchain-generated PE fixtures and fuzz parser/import/relocation input.
- Audit native imports and smoke-test unfamiliar platform functions.
- Keep binaries/resources/vendor DLLs private; publish source, synthetic
  fixtures and reviewed structural evidence.
- Use topic branches and PRs. Reconcile integration with current lab main
  before merging, preserving concurrent renderer work.
