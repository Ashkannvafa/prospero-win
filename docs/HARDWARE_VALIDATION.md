# FW 12.02 visible-and-audible validation

## Accepted run

Date: 2026-09-11 (local lab date). Owned PS5, firmware 12.02.

- Title/application: `PPSA99995` / `prospero-win`.
- Original private root: `pinball.exe`; 207 bound static imports; image size
  307200 bytes.
- Linked ELF SHA-256:
  `2387354266fc23415ef43e238548ab7b604c03c71f3d2a973e637db2ed428e2c`.
- Deployed fSELF SHA-256:
  `b755b0bd5ded13e944b7fd2262c5b7e5004a7af9af102454d43603b4bc26a824`.
- FTP deployment: 71 files, 4,136,361 bytes, exact verification of every file.
- `ps5log/1` run:
  `20260910T232509632Z_PPSA99995_prospero-win_0x1bb3e350d307f`.

At the accepted observation point the runtime remained active with no
`PW_RUNTIME_ABORT` or `PW_RUNTIME_SIGNAL`. After more than twelve minutes it
had retired 1,070,920,939 guest instructions, completed 5,557,517 adapter
calls and presented 1,029 changing
frames. Video telemetry reported `backend=agc-dma`, matching submit and flip
ownership with a zeroed completion fence.

The original WinMM/MMIO/WaveMix route opened 11025 Hz, 8-bit mono audio and
submitted 48,919 input bytes. The native adapter converted these into 212,736
stereo frames across 831 complete 256-frame SceAudioOut blocks. The cumulative
input hash was `0x47388e86`. This proves non-empty deterministic PCM crossed
the guest/native boundary; it is not inferred merely from a successful audio
open.

## Independent audiovisual observation

The private Remote Play capture paired with this artifact is 35.0 seconds of
1920×1080 H.264 at 60 fps plus 48 kHz stereo AAC. Audio analysis measured
mean level -18.7 dB and detected non-silent intervals during the title's
startup/effects. The capture and a decoded screenshot remain under the ignored
`research/gpu/captures/remoteplay/` tree for owner review; they are not public
repository inputs.

The board is visible and changes over time. Remaining GDI fidelity defects are
also visible: some auxiliary-panel regions are duplicated or stale. Therefore
this evidence established the **in-game / visible-and-audible** status, not
pixel-perfect rendering or playability.

## Repeatability and lifecycle

The same package was closed through the verified BigApp controller and
relaunched without a console reboot. A content swap requires one
ShadowMountPlus refresh after the exact FTP deployment; subsequent close and
relaunch of unchanged content does not. The runtime is intentionally
continuous and remains active until operator closure.

Remote Play capture resolves the PulseAudio monitor belonging to the verified
CLI-owned Chiaki process and fails closed if routing is absent or ambiguous.
An MP4 must contain both video and audio streams before it is accepted as
audiovisual evidence. Renderer/audio completion still comes from `ps5log/1`,
not from the capture alone.

## Root cause that unlocked audio

The Win32 dispatcher incorrectly modeled `mmioClose` as a three-argument
stdcall API. Its real contract has two arguments. Popping the extra dword
consumed WaveMix's saved ESI, so successfully loaded WAV pointers were written
through corrupted offsets and later appeared null. The corrected two-argument
frame, plus a permanent exact-ESP regression, restores the original effect
buffers. `PostMessageA`, `FST m64fp`, `FDIVRP`, REPZ `CMPSD` and scalar
operator delete complete the subsequent observed path.

`SOUND59.WAV` is not present in the original asset set. That optional missing
plunger sample is reported as not found; other effects, including the two
flipper mappings, supplied the PCM validated above.

## First-playable production evidence (2026-09-11)

The final production candidate uses linked ELF SHA-256
`3e858b04cdd576bbf27f404793871bb84d7846d1ba947b5507929f2251df3cc6`
and fSELF SHA-256
`a71688d0c95ddb07fc2b86be16cbc5fb6705208e2df8078d5449843c3e972458`.
Its continuous run is
`20260911T010344392Z_PPSA99995_prospero-win_0x1c09f53a24a2b`.
The corrected image shows the complete 600×416 table and both right-side
panels without the former duplicated source bands. The defect was a reversed
bottom-up DIB subrect formula: source Y already names a bottom-origin row, so
subtracting it from the full DIB height sampled an unrelated band. A focused
synthetic regression now distinguishes the two formulas; target telemetry
records the observed 600×416 source `(405,25,165,88)` case.

At startup this candidate loaded 473 bytes of persistent registry state. It
performed 16 confined `wavemix.inf` lookups with zero missing files/errors and
read 42,992 aggregate bytes. MCI telemetry recorded exactly one command,
`MCI_OPEN` (`0x803`); the game's default-off music capability then remained
disabled. Pad telemetry proves successful SceUserService/ScePad ownership,
connected chronological samples and zero synthetic events while the operator
was absent. `Create` is kept outside the keyboard map and posts an orderly
`WM_QUIT` on its raw physical press edge. It does not replace physical gameplay
acceptance.

The exact production run above passed the strict continuous validator beyond
ten minutes: 628,127,226 retired guest instructions, 2,876,256 adapter calls,
8,733 changing-frame flips, 901 audio blocks and 3,074 connected pad samples,
with no abort, signal, pad read error, missing profile or parse error. It was
then closed externally so the exact same source could undergo the independent
bounded teardown gate below. The immediately preceding run
`20260911T004134217Z_PPSA99995_prospero-win_0x1bf69a01a2f6c` supplied a second
strict ten-minute result with more than 700 million retired instructions and
7,600 flips, but predates the isolated Create-to-WM_QUIT lifecycle mapping.

After commit `ea1bc3e`, the deterministic production artifact was rebuilt,
redeployed and relaunched as
`20260911T012402917Z_PPSA99995_prospero-win_0x1c1bb08616b67`. The strict
continuous validator accepted that exact run beyond ten minutes with
649,958,605 retired instructions, 3,001,738 adapter calls, 7,122 changing-frame
flips, 901 audio blocks and 2,975 connected pad samples at the acceptance
point. It had zero aborts, signals, pad errors and profile errors, and remained
active afterward for physical gameplay acceptance.

Two bounded validation builds prove persistence and shutdown independently of
the continuous candidate:

- `20260911T003339056Z_PPSA99995_prospero-win_0x1befafea70a60` atomically
  wrote 473 bytes to title-owned `/download0` storage and ended with a clean
  `BYE`.
- `20260911T003421759Z_PPSA99995_prospero-win_0x1bf04efe9891e` loaded those
  same 473 bytes, then repeated the clean `BYE` cycle.

Both teardown records report successful Pad neutralize/close and user-service
termination, AudioOut close, GDI reset, VideoOut close, framebuffer unmap and
direct-memory release, AGC batch unmap/direct-memory release/virtual unmap/
module unload, DBT destruction, PE release and all four guest VM releases.

## Physical gameplay follow-up

The owner subsequently confirmed Cross plunger control, L1/R1 flippers,
scoring, a complete ball-loss/new-ball cycle, Options pause/resume and Square
new-game restart. An initially suspected stale
ball at the drain was disproved rather than patched: synchronized Remote Play
inspection showed the actual ball moving and later waiting in the right-hand
launcher, while live renderer state contained exactly one ball sprite. The
silver circle below the center lamp is also present in the original game
reference and is fixed table artwork. Temporary target-specific tracing used
for this classification was removed after the diagnosis.

The same play session exposed an actual missing x87 register-store form,
`FST ST(i)` (`DD D0+i`). Supporting that non-popping transfer prevented the
classified execute abort reached during flipper-adjacent physics. Unit tests
cover the instruction decode, register-stack semantics and captured
`FST ST(1); FSTP ST(0); FSTP m32real` sequence.

The clean post-fix production candidate has linked ELF SHA-256
`b5071e1ed0cab2fb64a4fe280d82b0059fc305ebfd95ac3681610cb25715a6cc`
and deployed fSELF SHA-256
`baed8c4fc70d10c7c63fba9822611df1e9edd241db2c885eb1d025701e1f7782`.
It launched as run
`20260911T080302217Z_PPSA99995_prospero-win_0x1d780c2f70b6d`; structured
telemetry established the expected DBT, GDI/AGC, AudioOut, Pad and persistent
state paths before the physical gameplay checklist passed. This establishes
Pinball as prospero-win's first playable compatibility target. It does not
claim a finished general runtime; pacing and presentation polish remain.
VideoOut unregister returned `0x80290009`, the measured resource-busy result;
closing VideoOut completed the observed deferred-release path and all later
resource releases succeeded. A title-manager kill cannot execute in-process
teardown and is classified separately from these orderly exits.

The exact current source also passed a fresh 18-second bounded gate as run
`20260911T011502976Z_PPSA99995_prospero-win_0x1c13d51ccd468`, linked ELF
SHA-256 `1bbf0feb14fff05350fc315277c45967b9a5ac171b2b9a4a213501bce42fe207`
and fSELF SHA-256
`3056195f1eb7f957c5134c572c04c08d566cb72ae438e4a46cee2d5a2cdbacd0`.
It loaded 473 state bytes, retired 13,784,396 guest instructions, presented
10 changing frames, emitted 878 complete audio blocks and ended gap-free with
the same all-subsystem teardown plus `BYE reason=validation-deadline`. The
runtime-evidence validator accepts its final `PW_RUNTIME_END` counters, which
include work after the last five-second heartbeat.

## Pending performance and system-close candidate

The async-audio/hashed-DBT candidate is not the artifact in the latest recorded
hardware run. Run
`20260912T221018758Z_PPSA99995_prospero-win_0x109083e5e5ec` reports schema 1,
blocks in the earlier synchronous audio path and ended by transport EOF without
`PW_RUNTIME_END` or `BYE`. It therefore documents an externally killed old
runtime, not validation of the performance change.

The current candidate also applies the lifecycle correction already merged in
the Gears and Xash3D renderers: after each successful
`sceAgcDriverSubmitDcb`, it invokes the real `sceAgcSuspendPoint`. A completion
fence protects command/data reuse; the suspend point independently allows the
system to suspend the AGC queue during Close Game. Host tests enforce ordering,
no suspend call after failed submission, suspend-error propagation and missing
callback rejection.

Hardware acceptance remains explicit: deploy the exact candidate, refresh
ShadowMountPlus once for changed title contents, confirm schema-2 queue/DBT
telemetry, then close and relaunch the title without a system-software error.
An external title-manager kill may still end telemetry at EOF because it cannot
guarantee in-process teardown; the close/relaunch observation and absence of a
GPU suspend timeout are the relevant system-close evidence.
