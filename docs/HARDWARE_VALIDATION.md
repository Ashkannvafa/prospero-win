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
this evidence closes visible-and-audible P4.5, not pixel-perfect rendering or
playability.

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
