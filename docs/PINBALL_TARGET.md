# First game: Windows Space Cadet Pinball

Target: execute the owner's original x86 PINBALL.EXE through prospero-win
without recompilation, display through the PS5 GPU, accept DualSense input
and support operator-controlled closure.

Status: owner's executable inspected on 2026-09-08. SHA-256:
`2bbc8234685fe2f6324040af6ea20123cf00c4a56882ce0d9074f0beefac67bc`.
PE32/i386, 281088 file bytes, 307200 image bytes, required base 0x01000000,
no base relocations. Static imports: 207 symbols across eight DLLs.
GDI32 supplies BitBlt/StretchDIBits and palettes; WINMM supplies waveOut,
MMIO and MCI. No static DirectDraw/Direct3D imports were found. LoadLibraryA
and GetProcAddress require further dynamic dependency analysis. Exact
version metadata and runtime working set remain unverified.

An independent host objdump inspection confirms stripped relocations,
no TLS directory and no delay-import directory. It does contain a bound
import directory and preserves the original name lookup tables. Rebind all
IAT entries from those tables; existing bound Windows addresses cannot be
called on PS5. The IAT is at RVA 0x1000 in .text, so binding must precede
final RX protection. Load-configuration and x86 exception/CRT semantics
still require inspection. Header stack reserve/commit: 256/64 KiB; heap
reserve/commit: 1 MiB/4 KiB. These are header requests, not measured usage.

## Host mapping result (2026-09-08)

The original binary above now maps through the loader at 0x01000000 without
relocations. The host run reported 307200 reserved bytes, nine graph nodes
(one image plus eight unimplemented host bindings), 75 host pages, zero WX
pages, four protection calls and balanced file ownership (one open/close).
Mapped checksum: 0x1bd76edecdb503e8 (the loader's existing checksum format).
This is host mapping evidence only: no guest instruction was executed and
no import address was bound. The subsequent PS5 result below covers the
16 KiB protection granularity versus the host's 4 KiB pages.

The VM backend now advertises optional exact-address reservation. It uses
an mmap hint, checks the returned address and releases an alternative
placement. A collision returns failure without replacing the existing
mapping. Synthetic tests hold a live sentinel-filled reservation while
attempting collision, then verify its bytes and test reuse after release.
Nonrelocatable images request their required base; relocatable fixtures
retain the existing arbitrary-placement path to keep rebase tests meaningful.

## PS5 mapping result (FW 12.02, 2026-09-08)

Run: `20260908T145242477Z_PPSA99995_prospero-win_0x1021ed623a4eb`.
Source commit: `013f328`. Native foundation: `37dd53602bdead63936f718004555ba10154be48`.

- Linked ELF SHA-256: `e2f50373caa17180a2df3b62ce191b1073105b73a2ff8e9ab35a219b5d5d836a`.
- fSELF SHA-256: `a42636fe23e3f56236f54ce1ca6426d298ea56212f3624850f7de0b1a90d05b4`.
- Transcript SHA-256: `c05b8973e6ba718a6022c67fd0ac8a5b5fe9524d715360cb40508a467cc36799`.
- Original file SHA-256 is pinned above; FTP verified all staged bytes.
- Actual/preferred base both 0x01000000; no relocations; 207 static imports.
- Image 307200 bytes; reservation 311296 bytes; 19 pages of 16384 bytes.
- Three verified sections; 279612 compared bytes; zero byte/zero-tail/alias
  mismatches; checksum 0x1bd76edecdb503e8 matches the host result.
- Three pages merge section/header contributors; one page is WX; four
  protection calls. WX remains a measured limitation, not a solved one.
- Nine graph nodes, eight host bindings, one mapped and released image;
  opens=closes=1, failures=0; clean BYE with reason pe-map-complete.
- Post-run supervisor status: no active BigApp; all four services healthy.

The independent validator accepted the manifest with:

```sh
python3 tools/validate_pe_map_evidence.py /private/path/run.json \
  --root pinball.exe --expect-modules 9 --expect-local 0 --expect-host 8 \
  --allow-i386 --allow-wx --expect-compat32 refused
```

This proves mapping the original PE32 file in the native title. It does not
prove guest execution, bound imports, rendering or playability. The gate
intentionally exits after the measurement; the eventual game runs until
operator closure.

## Inventory

Keep executable and resources outside this public project:

```sh
sha256sum /private/path/PINBALL.EXE
make inspect-only PE_INPUT=/private/path/PINBALL.EXE
```

This reads headers, layout and ordinary import names/ordinals without
mapping guest memory, resolving DLLs or executing code. Host/local labels
describe provisional policy, not Windows search-order conformance.
Malformed imports must return failure.

Record hash, version, machine, subsystem, image size, relocations, static
imports and resource filenames in a private inventory. Separately inspect
TLS, resources, delay imports and GetProcAddress/LoadLibrary calls; the
inspector does not enumerate those yet. Imports are not a full runtime trace.

## Acceptance and reference

Follow P0–P6 in ROADMAP.md. First output must come from the original
executable. Playability means launching a ball, both flippers, scoring and
restart with correct timing. Completion adds audio, persistence, stable
sessions and structured lifecycle evidence. Video alone does not prove
artifact identity, renderer completion or cleanup.

[SpaceCadetPinball](https://github.com/k4zmu2a/SpaceCadetPinball) provides
MIT-licensed reconstructed source and a modern SDL implementation useful
for understanding behavior. Its API choices do not establish the original
binary's imports. A native port is separate from Windows binary compatibility.
Original resources are not included upstream or here.

## Graphics direction

Implement observed graphics calls through a reusable AGC backend. Surface
upload/composition may combine CPU work with GPU presentation; report the
actual division. Showing Pinball does not prove Direct3D acceleration or
complete GDI/DirectDraw support.

Wine and DXVK are references or potential component sources under their
licences. D3D-to-AGC and DXVK plus Vulkan-on-AGC are later alternatives to
measure. DRM, anti-cheat and kernel drivers are out of scope.

## Reuse the Xash3D platform work

Reviewed ps5-xash3d commit 3a3025016131a440782fd1c0e123a85d512887e3.
Canonical files are xash/platform_ps5/audio_ps5.c/.h and in_ps5.c/.h;
SNDDMA adapter s_ps5.c remains engine-specific. SCEAUDIOOUT_PHASE5.md,
SCEPAD_PHASE5.md and HARDWARE_VALIDATION.md document FW 12.02 evidence.

- Audio: reuse the PCM ring/worker lifecycle, blocking-output ownership,
  whole 256-frame submission, resampling continuity and teardown tests.
  The current core is stereo S16, 44100-to-48000 Hz, not a general Windows
  audio backend. Adapt the formats/rates actually requested by Pinball.
- WinMM adapter: implement guest WAVEHDR layout, queue ownership,
  prepare/unprepare, pause/restart/reset and completion callbacks/messages.
  Copying PCM out of the producer ring is not proof it has played; preserve
  buffer lifetime and completion semantics. Route guest callbacks through
  the runtime rather than executing guest code on the AudioOut worker.
- MCI/MIDI and MMIO remain additional work; PCM output does not synthesize
  MIDI or implement Windows multimedia commands.
- Input: reuse chronological ScePad batches, press/release transitions,
  neutralisation on disconnect/interception/generation change and exact
  close ownership. Adapt events to Win32 key/mouse messages and window
  callbacks, rather than Xash movement actions. Pinball has no static
  DirectInput import, so a DirectInput implementation is not the first task.
- Preserve the tested contracts and ps5log/1 counters. Adapted backends need
  their own prospero-win hardware evidence; Xash evidence is the baseline.

The source files currently declare GPL-3.0-or-later; prospero-win declares
LGPL-2.1-or-later. Before extracting source, resolve and document compatible
component licensing/provenance. No source has been copied by this review.
