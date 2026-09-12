# Telemetry contract

The current native game runner uses `ps5log/1` over TCP exclusively. It does
not write logs to console storage or USB. Its continuous-runtime records are:

| Record | Carries |
| --- | --- |
| `PW_RUNTIME_BEGIN` | schema, title, private root basename and telemetry init status |
| `PW_RUNTIME_READY` | bound import count, guest entry and mapped image bytes |
| `PW_STATE_LOAD` / `PW_STATE_SAVE` | persistent registry bytes/generation and atomic-write syscall results |
| `PW_PAD_OPEN` / `PW_PAD_EVENT` / `PW_PAD_QUIT` | native ownership, physical press/release counters and an explicit Create-to-WM_QUIT lifecycle edge; absence of events never implies simulated input |
| `PW_VIDEO_FRAME` | changing frame hash, dimensions, flip/submit totals, `agc-dma` backend and completed fence state |
| `PW_AUDIO_OPEN` | requested guest PCM format and native-open result |
| `PW_AUDIO_QUEUE` | worker state, enqueue/completion counts, live/high-water depth, queue-full events, consumed blocks and output errors |
| `PW_RUNTIME_HEARTBEAT` | events, retired instructions, DBT cache/protection metrics, main-loop gap counters, adapter calls, window/GDI ownership, AGC flips, audio, pad, INI, MCI and idle-yield counters |
| `PW_GDI_STRETCH` | last observed StretchDIBits source/destination rectangle and DIB identity |
| `PW_RUNTIME_TEARDOWN` | result of every ordered backend/resource release |
| `PW_RUNTIME_END` | normal reason, guest exit code and final work counters |
| `PW_RUNTIME_ABORT` | classified stage and status before fail-closed exit |
| `PW_RUNTIME_SIGNAL` | signal, fault address and native register context before exit |

The production runner has no deadline and continues until the guest exits or
the operator closes it. `PW_TEST_EXIT_AFTER_MS` builds are validation-only and
exercise the same orderly teardown path with a bounded deadline.
Absence of `PW_RUNTIME_ABORT`/`PW_RUNTIME_SIGNAL`, rising heartbeats and an
external BigApp status are required to classify it as live. Audio acceptance
requires nonzero bytes, frames, blocks and hash; a successful open alone is
insufficient. Capture acceptance separately requires both a video and audio
stream, while renderer/audio ownership remains grounded in telemetry. See
HARDWARE_VALIDATION.md.

The asynchronous audio gate additionally requires `worker=1`, rising enqueue
and completion counts, `full=0`, `output_errors=0`, and a bounded high-water
mark. `loop_gap_max_ns`, `loop_gaps_16ms` and `loop_gaps_33ms` measure the
guest-thread symptom directly. DBT telemetry reports dispatches, compiles,
hits/misses, total/max hash probes and page-scoped protection calls/bytes. None
of these counters alone is a performance claim; compare identical scripted
workloads and exact artifacts.

Validate a live continuous transcript with:

```sh
python3 tools/validate_runtime_evidence.py <run.log> --continuous \
  --min-seconds 600 --min-flips 1000 --min-audio-blocks 800
```

Omit `--continuous` for a bounded orderly-exit transcript. The validator
requires exact title/app identity, contiguous sequence numbers, loaded
persistent state, native pad ownership, nonzero DBT/adapter/presentation/audio/
INI/pacing evidence, zero pad/profile errors and—on finite runs—successful
teardown plus a matching `BYE`. Its mutation tests prevent a missing or broken
field from passing silently. A bounded run takes its final flip/audio totals
from `PW_RUNTIME_END`, so work after the last heartbeat is not discarded.

After the owner's physical gameplay checklist, validate controller activity
and the Create-to-WM_QUIT exit in the same transcript with:

```sh
python3 tools/validate_runtime_evidence.py <run.log> \
  --min-seconds 60 --min-flips 100 --min-audio-blocks 800 \
  --min-pad-events 12 --require-pad-quit
```

This proves physical edges crossed the adapter and the orderly exit ran; the
owner's visual confirmation remains authoritative for scoring, ball loss and
the semantic effect of each mapped control.

The records below belong to the earlier finite PE mapping gate, which remains
available as a separate synthetic validation path.

## Synthetic Win64 call probe

Before loading the staged PE, the native adapter logs call6-begin and runs
project-authored code through the assembly SysV-to-Win64 bridge. PW_CALL6
records kind=synthetic-code, status, constant=42, alignment=8, weighted=278,
high=4294967574, sealed=1 and released=1. The code is constructed RW and
protected RX before calls; it is independent of Pinball's mapped image.

The validator checks exact results and uniqueness whenever this record is
present. --expect-call6 also rejects its absence, preserving validation of
older mapping-only runs. A successful record proves only the tested integer
call path, not PE32 execution, complete ABI preservation or Win32 imports.

## Image mapping records

One load produces one record set. The runtime does not format telemetry ad
hoc: `src/pw_gate.c` fills a report and the adapter emits each line verbatim
through `ps5log/1` over TCP. There are no log files on the console, no USB
and no filesystem fallback.

Formatting uses bounded in-tree helpers rather than `snprintf`. Every record
is shorter than the transport's per-record budget, which
`tests/test_native_contract.py` checks against the client header, so a record
can never be truncated into a transport error.

## Records

| Record | Emitted | Carries |
| --- | --- | --- |
| `PW_BEGIN` | once, before anything else | title, stage directory, root module, telemetry init results, registry size |
| `PW_FS_SMOKE` | once, before parsing | `sceKernelStat`/`sceKernelOpen`/`read`/`lseek`/`sceKernelClose` results, file size, first two bytes, `is_pe` |
| `PW_BOOT` | once | `schema`, `slice=pe-map`, root name and size, provider path, protection granularity, whether the backend aliases execution, module capacity |
| `PW_MODULE` | one per module | index, canonical name, kind, machine, whether natively executable, DLL flag, depth, dependency count, mapped flag, section count, image size, actual and preferred base, relocation blocks and applications, import count, zero-fill total, every verification counter, header presence, mapping checksum |
| `PW_DEP` | one per graph edge | module index and name, dependency index, name and kind |
| `PW_ORDER` | one per load position | position, module index, name |
| `PW_GRAPH` | once | module, local and host counts, cycle edges, maximum depth, reserved bytes, ordered count, instruction set |
| `PW_PROTECT` | one per mapped module | whether protections were installed, page total, merged pages, writable-executable pages, no-access pages, protect calls |
| `PW_FILES` | once | provider opens, closes, failures, bytes read |
| `PW_EXIT` | once, last | result and status name, module total, mapped and released counts, first missing dependency, truncated line count |
| `PW_ABORT` | instead of a gate run | the stage that refused, and why |

A failing run still emits `PW_BOOT` and `PW_EXIT`. A run that produces no
evidence is worse than a run that fails.

## Why the edges are emitted

`PW_ORDER` is the runtime's conclusion about load order. `PW_DEP` is the
evidence for it. `tools/validate_pe_map_evidence.py` re-derives the property
— every dependency at an earlier position, unless `PW_GRAPH` admits a cycle
— from the edges, and cross-checks each edge count against the module's own
declared `deps`. An independent checker that can only agree with the program
it is checking is not a checker.

## Validation

```sh
python3 tools/validate_pe_map_evidence.py <manifest> \
  --root sample.exe --expect-modules 4 --expect-local 1 --expect-host 2
```

The accepted-run conditions are listed in `PE_MAPPING_PHASE0.md`. Two
weakenings need an explicit flag, so neither can be accepted by accident:

- `--allow-i386` accepts a parse-and-map-only run of a 32-bit image, which
  cannot execute on this hardware;
- `--allow-wx` accepts writable-executable pages forced by a protection
  granularity coarser than the image's section alignment.

`tests/test_validate_pe_map_evidence.py` drives the validator with a
transcript the real gate produced (`test_pw_gate --emit`), then mutates that
transcript one field at a time. The validator is therefore tested against the
format the runtime actually emits, not against a hand-written imitation.
