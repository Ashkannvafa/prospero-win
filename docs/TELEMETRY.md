# Telemetry contract

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
