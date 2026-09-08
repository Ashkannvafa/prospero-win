# Provenance and attribution

## Licence

prospero-win is LGPL-2.1-or-later; see `LICENSE` and `LICENSING.md`. Every
source file carries an SPDX identifier. The vendored `ps5log` client below
is the laboratory's own code, under the same terms as its origin, and is
digest-pinned rather than modified here.

## Independently authored

The PE reader, layout planner, relocation engine, import reader, manual
mapper, dependency loader, gate report, memory and file contracts, host
tools, synthetic PE encoders and evidence validator in this repository are
written for this project. No Windows loader source, no Wine source and no
proprietary SDK file is copied into it.

The PE/COFF structures the reader parses are described by Microsoft's
published PE format specification. Only field offsets and semantics are
used; no Microsoft code, header or binary is included.

## Reused from the laboratory

- `native/ps5log/` is a verbatim copy of the `ps5log/1` client from the
  private laboratory's `projects/logging_server/client/`. It is pinned by
  SHA-256 in `tools/audit_publication.py`, so editing it here — which would
  silently fork the canonical client — fails the audit.
- The native shell, linker script, CRT and signing tool come from
  [BlackBearReloaded's PS5 Native App Boilerplate](https://github.com/blackbearreloaded/ps5-native-app-boilerplate),
  pinned by commit in `tools/build_native.sh` and fetched at build time.
  None of it is vendored here.

## Measured platform facts reused

Several design decisions follow limits the laboratory measured on FW 12.02
for its own ports rather than anything discovered here: the libc heap
ceiling and the resulting use of anonymous mappings for large allocations,
the unusability of libc directory listing on the read-only application
image, `sceKernelOpen` with libc `read`/`lseek` as the working file path, the
absence of a supported read-write to read-execute transition, and the rule
that a title must not return from `main()`. Each is cited where it shapes the
code.

## Not included

No game data, no third-party DLL, no firmware dump, no disassembly and no
decompiled output. Windows binaries are private build inputs supplied by
path at build time.
