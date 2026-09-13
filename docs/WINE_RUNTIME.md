# Reproducible i386 Wine PE runtime

Wine PE modules are build inputs, not sources of this repository. This
document defines how they are produced, how their identity is recorded and
what a second developer has to reproduce to obtain the same bytes.

The pinned reference is:

```text
Wine 490f6d5dcbb2a5047345b8af88d114bbcaad69a8  (Wine version 11.17)
```

## What is staged

`tools/build_wine_runtime.sh` builds the selected i386 PE modules and stages
them, with a manifest, into an ignored directory:

```text
.deps/wine-runtime/
    lib/i386-windows/ntdll.dll
    lib/i386-windows/kernelbase.dll
    lib/i386-windows/kernel32.dll
    wine-runtime-manifest.json
```

`ntdll`, `kernelbase` and `kernel32` are the first boot attempt's module set:
`kernel32` forwards into `kernelbase`, `kernelbase` forwards into `ntdll`, and
`ntdll` owns the versioned Unix-call boundary named in
[WINE_INTEGRATION.md](WINE_INTEGRATION.md). Nothing else is selected yet, so
the staged runtime is deliberately not a complete Win32 surface.

The modules are PE32/i386 images. The Unix-side modules (`*.so`) are *not*
staged: they are not loadable objects on this target, and the whole point of
the DBT is that guest PE code runs natively translated instead.

## Reproducing the build

```sh
# A clean checkout of the pinned revision is required. The script clones one
# when PROSPERO_WINE_SOURCE does not exist.
export PROSPERO_WINE_SOURCE=/private/wine-11.17
export PROSPERO_WINE_ROOT=/private/wine-build
tools/build_wine_runtime.sh --check-reproducible
```

Requirements the script enforces rather than assumes:

- the checkout is clean and its `HEAD` is exactly the pinned commit;
- the build is out-of-tree, in `PROSPERO_WINE_ROOT/build`;
- the environment is normalised: `LC_ALL=C`, `TZ=UTC`,
  `SOURCE_DATE_EPOCH=1000000000`;
- the configure line is fixed:
  `--enable-archs=i386,x86_64 --disable-tests`.

`--check-reproducible` performs two clean builds and compares every staged
module byte for byte before writing the manifest. On this host the PE linker
is GNU `ld` (binutils) through `i686-w64-mingw32-gcc`; it honours
`SOURCE_DATE_EPOCH` for the PE timestamp, which is the only non-deterministic
field otherwise present. The observed difference between two builds without
that variable is exactly the file-header `TimeDateStamp` and the derived
optional-header `Checksum`; with it, two clean rebuilds are byte-identical.
No field is zeroed, masked or excluded from the digest.

Tool versions that can change the bytes are recorded in the manifest, because
an identical source revision plus a different linker is a different runtime.

## Manifest contract

`tools/validate_wine_runtime.py write` hashes the staged modules and writes
the manifest; `check` validates a manifest against a staged tree.

The manifest records, per module, the canonical lowercase name, the relative
path inside the distribution, the byte size, the SHA-256 and the PE machine
and magic; plus the Wine commit, the configure line, the normalised
environment, the tool versions and the aggregate digest. The JSON schema is
[WINE_RUNTIME_MANIFEST.schema.json](WINE_RUNTIME_MANIFEST.schema.json).

The aggregate digest is reproducible from the manifest alone:

```text
sha256( concat( sorted_by_name( "name<TAB>size<TAB>sha256\n" ) ) )
```

`check` fails closed on: an unknown schema, an unknown architecture, a second
entry for the same canonical name, a name that is not a lowercase `.dll`, an
absolute or `..`-traversing path, a missing file, a size drift, a hash drift,
a module whose PE machine is not i386, a module that is not PE32, a path that
is not inside the declared library, and an aggregate digest that disagrees
with the module list it is supposed to summarise. Every one of those cases is
exercised by `tests/test_wine_runtime_manifest.py`.

## Publication rules

- Generated PE modules and the build tree stay in ignored directories
  (`.deps/`, `build/`). `tools/audit_publication.py` refuses a Windows binary
  anywhere in the tree, so a staged runtime can never be committed by
  accident.
- No Wine source is vendored. The manifest and this document are the whole
  public footprint of the runtime, and Wine remains LGPL-2.1-or-later with its
  own authorship and notices.
- The runtime directory is configured explicitly on both the host and the PS5
  provider. There is no fallback that would silently load an application-local
  `ntdll.dll`.

## Bounded ntdll entry gate

`tools/wine_ntdll_entry.c` is the integration milestone: it loads the staged
runtime, binds the real module graph, enters one exported ntdll function
through the IA-32 DBT and stops at Wine's versioned Unix-call boundary.

```sh
make build/host/wine_ntdll_entry
build/host/wine_ntdll_entry --runtime .deps/wine-runtime/lib/i386-windows \
    > /private/wine-ntdll-entry.txt
python3 tools/validate_wine_ntdll_evidence.py /private/wine-ntdll-entry.txt \
    --manifest .deps/wine-runtime/wine-runtime-manifest.json \
    --expect-entry NtClose
```

What the gate proves, and what it does not:

- it maps `ntdll.dll` and `kernelbase.dll` from `PW_FILE_RUNTIME`, and binds
  the 428 imports `kernelbase` declares against `ntdll`'s exports with the
  same resolver every other caller uses;
- it identifies the boundary structurally. Wine's i386 PE syscall stubs end in
  `call <__wine_syscall>`, and `__wine_syscall` is the single
  `jmp dword ptr [__wine_syscall_dispatcher]` thunk that references the
  exported dispatcher slot. The gate locates the slot through the export
  directory and the thunk by scanning the mapped `.text`, so the stop address
  is one the manifest-hashed image really contains;
- it enters the exported `NtClose` stub, retires its real instructions and
  stops *before* the dispatcher jump, reporting the syscall number the stub
  encoded (0x0f) and the number observed in EAX;
- it never calls a host Wine function, and it refuses to accept a stop that is
  not the Unix-call boundary.

It does not implement the Unix call, does not create a PEB/TEB, does not run
ntdll's process initialization and is not wired into title startup. A
classified stop is evidence, not a compatibility claim.

### How far real ntdll execution currently gets

Two entry points are measured, each with the engine's chaining, register
residency and lazy-flag modes toggled (four configurations, identical stop
kind, retired count and stop address):

| Entry | Result |
|---|---|
| `NtClose` | stops on the dispatcher thunk after 3 retired instructions, syscall `0x000f` |
| `LdrInitializeThunk` | retires 166 instructions over 22 dispatches and stops at an instruction family the DBT does not translate yet |

Reaching that point required two general instruction families and a minimal
guest thread block, all of which are now implemented and host-tested:

- **FS-prefixed absolute operands** (`mov r32, fs:[disp32]` and
  `mov fs:[disp32], r32`). Wine's ntdll reads `fs:[0x18]` (the TEB self
  pointer) on its first initialization instructions. The segment base is the
  guest's own FS base from `PwX86State`, never the host's, and the offset is
  bounded by the declared FS block before any dereference. GS and FS operands
  with a base or index stay refused.
- **LOCK-prefixed read-modify-write** for the group-1 memory forms
  (`lock add [mem], 1`, which Wine's critical sections use). The emitted host
  instruction carries the same prefix, so the host provides the atomicity; a
  register destination or a pure compare is not a legal LOCK form and stays
  refused.
- A **minimal guest TEB and PEB** owned by the gate: the TEB is what FS points
  at, with the documented NT offsets for `StackBase` (0x04), `StackLimit`
  (0x08), `Self` (0x18) and `ProcessEnvironmentBlock` (0x30), and the PEB is
  handed to ntdll's initialization entry as its first argument.
  `ThreadLocalStoragePointer` (0x2C) stays zero because no module of this
  distribution declares a TLS directory.

Both families have native i386 differential coverage: `make test` runs a
32-bit reference program that installs a real FS base with `set_thread_area`
and executes the same `mov edi, fs:[0x18]` and `lock addl $1, mem`
instructions on the host CPU, and the translated engine's output must match
it byte for byte.

The next unimplemented family on that path is the bit-test group
(`bt r/m32, r32`, `0f a3`), followed by the rest of Wine's loader
initialization, which needs a real PEB/`PEB_LDR_DATA` rather than the gate's
zeroed page. Neither is claimed as working.
