#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Generate synthetic PE images for prospero-win gates.

No Windows binary is committed to this repository and none is needed to
exercise the loader. This tool writes complete PE32 and PE32+ images with
real section tables, import descriptors and base-relocation blocks, so the
hardware gate can be staged from bytes the laboratory produced itself.

It is a second, independent encoder: `tests/test_make_test_pe.py` feeds its
output to the C parser through `inspect_pe`, so an error in either encoder
cannot silently certify the other.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path

DOS_MAGIC = 0x5A4D
NT_SIGNATURE = 0x00004550
OPT_MAGIC_PE32 = 0x010B
OPT_MAGIC_PE32PLUS = 0x020B
OPT_FIXED_PE32 = 0x60
OPT_FIXED_PE32PLUS = 0x70
MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
NT_OFFSET = 0x40
FILE_HEADER_BYTES = 20
SECTION_HEADER_BYTES = 40
DIRECTORY_ENTRIES = 16
DIR_IMPORT = 1
DIR_BASERELOC = 5

SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

FILE_EXECUTABLE_IMAGE = 0x0002
FILE_32BIT_MACHINE = 0x0100
FILE_DLL = 0x2000
DLLCHAR_DYNAMIC_BASE = 0x0040
DLLCHAR_NX_COMPAT = 0x0100

RELOC_HIGHLOW = 3
RELOC_DIR64 = 10


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


@dataclass
class Section:
    name: str
    characteristics: int
    data: bytes = b""
    virtual_size: int = 0


@dataclass
class Import:
    dll: str
    names: tuple[str, ...] = ()
    ordinals: tuple[int, ...] = ()


@dataclass
class Spec:
    name: str
    pe32plus: bool = True
    machine: int | None = None
    dll: bool = False
    image_base: int | None = None
    section_alignment: int = 0x1000
    file_alignment: int = 0x200
    entry_point_offset: int = 0
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    relocate_data_pointer: bool = True


class _Blob:
    """Growable little-endian byte buffer."""

    def __init__(self) -> None:
        self.data = bytearray()

    def __len__(self) -> int:
        return len(self.data)

    def append(self, chunk: bytes) -> int:
        offset = len(self.data)
        self.data += chunk
        return offset

    def u16(self, value: int) -> int:
        return self.append(struct.pack("<H", value))

    def u32(self, value: int) -> int:
        return self.append(struct.pack("<I", value))

    def pad_to(self, alignment: int) -> None:
        self.data += b"\0" * (align_up(len(self.data), alignment) - len(self.data))


def _build_import_blob(spec: Spec, base_rva: int) -> bytes:
    """Descriptors, thunk tables, hint/name entries and DLL name strings."""
    width = 8 if spec.pe32plus else 4
    ordinal_flag = 1 << 63 if spec.pe32plus else 1 << 31
    pack = "<Q" if spec.pe32plus else "<I"

    descriptors_bytes = (len(spec.imports) + 1) * 20
    tail = _Blob()
    lookup_offsets: list[int] = []
    address_offsets: list[int] = []
    name_offsets: list[list[int]] = []
    dll_offsets: list[int] = []

    def tail_rva(offset: int) -> int:
        return base_rva + descriptors_bytes + offset

    for entry in spec.imports:
        name_offsets.append([])
        for name in entry.names:
            tail.pad_to(2)
            name_offsets[-1].append(len(tail))
            tail.u16(1)
            tail.append(name.encode("ascii") + b"\0")
    for entry in spec.imports:
        dll_offsets.append(len(tail))
        tail.append(entry.dll.encode("ascii") + b"\0")

    tail.pad_to(width)
    for index, entry in enumerate(spec.imports):
        thunks = [tail_rva(offset) for offset in name_offsets[index]]
        thunks += [ordinal_flag | ordinal for ordinal in entry.ordinals]
        for table in ("lookup", "address"):
            offsets = lookup_offsets if table == "lookup" else address_offsets
            offsets.append(len(tail))
            for value in thunks:
                tail.append(struct.pack(pack, value))
            tail.append(struct.pack(pack, 0))

    descriptors = _Blob()
    for index, entry in enumerate(spec.imports):
        descriptors.u32(tail_rva(lookup_offsets[index]))
        descriptors.u32(0)                                  # TimeDateStamp
        descriptors.u32(0)                                  # ForwarderChain
        descriptors.u32(tail_rva(dll_offsets[index]))
        descriptors.u32(tail_rva(address_offsets[index]))
    descriptors.append(b"\0" * 20)                          # terminator
    assert len(descriptors) == descriptors_bytes
    return bytes(descriptors.data + tail.data)


def _build_reloc_blob(targets: list[tuple[int, int]], alignment: int) -> bytes:
    blob = _Blob()
    index = 0
    targets = sorted(targets)
    while index < len(targets):
        page = targets[index][0] & ~(alignment - 1)
        entries = []
        while index < len(targets) and (targets[index][0] & ~(alignment - 1)) == page:
            rva, kind = targets[index]
            entries.append((kind << 12) | (rva - page))
            index += 1
        if len(entries) % 2:
            entries.append(0)                               # ABSOLUTE padding
        blob.u32(page)
        blob.u32(8 + 2 * len(entries))
        for entry in entries:
            blob.u16(entry)
    return bytes(blob.data)


def build_pe(spec: Spec) -> bytes:
    """Encode one complete image and return its bytes."""
    if not spec.sections:
        raise ValueError("a PE image needs at least one section")
    machine = spec.machine
    if machine is None:
        machine = MACHINE_AMD64 if spec.pe32plus else MACHINE_I386
    image_base = spec.image_base
    if image_base is None:
        image_base = 0x140000000 if spec.pe32plus else 0x400000
    if image_base % spec.section_alignment:
        raise ValueError("image base must be section aligned")

    optional_fixed = OPT_FIXED_PE32PLUS if spec.pe32plus else OPT_FIXED_PE32
    optional_bytes = optional_fixed + 8 * DIRECTORY_ENTRIES
    sections = list(spec.sections)
    total_sections = len(sections) + len(
        [part for part in (spec.imports, spec.relocate_data_pointer) if part]
    )
    header_bytes = align_up(
        NT_OFFSET + 4 + FILE_HEADER_BYTES + optional_bytes +
        total_sections * SECTION_HEADER_BYTES,
        spec.file_alignment,
    )

    # First pass: place the caller's sections so the generated ones can
    # reference real addresses.
    placed: list[dict[str, object]] = []
    next_rva = align_up(header_bytes, spec.section_alignment)
    for section in sections:
        virtual_size = section.virtual_size or len(section.data)
        if virtual_size == 0:
            raise ValueError(f"section {section.name} is empty")
        placed.append({
            "name": section.name,
            "characteristics": section.characteristics,
            "rva": next_rva,
            "virtual_size": virtual_size,
            "data": section.data,
        })
        next_rva += align_up(virtual_size, spec.section_alignment)

    data_rva = next(
        (int(entry["rva"]) for entry in placed if entry["name"] == ".data"),
        int(placed[0]["rva"]),
    )
    entry_point = int(placed[0]["rva"]) + spec.entry_point_offset

    if spec.imports:
        blob = _build_import_blob(spec, next_rva)
        placed.append({
            "name": ".idata",
            "characteristics": SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ |
                               SCN_MEM_WRITE,
            "rva": next_rva,
            "virtual_size": len(blob),
            "data": blob,
        })
        import_rva = next_rva
        import_size = (len(spec.imports) + 1) * 20
        next_rva += align_up(len(blob), spec.section_alignment)
    else:
        import_rva = import_size = 0

    if spec.relocate_data_pointer:
        kind = RELOC_DIR64 if spec.pe32plus else RELOC_HIGHLOW
        blob = _build_reloc_blob([(data_rva, kind)], spec.section_alignment)
        placed.append({
            "name": ".reloc",
            "characteristics": SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ |
                               SCN_MEM_DISCARDABLE,
            "rva": next_rva,
            "virtual_size": len(blob),
            "data": blob,
        })
        reloc_rva = next_rva
        reloc_size = len(blob)
        next_rva += align_up(len(blob), spec.section_alignment)
    else:
        reloc_rva = reloc_size = 0

    size_of_image = next_rva
    if len(placed) != total_sections:
        raise AssertionError("section accounting mismatch")

    # Second pass: raw offsets and the final byte stream.
    next_raw = header_bytes
    for entry in placed:
        data = bytes(entry["data"])                         # type: ignore[arg-type]
        raw_size = align_up(len(data), spec.file_alignment)
        entry["raw_size"] = raw_size
        entry["raw_offset"] = next_raw if raw_size else 0
        next_raw += raw_size

    image = bytearray(next_raw)
    struct.pack_into("<H", image, 0, DOS_MAGIC)
    struct.pack_into("<I", image, 0x3C, NT_OFFSET)
    struct.pack_into("<I", image, NT_OFFSET, NT_SIGNATURE)

    file_header = NT_OFFSET + 4
    characteristics = FILE_EXECUTABLE_IMAGE
    if spec.dll:
        characteristics |= FILE_DLL
    if not spec.pe32plus:
        characteristics |= FILE_32BIT_MACHINE
    struct.pack_into("<H", image, file_header, machine)
    struct.pack_into("<H", image, file_header + 2, total_sections)
    struct.pack_into("<H", image, file_header + 16, optional_bytes)
    struct.pack_into("<H", image, file_header + 18, characteristics)

    optional = file_header + FILE_HEADER_BYTES
    struct.pack_into("<H", image, optional,
                     OPT_MAGIC_PE32PLUS if spec.pe32plus else OPT_MAGIC_PE32)
    struct.pack_into("<I", image, optional + 0x10, entry_point)
    struct.pack_into("<I", image, optional + 0x14, int(placed[0]["rva"]))
    if spec.pe32plus:
        struct.pack_into("<Q", image, optional + 0x18, image_base)
    else:
        struct.pack_into("<I", image, optional + 0x18, data_rva)
        struct.pack_into("<I", image, optional + 0x1C, image_base)
    struct.pack_into("<I", image, optional + 0x20, spec.section_alignment)
    struct.pack_into("<I", image, optional + 0x24, spec.file_alignment)
    struct.pack_into("<H", image, optional + 0x30, 4)       # subsystem version
    struct.pack_into("<I", image, optional + 0x38, size_of_image)
    struct.pack_into("<I", image, optional + 0x3C, header_bytes)
    struct.pack_into("<H", image, optional + 0x44, 3)       # console
    struct.pack_into("<H", image, optional + 0x46,
                     DLLCHAR_DYNAMIC_BASE | DLLCHAR_NX_COMPAT)
    struct.pack_into("<I", image, optional + optional_fixed - 4,
                     DIRECTORY_ENTRIES)

    directories = optional + optional_fixed
    if import_size:
        struct.pack_into("<I", image, directories + 8 * DIR_IMPORT, import_rva)
        struct.pack_into("<I", image, directories + 8 * DIR_IMPORT + 4,
                         import_size)
    if reloc_size:
        struct.pack_into("<I", image, directories + 8 * DIR_BASERELOC,
                         reloc_rva)
        struct.pack_into("<I", image, directories + 8 * DIR_BASERELOC + 4,
                         reloc_size)

    table = optional + optional_bytes
    for index, entry in enumerate(placed):
        offset = table + index * SECTION_HEADER_BYTES
        name = str(entry["name"]).encode("ascii")[:8]
        image[offset:offset + len(name)] = name
        struct.pack_into("<I", image, offset + 8, int(entry["virtual_size"]))
        struct.pack_into("<I", image, offset + 12, int(entry["rva"]))
        struct.pack_into("<I", image, offset + 16, int(entry["raw_size"]))
        struct.pack_into("<I", image, offset + 20, int(entry["raw_offset"]))
        struct.pack_into("<I", image, offset + 36,
                         int(entry["characteristics"]))
        data = bytes(entry["data"])                         # type: ignore[arg-type]
        start = int(entry["raw_offset"])
        image[start:start + len(data)] = data

    return bytes(image)


def sample_chain(pe32plus: bool = True) -> dict[str, bytes]:
    """A root executable, a third-party DLL it needs, and one host import.

    The shape mirrors a real classic PC game: the executable pulls in a
    vendor codec DLL that must be mapped for real, plus Win32 modules that
    prospero-win implements itself and never loads from disk.
    """
    code = bytes([0x48, 0x31, 0xC0, 0xC3]) if pe32plus else bytes([0x31, 0xC0, 0xC3])
    pointer = struct.pack("<Q" if pe32plus else "<I", 0)

    root = Spec(
        name="sample.exe",
        pe32plus=pe32plus,
        sections=[
            Section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE,
                    code.ljust(64, b"\x90")),
            Section(".data", SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ |
                    SCN_MEM_WRITE, pointer.ljust(64, b"\0")),
            Section(".bss", SCN_CNT_UNINITIALIZED_DATA | SCN_MEM_READ |
                    SCN_MEM_WRITE, b"", virtual_size=0x2000),
        ],
        imports=[
            Import("binkw32.dll", names=("BinkOpen", "BinkDoFrame")),
            Import("KERNEL32.dll", names=("CreateFileA",), ordinals=(0x0123,)),
        ],
    )
    codec = Spec(
        name="binkw32.dll",
        pe32plus=pe32plus,
        dll=True,
        image_base=(0x180000000 if pe32plus else 0x10000000),
        sections=[
            Section(".text", SCN_CNT_CODE | SCN_MEM_READ | SCN_MEM_EXECUTE,
                    code.ljust(64, b"\x90")),
            Section(".data", SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ |
                    SCN_MEM_WRITE, pointer.ljust(32, b"\0")),
        ],
        imports=[Import("msvcrt.dll", names=("malloc", "free"))],
    )
    return {spec.name: build_pe(spec) for spec in (root, codec)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="directory to write the sample chain into")
    parser.add_argument("--i386", action="store_true",
                        help="emit PE32/i386 instead of PE32+/amd64")
    arguments = parser.parse_args()

    arguments.out_dir.mkdir(parents=True, exist_ok=True)
    written = sample_chain(pe32plus=not arguments.i386)
    for name, data in written.items():
        path = arguments.out_dir / name
        path.write_bytes(data)
        print(f"{path} {len(data)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
