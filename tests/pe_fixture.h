/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Synthetic PE builder for host tests.
 *
 * Tests must never need a Windows binary: no game executable or
 * third-party DLL is committed to this repository or read during
 * `make test`. The builder emits complete PE32 and PE32+ images with real
 * section tables, import descriptors and base-relocation blocks, so parser
 * and mapper behaviour is exercised against bytes the test itself
 * specifies.
 *
 * tools/make_test_pe.py emits the same shape independently; a contract test
 * cross-checks the two encoders against the C parser, so a bug in one
 * cannot quietly certify the other.
 */
#ifndef PROSPERO_WIN_PE_FIXTURE_H
#define PROSPERO_WIN_PE_FIXTURE_H

#include <stdint.h>
#include <string.h>

#include "../src/pe_export.h"
#include "../src/pe_import.h"
#include "../src/pe_tls.h"

enum {
    PE_FIXTURE_MAX_SECTIONS = 8,
    PE_FIXTURE_MAX_IMPORTS = 6,
    PE_FIXTURE_MAX_NAMES = 8,
    /* Enough for a synthetic caller that builds many OBJECT_ATTRIBUTES and
     * stores as many absolute pointers as a real image would. */
    PE_FIXTURE_MAX_RELOCS = 128,
    PE_FIXTURE_MAX_EXPORTS = 16,
    PE_FIXTURE_MAX_TLS_CALLBACKS = 40,
};

typedef struct PeFixtureSection {
    const char *name;
    uint32_t characteristics;
    uint32_t virtual_size;          /* 0 uses data_bytes */
    const void *data;
    uint32_t data_bytes;
} PeFixtureSection;

typedef struct PeFixtureImport {
    const char *dll;
    const char *names[PE_FIXTURE_MAX_NAMES];    /* NULL terminated */
    uint16_t ordinals[PE_FIXTURE_MAX_NAMES];    /* 0 terminated */
} PeFixtureImport;

typedef struct PeFixtureReloc {
    uint32_t rva;
    uint16_t type;
} PeFixtureReloc;

/*
 * One function-table slot. A named entry also appears in the name table; an
 * entry with rva 0 and no forwarder is a sparse ordinal slot, which the
 * parser must reject rather than resolve. A forwarder string is written into
 * the export directory, where the PE format requires it to live.
 */
typedef struct PeFixtureExport {
    const char *name;               /* NULL: ordinal-only slot */
    uint32_t ordinal;               /* absolute; 0 means base + position */
    uint32_t rva;                   /* ignored when forwarder is set */
    const char *forwarder;          /* "MODULE.Symbol" or "MODULE.#41" */
} PeFixtureExport;

/*
 * TLS directory, template, index slot and callback array. Callback entries
 * are given as RVAs and written as guest virtual addresses, which is what a
 * PE image stores; `use_rvas` writes them as raw RVAs so a test can prove
 * that a file offset is not accepted as a guest address.
 */
typedef struct PeFixtureTls {
    const void *template_data;
    uint32_t template_bytes;
    uint32_t zero_fill;
    uint32_t characteristics;
    uint32_t callbacks[PE_FIXTURE_MAX_TLS_CALLBACKS];   /* RVAs */
    uint32_t callback_count;
    uint32_t padding_callbacks;     /* valid entries past the bound */
    int no_callbacks_pointer;       /* leave AddressOfCallBacks zero */
    int use_rvas;                   /* malformed: RVAs instead of VAs */
} PeFixtureTls;

typedef struct PeFixtureSpec {
    int pe32plus;
    uint16_t machine;               /* 0 derives from pe32plus */
    uint64_t image_base;
    uint32_t section_alignment;     /* 0 uses 0x1000 */
    uint32_t file_alignment;        /* 0 uses 0x200 */
    uint32_t entry_point;           /* absolute RVA; 0 leaves it unset */
    uint16_t characteristics;       /* 0 derives from dll */
    uint16_t dll_characteristics;
    int dll;
    int omit_lookup_table;          /* emit only FirstThunk, as a bound image */
    uint32_t directory_count;       /* 0 uses 16 */
    PeFixtureSection sections[PE_FIXTURE_MAX_SECTIONS];
    uint32_t section_count;
    PeFixtureImport imports[PE_FIXTURE_MAX_IMPORTS];
    uint32_t import_count;
    PeFixtureReloc relocs[PE_FIXTURE_MAX_RELOCS];
    uint32_t reloc_count;
    PeFixtureExport exports[PE_FIXTURE_MAX_EXPORTS];
    uint32_t export_count;
    uint32_t export_base;           /* 0 uses 1 */
    const char *export_module_name;  /* NULL uses "fixture.dll" */
    int has_tls;
    PeFixtureTls tls;
} PeFixtureSpec;

typedef struct PeFixtureWriter {
    uint8_t *bytes;
    size_t capacity;
    int failed;
} PeFixtureWriter;

static inline uint32_t fx_align(uint32_t value, uint32_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static inline void fx_u8(PeFixtureWriter *writer, size_t offset, uint8_t value)
{
    if (offset + 1u > writer->capacity) {
        writer->failed = 1;
        return;
    }
    writer->bytes[offset] = value;
}

static inline void fx_u16(PeFixtureWriter *writer, size_t offset,
                          uint16_t value)
{
    fx_u8(writer, offset, (uint8_t)(value & 0xffu));
    fx_u8(writer, offset + 1u, (uint8_t)((value >> 8) & 0xffu));
}

static inline void fx_u32(PeFixtureWriter *writer, size_t offset,
                          uint32_t value)
{
    fx_u16(writer, offset, (uint16_t)(value & 0xffffu));
    fx_u16(writer, offset + 2u, (uint16_t)((value >> 16) & 0xffffu));
}

static inline void fx_u64(PeFixtureWriter *writer, size_t offset,
                          uint64_t value)
{
    fx_u32(writer, offset, (uint32_t)(value & 0xffffffffu));
    fx_u32(writer, offset + 4u, (uint32_t)((value >> 32) & 0xffffffffu));
}

static inline void fx_blob(PeFixtureWriter *writer, size_t offset,
                           const void *data, size_t bytes)
{
    if (bytes == 0u)
        return;
    if (offset + bytes > writer->capacity) {
        writer->failed = 1;
        return;
    }
    memcpy(writer->bytes + offset, data, bytes);
}

static inline uint32_t fx_strlen(const char *value)
{
    uint32_t length = 0;

    while (value && value[length] != '\0')
        ++length;
    return length;
}

static inline uint32_t fx_named_count(const PeFixtureImport *import)
{
    uint32_t count = 0;

    while (count < PE_FIXTURE_MAX_NAMES && import->names[count] != NULL)
        ++count;
    return count;
}

static inline uint32_t fx_ordinal_count(const PeFixtureImport *import)
{
    uint32_t count = 0;

    while (count < PE_FIXTURE_MAX_NAMES && import->ordinals[count] != 0u)
        ++count;
    return count;
}

/* Byte size of the synthetic import section for one spec. */
static inline uint32_t fx_import_bytes(const PeFixtureSpec *spec,
                                       uint32_t width)
{
    uint32_t total;

    if (spec->import_count == 0u)
        return 0u;
    total = (spec->import_count + 1u) * PE_IMPORT_DESCRIPTOR_BYTES;
    for (uint32_t index = 0; index < spec->import_count; ++index) {
        const PeFixtureImport *import = &spec->imports[index];
        const uint32_t entries =
            fx_named_count(import) + fx_ordinal_count(import) + 1u;

        total += entries * width;               /* address table */
        if (!spec->omit_lookup_table)
            total += entries * width;           /* lookup table */
        for (uint32_t name = 0; name < fx_named_count(import); ++name)
            total += fx_align(2u + fx_strlen(import->names[name]) + 1u, 2u);
        total += fx_strlen(import->dll) + 1u;
    }
    return total;
}

/* Byte size of the synthetic .reloc section, blocks padded to four bytes. */
static inline uint32_t fx_reloc_bytes(const PeFixtureSpec *spec,
                                      uint32_t alignment)
{
    uint32_t total = 0;
    uint32_t index = 0;

    if (spec->reloc_count == 0u)
        return 0u;
    while (index < spec->reloc_count) {
        const uint32_t page = spec->relocs[index].rva & ~(alignment - 1u);
        uint32_t entries = 0;

        while (index + entries < spec->reloc_count &&
               (spec->relocs[index + entries].rva & ~(alignment - 1u)) == page)
            ++entries;
        total += 8u + fx_align(entries * 2u, 4u);
        index += entries;
    }
    return total;
}

static inline uint32_t fx_export_base(const PeFixtureSpec *spec)
{
    return spec->export_base != 0u ? spec->export_base : 1u;
}

static inline uint32_t fx_export_ordinal(const PeFixtureSpec *spec,
                                         uint32_t index)
{
    const PeFixtureExport *entry = &spec->exports[index];

    return entry->ordinal != 0u ? entry->ordinal : fx_export_base(spec) + index;
}

/* Highest ordinal index plus one: slots below it that no entry names stay
 * sparse, exactly as a linker may emit them. */
static inline uint32_t fx_export_function_count(const PeFixtureSpec *spec)
{
    uint32_t count = 0u;

    for (uint32_t index = 0; index < spec->export_count; ++index) {
        const uint32_t ordinal = fx_export_ordinal(spec, index);

        if (ordinal < fx_export_base(spec))
            return 0u;
        if (ordinal - fx_export_base(spec) + 1u > count)
            count = ordinal - fx_export_base(spec) + 1u;
    }
    return count;
}

static inline uint32_t fx_export_named_count(const PeFixtureSpec *spec)
{
    uint32_t count = 0u;

    for (uint32_t index = 0; index < spec->export_count; ++index)
        if (spec->exports[index].name != NULL)
            ++count;
    return count;
}

/* Byte size of the synthetic .edata section for one spec. */
static inline uint32_t fx_export_bytes(const PeFixtureSpec *spec)
{
    uint32_t cursor = PE_EXPORT_DIRECTORY_BYTES;
    const char *module_name = spec->export_module_name != NULL
        ? spec->export_module_name : "fixture.dll";
    const uint32_t functions = fx_export_function_count(spec);

    if (spec->export_count == 0u || functions == 0u)
        return 0u;
    cursor = fx_align(cursor, 2u);
    cursor += fx_strlen(module_name) + 1u;
    cursor += functions * 4u;
    cursor += fx_export_named_count(spec) * (4u + 2u);
    for (uint32_t index = 0; index < spec->export_count; ++index) {
        const PeFixtureExport *entry = &spec->exports[index];

        if (entry->name != NULL) {
            cursor = fx_align(cursor, 2u);
            cursor += fx_strlen(entry->name) + 1u;
        }
    }
    for (uint32_t index = 0; index < spec->export_count; ++index) {
        const PeFixtureExport *entry = &spec->exports[index];

        if (entry->forwarder != NULL) {
            cursor = fx_align(cursor, 2u);
            cursor += fx_strlen(entry->forwarder) + 1u;
        }
    }
    return cursor;
}

/* Byte size of the synthetic .tls section for one spec. */
static inline uint32_t fx_tls_bytes(const PeFixtureSpec *spec)
{
    uint32_t cursor = PE_TLS_DIRECTORY_BYTES;

    if (!spec->has_tls)
        return 0u;
    cursor = fx_align(cursor, 4u);
    cursor += spec->tls.template_bytes;
    cursor = fx_align(cursor, 4u);
    cursor += 4u;                                   /* AddressOfIndex slot */
    cursor = fx_align(cursor, 4u);
    cursor += (spec->tls.callback_count +
               (spec->tls.no_callbacks_pointer ? 0u : 1u) +
               spec->tls.padding_callbacks) * 4u;
    return cursor;
}

/*
 * Emits a complete image and returns its size, or 0 when the buffer is too
 * small or the spec is inconsistent. Relocation entries must be sorted by
 * RVA; the fixture asserts nothing, it simply refuses.
 */
static inline size_t pe_fixture_build(uint8_t *out, size_t capacity,
                                      const PeFixtureSpec *spec)
{
    PeFixtureWriter writer;
    const uint32_t section_alignment =
        spec->section_alignment != 0u ? spec->section_alignment : 0x1000u;
    const uint32_t file_alignment =
        spec->file_alignment != 0u ? spec->file_alignment : 0x200u;
    const uint32_t width = spec->pe32plus ? 8u : 4u;
    const uint32_t optional_fixed =
        spec->pe32plus ? PE_OPT_FIXED_PE32PLUS : PE_OPT_FIXED_PE32;
    const uint32_t directory_count =
        spec->directory_count != 0u ? spec->directory_count
                                    : PE_DIRECTORY_ENTRIES;
    /* SizeOfOptionalHeader covers the fixed part plus the directories. */
    const uint32_t optional_bytes = optional_fixed + 8u * directory_count;
    const uint32_t import_bytes = fx_import_bytes(spec, width);
    const uint32_t reloc_bytes = fx_reloc_bytes(spec, section_alignment);
    const uint32_t export_bytes = fx_export_bytes(spec);
    const uint32_t tls_bytes = fx_tls_bytes(spec);
    /* Generated sections are appended in a fixed order after the caller's:
     * .edata, .tls, .idata, .reloc. */
    const uint32_t generated_bytes[4] = {export_bytes, tls_bytes, import_bytes,
                                         reloc_bytes};
    const char *const generated_names[4] = {".edata", ".tls", ".idata",
                                            ".reloc"};
    const uint32_t generated_characteristics[4] = {
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ,
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE,
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE,
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ |
            PE_SCN_MEM_DISCARDABLE,
    };
    uint32_t generated_index[4] = {0u, 0u, 0u, 0u};
    uint32_t generated_count = 0u;
    uint32_t present_sizes[4];
    uint8_t present_kinds[4];
    const char *present_names[4];
    uint32_t present_characteristics[4];
    uint32_t total_sections;
    for (uint32_t index = 0; index < 4u; ++index) {
        if (generated_bytes[index] == 0u)
            continue;
        present_sizes[generated_count] = generated_bytes[index];
        present_kinds[generated_count] = (uint8_t)index;
        present_names[generated_count] = generated_names[index];
        present_characteristics[generated_count] =
            generated_characteristics[index];
        ++generated_count;
    }
    total_sections = spec->section_count + generated_count;
    const uint32_t nt_offset = 0x40u;
    uint32_t header_bytes;
    uint32_t virtual_addresses[PE_FIXTURE_MAX_SECTIONS + 4];
    uint32_t raw_offsets[PE_FIXTURE_MAX_SECTIONS + 4];
    uint32_t raw_sizes[PE_FIXTURE_MAX_SECTIONS + 4];
    uint32_t virtual_sizes[PE_FIXTURE_MAX_SECTIONS + 4];
    uint32_t characteristics[PE_FIXTURE_MAX_SECTIONS + 4];
    const char *names[PE_FIXTURE_MAX_SECTIONS + 4];
    uint32_t import_index = 0;
    uint32_t reloc_index = 0;
    uint32_t export_index = 0;
    uint32_t tls_index = 0;
    uint32_t next_rva;
    uint32_t next_raw;
    uint32_t size_of_image;
    size_t total_bytes;

    if (!out || !spec || spec->section_count == 0u ||
        spec->section_count > PE_FIXTURE_MAX_SECTIONS ||
        spec->export_count > PE_FIXTURE_MAX_EXPORTS ||
        spec->tls.callback_count > PE_FIXTURE_MAX_TLS_CALLBACKS ||
        total_sections > PE_FIXTURE_MAX_SECTIONS + 4u)
        return 0u;
    if ((section_alignment & (section_alignment - 1u)) != 0u ||
        (file_alignment & (file_alignment - 1u)) != 0u ||
        file_alignment > section_alignment || directory_count > 16u)
        return 0u;

    header_bytes = fx_align(nt_offset + 4u + PE_FILE_HEADER_BYTES +
                            optional_bytes +
                            total_sections * PE_SECTION_HEADER_BYTES,
                            file_alignment);

    next_rva = fx_align(header_bytes, section_alignment);
    next_raw = header_bytes;
    for (uint32_t index = 0; index < total_sections; ++index) {
        uint32_t declared;

        if (index < spec->section_count) {
            const PeFixtureSection *section = &spec->sections[index];

            names[index] = section->name;
            characteristics[index] = section->characteristics;
            raw_sizes[index] = fx_align(section->data_bytes, file_alignment);
            declared = section->virtual_size != 0u ? section->virtual_size
                                                   : section->data_bytes;
        } else {
            const uint32_t slot = index - spec->section_count;

            if (slot >= generated_count)
                return 0u;
            generated_index[slot] = index;
            names[index] = present_names[slot];
            characteristics[index] = present_characteristics[slot];
            raw_sizes[index] = fx_align(present_sizes[slot], file_alignment);
            declared = present_sizes[slot];
        }
        if (declared == 0u)
            return 0u;
        virtual_sizes[index] = declared;
        virtual_addresses[index] = next_rva;
        raw_offsets[index] = raw_sizes[index] != 0u ? next_raw : 0u;
        next_rva += fx_align(declared, section_alignment);
        next_raw += raw_sizes[index];
    }
    size_of_image = next_rva;
    total_bytes = next_raw;
    if (total_bytes > capacity)
        return 0u;

    /* The data directories are written before the section table, so the
     * generated-section indices must be resolved here. */
    for (uint32_t slot = 0; slot < generated_count; ++slot) {
        if (present_kinds[slot] == 0u)
            export_index = generated_index[slot];
        else if (present_kinds[slot] == 1u)
            tls_index = generated_index[slot];
        else if (present_kinds[slot] == 2u)
            import_index = generated_index[slot];
        else
            reloc_index = generated_index[slot];
    }

    writer.bytes = out;
    writer.capacity = capacity;
    writer.failed = 0;
    memset(out, 0, total_bytes);

    fx_u16(&writer, 0u, PE_DOS_MAGIC);
    fx_u32(&writer, 0x3cu, nt_offset);
    fx_u32(&writer, nt_offset, PE_NT_SIGNATURE);

    const size_t file_header = nt_offset + 4u;
    const uint16_t machine = spec->machine != 0u
        ? spec->machine
        : (uint16_t)(spec->pe32plus ? PE_MACHINE_AMD64 : PE_MACHINE_I386);
    uint16_t image_characteristics = spec->characteristics;

    if (image_characteristics == 0u) {
        image_characteristics = PE_FILE_EXECUTABLE_IMAGE;
        if (spec->dll)
            image_characteristics |= PE_FILE_DLL;
        if (!spec->pe32plus)
            image_characteristics |= PE_FILE_32BIT_MACHINE;
    }
    fx_u16(&writer, file_header, machine);
    fx_u16(&writer, file_header + 2u, (uint16_t)total_sections);
    fx_u16(&writer, file_header + 16u, (uint16_t)optional_bytes);
    fx_u16(&writer, file_header + 18u, image_characteristics);

    const size_t optional = file_header + PE_FILE_HEADER_BYTES;
    fx_u16(&writer, optional, (uint16_t)(spec->pe32plus
                                         ? PE_OPT_MAGIC_PE32PLUS
                                         : PE_OPT_MAGIC_PE32));
    fx_u32(&writer, optional + 0x10u, spec->entry_point);
    fx_u32(&writer, optional + 0x14u, virtual_addresses[0]);
    if (spec->pe32plus) {
        fx_u64(&writer, optional + 0x18u, spec->image_base);
    } else {
        fx_u32(&writer, optional + 0x1cu, (uint32_t)spec->image_base);
        fx_u32(&writer, optional + 0x18u, virtual_addresses[0]);
    }
    fx_u32(&writer, optional + 0x20u, section_alignment);
    fx_u32(&writer, optional + 0x24u, file_alignment);
    fx_u16(&writer, optional + 0x30u, 4u);              /* subsystem version */
    fx_u32(&writer, optional + 0x38u, size_of_image);
    fx_u32(&writer, optional + 0x3cu, header_bytes);
    fx_u16(&writer, optional + 0x44u, 3u);              /* console subsystem */
    fx_u16(&writer, optional + 0x46u, spec->dll_characteristics);
    fx_u32(&writer, optional + optional_fixed - 4u, directory_count);

    /* Data directories start right after the fixed optional-header part. */
    const size_t directory_base = optional + optional_fixed;
    if (export_bytes != 0u && directory_count > PE_DIR_EXPORT) {
        fx_u32(&writer, directory_base + 8u * PE_DIR_EXPORT,
               virtual_addresses[export_index]);
        fx_u32(&writer, directory_base + 8u * PE_DIR_EXPORT + 4u,
               export_bytes);
    }
    if (tls_bytes != 0u && directory_count > PE_DIR_TLS) {
        fx_u32(&writer, directory_base + 8u * PE_DIR_TLS,
               virtual_addresses[tls_index]);
        fx_u32(&writer, directory_base + 8u * PE_DIR_TLS + 4u, tls_bytes);
    }
    if (import_bytes != 0u && directory_count > PE_DIR_IMPORT) {
        fx_u32(&writer, directory_base + 8u * PE_DIR_IMPORT,
               virtual_addresses[import_index]);
        fx_u32(&writer, directory_base + 8u * PE_DIR_IMPORT + 4u,
               (spec->import_count + 1u) * PE_IMPORT_DESCRIPTOR_BYTES);
    }
    if (reloc_bytes != 0u && directory_count > PE_DIR_BASERELOC) {
        fx_u32(&writer, directory_base + 8u * PE_DIR_BASERELOC,
               virtual_addresses[reloc_index]);
        fx_u32(&writer, directory_base + 8u * PE_DIR_BASERELOC + 4u,
               reloc_bytes);
    }

    const size_t section_table = optional + optional_bytes;
    for (uint32_t index = 0; index < total_sections; ++index) {
        const size_t entry = section_table + index * PE_SECTION_HEADER_BYTES;
        const uint32_t length = fx_strlen(names[index]);

        fx_blob(&writer, entry, names[index],
                length < PE_SECTION_NAME_BYTES ? length
                                               : PE_SECTION_NAME_BYTES);
        fx_u32(&writer, entry + 8u, virtual_sizes[index]);
        fx_u32(&writer, entry + 12u, virtual_addresses[index]);
        fx_u32(&writer, entry + 16u, raw_sizes[index]);
        fx_u32(&writer, entry + 20u, raw_offsets[index]);
        fx_u32(&writer, entry + 36u, characteristics[index]);
    }

    for (uint32_t index = 0; index < spec->section_count; ++index) {
        const PeFixtureSection *section = &spec->sections[index];

        if (section->data && section->data_bytes != 0u)
            fx_blob(&writer, raw_offsets[index], section->data,
                    section->data_bytes);
    }

    if (export_bytes != 0u) {
        const uint32_t base_rva = virtual_addresses[export_index];
        const size_t base_raw = raw_offsets[export_index];
        const char *module_name = spec->export_module_name != NULL
            ? spec->export_module_name : "fixture.dll";
        const uint32_t functions = fx_export_function_count(spec);
        const uint32_t named = fx_export_named_count(spec);
        uint32_t cursor = PE_EXPORT_DIRECTORY_BYTES;
        uint32_t module_name_off;
        uint32_t functions_off;
        uint32_t names_off;
        uint32_t ordinals_off;
        uint32_t name_off[PE_FIXTURE_MAX_EXPORTS];
        uint32_t forward_off[PE_FIXTURE_MAX_EXPORTS];
        uint32_t name_slot = 0u;

        memset(name_off, 0, sizeof(name_off));
        memset(forward_off, 0, sizeof(forward_off));
        cursor = fx_align(cursor, 2u);
        module_name_off = cursor;
        cursor += fx_strlen(module_name) + 1u;
        functions_off = cursor;
        cursor += functions * 4u;
        names_off = cursor;
        cursor += named * 4u;
        ordinals_off = cursor;
        cursor += named * 2u;
        for (uint32_t index = 0; index < spec->export_count; ++index) {
            if (spec->exports[index].name == NULL)
                continue;
            cursor = fx_align(cursor, 2u);
            name_off[index] = cursor;
            cursor += fx_strlen(spec->exports[index].name) + 1u;
        }
        for (uint32_t index = 0; index < spec->export_count; ++index) {
            if (spec->exports[index].forwarder == NULL)
                continue;
            cursor = fx_align(cursor, 2u);
            forward_off[index] = cursor;
            cursor += fx_strlen(spec->exports[index].forwarder) + 1u;
        }
        if (cursor != export_bytes)
            return 0u;

        fx_u32(&writer, base_raw + 12u, base_rva + module_name_off);
        fx_u32(&writer, base_raw + 16u, fx_export_base(spec));
        fx_u32(&writer, base_raw + 20u, functions);
        fx_u32(&writer, base_raw + 24u, named);
        fx_u32(&writer, base_raw + 28u, base_rva + functions_off);
        fx_u32(&writer, base_raw + 32u, base_rva + names_off);
        fx_u32(&writer, base_raw + 36u, base_rva + ordinals_off);
        fx_blob(&writer, base_raw + module_name_off, module_name,
                fx_strlen(module_name) + 1u);

        for (uint32_t index = 0; index < spec->export_count; ++index) {
            const PeFixtureExport *entry = &spec->exports[index];
            const uint32_t slot =
                fx_export_ordinal(spec, index) - fx_export_base(spec);
            const uint32_t value = entry->forwarder != NULL
                ? base_rva + forward_off[index] : entry->rva;

            fx_u32(&writer, base_raw + functions_off + slot * 4u, value);
            if (entry->name != NULL) {
                fx_u32(&writer, base_raw + names_off + name_slot * 4u,
                       base_rva + name_off[index]);
                fx_u16(&writer, base_raw + ordinals_off + name_slot * 2u,
                       (uint16_t)slot);
                fx_blob(&writer, base_raw + name_off[index], entry->name,
                        fx_strlen(entry->name) + 1u);
                ++name_slot;
            }
            if (entry->forwarder != NULL)
                fx_blob(&writer, base_raw + forward_off[index],
                        entry->forwarder, fx_strlen(entry->forwarder) + 1u);
        }
    }

    if (tls_bytes != 0u) {
        const uint32_t base_rva = virtual_addresses[tls_index];
        const size_t base_raw = raw_offsets[tls_index];
        const uint64_t image_base = spec->image_base;
        uint32_t cursor = PE_TLS_DIRECTORY_BYTES;
        uint32_t template_off = 0u;
        uint32_t index_off;
        uint32_t callbacks_off = 0u;
        uint64_t start_va;
        uint64_t end_va;
        uint64_t index_va;
        uint64_t callbacks_va;

        if (spec->tls.template_bytes != 0u) {
            cursor = fx_align(cursor, 4u);
            template_off = cursor;
            cursor += spec->tls.template_bytes;
        }
        cursor = fx_align(cursor, 4u);
        index_off = cursor;
        cursor += 4u;
        if (!spec->tls.no_callbacks_pointer) {
            cursor = fx_align(cursor, 4u);
            callbacks_off = cursor;
            cursor += (spec->tls.callback_count + 1u +
                       spec->tls.padding_callbacks) * 4u;
        }
        if (cursor != tls_bytes)
            return 0u;

        start_va = image_base + base_rva + template_off;
        end_va = start_va + spec->tls.template_bytes;
        index_va = image_base + base_rva + index_off;
        callbacks_va = image_base + base_rva + callbacks_off;
        if (spec->tls.template_bytes == 0u) {
            start_va = 0u;
            end_va = 0u;
        }
        if (spec->tls.use_rvas) {
            start_va -= image_base;
            end_va -= image_base;
            index_va -= image_base;
            callbacks_va -= image_base;
        }
        fx_u32(&writer, base_raw, (uint32_t)start_va);
        fx_u32(&writer, base_raw + 4u, (uint32_t)end_va);
        fx_u32(&writer, base_raw + 8u, (uint32_t)index_va);
        fx_u32(&writer, base_raw + 12u,
               spec->tls.no_callbacks_pointer ? 0u : (uint32_t)callbacks_va);
        fx_u32(&writer, base_raw + 16u, spec->tls.zero_fill);
        fx_u32(&writer, base_raw + 20u, spec->tls.characteristics);
        if (spec->tls.template_bytes != 0u)
            fx_blob(&writer, base_raw + template_off,
                    spec->tls.template_data, spec->tls.template_bytes);
        if (!spec->tls.no_callbacks_pointer) {
            for (uint32_t index = 0; index < spec->tls.callback_count; ++index)
                fx_u32(&writer, base_raw + callbacks_off + index * 4u,
                       (uint32_t)(image_base + spec->tls.callbacks[index]));
            for (uint32_t index = 0; index < spec->tls.padding_callbacks;
                 ++index)
                fx_u32(&writer,
                       base_raw + callbacks_off +
                           (spec->tls.callback_count + 1u + index) * 4u,
                       (uint32_t)(image_base + spec->tls.callbacks[0]));
        }
    }

    if (import_bytes != 0u) {
        const uint32_t base_rva = virtual_addresses[import_index];
        const size_t base_raw = raw_offsets[import_index];
        uint32_t cursor = (spec->import_count + 1u) * PE_IMPORT_DESCRIPTOR_BYTES;
        uint32_t lookup_offsets[PE_FIXTURE_MAX_IMPORTS];
        uint32_t address_offsets[PE_FIXTURE_MAX_IMPORTS];
        uint32_t name_offsets[PE_FIXTURE_MAX_IMPORTS][PE_FIXTURE_MAX_NAMES];
        uint32_t dll_offsets[PE_FIXTURE_MAX_IMPORTS];

        for (uint32_t index = 0; index < spec->import_count; ++index) {
            const PeFixtureImport *import = &spec->imports[index];
            const uint32_t entries =
                fx_named_count(import) + fx_ordinal_count(import) + 1u;

            if (!spec->omit_lookup_table) {
                lookup_offsets[index] = cursor;
                cursor += entries * width;
            } else {
                lookup_offsets[index] = 0u;
            }
            address_offsets[index] = cursor;
            cursor += entries * width;
        }
        for (uint32_t index = 0; index < spec->import_count; ++index) {
            const PeFixtureImport *import = &spec->imports[index];

            for (uint32_t name = 0; name < fx_named_count(import); ++name) {
                name_offsets[index][name] = cursor;
                cursor += fx_align(2u + fx_strlen(import->names[name]) + 1u,
                                   2u);
            }
        }
        for (uint32_t index = 0; index < spec->import_count; ++index) {
            dll_offsets[index] = cursor;
            cursor += fx_strlen(spec->imports[index].dll) + 1u;
        }
        if (cursor != import_bytes)
            return 0u;

        for (uint32_t index = 0; index < spec->import_count; ++index) {
            const PeFixtureImport *import = &spec->imports[index];
            const size_t descriptor =
                base_raw + index * PE_IMPORT_DESCRIPTOR_BYTES;
            const uint32_t named = fx_named_count(import);
            const uint32_t ordinals = fx_ordinal_count(import);

            fx_u32(&writer, descriptor,
                   lookup_offsets[index] != 0u
                       ? base_rva + lookup_offsets[index] : 0u);
            fx_u32(&writer, descriptor + 12u, base_rva + dll_offsets[index]);
            fx_u32(&writer, descriptor + 16u,
                   base_rva + address_offsets[index]);
            fx_blob(&writer, base_raw + dll_offsets[index], import->dll,
                    fx_strlen(import->dll) + 1u);

            for (uint32_t slot = 0; slot < named + ordinals; ++slot) {
                uint64_t value;

                if (slot < named) {
                    value = base_rva + name_offsets[index][slot];
                } else {
                    const uint16_t ordinal = import->ordinals[slot - named];

                    value = spec->pe32plus
                        ? (0x8000000000000000ull | ordinal)
                        : (0x80000000ull | ordinal);
                }
                if (width == 4u) {
                    fx_u32(&writer,
                           base_raw + address_offsets[index] + slot * width,
                           (uint32_t)value);
                    if (lookup_offsets[index] != 0u)
                        fx_u32(&writer,
                               base_raw + lookup_offsets[index] + slot * width,
                               (uint32_t)value);
                } else {
                    fx_u64(&writer,
                           base_raw + address_offsets[index] + slot * width,
                           value);
                    if (lookup_offsets[index] != 0u)
                        fx_u64(&writer,
                               base_raw + lookup_offsets[index] + slot * width,
                               value);
                }
            }
            for (uint32_t name = 0; name < named; ++name) {
                const size_t entry = base_raw + name_offsets[index][name];

                fx_u16(&writer, entry, (uint16_t)(name + 1u));
                fx_blob(&writer, entry + 2u, import->names[name],
                        fx_strlen(import->names[name]) + 1u);
            }
        }
    }

    if (reloc_bytes != 0u) {
        const size_t base_raw = raw_offsets[reloc_index];
        size_t cursor = base_raw;
        uint32_t index = 0;

        while (index < spec->reloc_count) {
            const uint32_t page =
                spec->relocs[index].rva & ~(section_alignment - 1u);
            uint32_t entries = 0;
            uint32_t block_bytes;

            while (index + entries < spec->reloc_count &&
                   (spec->relocs[index + entries].rva &
                    ~(section_alignment - 1u)) == page)
                ++entries;
            block_bytes = 8u + fx_align(entries * 2u, 4u);
            fx_u32(&writer, cursor, page);
            fx_u32(&writer, cursor + 4u, block_bytes);
            for (uint32_t entry = 0; entry < entries; ++entry) {
                const PeFixtureReloc *reloc = &spec->relocs[index + entry];
                const uint16_t value =
                    (uint16_t)((uint16_t)(reloc->type << 12) |
                               (uint16_t)(reloc->rva - page));

                fx_u16(&writer, cursor + 8u + entry * 2u, value);
            }
            cursor += block_bytes;
            index += entries;
        }
    }

    return writer.failed ? 0u : total_bytes;
}

#endif
