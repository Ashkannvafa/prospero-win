/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_image.h"

#include <string.h>

static uint16_t read_u16(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8));
}

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    return (uint64_t)read_u32(bytes) | ((uint64_t)read_u32(bytes + 4) << 32);
}

static int span_ok(size_t size, uint64_t offset, uint64_t bytes)
{
    return bytes <= size && offset <= (uint64_t)size - bytes;
}

static int power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static int parse_optional_header(PeImage *image, const uint8_t *optional,
                                 uint32_t optional_bytes)
{
    uint32_t fixed;
    uint32_t directory_offset;
    uint32_t declared;

    if (optional_bytes < 2u)
        return PW_ERR_TRUNCATED;
    image->optional_magic = read_u16(optional);
    if (image->optional_magic == PE_OPT_MAGIC_PE32)
        fixed = PE_OPT_FIXED_PE32;
    else if (image->optional_magic == PE_OPT_MAGIC_PE32PLUS)
        fixed = PE_OPT_FIXED_PE32PLUS;
    else
        return PW_ERR_UNSUPPORTED;
    if (optional_bytes < fixed)
        return PW_ERR_TRUNCATED;

    /*
     * AddressOfEntryPoint, SectionAlignment, FileAlignment, SizeOfImage,
     * SizeOfHeaders, Subsystem and DllCharacteristics sit at identical
     * offsets in both optional-header shapes; only ImageBase and the
     * stack/heap sizes differ, which is why the directory count moves.
     */
    image->entry_point = read_u32(optional + 0x10);
    if (image->optional_magic == PE_OPT_MAGIC_PE32)
        image->image_base = read_u32(optional + 0x1c);
    else
        image->image_base = read_u64(optional + 0x18);
    image->section_alignment = read_u32(optional + 0x20);
    image->file_alignment = read_u32(optional + 0x24);
    image->size_of_image = read_u32(optional + 0x38);
    image->size_of_headers = read_u32(optional + 0x3c);
    image->subsystem = read_u16(optional + 0x44);
    image->dll_characteristics = read_u16(optional + 0x46);
    directory_offset = fixed - 4u;
    declared = read_u32(optional + directory_offset);

    if (!power_of_two(image->section_alignment) ||
        !power_of_two(image->file_alignment))
        return PW_ERR_MALFORMED;
    if (image->file_alignment > image->section_alignment)
        return PW_ERR_MALFORMED;
    if (image->section_alignment != image->file_alignment &&
        image->file_alignment < 512u)
        return PW_ERR_MALFORMED;
    if (image->size_of_image == 0u || image->size_of_headers == 0u)
        return PW_ERR_MALFORMED;

    if (declared > PE_DIRECTORY_ENTRIES)
        declared = PE_DIRECTORY_ENTRIES;
    image->directory_count = declared;
    for (uint32_t index = 0; index < declared; ++index) {
        const uint32_t entry = fixed + index * 8u;
        if (optional_bytes < entry + 8u)
            return PW_ERR_TRUNCATED;
        image->directories[index].virtual_address = read_u32(optional + entry);
        image->directories[index].size = read_u32(optional + entry + 4u);
    }
    return PW_OK;
}

static int parse_sections(PeImage *image, const uint8_t *table)
{
    for (uint16_t index = 0; index < image->section_count; ++index) {
        const uint8_t *entry = table + (size_t)index * PE_SECTION_HEADER_BYTES;
        PeSection *section = &image->sections[index];

        memcpy(section->name, entry, PE_SECTION_NAME_BYTES);
        section->name[PE_SECTION_NAME_BYTES] = '\0';
        section->virtual_size = read_u32(entry + 8);
        section->virtual_address = read_u32(entry + 12);
        section->raw_size = read_u32(entry + 16);
        section->raw_offset = read_u32(entry + 20);
        section->characteristics = read_u32(entry + 36);

        /* Raw bytes must exist in the span they claim. */
        if (section->raw_size != 0u &&
            !span_ok(image->size, section->raw_offset, section->raw_size))
            return PW_ERR_TRUNCATED;
    }
    return PW_OK;
}

int pe_image_parse(PeImage *image, const void *bytes, size_t size)
{
    const uint8_t *base = bytes;
    uint32_t optional_bytes;
    uint64_t table_offset;
    int status;

    if (!image || !bytes)
        return PW_ERR_PRECONDITION;
    memset(image, 0, sizeof(*image));
    if (size < PE_DOS_HEADER_BYTES)
        return PW_ERR_TRUNCATED;
    if (read_u16(base) != PE_DOS_MAGIC)
        return PW_ERR_NOT_PE;

    image->nt_offset = read_u32(base + 0x3c);
    if ((image->nt_offset & 3u) != 0u || image->nt_offset < PE_DOS_HEADER_BYTES)
        return PW_ERR_MALFORMED;
    if (!span_ok(size, image->nt_offset, 4u + PE_FILE_HEADER_BYTES))
        return PW_ERR_TRUNCATED;
    if (read_u32(base + image->nt_offset) != PE_NT_SIGNATURE)
        return PW_ERR_NOT_PE;

    image->bytes = base;
    image->size = size;

    const uint8_t *file_header = base + image->nt_offset + 4u;
    image->machine = read_u16(file_header);
    image->section_count = read_u16(file_header + 2);
    optional_bytes = read_u16(file_header + 16);
    image->characteristics = read_u16(file_header + 18);
    image->optional_header_bytes = optional_bytes;

    if (image->machine != PE_MACHINE_I386 &&
        image->machine != PE_MACHINE_AMD64)
        return PW_ERR_UNSUPPORTED;
    if (image->section_count == 0u || image->section_count > PE_MAX_SECTIONS)
        return PW_ERR_MALFORMED;

    const uint64_t optional_offset =
        (uint64_t)image->nt_offset + 4u + PE_FILE_HEADER_BYTES;
    if (!span_ok(size, optional_offset, optional_bytes))
        return PW_ERR_TRUNCATED;
    status = parse_optional_header(image, base + optional_offset,
                                   optional_bytes);
    if (status != PW_OK)
        return status;

    table_offset = optional_offset + optional_bytes;
    if (!span_ok(size, table_offset,
                 (uint64_t)image->section_count * PE_SECTION_HEADER_BYTES))
        return PW_ERR_TRUNCATED;
    if (table_offset + (uint64_t)image->section_count *
        PE_SECTION_HEADER_BYTES > image->size_of_headers)
        return PW_ERR_MALFORMED;
    return parse_sections(image, base + table_offset);
}

int pe_image_is_dll(const PeImage *image)
{
    return image && (image->characteristics & PE_FILE_DLL) != 0u;
}

int pe_image_machine_is_native(const PeImage *image)
{
    return image && image->machine == PE_MACHINE_AMD64;
}

const char *pe_image_machine_name(const PeImage *image)
{
    if (!image)
        return "none";
    switch (image->machine) {
    case PE_MACHINE_I386: return "i386";
    case PE_MACHINE_AMD64: return "amd64";
    default: return "unknown";
    }
}

const PeDataDirectory *pe_image_directory(const PeImage *image,
                                          unsigned index)
{
    if (!image || index >= image->directory_count)
        return NULL;
    return &image->directories[index];
}

static uint32_t section_virtual_bytes(const PeSection *section)
{
    return section->virtual_size != 0u ? section->virtual_size
                                       : section->raw_size;
}

const PeSection *pe_image_section_for_rva(const PeImage *image, uint32_t rva)
{
    if (!image)
        return NULL;
    for (uint16_t index = 0; index < image->section_count; ++index) {
        const PeSection *section = &image->sections[index];
        const uint32_t bytes = section_virtual_bytes(section);
        if (bytes == 0u)
            continue;
        if (rva >= section->virtual_address &&
            rva - section->virtual_address < bytes)
            return section;
    }
    return NULL;
}

int pe_image_file_offset(const PeImage *image, uint32_t rva, uint32_t bytes,
                         size_t *file_offset)
{
    const PeSection *section;
    uint32_t offset_in_section;

    if (!image || !image->bytes || !file_offset)
        return PW_ERR_PRECONDITION;
    if (bytes == 0u)
        return PW_ERR_PRECONDITION;

    /* The header region is mapped one to one with the file. */
    if (rva < image->size_of_headers) {
        if ((uint64_t)rva + bytes > image->size_of_headers)
            return PW_ERR_MALFORMED;
        if (!span_ok(image->size, rva, bytes))
            return PW_ERR_TRUNCATED;
        *file_offset = rva;
        return PW_OK;
    }

    section = pe_image_section_for_rva(image, rva);
    if (!section)
        return PW_ERR_NOT_FOUND;
    offset_in_section = rva - section->virtual_address;
    if (offset_in_section >= section->raw_size)
        return PW_ERR_NOT_FOUND;   /* uninitialised tail: no bytes on disk */
    if ((uint64_t)offset_in_section + bytes > section->raw_size)
        return PW_ERR_MALFORMED;
    if (!span_ok(image->size, (uint64_t)section->raw_offset + offset_in_section,
                 bytes))
        return PW_ERR_TRUNCATED;
    *file_offset = (size_t)section->raw_offset + offset_in_section;
    return PW_OK;
}

int pe_image_read_name(const PeImage *image, uint32_t rva, char *out,
                       size_t out_bytes)
{
    const PeSection *section;
    size_t available;
    size_t offset;
    size_t length = 0;

    if (!image || !image->bytes || !out || out_bytes == 0u)
        return PW_ERR_PRECONDITION;
    out[0] = '\0';

    if (rva < image->size_of_headers) {
        if (rva >= image->size)
            return PW_ERR_TRUNCATED;
        offset = rva;
        available = image->size_of_headers - rva;
        if (available > image->size - rva)
            available = image->size - rva;
    } else {
        uint32_t offset_in_section;
        section = pe_image_section_for_rva(image, rva);
        if (!section)
            return PW_ERR_NOT_FOUND;
        offset_in_section = rva - section->virtual_address;
        if (offset_in_section >= section->raw_size)
            return PW_ERR_NOT_FOUND;
        offset = (size_t)section->raw_offset + offset_in_section;
        available = section->raw_size - offset_in_section;
        if (offset >= image->size)
            return PW_ERR_TRUNCATED;
        if (available > image->size - offset)
            available = image->size - offset;
    }

    while (length < available && image->bytes[offset + length] != '\0') {
        const uint8_t value = image->bytes[offset + length];
        if (value < 0x20u || value > 0x7eu)
            return PW_ERR_MALFORMED;
        ++length;
    }
    if (length == available)
        return PW_ERR_MALFORMED;    /* unterminated inside its own section */
    if (length == 0u)
        return PW_ERR_MALFORMED;
    if (length + 1u > out_bytes)
        return PW_ERR_LIMIT;
    memcpy(out, image->bytes + offset, length);
    out[length] = '\0';
    return PW_OK;
}
