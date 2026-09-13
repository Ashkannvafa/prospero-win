/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_export.h"

#include <string.h>

enum {
    /* A Windows ordinal is 16 bits wide, so the base plus the function count
     * must stay inside 0x10000. This also bounds every later addition. */
    PE_EXPORT_ORDINAL_LIMIT = 0x10000u,
};

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int read_u32_at(const PeImage *image, uint32_t rva, uint32_t *value)
{
    size_t offset;
    const int status = pe_image_file_offset(image, rva, 4u, &offset);

    if (status != PW_OK)
        return status;
    *value = read_u32(image->bytes + offset);
    return PW_OK;
}

static int read_u16_at(const PeImage *image, uint32_t rva, uint16_t *value)
{
    size_t offset;
    const int status = pe_image_file_offset(image, rva, 2u, &offset);

    if (status != PW_OK)
        return status;
    *value = (uint16_t)((uint16_t)image->bytes[offset] |
                        (uint16_t)((uint16_t)image->bytes[offset + 1] << 8));
    return PW_OK;
}

static int in_directory(const PeExportDirectory *directory, uint32_t rva)
{
    return (uint64_t)rva >= directory->directory_rva &&
           (uint64_t)rva < (uint64_t)directory->directory_rva +
                          directory->directory_size;
}

/*
 * Borrows the directory-bound reader: the string must start inside the export
 * directory and its terminator must also be inside it, so a corrupt RVA
 * cannot walk into unrelated file bytes.
 */
static int read_forwarder(const PeImage *image,
                          const PeExportDirectory *directory, uint32_t rva,
                          char *out, size_t out_bytes)
{
    uint32_t remaining;
    size_t length = 0;

    if (!in_directory(directory, rva))
        return PW_ERR_MALFORMED;
    remaining = directory->directory_rva + directory->directory_size - rva;
    for (;;) {
        size_t offset;
        uint8_t byte;
        int status;

        if (length >= remaining || length + 1u >= out_bytes)
            return PW_ERR_MALFORMED;
        status = pe_image_file_offset(image, rva + (uint32_t)length, 1u,
                                      &offset);
        if (status != PW_OK)
            return status;
        byte = image->bytes[offset];
        if (byte == 0u) {
            out[length] = '\0';
            return length != 0u ? PW_OK : PW_ERR_MALFORMED;
        }
        out[length] = (char)byte;
        ++length;
    }
}

int pe_export_read_index(const PeImage *image,
                         const PeExportDirectory *directory, uint32_t index,
                         PeExportSymbol *out)
{
    PeExportSymbol symbol;
    uint32_t rva;
    int status;

    if (!image || !image->bytes || !directory || !out)
        return PW_ERR_PRECONDITION;
    if (index >= directory->function_count)
        return PW_ERR_MALFORMED;
    status = read_u32_at(image, directory->functions_rva + index * 4u, &rva);
    if (status != PW_OK)
        return status;
    if (rva == 0u)
        return PW_ERR_NOT_FOUND;                /* sparse slot */

    memset(&symbol, 0, sizeof(symbol));
    symbol.index = index;
    symbol.ordinal = directory->ordinal_base + index;
    symbol.rva = rva;
    if (in_directory(directory, rva)) {
        status = read_forwarder(image, directory, rva, symbol.target,
                                sizeof(symbol.target));
        if (status != PW_OK)
            return status;
        symbol.forwarder_rva = rva;
        symbol.is_forwarder = 1u;
    } else {
        /*
         * The RVA must land in a mapped section. It does not have to have
         * file bytes: an exported pointer in .bss is a legal data export,
         * and Wine's ntdll publishes __wine_syscall_dispatcher exactly that
         * way.
         */
        const PeSection *section = pe_image_section_for_rva(image, rva);

        if (!section)
            return PW_ERR_MALFORMED;
        symbol.is_code =
            (uint8_t)((section->characteristics & PE_SCN_MEM_EXECUTE) != 0u);
    }
    *out = symbol;
    return PW_OK;
}

/* Fills the published name for a function-table index, when one exists. */
static int name_for_index(const PeImage *image,
                          const PeExportDirectory *directory, uint32_t index,
                          char *out, size_t out_bytes)
{
    for (uint32_t name_index = 0; name_index < directory->name_count;
         ++name_index) {
        uint16_t slot;
        uint32_t name_rva;
        int status;

        status = read_u16_at(image, directory->ordinals_rva + name_index * 2u,
                             &slot);
        if (status != PW_OK)
            return status;
        if (slot != index)
            continue;
        status = read_u32_at(image, directory->names_rva + name_index * 4u,
                             &name_rva);
        if (status != PW_OK)
            return status;
        return pe_image_read_name(image, name_rva, out, out_bytes);
    }
    return PW_ERR_NOT_FOUND;
}

int pe_export_find_name(const PeImage *image, const PeExportDirectory *directory,
                        const char *name, PeExportSymbol *out)
{
    uint32_t found_slot = 0u;
    int found = 0;

    if (!image || !image->bytes || !directory || !name || !out)
        return PW_ERR_PRECONDITION;
    for (uint32_t name_index = 0; name_index < directory->name_count;
         ++name_index) {
        char candidate[PE_EXPORT_NAME_MAX + 1];
        uint16_t slot;
        uint32_t name_rva;
        PeExportSymbol symbol;
        int status;

        status = read_u32_at(image, directory->names_rva + name_index * 4u,
                             &name_rva);
        if (status != PW_OK)
            return status;
        status = pe_image_read_name(image, name_rva, candidate,
                                    sizeof(candidate));
        if (status != PW_OK)
            return status;
        if (strcmp(candidate, name) != 0)
            continue;
        status = read_u16_at(image, directory->ordinals_rva + name_index * 2u,
                             &slot);
        if (status != PW_OK)
            return status;
        if (slot >= directory->function_count)
            return PW_ERR_MALFORMED;
        /*
         * A name may appear once. Two name entries that disagree about the
         * function index are conflicting data: resolving to whichever comes
         * first would silently pick a definition the image does not have.
         */
        if (found) {
            if (found_slot != slot)
                return PW_ERR_MALFORMED;
            continue;
        }
        found_slot = slot;
        found = 1;
        status = pe_export_read_index(image, directory, slot, &symbol);
        if (status != PW_OK)
            return status;
        memcpy(symbol.name, candidate, sizeof(symbol.name));
        symbol.name[PE_EXPORT_NAME_MAX] = '\0';
        *out = symbol;
    }
    return found ? PW_OK : PW_ERR_NOT_FOUND;
}

int pe_export_find_ordinal(const PeImage *image,
                           const PeExportDirectory *directory,
                           uint32_t ordinal, PeExportSymbol *out)
{
    PeExportSymbol symbol;
    int status;

    if (!image || !image->bytes || !directory || !out)
        return PW_ERR_PRECONDITION;
    if (ordinal < directory->ordinal_base)
        return PW_ERR_NOT_FOUND;
    if ((uint64_t)ordinal >= (uint64_t)directory->ordinal_base +
                              directory->function_count)
        return PW_ERR_NOT_FOUND;
    status = pe_export_read_index(image, directory,
                                  ordinal - directory->ordinal_base, &symbol);
    if (status != PW_OK)
        return status;
    symbol.by_ordinal = 1u;
    /* The name is informational here; an ordinal-only export is normal. */
    (void)name_for_index(image, directory, symbol.index, symbol.name,
                         sizeof(symbol.name));
    *out = symbol;
    return PW_OK;
}

int pe_export_parse(PeExportDirectory *directory, const PeImage *image)
{
    const PeDataDirectory *entry;
    uint8_t header[PE_EXPORT_DIRECTORY_BYTES];
    size_t offset;
    int status;

    if (!directory || !image || !image->bytes)
        return PW_ERR_PRECONDITION;
    memset(directory, 0, sizeof(*directory));
    entry = pe_image_directory(image, PE_DIR_EXPORT);
    if (!entry || entry->virtual_address == 0u || entry->size == 0u)
        return PW_OK;
    if (entry->size < PE_EXPORT_DIRECTORY_BYTES)
        return PW_ERR_MALFORMED;
    status = pe_image_file_offset(image, entry->virtual_address,
                                  PE_EXPORT_DIRECTORY_BYTES, &offset);
    if (status != PW_OK)
        return status;
    memcpy(header, image->bytes + offset, sizeof(header));

    directory->directory_rva = entry->virtual_address;
    directory->directory_size = entry->size;
    directory->module_name_rva = read_u32(header + 12u);
    directory->ordinal_base = read_u32(header + 16u);
    directory->function_count = read_u32(header + 20u);
    directory->name_count = read_u32(header + 24u);
    directory->functions_rva = read_u32(header + 28u);
    directory->names_rva = read_u32(header + 32u);
    directory->ordinals_rva = read_u32(header + 36u);

    if (directory->function_count > PE_EXPORT_MAX_FUNCTIONS ||
        directory->name_count > PE_EXPORT_MAX_NAMES)
        return PW_ERR_LIMIT;
    if (directory->name_count > directory->function_count)
        return PW_ERR_MALFORMED;
    if ((uint64_t)directory->ordinal_base + directory->function_count >
        PE_EXPORT_ORDINAL_LIMIT)
        return PW_ERR_MALFORMED;
    if (directory->module_name_rva == 0u)
        return PW_ERR_MALFORMED;
    status = pe_image_read_name(image, directory->module_name_rva,
                                directory->module_name,
                                sizeof(directory->module_name));
    if (status != PW_OK)
        return status;
    if (directory->function_count != 0u) {
        if (directory->functions_rva == 0u ||
            pe_image_file_offset(image, directory->functions_rva,
                                 directory->function_count * 4u,
                                 &offset) != PW_OK)
            return PW_ERR_MALFORMED;
    }
    if (directory->name_count != 0u) {
        if (directory->names_rva == 0u || directory->ordinals_rva == 0u ||
            pe_image_file_offset(image, directory->names_rva,
                                 directory->name_count * 4u,
                                 &offset) != PW_OK ||
            pe_image_file_offset(image, directory->ordinals_rva,
                                 directory->name_count * 2u,
                                 &offset) != PW_OK)
            return PW_ERR_MALFORMED;
    }
    return PW_OK;
}
