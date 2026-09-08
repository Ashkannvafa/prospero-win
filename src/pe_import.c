#include "pe_import.h"

#include <string.h>

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_u64(const uint8_t *bytes)
{
    return (uint64_t)read_u32(bytes) | ((uint64_t)read_u32(bytes + 4) << 32);
}

static int thunk_bytes(const PeImage *image, uint32_t *bytes)
{
    if (image->optional_magic == PE_OPT_MAGIC_PE32)
        *bytes = 4u;
    else if (image->optional_magic == PE_OPT_MAGIC_PE32PLUS)
        *bytes = 8u;
    else
        return PW_ERR_UNSUPPORTED;
    return PW_OK;
}

static int read_thunk(const PeImage *image, uint32_t rva, uint32_t width,
                      uint64_t *value)
{
    size_t offset;
    const int status = pe_image_file_offset(image, rva, width, &offset);

    if (status != PW_OK)
        return status;
    *value = width == 4u ? read_u32(image->bytes + offset)
                         : read_u64(image->bytes + offset);
    return PW_OK;
}

static int thunk_is_ordinal(uint32_t width, uint64_t value)
{
    return width == 4u ? (value & 0x80000000u) != 0u
                       : (value & 0x8000000000000000ull) != 0u;
}

static int count_thunks(const PeImage *image, uint32_t table_rva,
                        uint32_t width, uint32_t *named, uint32_t *ordinal)
{
    uint32_t index = 0;

    *named = 0u;
    *ordinal = 0u;
    for (;;) {
        uint64_t value;
        uint32_t rva;
        int status;

        if (index >= PE_IMPORT_MAX_SYMBOLS)
            return PW_ERR_LIMIT;
        if (table_rva > 0xffffffffu - index * width)
            return PW_ERR_OVERFLOW;
        rva = table_rva + index * width;
        status = read_thunk(image, rva, width, &value);
        if (status != PW_OK)
            return status;
        if (value == 0u)
            break;
        if (thunk_is_ordinal(width, value))
            ++*ordinal;
        else
            ++*named;
        ++index;
    }
    return PW_OK;
}

int pe_import_parse(PeImportTable *table, const PeImage *image)
{
    const PeDataDirectory *directory;
    uint32_t width;
    int status;

    if (!table || !image || !image->bytes)
        return PW_ERR_PRECONDITION;
    memset(table, 0, sizeof(*table));

    directory = pe_image_directory(image, PE_DIR_IMPORT);
    if (!directory || directory->virtual_address == 0u || directory->size == 0u)
        return PW_OK;
    status = thunk_bytes(image, &width);
    if (status != PW_OK)
        return status;

    for (uint32_t index = 0;; ++index) {
        uint8_t descriptor[PE_IMPORT_DESCRIPTOR_BYTES];
        PeImportModule *module;
        uint32_t rva;
        size_t offset;
        uint32_t lookup;
        uint32_t address;
        uint32_t name_rva;

        if (index > 0xffffffffu / PE_IMPORT_DESCRIPTOR_BYTES)
            return PW_ERR_OVERFLOW;
        rva = directory->virtual_address + index * PE_IMPORT_DESCRIPTOR_BYTES;
        status = pe_image_file_offset(image, rva, PE_IMPORT_DESCRIPTOR_BYTES,
                                      &offset);
        if (status != PW_OK)
            return status;
        memcpy(descriptor, image->bytes + offset, sizeof(descriptor));

        lookup = read_u32(descriptor);
        name_rva = read_u32(descriptor + 12);
        address = read_u32(descriptor + 16);
        if (lookup == 0u && name_rva == 0u && address == 0u)
            break;                              /* terminating descriptor */
        if (name_rva == 0u || address == 0u)
            return PW_ERR_MALFORMED;
        if (table->module_count >= PE_IMPORT_MAX_MODULES)
            return PW_ERR_LIMIT;

        module = &table->modules[table->module_count];
        memset(module, 0, sizeof(*module));
        status = pe_image_read_name(image, name_rva, module->name,
                                     sizeof(module->name));
        if (status != PW_OK)
            return status;
        module->name_rva = name_rva;
        module->lookup_table_rva = lookup;
        module->address_table_rva = address;
        module->timestamp = read_u32(descriptor + 4);
        module->forwarder_chain = read_u32(descriptor + 8);
        module->bound = module->timestamp != 0u &&
                        module->timestamp != 0xffffffffu;

        /*
         * The lookup table survives binding; the address table does not.
         * Prefer it whenever the linker emitted one.
         */
        status = count_thunks(image, lookup != 0u ? lookup : address, width,
                              &module->named_count, &module->ordinal_count);
        if (status != PW_OK)
            return status;
        table->symbol_count += module->named_count + module->ordinal_count;
        ++table->module_count;
    }
    return PW_OK;
}

int pe_import_enumerate(const PeImage *image, const PeImportModule *module,
                        PeImportSymbol *out, uint32_t capacity,
                        uint32_t *count)
{
    uint32_t width;
    uint32_t source_rva;
    uint32_t index = 0;
    int status;

    if (!image || !image->bytes || !module || !out || !count)
        return PW_ERR_PRECONDITION;
    *count = 0u;
    status = thunk_bytes(image, &width);
    if (status != PW_OK)
        return status;
    source_rva = module->lookup_table_rva != 0u ? module->lookup_table_rva
                                                : module->address_table_rva;
    if (source_rva == 0u)
        return PW_ERR_MALFORMED;

    for (;;) {
        uint64_t value;
        PeImportSymbol *symbol;

        if (index >= PE_IMPORT_MAX_SYMBOLS)
            return PW_ERR_LIMIT;
        if (source_rva > 0xffffffffu - index * width ||
            module->address_table_rva > 0xffffffffu - index * width)
            return PW_ERR_OVERFLOW;
        status = read_thunk(image, source_rva + index * width, width, &value);
        if (status != PW_OK)
            return status;
        if (value == 0u)
            break;
        if (index >= capacity)
            return PW_ERR_LIMIT;

        symbol = &out[index];
        memset(symbol, 0, sizeof(*symbol));
        symbol->thunk_rva = module->address_table_rva + index * width;
        if (thunk_is_ordinal(width, value)) {
            symbol->by_ordinal = 1u;
            symbol->ordinal = (uint16_t)(value & 0xffffu);
        } else {
            const uint32_t hint_rva = (uint32_t)value;
            size_t offset;

            status = pe_image_file_offset(image, hint_rva, 2u, &offset);
            if (status != PW_OK)
                return status;
            symbol->hint = (uint16_t)((uint16_t)image->bytes[offset] |
                                      (uint16_t)((uint16_t)image->bytes[offset + 1] << 8));
            status = pe_image_read_name(image, hint_rva + 2u, symbol->name,
                                         sizeof(symbol->name));
            if (status != PW_OK)
                return status;
        }
        ++index;
    }
    *count = index;
    return PW_OK;
}
