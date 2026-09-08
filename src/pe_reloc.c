#include "pe_reloc.h"

#include <string.h>

static int patch_u16(uint8_t *mapped, uint32_t image_bytes, uint32_t target,
                     uint16_t addend)
{
    uint16_t value;

    if (image_bytes < 2u || target > image_bytes - 2u)
        return PW_ERR_MALFORMED;
    memcpy(&value, mapped + target, sizeof(value));
    value = (uint16_t)(value + addend);
    memcpy(mapped + target, &value, sizeof(value));
    return PW_OK;
}

static int patch_u32(uint8_t *mapped, uint32_t image_bytes, uint32_t target,
                     uint32_t addend)
{
    uint32_t value;

    if (image_bytes < 4u || target > image_bytes - 4u)
        return PW_ERR_MALFORMED;
    memcpy(&value, mapped + target, sizeof(value));
    value += addend;
    memcpy(mapped + target, &value, sizeof(value));
    return PW_OK;
}

static int patch_u64(uint8_t *mapped, uint32_t image_bytes, uint32_t target,
                     uint64_t addend)
{
    uint64_t value;

    if (image_bytes < 8u || target > image_bytes - 8u)
        return PW_ERR_MALFORMED;
    memcpy(&value, mapped + target, sizeof(value));
    value += addend;
    memcpy(mapped + target, &value, sizeof(value));
    return PW_OK;
}

int pe_reloc_apply(uint8_t *mapped, uint32_t image_bytes,
                   const PeDataDirectory *directory,
                   uint64_t preferred_base, uint64_t actual_base,
                   PeRelocStats *stats)
{
    uint64_t delta;
    uint32_t cursor;
    uint32_t end;

    if (!mapped || !stats || image_bytes == 0u)
        return PW_ERR_PRECONDITION;
    memset(stats, 0, sizeof(*stats));
    delta = actual_base - preferred_base;
    stats->delta = delta;

    /*
     * A NULL directory means the image's data-directory array is shorter
     * than the base-relocation slot, which is well formed and equivalent
     * to an empty directory. It is not a caller error: reporting it as one
     * would send the next reader hunting for a bug in the mapper.
     */
    if (!directory || directory->virtual_address == 0u ||
        directory->size == 0u)
        return delta == 0u ? PW_OK : PW_ERR_UNSUPPORTED;
    if (directory->size > image_bytes ||
        directory->virtual_address > image_bytes - directory->size)
        return PW_ERR_MALFORMED;

    cursor = directory->virtual_address;
    end = directory->virtual_address + directory->size;
    while (cursor + 8u <= end) {
        uint32_t block_rva;
        uint32_t block_bytes;
        uint32_t entry_count;

        memcpy(&block_rva, mapped + cursor, sizeof(block_rva));
        memcpy(&block_bytes, mapped + cursor + 4u, sizeof(block_bytes));
        if (block_bytes == 0u)
            break;                          /* conventional terminator */
        if (block_bytes < 8u || (block_bytes & 1u) != 0u ||
            block_bytes > end - cursor)
            return PW_ERR_MALFORMED;
        if (block_rva >= image_bytes)
            return PW_ERR_MALFORMED;

        entry_count = (block_bytes - 8u) / 2u;
        for (uint32_t index = 0; index < entry_count; ++index) {
            uint16_t entry;
            uint32_t type;
            uint32_t target;
            int status;

            memcpy(&entry, mapped + cursor + 8u + index * 2u, sizeof(entry));
            type = (uint32_t)(entry >> 12);
            ++stats->entries;
            if (type == PE_RELOC_ABSOLUTE) {
                ++stats->absolute;
                continue;
            }
            if (block_rva > image_bytes - 1u)
                return PW_ERR_MALFORMED;
            target = block_rva + (uint32_t)(entry & 0x0fffu);
            if (target >= image_bytes)
                return PW_ERR_MALFORMED;

            switch (type) {
            case PE_RELOC_HIGHLOW:
                ++stats->highlow;
                if (delta == 0u)
                    continue;
                status = patch_u32(mapped, image_bytes, target,
                                   (uint32_t)delta);
                break;
            case PE_RELOC_DIR64:
                ++stats->dir64;
                if (delta == 0u)
                    continue;
                status = patch_u64(mapped, image_bytes, target, delta);
                break;
            case PE_RELOC_HIGH:
                ++stats->high_or_low;
                if (delta == 0u)
                    continue;
                status = patch_u16(mapped, image_bytes, target,
                                   (uint16_t)((delta >> 16) & 0xffffu));
                break;
            case PE_RELOC_LOW:
                ++stats->high_or_low;
                if (delta == 0u)
                    continue;
                status = patch_u16(mapped, image_bytes, target,
                                   (uint16_t)(delta & 0xffffu));
                break;
            default:
                /* HIGHADJ carries an extra word; refuse instead of desyncing. */
                return PW_ERR_UNSUPPORTED;
            }
            if (status != PW_OK)
                return status;
            ++stats->applied;
        }
        ++stats->blocks;
        cursor += block_bytes;
    }
    return PW_OK;
}
