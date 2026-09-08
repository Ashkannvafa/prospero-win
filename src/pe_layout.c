#include "pe_layout.h"

#include <string.h>

enum {
    PE_MIN_SECTION_ALIGNMENT = 4096u,   /* one page; smaller needs raw mapping */
};

static int align_up_u32(uint32_t value, uint32_t alignment, uint32_t *out)
{
    const uint32_t mask = alignment - 1u;
    if (value > 0xffffffffu - mask)
        return PW_ERR_OVERFLOW;
    *out = (value + mask) & ~mask;
    return PW_OK;
}

unsigned pe_layout_protection(uint32_t characteristics, int *derived)
{
    unsigned protection = 0u;

    if (derived)
        *derived = 0;
    if ((characteristics & PE_SCN_MEM_READ) != 0u)
        protection |= PW_PROT_READ;
    if ((characteristics & PE_SCN_MEM_WRITE) != 0u)
        protection |= PW_PROT_WRITE;
    if ((characteristics & PE_SCN_MEM_EXECUTE) != 0u)
        protection |= PW_PROT_EXEC;
    if (protection != 0u)
        return protection;

    /*
     * Some linkers emit a code or data section with no access bits. Windows
     * maps that as no-access; a loader that then jumps into it faults with
     * the signature the porting playbook calls a control-transfer class
     * fault. Normalise instead, and record that the protection was derived
     * rather than declared, so telemetry can show how often it happens.
     */
    if (derived)
        *derived = 1;
    if ((characteristics & PE_SCN_CNT_CODE) != 0u)
        return PW_PROT_READ | PW_PROT_EXEC;
    if ((characteristics & (PE_SCN_CNT_INITIALIZED_DATA |
                            PE_SCN_CNT_UNINITIALIZED_DATA)) != 0u)
        return PW_PROT_READ;
    return PW_PROT_NONE;
}

int pe_layout_plan(PeLayout *layout, const PeImage *image)
{
    uint32_t previous_end = 0u;
    uint32_t header_span = 0u;
    int status;

    if (!layout || !image || !image->bytes)
        return PW_ERR_PRECONDITION;
    memset(layout, 0, sizeof(*layout));

    if (image->section_alignment < PE_MIN_SECTION_ALIGNMENT)
        return PW_ERR_UNSUPPORTED;      /* raw-mapped image, not handled */
    if ((image->image_base & (image->section_alignment - 1u)) != 0u)
        return PW_ERR_MALFORMED;
    if (image->size_of_headers > image->size)
        return PW_ERR_TRUNCATED;

    layout->preferred_base = image->image_base;
    layout->section_alignment = image->section_alignment;
    layout->entry_point = image->entry_point;
    layout->header_bytes = image->size_of_headers;
    layout->dynamic_base =
        (image->dll_characteristics & PE_DLLCHAR_DYNAMIC_BASE) != 0u;
    layout->nx_compat =
        (image->dll_characteristics & PE_DLLCHAR_NX_COMPAT) != 0u;

    const PeDataDirectory *reloc =
        pe_image_directory(image, PE_DIR_BASERELOC);
    layout->relocatable = reloc && reloc->virtual_address != 0u &&
                          reloc->size != 0u;

    status = align_up_u32(image->size_of_image, image->section_alignment,
                          &layout->image_bytes);
    if (status != PW_OK)
        return status;
    status = align_up_u32(image->size_of_headers, image->section_alignment,
                          &header_span);
    if (status != PW_OK)
        return status;
    if (header_span > layout->image_bytes)
        return PW_ERR_MALFORMED;
    previous_end = header_span;

    for (uint16_t index = 0; index < image->section_count; ++index) {
        const PeSection *source = &image->sections[index];
        PeLayoutSection *target = &layout->sections[index];
        uint32_t virtual_bytes;
        uint32_t mapped_bytes;
        uint32_t raw_bytes;
        int derived = 0;

        if ((source->virtual_address & (image->section_alignment - 1u)) != 0u)
            return PW_ERR_MALFORMED;
        if (source->virtual_address < previous_end)
            return PW_ERR_MALFORMED;    /* unordered or overlapping */

        virtual_bytes = source->virtual_size != 0u ? source->virtual_size
                                                   : source->raw_size;
        if (virtual_bytes == 0u)
            return PW_ERR_MALFORMED;
        status = align_up_u32(virtual_bytes, image->section_alignment,
                              &mapped_bytes);
        if (status != PW_OK)
            return status;
        if (mapped_bytes > layout->image_bytes ||
            source->virtual_address > layout->image_bytes - mapped_bytes)
            return PW_ERR_MALFORMED;

        /*
         * File alignment padding routinely makes SizeOfRawData larger than
         * VirtualSize; only the virtual span is copied, and the rest of the
         * mapped span is zero filled.
         */
        raw_bytes = source->raw_size < virtual_bytes ? source->raw_size
                                                     : virtual_bytes;
        if (raw_bytes != 0u &&
            (source->raw_offset > image->size ||
             raw_bytes > image->size - source->raw_offset))
            return PW_ERR_TRUNCATED;

        memcpy(target->name, source->name, sizeof(target->name));
        target->rva = source->virtual_address;
        target->mapped_bytes = mapped_bytes;
        target->virtual_bytes = virtual_bytes;
        target->raw_offset = source->raw_offset;
        target->raw_bytes = raw_bytes;
        target->zero_bytes = mapped_bytes - raw_bytes;
        target->characteristics = source->characteristics;
        target->protection =
            (uint8_t)pe_layout_protection(source->characteristics, &derived);
        target->derived_protection = (uint8_t)derived;
        target->uninitialized =
            (source->characteristics & PE_SCN_CNT_UNINITIALIZED_DATA) != 0u;
        target->discardable =
            (source->characteristics & PE_SCN_MEM_DISCARDABLE) != 0u;

        if ((target->protection & PW_PROT_EXEC) != 0u)
            layout->exec_bytes += mapped_bytes;
        if ((target->protection & PW_PROT_WRITE) != 0u)
            layout->write_bytes += mapped_bytes;
        layout->copy_bytes += raw_bytes;
        layout->zero_bytes += target->zero_bytes;

        previous_end = source->virtual_address + mapped_bytes;
        layout->section_count = (uint32_t)index + 1u;
    }

    if (previous_end > layout->image_bytes)
        return PW_ERR_MALFORMED;
    if (layout->entry_point != 0u &&
        layout->entry_point >= layout->image_bytes)
        return PW_ERR_MALFORMED;
    return PW_OK;
}
