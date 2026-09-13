/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_tls.h"

#include <string.h>

static uint32_t read_u32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int readable(const PeImage *image, uint32_t rva, uint32_t bytes)
{
    return pe_image_file_offset(image, rva, bytes, &(size_t){0}) == PW_OK;
}

/* Guest VA -> RVA. A field below the image base is a file offset or a host
 * pointer, not a guest address, and must not be accepted silently. */
static int va_to_rva(const PeImage *image, uint32_t va, uint32_t bytes,
                     uint32_t *rva)
{
    if (va == 0u)
        return PW_ERR_NOT_FOUND;
    if ((uint64_t)va < image->image_base ||
        (uint64_t)va - image->image_base > 0xffffffffull)
        return PW_ERR_MALFORMED;
    *rva = (uint32_t)((uint64_t)va - image->image_base);
    if (!readable(image, *rva, bytes))
        return PW_ERR_MALFORMED;
    return PW_OK;
}

static int parse_callbacks(const PeImage *image, PeTlsDirectory *tls,
                           uint32_t callbacks_rva)
{
    for (uint32_t index = 0;; ++index) {
        size_t offset;
        uint32_t va;
        uint32_t rva;
        int status;

        if (index >= PE_TLS_MAX_CALLBACKS) {
            /* Still nonzero after the bound: the array is not a TLS callback
             * table, or it is one nobody should execute. */
            return PW_ERR_LIMIT;
        }
        if (callbacks_rva > 0xffffffffu - index * 4u)
            return PW_ERR_MALFORMED;
        status = pe_image_file_offset(image, callbacks_rva + index * 4u, 4u,
                                      &offset);
        if (status != PW_OK)
            return PW_ERR_MALFORMED;
        va = read_u32(image->bytes + offset);
        if (va == 0u) {
            tls->callback_count = index;
            return PW_OK;
        }
        status = va_to_rva(image, va, 1u, &rva);
        if (status != PW_OK)
            return status;
        {
            const PeSection *section = pe_image_section_for_rva(image, rva);

            if (!section || (section->characteristics & PE_SCN_MEM_EXECUTE) == 0u)
                return PW_ERR_MALFORMED;
        }
        tls->callbacks[index].va = va;
        tls->callbacks[index].rva = rva;
    }
}

int pe_tls_parse(PeTlsDirectory *tls, const PeImage *image)
{
    const PeDataDirectory *entry;
    uint8_t header[PE_TLS_DIRECTORY_BYTES];
    size_t offset;
    int status;

    if (!tls || !image || !image->bytes)
        return PW_ERR_PRECONDITION;
    memset(tls, 0, sizeof(*tls));
    entry = pe_image_directory(image, PE_DIR_TLS);
    if (!entry || entry->virtual_address == 0u || entry->size == 0u)
        return PW_OK;
    if (entry->size < PE_TLS_DIRECTORY_BYTES)
        return PW_ERR_MALFORMED;
    status = pe_image_file_offset(image, entry->virtual_address,
                                  PE_TLS_DIRECTORY_BYTES, &offset);
    if (status != PW_OK)
        return status;
    memcpy(header, image->bytes + offset, sizeof(header));

    tls->directory_rva = entry->virtual_address;
    tls->directory_size = entry->size;
    tls->start_va = read_u32(header);
    tls->end_va = read_u32(header + 4u);
    tls->index_va = read_u32(header + 8u);
    tls->callbacks_va = read_u32(header + 12u);
    tls->zero_fill = read_u32(header + 16u);
    tls->characteristics = read_u32(header + 20u);

    if (tls->zero_fill > PE_TLS_MAX_ZERO_FILL)
        return PW_ERR_LIMIT;

    /* Template start and end are either both present or both absent. */
    if ((tls->start_va == 0u) != (tls->end_va == 0u))
        return PW_ERR_MALFORMED;
    if (tls->start_va != 0u) {
        uint32_t start_rva;

        if (tls->end_va < tls->start_va)
            return PW_ERR_MALFORMED;
        tls->template_bytes = tls->end_va - tls->start_va;
        if (tls->template_bytes > PE_TLS_MAX_TEMPLATE)
            return PW_ERR_LIMIT;
        status = va_to_rva(image, tls->start_va, tls->template_bytes,
                           &start_rva);
        if (status != PW_OK)
            return status;
        tls->template_rva = start_rva;
    }
    if (tls->template_bytes > 0xffffffffu - tls->zero_fill)
        return PW_ERR_OVERFLOW;
    tls->storage_bytes = tls->template_bytes + tls->zero_fill;

    /* The index slot is where the loader publishes this module's TLS index. */
    if (tls->index_va == 0u)
        return PW_ERR_MALFORMED;
    if ((tls->index_va & 3u) != 0u)
        return PW_ERR_MALFORMED;
    status = va_to_rva(image, tls->index_va, 4u, &tls->index_rva);
    if (status != PW_OK)
        return status;

    if (tls->callbacks_va == 0u)
        return PW_OK;
    if ((tls->callbacks_va & 3u) != 0u)
        return PW_ERR_MALFORMED;
    {
        uint32_t callbacks_rva;

        status = va_to_rva(image, tls->callbacks_va, 4u, &callbacks_rva);
        if (status != PW_OK)
            return status;
        status = parse_callbacks(image, tls, callbacks_rva);
        if (status != PW_OK)
            return status;
    }
    return PW_OK;
}
