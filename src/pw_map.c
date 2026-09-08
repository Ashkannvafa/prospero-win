#include "pw_map.h"

#include <string.h>

static const uint64_t FNV64_OFFSET = 1469598103934665603ull;
static const uint64_t FNV64_PRIME = 1099511628211ull;

static uint64_t checksum_bytes(const uint8_t *bytes, size_t count)
{
    uint64_t hash = FNV64_OFFSET;

    for (size_t index = 0; index < count; ++index) {
        hash ^= bytes[index];
        hash *= FNV64_PRIME;
    }
    return hash;
}

static int all_zero(const uint8_t *bytes, size_t count)
{
    for (size_t index = 0; index < count; ++index) {
        if (bytes[index] != 0u)
            return 0;
    }
    return 1;
}

int pw_map_image(PwMappedImage *mapped, const PeImage *image,
                 const PeLayout *layout, const PwVmBackend *backend)
{
    uint8_t *write;
    int status;

    if (!mapped || !image || !image->bytes || !layout ||
        !pw_vm_backend_valid(backend))
        return PW_ERR_PRECONDITION;
    if (layout->image_bytes == 0u || layout->section_count == 0u)
        return PW_ERR_PRECONDITION;
    memset(mapped, 0, sizeof(*mapped));

    status = backend->reserve(backend->context, layout->image_bytes,
                              layout->section_alignment, &mapped->region);
    if (status != PW_OK)
        return status;
    if (!mapped->region.write_base || !mapped->region.exec_base ||
        mapped->region.bytes < layout->image_bytes) {
        (void)backend->release(backend->context, &mapped->region);
        return PW_ERR_VM;
    }

    mapped->image_bytes = layout->image_bytes;
    mapped->section_count = layout->section_count;
    mapped->entry_point = layout->entry_point;
    mapped->preferred_base = layout->preferred_base;
    mapped->actual_base = (uint64_t)(uintptr_t)mapped->region.exec_base;
    mapped->aliased_exec =
        mapped->region.exec_base != mapped->region.write_base ? 1u : 0u;
    mapped->address_bits =
        image->optional_magic == PE_OPT_MAGIC_PE32 ? 32u : 64u;

    status = backend->commit(backend->context, &mapped->region, 0u,
                             layout->image_bytes,
                             PW_PROT_READ | PW_PROT_WRITE);
    if (status != PW_OK) {
        (void)backend->release(backend->context, &mapped->region);
        return status;
    }

    write = mapped->region.write_base;
    /* Never trust a fresh mapping to be zero: .bss correctness depends on it. */
    memset(write, 0, layout->image_bytes);
    if (layout->header_bytes > image->size) {
        (void)backend->release(backend->context, &mapped->region);
        return PW_ERR_TRUNCATED;
    }
    memcpy(write, image->bytes, layout->header_bytes);

    for (uint32_t index = 0; index < layout->section_count; ++index) {
        const PeLayoutSection *section = &layout->sections[index];

        if (section->raw_bytes == 0u)
            continue;
        if (section->raw_offset > image->size ||
            section->raw_bytes > image->size - section->raw_offset) {
            (void)backend->release(backend->context, &mapped->region);
            return PW_ERR_TRUNCATED;
        }
        memcpy(write + section->rva, image->bytes + section->raw_offset,
               section->raw_bytes);
    }

    /*
     * A PE32 image expresses relocations as 32-bit HIGHLOW addends, so a
     * rebase is only representable while the whole image lives below 4 GiB.
     * Refuse loudly instead of writing truncated pointers.
     */
    if (mapped->address_bits == 32u &&
        mapped->actual_base != mapped->preferred_base &&
        mapped->actual_base + layout->image_bytes > 0x100000000ull) {
        (void)backend->release(backend->context, &mapped->region);
        return PW_ERR_UNSUPPORTED;
    }

    status = pe_reloc_apply(write, layout->image_bytes,
                            pe_image_directory(image, PE_DIR_BASERELOC),
                            mapped->preferred_base, mapped->actual_base,
                            &mapped->relocs);
    if (status != PW_OK) {
        (void)backend->release(backend->context, &mapped->region);
        return status;
    }
    return PW_OK;
}

int pw_map_verify(const PwMappedImage *mapped, const PeImage *image,
                  const PeLayout *layout, PwMapVerify *out)
{
    const uint8_t *write;
    const uint8_t *exec;

    if (!mapped || !image || !image->bytes || !layout || !out)
        return PW_ERR_PRECONDITION;
    if (!mapped->region.write_base)
        return PW_ERR_STATE;
    if (mapped->protections_applied)
        return PW_ERR_STATE;   /* pages may no longer be readable */
    memset(out, 0, sizeof(*out));

    write = mapped->region.write_base;
    exec = mapped->region.exec_base;

    /*
     * A shallow header check, not a reparse: in the mapped view the section
     * table's raw offsets still refer to file positions, so a full parse of
     * this view is expected to fail and would prove nothing.
     */
    if (mapped->image_bytes >= PE_DOS_HEADER_BYTES &&
        write[0] == 'M' && write[1] == 'Z') {
        const uint32_t nt = image->nt_offset;

        if (nt + 4u <= mapped->image_bytes && write[nt] == 'P' &&
            write[nt + 1u] == 'E' && write[nt + 2u] == '\0' &&
            write[nt + 3u] == '\0')
            out->headers_present = 1u;
    }

    for (uint32_t index = 0; index < layout->section_count; ++index) {
        const PeLayoutSection *section = &layout->sections[index];
        const uint32_t zero_offset = section->rva + section->raw_bytes;

        ++out->sections_checked;
        if (mapped->relocs.applied == 0u && section->raw_bytes != 0u) {
            if (memcmp(write + section->rva,
                       image->bytes + section->raw_offset,
                       section->raw_bytes) != 0)
                ++out->raw_mismatches;
            out->bytes_compared += section->raw_bytes;
        }
        if (section->zero_bytes != 0u &&
            !all_zero(write + zero_offset, section->zero_bytes))
            ++out->zero_tail_violations;
        if (mapped->aliased_exec &&
            (section->protection & PW_PROT_EXEC) != 0u &&
            memcmp(write + section->rva, exec + section->rva,
                   section->mapped_bytes) != 0)
            ++out->alias_mismatches;
    }
    out->checksum = checksum_bytes(write, mapped->image_bytes);
    return PW_OK;
}

/* Union of the protections of every section overlapping one page. */
static unsigned page_protection(const PeLayout *layout, uint64_t page_start,
                                uint64_t page_bytes, uint32_t header_bytes,
                                uint32_t *contributors)
{
    const uint64_t page_end = page_start + page_bytes;
    unsigned protection = PW_PROT_NONE;

    *contributors = 0u;
    if (page_start < header_bytes) {
        protection |= PW_PROT_READ;   /* headers stay readable, never writable */
        ++*contributors;
    }
    for (uint32_t index = 0; index < layout->section_count; ++index) {
        const PeLayoutSection *section = &layout->sections[index];
        const uint64_t start = section->rva;
        const uint64_t end = start + section->mapped_bytes;

        if (start >= page_end)
            break;                    /* sections are ordered by RVA */
        if (end <= page_start)
            continue;
        protection |= section->protection;
        ++*contributors;
    }
    return protection;
}

int pw_map_finalize_protections(PwMappedImage *mapped, const PeLayout *layout,
                                const PwVmBackend *backend)
{
    size_t page;
    uint64_t cursor = 0u;
    uint64_t run_start = 0u;
    unsigned run_protection = PW_PROT_NONE;
    int have_run = 0;

    if (!mapped || !layout || !pw_vm_backend_valid(backend))
        return PW_ERR_PRECONDITION;
    if (!mapped->region.write_base)
        return PW_ERR_STATE;
    if (mapped->protections_applied)
        return PW_ERR_STATE;
    if ((backend->capabilities & PW_VM_CAP_PROTECT) == 0u || !backend->protect)
        return PW_ERR_UNSUPPORTED;

    page = backend->page_bytes;
    memset(&mapped->protection, 0, sizeof(mapped->protection));

    while (cursor < mapped->image_bytes) {
        uint64_t span = page;
        uint32_t contributors = 0u;
        unsigned protection;

        if (span > mapped->image_bytes - cursor)
            span = mapped->image_bytes - cursor;
        protection = page_protection(layout, cursor, page,
                                     layout->header_bytes, &contributors);
        ++mapped->protection.pages;
        if (contributors > 1u)
            ++mapped->protection.merged_pages;
        if ((protection & PW_PROT_WRITE) != 0u &&
            (protection & PW_PROT_EXEC) != 0u)
            ++mapped->protection.wx_pages;
        if (protection == PW_PROT_NONE)
            ++mapped->protection.no_access_pages;

        if (!have_run) {
            run_start = cursor;
            run_protection = protection;
            have_run = 1;
        } else if (protection != run_protection) {
            const int status =
                backend->protect(backend->context, &mapped->region,
                                 (size_t)run_start,
                                 (size_t)(cursor - run_start), run_protection);
            if (status != PW_OK)
                return status;
            ++mapped->protection.protect_calls;
            run_start = cursor;
            run_protection = protection;
        }
        cursor += span;
    }

    if (have_run) {
        const int status =
            backend->protect(backend->context, &mapped->region,
                             (size_t)run_start,
                             (size_t)(mapped->image_bytes - run_start),
                             run_protection);
        if (status != PW_OK)
            return status;
        ++mapped->protection.protect_calls;
    }
    mapped->protections_applied = 1u;
    return PW_OK;
}

int pw_map_release(PwMappedImage *mapped, const PwVmBackend *backend)
{
    int status;

    if (!mapped || !pw_vm_backend_valid(backend))
        return PW_ERR_PRECONDITION;
    if (!mapped->region.write_base)
        return PW_OK;
    status = backend->release(backend->context, &mapped->region);
    if (status != PW_OK)
        return status;
    memset(mapped, 0, sizeof(*mapped));
    return PW_OK;
}

void *pw_map_writable(const PwMappedImage *mapped, uint32_t rva, size_t bytes)
{
    if (!mapped || !mapped->region.write_base || bytes == 0u)
        return NULL;
    if (bytes > mapped->image_bytes || rva > mapped->image_bytes - bytes)
        return NULL;
    return (uint8_t *)mapped->region.write_base + rva;
}

uint64_t pw_map_exec_address(const PwMappedImage *mapped, uint32_t rva)
{
    if (!mapped || !mapped->region.exec_base || rva >= mapped->image_bytes)
        return 0u;
    return mapped->actual_base + rva;
}
