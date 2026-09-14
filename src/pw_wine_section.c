/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Image sections. See pw_wine_section.h for why the loader needs them and why
 * the description outlives the file handle.
 */
#include "pw_wine_section.h"

#include "pe_image.h"
#include "pe_layout.h"
#include "pw_wine_context.h"
#include "pw_wine_handle.h"

#include <string.h>

enum {
    /* The shape ntdll's loader asks for: an image section over a file, mapped
     * executable, with no name and no explicit maximum size. */
    PW_WINE_SECTION_SEC_IMAGE = 0x01000000u,
    /* SECTION_ALL_ACCESS, the only access bits a section can be asked for. */
    PW_WINE_SECTION_ACCESS_MASK = 0x000f001fu,
};

static void put_le16(uint8_t *out, uint32_t offset, uint16_t value)
{
    out[offset + 0u] = (uint8_t)(value & 0xffu);
    out[offset + 1u] = (uint8_t)((value >> 8) & 0xffu);
}

static void put_le32(uint8_t *out, uint32_t offset, uint32_t value)
{
    out[offset + 0u] = (uint8_t)(value & 0xffu);
    out[offset + 1u] = (uint8_t)((value >> 8) & 0xffu);
    out[offset + 2u] = (uint8_t)((value >> 16) & 0xffu);
    out[offset + 3u] = (uint8_t)((value >> 24) & 0xffu);
}

/*
 * NtCreateSection for the one shape a loader uses: an unnamed SEC_IMAGE
 * section over an open file handle, created executable. The image is described
 * from the file's own headers here, once, and the description is what
 * NtQuerySection answers from - the loader asks immediately after creating the
 * section and before it closes the file handle.
 *
 * Every other shape is a real NTSTATUS rather than a fabricated section: a
 * named section, a data section (SEC_COMMIT/SEC_RESERVE and friends) and a
 * protection this run does not install are STATUS_NOT_SUPPORTED, an access mask
 * with bits outside SECTION_ALL_ACCESS is STATUS_ACCESS_DENIED, and a file that
 * is not a PE image is STATUS_INVALID_IMAGE_FORMAT.
 */
int pw_wine_section_create(PwWineCallContext *calls,
                           const PwUnixCallFrame *frame,
                           PwUnixCallAccess guest, void *context,
                           uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t desired_access = frame->args[1];
    const uint32_t attributes_pointer = frame->args[2];
    const uint32_t maximum_pointer = frame->args[3];
    const uint32_t protection = frame->args[4];
    const uint32_t allocation_attributes = frame->args[5];
    const uint32_t file_handle = frame->args[6];
    PwNtObject *file = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    PwNtObject section_object;
    uint8_t headers[PW_WINE_SECTION_HEADER_BYTES];
    uint32_t read_bytes = 0u;
    uint64_t maximum = 0u;
    uint32_t handle = 0u;

    if (handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    if (attributes_pointer != 0u) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (allocation_attributes != PW_WINE_SECTION_SEC_IMAGE ||
        protection != PW_WINE_SECTION_PAGE_EXECUTE_READ) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if ((desired_access & ~PW_WINE_SECTION_ACCESS_MASK) != 0u) {
        *status = PW_NT_ACCESS_DENIED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (pw_wine_handle_lookup(calls, file_handle, &file, &kind) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (kind != PW_NT_HANDLE_FILE || file->path[0] == '\0') {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (maximum_pointer != 0u) {
        if (guest(context, maximum_pointer, &maximum, 8u, 0) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
        /* No explicit size, or exactly the file's: the loader's shape. */
        if (maximum != 0u && maximum != file->size) {
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_refusals++;
            return PW_OK;
        }
    }
    if (!calls->config->files) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (calls->config->files->read(calls->config->files->context, file->token,
                                   0u, headers, sizeof(headers),
                                   &read_bytes) != PW_WINE_FILE_OK ||
        read_bytes == 0u) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (calls->section_count >= PW_WINE_GATE_MAX_SECTIONS) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_refusals++;
        return PW_OK;
    }
    /*
     * The headers are described here and the section data is read on demand
     * when a view is mapped, so this is the header-only parse: the same
     * validation, without requiring the file's bytes to be in this span. It
     * parses straight into the section, which owns the bytes the parse points
     * into, and a failure leaves the entry unused.
     */
    section = &calls->sections[calls->section_count];
    memset(section, 0, sizeof(*section));
    memcpy(section->headers, headers, read_bytes);
    if (pe_image_parse_headers(&section->image, section->headers,
                               read_bytes) != PW_OK) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_refusals++;
        return PW_OK;
    }
    memcpy(section->name, file->path, strlen(file->path) + 1u);
    section->file_size = file->size;
    section->protection = protection;
    section->attributes = allocation_attributes;
    /*
     * The handle names the section, not the file: what makes the section
     * alive is its own description, which is why the entry below can outlive
     * the file handle the loader is about to close.
     */
    if (pw_wine_handle_object(section, section->image.size_of_image,
                              section->name, &section_object) != PW_OK ||
        pw_wine_handle_alloc(calls, &section_object, PW_NT_HANDLE_SECTION,
                             &handle) != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_refusals++;
        return PW_OK;
    }
    calls->section_count++;
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    calls->report->section_creates++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtQuerySection. SectionImageInformation is the class the loader asks for and
 * the one is_valid_binary reads: TransferAddress is the image's own base plus
 * its entry point, exactly as wine fills it for a section that is not mapped
 * yet (dlls/ntdll/unix/virtual.c:6596-6619), and Machine is what decides
 * whether the image is one this process can run. SectionBasicInformation is
 * answered too, with a null BaseAddress because nothing is mapped yet.
 */
int pw_wine_section_query(PwWineCallContext *calls,
                          const PwUnixCallFrame *frame,
                          PwUnixCallAccess guest, void *context,
                          uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t information_class = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t result_pointer = frame->args[4];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    uint8_t block[PW_WINE_SECTION_IMAGE_BYTES];
    uint32_t needed = 0u;
    uint32_t transfer = 0u;
    const uint32_t base_address = 0u;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_SECTION || object->token == NULL) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    section = object->token;
    if (information_class == PW_WINE_SECTION_IMAGE_INFORMATION) {
        needed = PW_WINE_SECTION_IMAGE_BYTES;
    } else if (information_class == PW_WINE_SECTION_BASIC_INFORMATION) {
        needed = PW_WINE_SECTION_BASIC_BYTES;
    } else {
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->section_refusals++;
        return PW_OK;
    }
    calls->report->section_queries++;
    if (result_pointer != 0u &&
        guest(context, result_pointer, &needed, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (information_pointer == 0u || length < needed) {
        *status = PW_NT_INFO_LENGTH_MISMATCH;
        calls->report->section_refusals++;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    if (information_class == PW_WINE_SECTION_BASIC_INFORMATION) {
        put_le32(block, 0u, section->attributes);       /* Attributes */
        put_le32(block, 4u, base_address);              /* BaseAddress */
        put_le32(block, 8u, section->image.size_of_image);  /* Size */
    } else {
        const PeImage *image = &section->image;
        uint8_t contains_code = 0u;

        for (uint32_t index = 0u; index < image->section_count; ++index)
            if ((image->sections[index].characteristics & PE_SCN_MEM_EXECUTE)
                != 0u)
                contains_code = 1u;
        transfer = (uint32_t)image->image_base + image->entry_point;
        put_le32(block, 0u, transfer);                  /* TransferAddress */
        put_le32(block, 8u, image->stack_reserve);      /* MaximumStackSize */
        put_le32(block, 12u, image->stack_commit);     /* CommittedStackSize */
        put_le32(block, 16u, image->subsystem);         /* SubSystemType */
        put_le16(block, 20u, image->subsystem_version_minor);
        put_le16(block, 22u, image->subsystem_version_major);
        put_le16(block, 24u, image->os_version_major);
        put_le16(block, 26u, image->os_version_minor);
        put_le16(block, 28u, image->characteristics);
        put_le16(block, 30u, image->dll_characteristics);
        put_le16(block, 32u, image->machine);
        block[34] = contains_code;
        block[35] = PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED |
                    PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB;
        put_le32(block, 40u, (uint32_t)section->file_size);
        put_le32(block, 44u, image->checksum);
    }
    if (guest(context, information_pointer, block, needed, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtMapViewOfSection for the one shape a loader asks for: the section mapped
 * into this process, executable, with no offset into the section and no
 * explicit view size.
 *
 * The image is placed the way a mapper places one - the file's headers where
 * the image begins and each section's raw bytes at its own virtual address,
 * with the alignment gaps left zero and the load-time protections taken from
 * the section table - and nothing is relocated: a SEC_IMAGE view is the image
 * as the file holds it, and relocating it is the loader's own later work
 * through NtProtectVirtualMemory, which is also how it asks for pages it wants
 * to write.
 *
 * The base is the image's preferred one when this run can place it there,
 * because that is what a real process gets and what spares the loader the
 * relocation; otherwise the view goes where the run's own allocator has room
 * and the loader relocates it. Either way the guest is told the base it
 * actually got, and the whole view joins the run's regions so an unmap or a
 * cleanup gives back exactly what was mapped.
 */
int pw_wine_section_map_view(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t process_handle = frame->args[1];
    const uint32_t base_pointer = frame->args[2];
    const uint32_t zero_bits = frame->args[3];
    const uint32_t commit_size = frame->args[4];
    const uint32_t offset_pointer = frame->args[5];
    const uint32_t size_pointer = frame->args[6];
    const uint32_t inherit_disposition = frame->args[7];
    const uint32_t allocation_type = frame->args[8];
    const uint32_t page_protection = frame->args[9];
    PwX86State *state = context;
    const PwVmBackend *backend = &calls->vm->base;
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    const PeImage *image;
    PwVmRegion region;
    uint32_t base = 0u;
    uint32_t hint = 0u;
    uint32_t view_size = 0u;
    uint32_t bytes = 0u;
    uint32_t writable_low = 0u;
    uint32_t writable_high = 0u;
    void *span_handle = NULL;
    uint64_t span_size = 0u;
    uint32_t read_bytes = 0u;
    uint32_t header_bytes = 0u;
    int result;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_SECTION || object->token == NULL) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    section = object->token;
    image = &section->image;
    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (base_pointer == 0u ||
        guest(context, base_pointer, &hint, 4u, 0) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (size_pointer != 0u) {
        if (guest(context, size_pointer, &view_size, 4u, 0) != PW_OK) {
            *argument_index = 7u;
            return PW_ERR_MALFORMED;
        }
        if (view_size != 0u && view_size < image->size_of_image) {
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
    }
    /* The one shape: no zero bits, no commit size, no offset into the section,
     * no allocation type, and the protection a loader asks for. */
    if (zero_bits != 0u || commit_size != 0u || offset_pointer != 0u ||
        allocation_type != 0u ||
        page_protection != PW_WINE_SECTION_PAGE_EXECUTE_READ) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    if (inherit_disposition != PW_WINE_SECTION_VIEW_SHARE &&
        inherit_disposition != PW_WINE_SECTION_VIEW_UNMAP) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    if (image->size_of_image == 0u ||
        (image->size_of_image & (PW_WINE_SECTION_PAGE_BYTES - 1u)) != 0u) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    /*
     * Every section must fit inside the image, and the bytes it claims must
     * exist in the file: the header-only parse could not check the second one,
     * because it never held the file, and this is where they are read.
     */
    for (uint32_t index = 0u; index < image->section_count; ++index) {
        const PeSection *entry = &image->sections[index];
        const uint64_t span = entry->virtual_size > entry->raw_size
            ? entry->virtual_size : entry->raw_size;

        if ((uint64_t)entry->virtual_address + span > image->size_of_image ||
            (entry->raw_size != 0u &&
             (uint64_t)entry->raw_offset + entry->raw_size >
                 section->file_size)) {
            *status = PW_NT_INVALID_IMAGE_FORMAT;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
        if ((entry->characteristics & PE_SCN_MEM_WRITE) != 0u &&
            entry->raw_size != 0u) {
            const uint32_t low = entry->virtual_address;
            const uint32_t high = low + (uint32_t)span;

            if (writable_low == 0u || low < writable_low)
                writable_low = low;
            if (high > writable_high)
                writable_high = high;
        }
    }
    if (calls->region_count >= PW_WINE_GATE_MAX_CALL_REGIONS ||
        !calls->config->files || section->name[0] == '\0') {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    bytes = image->size_of_image;
    memset(&region, 0, sizeof(region));
    /*
     * The preferred base first: an image placed where it wants to be needs no
     * relocation. When this run cannot place it there the view goes where the
     * allocator has room, and the loader relocates it.
     */
    result = backend->reserve_at(backend->context,
                                 hint != 0u ? hint : (uint32_t)image->image_base,
                                 bytes, (uint32_t)backend->page_bytes, &region);
    if (result != PW_OK) {
        uint32_t candidate = PW_WINE_GATE_HEAP_BASE;

        result = PW_ERR_VM;
        for (; (uint64_t)candidate + bytes <= PW_WINE_GATE_HEAP_LIMIT;
             candidate += (uint32_t)backend->page_bytes) {
            if (backend->reserve_at(backend->context, candidate, bytes,
                                    (uint32_t)backend->page_bytes,
                                    &region) == PW_OK) {
                result = PW_OK;
                break;
            }
        }
    }
    if (result != PW_OK) {
        *status = PW_NT_CONFLICTING_ADDRESSES;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    result = backend->commit(backend->context, &region, 0u, region.bytes,
                             PW_PROT_READ | PW_PROT_WRITE | PW_PROT_EXEC);
    if (result != PW_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    base = (uint32_t)(uintptr_t)region.exec_base;
    header_bytes = image->size_of_headers < section->file_size
        ? image->size_of_headers : (uint32_t)section->file_size;
    /*
     * The bytes, straight from the service into the mapping the guest will
     * use: the headers where the image begins, then each section at its own
     * virtual address. A short read is a file that does not hold the image its
     * headers describe, and the whole view goes back.
     */
    if (calls->config->files->open(calls->config->files->context,
                                   section->name, &span_size,
                                   &span_handle) != PW_WINE_FILE_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    result = PW_OK;
    if (span_size < section->file_size ||
        calls->config->files->read(calls->config->files->context, span_handle,
                                   0u, (void *)(uintptr_t)base, header_bytes,
                                   &read_bytes) != PW_WINE_FILE_OK ||
        read_bytes != header_bytes)
        result = PW_ERR_NOT_FOUND;
    for (uint32_t index = 0u;
         result == PW_OK && index < image->section_count; ++index) {
        const PeSection *entry = &image->sections[index];

        if (entry->raw_size == 0u)
            continue;
        if (calls->config->files->read(
                calls->config->files->context, span_handle, entry->raw_offset,
                (void *)(uintptr_t)(base + entry->virtual_address),
                entry->raw_size, &read_bytes) != PW_WINE_FILE_OK ||
            read_bytes != entry->raw_size)
            result = PW_ERR_NOT_FOUND;
    }
    calls->config->files->close(calls->config->files->context, span_handle);
    if (result != PW_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    /*
     * The load-time protections, section by section, from the characteristics
     * the section table carries: they are the host's side of the same rule the
     * declared regions express - code readable and executable, data readable
     * and writable, and the page the headers live on readable.
     */
    if (backend->protect(backend->context, &region, 0u, header_bytes,
                         PW_PROT_READ) != PW_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    for (uint32_t index = 0u; index < image->section_count; ++index) {
        const PeSection *entry = &image->sections[index];
        const uint64_t span = entry->virtual_size > entry->raw_size
            ? entry->virtual_size : entry->raw_size;
        int derived = 0;
        unsigned protection;

        if (span == 0u ||
            (uint64_t)entry->virtual_address + span > image->size_of_image)
            continue;
        protection = pe_layout_protection(entry->characteristics, &derived);
        if (protection == 0u)
            continue;
        if (backend->protect(backend->context, &region,
                             entry->virtual_address, (size_t)span,
                             protection) != PW_OK) {
            (void)backend->release(backend->context, &region);
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
    }
    /*
     * The guest's view of the same mapping: the whole image is readable, and
     * the union of the writable sections is writable - the rule the process
     * graph's own modules are declared by. A page becomes writable for the
     * guest when NtProtectVirtualMemory says so.
     */
    if (state->memory_count + 2u > PW_X86_MEMORY_REGIONS) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    state->memory[state->memory_count++] = (PwX86Memory){
        .low = base,
        .high = (uint64_t)base + bytes,
        .permissions = PW_X86_READ,
    };
    if (writable_low != 0u && writable_low < writable_high) {
        state->memory[state->memory_count++] = (PwX86Memory){
            .low = base + writable_low,
            .high = (uint64_t)base + writable_high,
            .permissions = PW_X86_READ | PW_X86_WRITE,
        };
    }
    calls->regions[calls->region_count] = region;
    calls->region_owned[calls->region_count] = 0u;
    calls->region_count++;
    calls->report->call_regions = calls->region_count;
    calls->report->section_views++;
    if (guest(context, base_pointer, &base, 4u, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (size_pointer != 0u &&
        guest(context, size_pointer, &bytes, 4u, 1) != PW_OK) {
        *argument_index = 7u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
