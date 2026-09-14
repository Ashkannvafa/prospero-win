/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Image sections. See pw_wine_section.h for why the loader needs them and why
 * the description outlives the file handle.
 */
#include "pw_wine_section.h"

#include "pe_image.h"
#include "pw_wine_context.h"
#include "pw_wine_handle.h"

#include <string.h>

enum {
    /* The shape ntdll's loader asks for: an image section over a file, mapped
     * executable, with no name and no explicit maximum size. */
    PW_WINE_SECTION_SEC_IMAGE = 0x01000000u,
    PW_WINE_SECTION_PAGE_EXECUTE_READ = 0x20u,
    /* SECTION_ALL_ACCESS, the only access bits a section can be asked for. */
    PW_WINE_SECTION_ACCESS_MASK = 0x000f001fu,
    /* How much of the file is read to describe the image: enough for the DOS
     * and NT headers and the section table of any PE this project loads. */
    PW_WINE_SECTION_HEADER_BYTES = 4096u,
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
    PeImage image;
    uint8_t headers[PW_WINE_SECTION_HEADER_BYTES];
    uint32_t read_bytes = 0u;
    uint64_t maximum = 0u;
    uint32_t handle = 0u;
    uint8_t contains_code = 0u;

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
    /*
     * The headers are described here and the section data is read on demand
     * when a view is mapped, so this is the header-only parse: the same
     * validation, without requiring the file's bytes to be in this span.
     */
    if (pe_image_parse_headers(&image, headers, read_bytes) != PW_OK) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (calls->section_count >= PW_WINE_GATE_MAX_SECTIONS) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_refusals++;
        return PW_OK;
    }
    for (uint32_t index = 0u; index < image.section_count; ++index)
        if ((image.sections[index].characteristics & PE_SCN_MEM_EXECUTE) != 0u)
            contains_code = 1u;
    section = &calls->sections[calls->section_count];
    memset(section, 0, sizeof(*section));
    memcpy(section->name, file->path, strlen(file->path) + 1u);
    section->file_size = file->size;
    section->protection = protection;
    section->attributes = allocation_attributes;
    section->image_size = image.size_of_image;
    section->image_base = image.image_base;
    section->entry_point = image.entry_point;
    section->stack_reserve = image.stack_reserve;
    section->stack_commit = image.stack_commit;
    section->subsystem = image.subsystem;
    section->subsystem_version_minor = image.subsystem_version_minor;
    section->subsystem_version_major = image.subsystem_version_major;
    section->os_version_major = image.os_version_major;
    section->os_version_minor = image.os_version_minor;
    section->characteristics = image.characteristics;
    section->dll_characteristics = image.dll_characteristics;
    section->machine = image.machine;
    section->contains_code = contains_code;
    section->image_flags = PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED |
                           PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB;
    section->checksum = image.checksum;
    /*
     * The handle names the section, not the file: what makes the section
     * alive is its own description, which is why the entry below can outlive
     * the file handle the loader is about to close.
     */
    if (pw_wine_handle_object(section, section->image_size, section->name,
                              &section_object) != PW_OK ||
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
        put_le32(block, 8u, section->image_size);       /* Size */
    } else {
        transfer = (uint32_t)section->image_base + section->entry_point;
        put_le32(block, 0u, transfer);                  /* TransferAddress */
        put_le32(block, 8u, section->stack_reserve);    /* MaximumStackSize */
        put_le32(block, 12u, section->stack_commit);    /* CommittedStackSize */
        put_le32(block, 16u, section->subsystem);       /* SubSystemType */
        put_le16(block, 20u, section->subsystem_version_minor);
        put_le16(block, 22u, section->subsystem_version_major);
        put_le16(block, 24u, section->os_version_major);
        put_le16(block, 26u, section->os_version_minor);
        put_le16(block, 28u, section->characteristics);
        put_le16(block, 30u, section->dll_characteristics);
        put_le16(block, 32u, section->machine);
        block[34] = section->contains_code;
        block[35] = section->image_flags;
        put_le32(block, 40u, (uint32_t)section->file_size);
        put_le32(block, 44u, section->checksum);
    }
    if (guest(context, information_pointer, block, needed, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
