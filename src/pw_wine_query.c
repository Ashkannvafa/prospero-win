/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The calls whose answer is host state rather than a platform object: the Wine
 * version of the running distribution, the SID the process runs as, and the
 * process image described out of the mapped module's own PE headers. See
 * pw_wine_query.h.
 */
#include "pw_wine_query.h"

#include "pw_wine_context.h"
#include "pw_wine_path.h"

#include <string.h>

/* SYSTEM_INFORMATION_CLASS value this bridge answers (a Wine extension). */
enum {
    PW_WINE_SYSTEM_WINE_VERSION_INFORMATION = 1000u,
};

/*
 * NtQuerySystemInformation for the one class ntdll initialization asks
 * about: SystemWineVersionInformation, which version_init() stores so that
 * wine_get_version, wine_get_build_id and wine_get_host_version can read it.
 * The answer is the four NUL-terminated strings Wine packs together, and it
 * comes from the host - the version of the distribution actually being run -
 * so the guest cannot be told a version that is not the modules it executes.
 * Anything else is answered with STATUS_INVALID_INFO_CLASS, and a short
 * buffer with STATUS_INFO_LENGTH_MISMATCH, which is what Wine returns too.
 */
int pw_wine_query_system_information(PwWineCallContext *calls,
                                            const PwUnixCallFrame *frame,
                                            PwUnixCallAccess guest,
                                            void *context, uint32_t *status,
                                            uint32_t *argument_index)
{
    const uint32_t information_class = frame->args[0];
    const uint32_t information_pointer = frame->args[1];
    const uint32_t length = frame->args[2];
    const uint32_t return_pointer = frame->args[3];
    const PwWineGateConfig *config = calls->config;
    const uint32_t needed = config->wine_version_info_bytes;
    void *source = (void *)(uintptr_t)config->wine_version_info;

    if (information_class != PW_WINE_SYSTEM_WINE_VERSION_INFORMATION) {
        *status = PW_NT_INVALID_INFO_CLASS;
        return PW_OK;
    }
    if (source == NULL || needed == 0u) {
        *status = PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    if (return_pointer != 0u) {
        uint32_t written = needed;

        if (guest(context, return_pointer, &written, 4u, 1) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
    }
    if (length < needed) {
        *status = PW_NT_INFO_LENGTH_MISMATCH;
        return PW_OK;
    }
    if (information_pointer == 0u ||
        guest(context, information_pointer, source, needed, 1) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* TOKEN_USER {SID_AND_ATTRIBUTES User}, and the pseudo-handles holding it. */
enum {
    PW_WINE_TOKEN_USER = 1u,
    PW_WINE_TOKEN_HEADER = 8u,
    PW_WINE_TOKEN_MAX_SID = 256u,
    PW_WINE_TOKEN_CURRENT_PROCESS = 0xfffffffcu,        /* ~3 */
    PW_WINE_TOKEN_CURRENT_THREAD = 0xfffffffbu,         /* ~4 */
    PW_WINE_TOKEN_CURRENT_THREAD_EFFECTIVE = 0xfffffffau, /* ~5 */
};

/*
 * NtQueryInformationToken for TokenUser, which is what
 * RtlFormatCurrentUserKeyPath asks for before it builds
 * \Registry\User\<SID> and opens HKCU. The answer is the SID the host declares
 * for the process plus a zero attribute word, laid out the way NT lays it out:
 * the descriptor first, the SID immediately after it, and the SID pointer
 * naming that guest address. A short buffer reports the length it needed with
 * STATUS_BUFFER_TOO_SMALL, an unknown class is STATUS_INVALID_INFO_CLASS, and
 * a handle that is not one of the current-token pseudo-handles is
 * STATUS_INVALID_HANDLE.
 */
int pw_wine_query_token(PwWineCallContext *calls,
                                           const PwUnixCallFrame *frame,
                                           PwUnixCallAccess guest,
                                           void *context, uint32_t *status,
                                           uint32_t *argument_index)
{
    const uint32_t token_handle = frame->args[0];
    const uint32_t information_class = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t result_pointer = frame->args[4];
    const PwWineGateConfig *config = calls->config;
    const uint32_t sid_bytes = config->token_user_sid_bytes;
    uint8_t header[PW_WINE_TOKEN_HEADER];
    uint32_t sid_address = 0u;
    uint32_t needed = 0u;

    if (information_class != PW_WINE_TOKEN_USER) {
        *status = PW_NT_INVALID_INFO_CLASS;
        return PW_OK;
    }
    if (token_handle != PW_WINE_TOKEN_CURRENT_PROCESS &&
        token_handle != PW_WINE_TOKEN_CURRENT_THREAD &&
        token_handle != PW_WINE_TOKEN_CURRENT_THREAD_EFFECTIVE) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    calls->report->token_queries++;
    if (config->token_user_sid == NULL || sid_bytes < 8u ||
        sid_bytes > PW_WINE_TOKEN_MAX_SID || sid_bytes % 4u != 0u) {
        *status = PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    needed = PW_WINE_TOKEN_HEADER + sid_bytes;
    if (result_pointer != 0u &&
        guest(context, result_pointer, &needed, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (information_pointer == 0u || length < needed) {
        *status = PW_NT_BUFFER_TOO_SMALL;
        return PW_OK;
    }
    sid_address = information_pointer + PW_WINE_TOKEN_HEADER;
    memset(header, 0, sizeof(header));
    memcpy(header, &sid_address, 4u);           /* User.Sid */
    /* User.Attributes stays zero, as Wine writes it. */
    if (guest(context, information_pointer, header, sizeof(header), 1) !=
            PW_OK ||
        guest(context, sid_address, (void *)(uintptr_t)config->token_user_sid,
              sid_bytes, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* PROCESSINFOCLASS value and SECTION_IMAGE_INFORMATION, which is what ntdll's
 * loader asks about the image the process is running. */
enum {
    PW_WINE_PROCESS_IMAGE_INFORMATION = 0x25u,
    PW_WINE_SECTION_IMAGE_BYTES = 48u,
    /* ImageFlags: the image was relocated when it was mapped, and it lives
     * below 4 GiB. Nothing else applies to a native i386 PE. */
    PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED = 0x04u,
    PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB = 0x10u,
    PW_NT_CURRENT_PROCESS = 0xffffffffu,
};

/*
 * NtQueryInformationProcess for ProcessImageInformation: the class
 * build_main_module asks for before it decides whether the module the process
 * was handed is an executable. Every field is read out of that module's own PE
 * headers - the transfer address is its entry point, the stack sizes, versions,
 * characteristics, machine and checksum are its optional and file headers - so
 * the answer describes the image that is actually mapped, and ntdll's own
 * check (ImageCharacteristics & IMAGE_FILE_DLL) sees the truth.
 */
int pw_wine_query_process_image(PwWineCallContext *calls,
                                             const PwUnixCallFrame *frame,
                                             PwUnixCallAccess guest,
                                             void *context, uint32_t *status,
                                             uint32_t *argument_index)
{
    const uint32_t process_handle = frame->args[0];
    const uint32_t information_class = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t result_pointer = frame->args[4];
    const PwModule *root = calls->root;
    uint8_t block[PW_WINE_SECTION_IMAGE_BYTES];
    uint32_t needed = PW_WINE_SECTION_IMAGE_BYTES;

    if (process_handle != PW_NT_CURRENT_PROCESS) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != PW_WINE_PROCESS_IMAGE_INFORMATION) {
        *status = PW_NT_INVALID_INFO_CLASS;
        return PW_OK;
    }
    calls->report->process_queries++;
    if (root == NULL || root->mapped.actual_base == 0u) {
        *status = PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    if (result_pointer != 0u &&
        guest(context, result_pointer, &needed, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (information_pointer == 0u || length < sizeof(block)) {
        *status = PW_NT_INFO_LENGTH_MISMATCH;
        return PW_OK;
    }
    {
        const PeImage *image = &root->image;
        const uint32_t image_base = (uint32_t)root->mapped.actual_base;
        const uint32_t transfer = image_base + image->entry_point;
        const uint32_t subsystem = image->subsystem;
        const uint16_t characteristics = image->characteristics;
        const uint16_t dll_characteristics = image->dll_characteristics;
        const uint16_t machine = image->machine;
        const uint32_t file_size = (uint32_t)root->span.size;
        uint8_t contains_code = 0u;
        uint8_t flags = PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED |
                        PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB;

        for (uint32_t index = 0u; index < image->section_count; ++index)
            if ((image->sections[index].characteristics &
                 PE_SCN_MEM_EXECUTE) != 0u)
                contains_code = 1u;
        memset(block, 0, sizeof(block));
        memcpy(block + 0u, &transfer, 4u);
        memcpy(block + 8u, &image->stack_reserve, 4u);
        memcpy(block + 12u, &image->stack_commit, 4u);
        memcpy(block + 16u, &subsystem, 4u);
        memcpy(block + 20u, &image->subsystem_version_minor, 2u);
        memcpy(block + 22u, &image->subsystem_version_major, 2u);
        memcpy(block + 24u, &image->os_version_major, 2u);
        memcpy(block + 26u, &image->os_version_minor, 2u);
        memcpy(block + 28u, &characteristics, 2u);
        memcpy(block + 30u, &dll_characteristics, 2u);
        memcpy(block + 32u, &machine, 2u);
        block[34] = contains_code;
        block[35] = flags;
        memcpy(block + 40u, &file_size, 4u);
        memcpy(block + 44u, &image->checksum, 4u);
        calls->report->process_image_characteristics = characteristics;
    }
    if (guest(context, information_pointer, block, sizeof(block), 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
