/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The file adapter. The shape a Wine loader uses, the gate-owned directory
 * object, the IO_STATUS write-back and the NTSTATUS for every refused shape
 * live here; the files themselves live behind PwWineFileService. See
 * pw_wine_file.h.
 */
#include "pw_wine_file.h"

#include "pw_wine_context.h"
#include "pw_wine_handle.h"
#include "pw_wine_path.h"

#include <string.h>

void pw_wine_file_io_status(PwUnixCallAccess guest, void *context,
                            uint32_t address, uint32_t status,
                            uint64_t information)
{
    uint8_t block[8];

    memcpy(block, &status, 4u);
    memcpy(block + 4u, &information, 4u);
    (void)guest(context, address, block, sizeof(block), 1);
}

/*
 * The Windows directory itself is a gate-owned object. There is no
 * enumeration and no platform token behind it: the loader only needs its
 * existence, and FileStandardInformation reporting Directory = 1.
 */
int pw_wine_file_open_directory(PwWineCallContext *calls, const char *reported,
                                 uint32_t handle_pointer, uint32_t io_pointer,
                                 PwUnixCallAccess guest, void *context,
                                 uint32_t *status, uint32_t *argument_index)
{
    uint32_t handle = 0u;
    PwNtObject handle_object;

    /*
     * The canonical names this unit produces fit the handle's field by
     * construction; a refusal here would be a malformed call rather than a
     * status the guest could act on.
     */
    if (pw_wine_handle_object(NULL, 0u, NULL, &handle_object) != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (pw_wine_handle_alloc(calls, &handle_object,
                          PW_NT_HANDLE_DIRECTORY, &handle) != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    pw_wine_file_io_status(guest, context, io_pointer, PW_NT_SUCCESS, 0u);
    memcpy(calls->report->last_file, reported, strlen(reported) + 1u);
    calls->report->file_opens++;
    calls->report->file_directories++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtOpenFile for the runtime distribution. The accepted shape is the one a
 * loader uses: an OBJECT_ATTRIBUTES with a UNICODE_STRING name under the
 * Windows directory. Anything else is answered with a real NTSTATUS.
 */
int pw_wine_file_open(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    uint8_t attributes[24];
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t attributes_pointer = frame->args[2];
    const uint32_t io_pointer = frame->args[3];
    uint32_t name_pointer = 0u;
    char wide[2u * PW_WINE_GATE_MAX_PATH];
    char name[PW_WINE_GATE_MAX_PATH + 1];
    int directory = 0;
    uint64_t size = 0u;
    void *token = NULL;
    uint32_t handle = 0u;

    if (attributes_pointer == 0u || io_pointer == 0u || handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, attributes_pointer, attributes, sizeof(attributes),
              0) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    memcpy(&name_pointer, attributes + 8u, 4u);
    if (name_pointer == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (pw_wine_path_read_unicode(guest, context, name_pointer, wide, sizeof(wide)) !=
        PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_runtime(wide, name, sizeof(name), &directory, status) !=
        PW_OK) {
        const size_t length = strlen(wide);

        if (length <= PW_WINE_GATE_MAX_PATH)
            memcpy(calls->report->last_file, wide, length + 1u);
        calls->report->file_refusals++;
        return PW_OK;
    }
    /*
     * The Windows directory itself is a gate-owned object: there is no
     * enumeration and no platform token behind it, and the loader only needs
     * its existence and Directory = 1 from the standard information.
     */
    if (directory)
        return pw_wine_file_open_directory(calls, wide, handle_pointer, io_pointer,
                                     guest, context, status, argument_index);
    if (!calls->config->files) {
        *status = PW_NT_NOT_IMPLEMENTED;
        calls->report->file_refusals++;
        return PW_OK;
    }
    switch (calls->config->files->open(calls->config->files->context, name,
                                       &size, &token)) {
    case PW_WINE_FILE_OK:
        break;
    case PW_WINE_FILE_NOT_FOUND:
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        calls->report->file_refusals++;
        return PW_OK;
    case PW_WINE_FILE_DENIED:
        *status = PW_NT_ACCESS_DENIED;
        calls->report->file_refusals++;
        return PW_OK;
    default:
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->file_refusals++;
        return PW_OK;
    }
    PwNtObject handle_object;

    if (pw_wine_handle_object(token, size, NULL, &handle_object) != PW_OK) {
        calls->config->files->close(calls->config->files->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (pw_wine_handle_alloc(calls, &handle_object,
                          PW_NT_HANDLE_FILE, &handle) != PW_OK) {
        calls->config->files->close(calls->config->files->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    pw_wine_file_io_status(guest, context, io_pointer, PW_NT_SUCCESS, 0u);
    memcpy(calls->report->last_file, name, strlen(name) + 1u);
    calls->report->file_opens++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

int pw_wine_file_read(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[4];
    const uint32_t buffer = frame->args[5];
    const uint32_t length = frame->args[6];
    const uint32_t offset_pointer = frame->args[7];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    uint64_t offset = 0u;
    uint8_t staging[PW_WINE_GATE_MAX_READ];
    uint32_t read_bytes = 0u;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (kind == PW_NT_HANDLE_DIRECTORY) {
        *status = PW_NT_INVALID_DEVICE_REQUEST;
        calls->report->file_refusals++;
        return PW_OK;
    }
    if (kind != PW_NT_HANDLE_FILE) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (io_pointer == 0u || buffer == 0u || length == 0u) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (length > PW_WINE_GATE_MAX_READ) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->file_refusals++;
        return PW_OK;
    }
    offset = object->offset;
    if (offset_pointer != 0u) {
        uint8_t raw[8];
        uint32_t low = 0u, high = 0u;

        if (guest(context, offset_pointer, raw, sizeof(raw), 0) != PW_OK) {
            *argument_index = 7u;
            return PW_ERR_MALFORMED;
        }
        memcpy(&low, raw, 4u);
        memcpy(&high, raw + 4u, 4u);
        offset = (uint64_t)low | ((uint64_t)high << 32);
    }
    if (offset > object->size) {
        pw_wine_file_io_status(guest, context, io_pointer, PW_NT_END_OF_FILE, 0u);
        *status = PW_NT_SUCCESS;
        return PW_OK;
    }
    if (!calls->config->files ||
        calls->config->files->read(calls->config->files->context,
                                   object->token, offset, staging, length,
                                   &read_bytes) != PW_WINE_FILE_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (read_bytes != 0u &&
        guest(context, buffer, staging, read_bytes, 1) != PW_OK) {
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    object->offset = offset + read_bytes;
    pw_wine_file_io_status(guest, context, io_pointer, PW_NT_SUCCESS, read_bytes);
    calls->report->file_reads++;
    calls->report->file_bytes += read_bytes;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

int pw_wine_file_query_information(PwWineCallContext *calls,
                                          const PwUnixCallFrame *frame,
                                          PwUnixCallAccess guest, void *context,
                                          uint32_t *status,
                                          uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t information_class = frame->args[4];
    uint8_t block[22];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    uint32_t written;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (kind != PW_NT_HANDLE_FILE &&
        kind != PW_NT_HANDLE_DIRECTORY) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != 5u) {         /* FileStandardInformation */
        *status = PW_NT_INVALID_INFO_CLASS;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, &object->size, 8u);        /* AllocationSize */
    memcpy(block + 8u, &object->size, 8u);   /* EndOfFile */
    block[21] =
        kind == PW_NT_HANDLE_DIRECTORY ? 1u : 0u;
    written = length < sizeof(block) ? length : sizeof(block);
    if (written != 0u &&
        (information_pointer == 0u ||
         guest(context, information_pointer, block, written, 1) != PW_OK)) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (io_pointer != 0u)
        pw_wine_file_io_status(guest, context, io_pointer, PW_NT_SUCCESS, written);
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* FileFsDeviceInformation: FILE_FS_DEVICE_INFORMATION {DeviceType, Characteristics}. */
enum {
    PW_WINE_FS_DEVICE_INFORMATION = 4u,
    PW_WINE_FS_DEVICE_INFORMATION_BYTES = 8u,
    /* FILE_DEVICE_DISK_FILE_SYSTEM: the runtime distribution is a directory
     * tree on a fixed disk, and the gate does not probe the host for it. */
    PW_WINE_DEVICE_DISK_FILE_SYSTEM = 0x00000008u,
};

/*
 * NtQueryVolumeInformationFile for a gate-owned handle. The loader asks one
 * question about the directory it just opened: RtlSetCurrentDirectory_U
 * queries FileFsDeviceInformation and closes the handle again when
 * FILE_REMOVABLE_MEDIA is set. The runtime distribution is a fixed disk, so
 * the answer carries no characteristics; every other information class stays
 * unhandled and the guest is told so with a real NTSTATUS.
 */
int pw_wine_file_query_volume_information(PwWineCallContext *calls,
                                                 const PwUnixCallFrame *frame,
                                                 PwUnixCallAccess guest,
                                                 void *context,
                                                 uint32_t *status,
                                                 uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t information_class = frame->args[4];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    uint8_t block[8];
    const uint32_t device_type = PW_WINE_DEVICE_DISK_FILE_SYSTEM;
    const uint32_t characteristics = 0u;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    /* A key is not a file object: the volume information classes describe a
     * device the handle is not attached to. */
    if (kind != PW_NT_HANDLE_FILE &&
        kind != PW_NT_HANDLE_DIRECTORY) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != PW_WINE_FS_DEVICE_INFORMATION) {
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->file_refusals++;
        return PW_OK;
    }
    if (length < PW_WINE_FS_DEVICE_INFORMATION_BYTES) {
        *status = PW_NT_BUFFER_TOO_SMALL;
        if (io_pointer != 0u)
            pw_wine_file_io_status(guest, context, io_pointer, *status, 0u);
        calls->report->file_refusals++;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, &device_type, 4u);
    memcpy(block + 4u, &characteristics, 4u);
    if (information_pointer == 0u ||
        guest(context, information_pointer, block, sizeof(block), 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (io_pointer != 0u)
        pw_wine_file_io_status(guest, context, io_pointer, PW_NT_SUCCESS,
                        sizeof(block));
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
