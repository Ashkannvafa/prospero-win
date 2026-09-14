/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The object-namespace adapter: \KnownDlls and the sections inside it, with
 * the profile behind PwWineObjectService deciding what the namespace holds and
 * a name it does not declare answering STATUS_OBJECT_NAME_NOT_FOUND. See
 * pw_wine_object.h.
 */
#include "pw_wine_object.h"

#include "pw_wine_context.h"
#include "pw_wine_handle.h"
#include "pw_wine_path.h"

#include <string.h>

/*
 * OBJECT_ATTRIBUTES to one canonical object path, absolute or relative to a
 * directory object the gate owns.
 */
int pw_wine_object_resolve(PwWineCallContext *calls,
                               uint32_t attributes_pointer,
                               PwUnixCallAccess guest, void *context,
                               char *canonical, size_t canonical_bytes,
                               uint32_t *status, uint32_t *argument_index)
{
    uint8_t attributes[24];
    uint32_t name_pointer = 0u;
    uint32_t root_handle = 0u;
    char name[PW_WINE_GATE_MAX_PATH + 1];
    char relative[PW_WINE_GATE_MAX_PATH + 1];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;

    if (attributes_pointer == 0u) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, attributes_pointer, attributes, sizeof(attributes),
              0) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    memcpy(&root_handle, attributes + 4u, 4u);     /* RootDirectory */
    memcpy(&name_pointer, attributes + 8u, 4u);    /* ObjectName */
    if (name_pointer == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (pw_wine_path_read_unicode(guest, context, name_pointer, name, sizeof(name)) !=
        PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (root_handle == 0u) {
        if (pw_wine_path_object(name, canonical, canonical_bytes, status) !=
            PW_OK) {
            const size_t length = strlen(name);

            if (length <= PW_WINE_GATE_MAX_PATH)
                memcpy(calls->report->last_object, name, length + 1u);
            calls->report->object_refusals++;
            return PW_OK;
        }
    } else {
        size_t used = 0u;

        if (pw_wine_handle_lookup(calls, root_handle, &object, &kind) != PW_OK ||
            kind != PW_NT_HANDLE_OBJECT_DIRECTORY) {
            *status = PW_NT_INVALID_HANDLE;
            return PW_OK;
        }
        used = strlen(object->path);
        if (used + strlen(name) + 2u > sizeof(relative)) {
            *status = PW_NT_OBJECT_NAME_INVALID;
            calls->report->object_refusals++;
            return PW_OK;
        }
        memcpy(relative, object->path, used);
        relative[used++] = '\\';
        memcpy(relative + used, name, strlen(name) + 1u);
        if (pw_wine_path_object(relative, canonical, canonical_bytes,
                                  status) != PW_OK) {
            calls->report->object_refusals++;
            return PW_OK;
        }
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtOpenDirectoryObject and NtOpenSection share everything except the kind
 * they ask the profile for: the path resolution, the handle bookkeeping and
 * the NTSTATUS a profile without the name produces.
 */
int pw_wine_object_open(PwWineCallContext *calls,
                               const PwUnixCallFrame *frame,
                               PwUnixCallAccess guest, void *context,
                               PwWineObjectKind kind, unsigned handle_kind,
                               uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t attributes_pointer = frame->args[2];
    char canonical[PW_WINE_GATE_MAX_PATH + 1];
    void *token = NULL;
    uint32_t handle = 0u;
    int result;

    if (handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    result = pw_wine_object_resolve(calls, attributes_pointer, guest, context,
                                 canonical, sizeof(canonical), status,
                                 argument_index);
    if (result != PW_OK)
        return result;
    if (*status != PW_NT_SUCCESS)
        return PW_OK;
    if (!calls->config->objects) {
        *status = PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    switch (calls->config->objects->open(calls->config->objects->context, kind,
                                         canonical, &token)) {
    case PW_WINE_OBJECT_OK:
        break;
    case PW_WINE_OBJECT_NOT_FOUND:
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        memcpy(calls->report->last_object, canonical, strlen(canonical) + 1u);
        calls->report->object_refusals++;
        return PW_OK;
    case PW_WINE_OBJECT_DENIED:
        *status = PW_NT_ACCESS_DENIED;
        calls->report->object_refusals++;
        return PW_OK;
    default:
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->object_refusals++;
        return PW_OK;
    }
    PwNtObject handle_object;

    if (pw_wine_handle_object(token, 0u, canonical, &handle_object) != PW_OK) {
        calls->config->objects->close(calls->config->objects->context, token);
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_OK;
    }
    if (pw_wine_handle_alloc(calls, &handle_object, handle_kind, &handle) !=
        PW_OK) {
        calls->config->objects->close(calls->config->objects->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    memcpy(calls->report->last_object, canonical, strlen(canonical) + 1u);
    calls->report->object_opens++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * Services one intercepted Unix call. PW_WINE_STOP_NONE means the guest may
 * continue: the handler's NTSTATUS is in EAX, the stdcall frame is popped and
 * EIP returns to the stub, exactly as Wine's own dispatcher would leave it.
 * Any other value is the reason the run stopped, and the guest state is
 * untouched so the evidence describes the boundary itself.
 */
/* The two object-namespace entries differ only in what they ask for, and
 * NtClose is a service like any other, so each gets a uniform-signature
 * adapter to appear in the registry. */
int pw_wine_object_open_directory(PwWineCallContext *calls,
                                        const PwUnixCallFrame *frame,
                                        PwUnixCallAccess guest, void *context,
                                        uint32_t *status,
                                        uint32_t *argument_index)
{
    return pw_wine_object_open(calls, frame, guest, context,
                               PW_WINE_OBJECT_DIRECTORY,
                               PW_NT_HANDLE_OBJECT_DIRECTORY, status,
                               argument_index);
}

int pw_wine_object_open_section(PwWineCallContext *calls,
                               const PwUnixCallFrame *frame,
                               PwUnixCallAccess guest, void *context,
                               uint32_t *status, uint32_t *argument_index)
{
    return pw_wine_object_open(calls, frame, guest, context,
                               PW_WINE_OBJECT_SECTION, PW_NT_HANDLE_SECTION,
                               status, argument_index);
}
