/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * What the run does around the typed handle table: publish the live count,
 * close the right service token on release, and answer NtClose for every
 * kind. See pw_wine_handle.h.
 */
#include "pw_wine_handle.h"

#include "pw_wine_context.h"

#include <string.h>

/*
 * Platform file service plumbing. Handles are gate-owned indices so a guest
 * cannot forge one: the value carries a fixed base and the slot has to be
 * live, and every guest buffer is reached through the dispatcher's validated
 * accessor.
 */
/*
 * Handles are gate-owned and typed. The value the guest sees is opaque and
 * generation-safe, so a handle it kept from a released slot is refused rather
 * than naming whatever was allocated next; the table itself lives in
 * src/pw_nt_handle.[ch].
 */
int pw_wine_handle_alloc(PwWineCallContext *calls, const PwNtObject *object,
                             unsigned kind, uint32_t *value)
{
    const int status =
        pw_nt_handle_alloc(&calls->handles, kind, object, value);

    calls->report->file_handles = calls->handles.live;
    return status;
}

int pw_wine_handle_lookup(PwWineCallContext *calls, uint32_t value,
                              PwNtObject **object, unsigned *kind)
{
    return pw_nt_handle_lookup(&calls->handles, value, object, kind);
}

int pw_wine_handle_release(PwWineCallContext *calls, uint32_t value)
{
    PwNtObject released;
    unsigned kind = PW_NT_HANDLE_NONE;

    memset(&released, 0, sizeof(released));
    if (pw_nt_handle_release(&calls->handles, value, &released, &kind) != PW_OK)
        return PW_ERR_NOT_FOUND;
    if (released.token) {
        if (kind == PW_NT_HANDLE_FILE && calls->config->files)
            calls->config->files->close(calls->config->files->context,
                                        released.token);
        else if (kind == PW_NT_HANDLE_KEY && calls->config->registry)
            calls->config->registry->close(calls->config->registry->context,
                                           released.token);
        else if ((kind == PW_NT_HANDLE_OBJECT_DIRECTORY ||
                  kind == PW_NT_HANDLE_SECTION) && calls->config->objects)
            calls->config->objects->close(calls->config->objects->context,
                                          released.token);
    }
    calls->report->file_closes++;
    calls->report->file_handles = calls->handles.live;
    return PW_OK;
}

/* What a handle names, built once at the call site. */
PwNtObject pw_wine_handle_object(void *token, uint64_t size, const char *path)
{
    PwNtObject object;

    memset(&object, 0, sizeof(object));
    object.token = token;
    object.size = size;
    if (path)
        memcpy(object.path, path, strlen(path) + 1u);
    return object;
}

int pw_wine_handle_close(PwWineCallContext *calls, const PwUnixCallFrame *frame,
                        PwUnixCallAccess guest, void *context,
                        uint32_t *status, uint32_t *argument_index)
{
    (void)guest;
    (void)context;
    (void)argument_index;
    *status = pw_wine_handle_release(calls, frame->args[0]) == PW_OK
                  ? PW_NT_SUCCESS
                  : PW_NT_INVALID_HANDLE;
    return PW_OK;
}
