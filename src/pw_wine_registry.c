/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The registry adapter: one canonical key path per guest name, validated
 * components, KEY_VALUE_* answers laid out the way NT lays them out, and the
 * profile behind PwWineRegistryService deciding what exists. See
 * pw_wine_registry.h.
 */
#include "pw_wine_registry.h"

#include "pw_wine_context.h"
#include "pw_wine_handle.h"
#include "pw_wine_path.h"

#include <string.h>

/*
 * KEY_VALUE_INFORMATION_CLASS value ntdll's own option readers use, and the
 * fixed part of the answer whose layout is
 * KEY_VALUE_PARTIAL_INFORMATION {TitleIndex, Type, DataLength, Data[1]}.
 */
enum {
    PW_WINE_KEY_VALUE_PARTIAL_INFORMATION = 2u,
    PW_WINE_KEY_VALUE_PARTIAL_HEADER = 12u,
};

/*
 * Turns OBJECT_ATTRIBUTES into one canonical key path. The accepted shapes are
 * Wine's own: an absolute name under the registry namespace, or a name
 * relative to a key handle the gate already owns (which is how ntdll opens
 * HKCU\Software\Wine from the handle RtlOpenCurrentUser returns, and how it
 * names \Registry\User\<SID>). A refused path is counted and recorded here,
 * because both NtOpenKey and NtCreateKey report it the same way.
 */
int pw_wine_registry_resolve(PwWineCallContext *calls,
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
        if (pw_wine_path_registry(name, canonical, canonical_bytes,
                                    status) != PW_OK) {
            const size_t length = strlen(name);

            if (length <= PW_WINE_GATE_MAX_PATH)
                memcpy(calls->report->last_key, name, length + 1u);
            calls->report->key_refusals++;
            return PW_OK;
        }
    } else {
        size_t used = 0u;

        if (pw_wine_handle_lookup(calls, root_handle, &object, &kind) != PW_OK ||
            kind != PW_NT_HANDLE_KEY) {
            *status = PW_NT_INVALID_HANDLE;
            return PW_OK;
        }
        /* A relative name is resolved against the key's canonical path and
         * then revalidated as a whole, so it cannot leave the namespace. */
        used = strlen(object->path);
        if (used + strlen(name) + 2u > sizeof(relative)) {
            *status = PW_NT_OBJECT_NAME_INVALID;
            calls->report->key_refusals++;
            return PW_OK;
        }
        memcpy(relative, object->path, used);
        relative[used++] = '\\';
        memcpy(relative + used, name, strlen(name) + 1u);
        if (pw_wine_path_registry(relative, canonical, canonical_bytes,
                                    status) != PW_OK) {
            calls->report->key_refusals++;
            return PW_OK;
        }
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtOpenKey and NtOpenKeyEx. The two take the same first three arguments -
 * the handle slot, the access mask and the OBJECT_ATTRIBUTES - and the
 * extended form adds the open options (dlls/ntdll/unix/registry.c:133). Wine's
 * own NtOpenKey is defined as NtOpenKeyEx with no options, and the only option
 * it defines is REG_OPTION_OPEN_LINK, which asks for a link object rather than
 * the key it points at: this profile carries no links, and Wine only warns
 * about an option outside that mask and opens the key anyway, so both shapes
 * answer out of the same path here.
 *
 * A key the profile does not declare answers
 * STATUS_OBJECT_NAME_NOT_FOUND, so ntdll keeps its own defaults instead of
 * being handed invented content, and the canonical path is remembered with the
 * handle because that is what a later relative open resolves against.
 */
int pw_wine_registry_open(PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t attributes_pointer = frame->args[2];
    char canonical[PW_WINE_GATE_MAX_PATH + 1];
    void *token = NULL;
    uint32_t handle = 0u;

    if (handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    /*
     * A resolve that *rejects* the call - an argument the run cannot read, or a
     * name it cannot decode - is not an NTSTATUS: it is the gate refusing to
     * service the call at all, and it has to surface as that, with the argument
     * that failed. Swallowing it here reported an unreadable OBJECT_ATTRIBUTES
     * as "the service is not implemented", which named the wrong problem.
     */
    {
        const int resolved = pw_wine_registry_resolve(
            calls, attributes_pointer, guest, context, canonical,
            sizeof(canonical), status, argument_index);

        if (resolved != PW_OK)
            return resolved;
        if (*status != PW_NT_SUCCESS)
            return PW_OK;
    }
    if (!calls->config->registry ||
        calls->config->registry->open(calls->config->registry->context,
                                      canonical, &token) !=
            PW_WINE_REGISTRY_OK) {
        *status = calls->config->registry ? PW_NT_OBJECT_NAME_NOT_FOUND
                                          : PW_NT_NOT_SUPPORTED;
        memcpy(calls->report->last_key, canonical, strlen(canonical) + 1u);
        calls->report->key_refusals++;
        return PW_OK;
    }
    PwNtObject handle_object;

    /* A refused construction means the canonical path did not fit the handle's
     * own field; that is a malformed name, and the token goes back. */
    if (pw_wine_handle_object(token, 0u, canonical, &handle_object) != PW_OK) {
        calls->config->registry->close(calls->config->registry->context, token);
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_OK;
    }
    if (pw_wine_handle_alloc(calls, &handle_object, PW_NT_HANDLE_KEY,
                          &handle) != PW_OK) {
        calls->config->registry->close(calls->config->registry->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    memcpy(calls->report->last_key, canonical, strlen(canonical) + 1u);
    calls->report->key_opens++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* REG_OPENED_EXISTING_KEY and REG_CREATED_NEW_KEY, as NtCreateKey reports. */
enum {
    PW_WINE_REG_CREATED_NEW_KEY = 1u,
    PW_WINE_REG_OPENED_EXISTING_KEY = 2u,
};

/*
 * NtCreateKey, which is create-or-open in NT. RtlOpenCurrentUser reaches it
 * with the \Registry\User\<SID> path it formatted from the token, so the gate
 * resolves the path exactly as NtOpenKey does and then asks the profile. A
 * profile with no writable hive answers NOT_FOUND for a key it does not
 * declare; the disposition it reports for a key it does have is
 * REG_OPENED_EXISTING_KEY, so the guest knows nothing was created.
 */
int pw_wine_registry_create(PwWineCallContext *calls,
                              const PwUnixCallFrame *frame,
                              PwUnixCallAccess guest, void *context,
                              uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t attributes_pointer = frame->args[2];
    const uint32_t disposition_pointer = frame->args[6];
    char canonical[PW_WINE_GATE_MAX_PATH + 1];
    void *token = NULL;
    uint32_t handle = 0u;
    uint32_t created = 0u;

    if (handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    /*
     * A resolve that *rejects* the call - an argument the run cannot read, or a
     * name it cannot decode - is not an NTSTATUS: it is the gate refusing to
     * service the call at all, and it has to surface as that, with the argument
     * that failed. Swallowing it here reported an unreadable OBJECT_ATTRIBUTES
     * as "the service is not implemented", which named the wrong problem.
     */
    {
        const int resolved = pw_wine_registry_resolve(
            calls, attributes_pointer, guest, context, canonical,
            sizeof(canonical), status, argument_index);

        if (resolved != PW_OK)
            return resolved;
        if (*status != PW_NT_SUCCESS)
            return PW_OK;
    }
    if (!calls->config->registry || !calls->config->registry->create) {
        *status = PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    if (calls->config->registry->create(calls->config->registry->context,
                                        canonical, &token, &created) !=
        PW_WINE_REGISTRY_OK) {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        memcpy(calls->report->last_key, canonical, strlen(canonical) + 1u);
        calls->report->key_refusals++;
        return PW_OK;
    }
    PwNtObject handle_object;

    if (pw_wine_handle_object(token, 0u, canonical, &handle_object) != PW_OK) {
        calls->config->registry->close(calls->config->registry->context, token);
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_OK;
    }
    if (pw_wine_handle_alloc(calls, &handle_object, PW_NT_HANDLE_KEY,
                          &handle) != PW_OK) {
        calls->config->registry->close(calls->config->registry->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (disposition_pointer != 0u) {
        uint32_t disposition = created != 0u ? PW_WINE_REG_CREATED_NEW_KEY
                                             : PW_WINE_REG_OPENED_EXISTING_KEY;

        if (guest(context, disposition_pointer, &disposition, 4u, 1) != PW_OK) {
            (void)pw_wine_handle_release(calls, handle);
            *argument_index = 7u;
            return PW_ERR_MALFORMED;
        }
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)pw_wine_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    memcpy(calls->report->last_key, canonical, strlen(canonical) + 1u);
    calls->report->key_creates++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtQueryValueKey for KeyValuePartialInformation, the class ntdll's own
 * option readers use. The answer is written the way Wine writes it: a
 * KEY_VALUE_PARTIAL_INFORMATION header, then as much of the data as fits,
 * with the required length reported back through ResultLength. A buffer
 * shorter than the fixed part is STATUS_BUFFER_TOO_SMALL, one that cannot
 * hold the whole value is STATUS_BUFFER_OVERFLOW (the informational status
 * Wine itself returns), and the value bytes only ever come from the host
 * service, never from the gate.
 */
/*
 * NtSetValueKey( KeyHandle, ValueName, TitleIndex, Type, Data, DataSize ): the
 * guest writing a value on a key it has open. The key is one the gate handed
 * out, the value name goes through the same translation a query's does, and the
 * data is read through the validated accessor into the gate's own buffer before
 * the service is asked to store it - so a guest pointer the run cannot read is
 * refused before anything is stored, and the service never sees a guest
 * address. A service without a writable store answers NOT_SUPPORTED, which is
 * what a key on a read-only hive would say.
 */
int pw_wine_registry_set_value(PwWineCallContext *calls,
                               const PwUnixCallFrame *frame,
                               PwUnixCallAccess guest, void *context,
                               uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t name_pointer = frame->args[1];
    const uint32_t type = frame->args[3];
    const uint32_t data_pointer = frame->args[4];
    const uint32_t data_size = frame->args[5];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    char name[PW_WINE_GATE_MAX_PATH + 1];
    char canonical[PW_WINE_GATE_MAX_PATH + 1];
    uint8_t bytes[PW_WINE_GATE_MAX_VALUE];

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_KEY) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (name_pointer == 0u) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_value_name(guest, context, name_pointer, name,
                              sizeof(name)) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_value(name, canonical, sizeof(canonical), status) !=
        PW_OK) {
        calls->report->key_refusals++;
        return PW_OK;
    }
    if (data_size > PW_WINE_GATE_MAX_VALUE ||
        (data_size != 0u && data_pointer == 0u)) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->key_refusals++;
        return PW_OK;
    }
    /* The whole value is proved readable before anything is stored. */
    if (data_size != 0u &&
        guest(context, data_pointer, bytes, data_size, 0) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (!calls->config->registry ||
        !calls->config->registry->set_value) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->key_refusals++;
        return PW_OK;
    }
    if (calls->config->registry->set_value(calls->config->registry->context,
                                           object->token, canonical, type,
                                           bytes, data_size) !=
        PW_WINE_REGISTRY_OK) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->key_refusals++;
        return PW_OK;
    }
    calls->report->key_sets++;
    calls->report->last_value[0] = '\0';
    if (strlen(canonical) <= PW_WINE_GATE_MAX_PATH)
        memcpy(calls->report->last_value, canonical,
               strlen(canonical) + 1u);
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

int pw_wine_registry_query_value(PwWineCallContext *calls,
                                   const PwUnixCallFrame *frame,
                                   PwUnixCallAccess guest, void *context,
                                   uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t name_pointer = frame->args[1];
    const uint32_t information_class = frame->args[2];
    const uint32_t information_pointer = frame->args[3];
    const uint32_t length = frame->args[4];
    const uint32_t result_pointer = frame->args[5];
    uint8_t header[PW_WINE_KEY_VALUE_PARTIAL_HEADER];
    const void *value_bytes = NULL;
    uint32_t value_type = 0u;
    uint32_t value_size = 0u;
    uint32_t needed = 0u;
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    char name[PW_WINE_GATE_MAX_PATH + 1];
    char canonical[PW_WINE_GATE_MAX_PATH + 1];

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_KEY) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != PW_WINE_KEY_VALUE_PARTIAL_INFORMATION) {
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->key_refusals++;
        return PW_OK;
    }
    if (name_pointer == 0u || information_pointer == 0u) {
        *argument_index = name_pointer == 0u ? 2u : 4u;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_value_name(guest, context, name_pointer, name,
                              sizeof(name)) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_value(name, canonical, sizeof(canonical), status) !=
        PW_OK) {
        calls->report->key_refusals++;
        return PW_OK;
    }
    calls->report->key_queries++;
    if (!calls->config->registry ||
        calls->config->registry->query(calls->config->registry->context,
                                       object->token, canonical,
                                       &value_type, &value_bytes,
                                       &value_size) != PW_WINE_REGISTRY_OK ||
        (value_size != 0u && value_bytes == NULL) ||
        value_size > PW_WINE_GATE_MAX_VALUE) {
        *status = calls->config->registry ? PW_NT_OBJECT_NAME_NOT_FOUND
                                          : PW_NT_NOT_SUPPORTED;
        calls->report->key_refusals++;
        return PW_OK;
    }
    calls->report->key_values++;
    memset(header, 0, sizeof(header));              /* TitleIndex */
    memcpy(header + 4u, &value_type, 4u);           /* Type */
    memcpy(header + 8u, &value_size, 4u);           /* DataLength */
    needed = PW_WINE_KEY_VALUE_PARTIAL_HEADER + value_size;
    if (result_pointer != 0u &&
        guest(context, result_pointer, &needed, 4u, 1) != PW_OK) {
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    {
        const uint32_t header_bytes =
            length < PW_WINE_KEY_VALUE_PARTIAL_HEADER
                ? length
                : PW_WINE_KEY_VALUE_PARTIAL_HEADER;

        if (header_bytes != 0u &&
            guest(context, information_pointer, header, header_bytes, 1) !=
                PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
    }
    if (length > PW_WINE_KEY_VALUE_PARTIAL_HEADER && value_size != 0u) {
        uint32_t data_bytes = length - PW_WINE_KEY_VALUE_PARTIAL_HEADER;
        void *data = (void *)(uintptr_t)value_bytes;

        if (data_bytes > value_size)
            data_bytes = value_size;
        if (guest(context, information_pointer +
                              PW_WINE_KEY_VALUE_PARTIAL_HEADER,
                  data, data_bytes, 1) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
    }
    *status = length < PW_WINE_KEY_VALUE_PARTIAL_HEADER
                  ? PW_NT_BUFFER_TOO_SMALL
                  : (length < needed ? PW_NT_BUFFER_OVERFLOW
                                     : PW_NT_SUCCESS);
    return PW_OK;
}
