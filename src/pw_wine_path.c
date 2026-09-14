/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Name translation for the three namespaces the bridge exposes. See
 * pw_wine_path.h for the contract; every function here reads guest memory only
 * through the PwUnixCallAccess it is handed and never calls a platform
 * service, which is what lets the same rules serve files, the registry and the
 * object namespace.
 */
#include "pw_wine_path.h"

#include <string.h>

/*
 * The registry namespace this gate serves. A guest path is accepted only
 * under one of these two roots: anything else - a device path, a relative
 * name with no key handle, a path with an empty component - is answered with
 * a real NTSTATUS and never reaches the platform service.
 */
int pw_wine_path_registry_root(const char *canonical, const char *root)
{
    if (!canonical || !root)
        return 0;

    const size_t length = strlen(root);

    return strncmp(canonical, root, length) == 0 &&
           (canonical[length] == '\0' || canonical[length] == '\\');
}

/*
 * \Registry\Machine\... and \Registry\User\... become one canonical
 * lower-case path whose components are all validated: printable ASCII with no
 * separator, no colon and no "." or ".." component, so nothing the guest
 * writes can turn into a different path inside the host's registry profile.
 */
int pw_wine_path_registry(const char *path, char *out, size_t out_bytes,
                                   uint32_t *status)
{
    const char *rest = path;
    static const char root_prefix[] = "\\registry\\";
    size_t used = 0u;
    size_t length = 0u;
    size_t components = 0u;

    if (!status || !path || !out)
        return PW_ERR_PRECONDITION;
    /* The namespace prefix itself has to fit before a byte of it is copied. */
    if (out_bytes < sizeof(root_prefix)) {
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_ERR_MALFORMED;
    }
    if (!pw_wine_path_prefix(rest, root_prefix, &used)) {
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_ERR_NOT_FOUND;
    }
    memcpy(out, root_prefix, sizeof(root_prefix) - 1u);
    length = sizeof(root_prefix) - 1u;
    rest += used;
    while (*rest != '\0') {
        size_t component = 0u;

        if (*rest == '\\') {
            *status = PW_NT_OBJECT_NAME_INVALID;   /* empty component */
            return PW_ERR_MALFORMED;
        }
        while (rest[component] != '\0' && rest[component] != '\\') {
            const unsigned char character = (unsigned char)rest[component];

            if (character < 0x20u || character > 0x7eu || character == '/' ||
                character == ':') {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            if (length + 1u >= out_bytes) {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            out[length++] = pw_wine_path_lower((char)character);
            ++component;
        }
        if ((component == 1u && rest[0] == '.') ||
            (component == 2u && rest[0] == '.' && rest[1] == '.')) {
            *status = PW_NT_OBJECT_NAME_INVALID;
            return PW_ERR_MALFORMED;
        }
        ++components;
        rest += component;
        if (*rest == '\\') {
            if (length + 1u >= out_bytes) {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            out[length++] = '\\';
            ++rest;
            if (*rest == '\0') {                /* trailing separator */
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
        }
    }
    /* Terminate before the root check below reads `out` as a C string. */
    out[length] = '\0';
    if (components == 0u ||
        !(pw_wine_path_registry_root(out, "\\registry\\machine") ||
          pw_wine_path_registry_root(out, "\\registry\\user"))) {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_NOT_FOUND;
    }
    out[length] = '\0';
    return PW_OK;
}

/*
 * Reads a registry value name: an empty UNICODE_STRING is the key's default
 * value, which is a real value rather than a missing name.
 */
int pw_wine_path_value_name(PwUnixCallAccess guest, void *context,
                                 uint32_t address, char *out, size_t out_bytes)
{
    uint8_t header[8];
    uint16_t length = 0u;

    if (!guest || !out || out_bytes == 0u)
        return PW_ERR_MALFORMED;
    if (guest(context, address, header, sizeof(header), 0) != PW_OK)
        return PW_ERR_MALFORMED;
    memcpy(&length, header, 2u);
    if (length == 0u) {
        out[0] = '\0';
        return PW_OK;
    }
    return pw_wine_path_read_unicode(guest, context, address, out, out_bytes);
}

/* Lower-cases a value name: names are ASCII in this profile. */
int pw_wine_path_value(const char *name, char *out, size_t out_bytes,
                                   uint32_t *status)
{
    size_t length = 0u;

    if (!status || !name || !out)
        return PW_ERR_PRECONDITION;
    if (out_bytes == 0u) {
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_ERR_MALFORMED;
    }
    while (name[length] != '\0') {
        const unsigned char character = (unsigned char)name[length];

        if (character < 0x20u || character > 0x7eu || character == '\\' ||
            character == '/' || character == ':') {
            *status = PW_NT_OBJECT_NAME_INVALID;
            return PW_ERR_MALFORMED;
        }
        if (length + 1u >= out_bytes) {
            *status = PW_NT_OBJECT_NAME_INVALID;
            return PW_ERR_MALFORMED;
        }
        out[length] = pw_wine_path_lower((char)character);
        ++length;
    }
    out[length] = '\0';
    return PW_OK;
}

char pw_wine_path_lower(char value)
{
    return value >= 'A' && value <= 'Z' ? (char)(value + 32) : value;
}

int pw_wine_path_prefix(const char *text, const char *prefix, size_t *used)
{
    size_t index = 0u;

    if (!text || !prefix)
        return 0;
    for (; prefix[index] != '\0'; ++index) {
        /* A shorter string cannot match a longer prefix: stop at its
         * terminator instead of reading past the end of it. */
        if (text[index] == '\0')
            return 0;
        if (pw_wine_path_lower(text[index]) != pw_wine_path_lower(prefix[index]))
            return 0;
    }
    if (used)
        *used = index;
    return 1;
}

/*
 * Translates a guest DOS/NT path into a canonical file name inside the
 * runtime distribution, or fails. Only the two prefixes a Wine loader uses
 * are accepted, the remainder must be a single path component, and the result
 * is lower-cased, so ".." or an absolute host path cannot reach the service.
 */
int pw_wine_path_runtime(const char *path, char *out, size_t out_bytes,
                                  int *is_directory, uint32_t *status)
{
    const char *rest = path;
    size_t used = 0u;
    size_t length = 0u;
    int directory = 0;

    if (!status || !path || !out)
        return PW_ERR_PRECONDITION;
    if (out_bytes == 0u) {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_MALFORMED;
    }
    if (pw_wine_path_prefix(rest, "\\??\\", &used))
        rest += used;
    if (pw_wine_path_prefix(rest, "C:\\windows\\system32", &used) ||
        pw_wine_path_prefix(rest, "C:\\windows", &used)) {
        rest += used;
        /* The directory itself: a single trailing separator, no component. */
        if (*rest == '\\' && rest[1] == '\0') {
            rest += 1u;
            directory = 1;
        } else if (*rest == '\0') {
            directory = 1;
        } else if (*rest != '\\') {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_NOT_FOUND;
        } else {
            rest += 1u;
        }
    } else {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_NOT_FOUND;
    }
    while (rest[length] != '\0') {
        const char character = rest[length];

        if (character == '\\' || character == '/' || character == ':' ||
            character == '\0' || length + 1u >= out_bytes) {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_MALFORMED;
        }
        out[length] = pw_wine_path_lower(character);
        ++length;
    }
    if (length == 0u) {
        if (!directory) {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_MALFORMED;
        }
        out[0] = '\0';
        if (is_directory)
            *is_directory = 1;
        return PW_OK;
    }
    if (length >= 2u && out[length - 1u] == '.' && out[length - 2u] == '.') {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_MALFORMED;
    }
    out[length] = '\0';
    if (is_directory)
        *is_directory = 0;
    return PW_OK;
}

/* Reads a guest UNICODE_STRING and converts it to ASCII. */
int pw_wine_path_read_unicode(PwUnixCallAccess guest, void *context,
                              uint32_t address, char *out, size_t out_bytes)
{
    uint8_t header[8];
    uint32_t buffer = 0u;
    uint16_t length = 0u;

    if (!guest || !out || out_bytes == 0u)
        return PW_ERR_MALFORMED;
    if (guest(context, address, header, sizeof(header), 0) != PW_OK)
        return PW_ERR_MALFORMED;
    memcpy(&length, header, 2u);
    memcpy(&buffer, header + 4u, 4u);
    if (length == 0u || (length & 1u) != 0u || buffer == 0u ||
        length / 2u + 1u > out_bytes)
        return PW_ERR_MALFORMED;
    for (uint32_t index = 0; index < length / 2u; ++index) {
        uint16_t unit = 0u;

        if (guest(context, buffer + index * 2u, &unit, 2u, 0) != PW_OK)
            return PW_ERR_MALFORMED;
        if (unit > 0x7fu)
            return PW_ERR_UNSUPPORTED;   /* the runtime paths are ASCII */
        out[index] = (char)unit;
    }
    out[length / 2u] = '\0';
    return PW_OK;
}

/*
 * Object-namespace paths. An absolute name starts with '\' and every
 * component is validated like a registry component; a relative name is
 * resolved against a directory object the gate already owns, which is how
 * Wine asks for "\KnownDlls\kernel32.dll" (the directory handle plus the DLL
 * name).
 */
int pw_wine_path_object(const char *path, char *out, size_t out_bytes,
                                 uint32_t *status)
{
    const char *rest = path;
    size_t length = 1u;
    size_t components = 0u;

    if (!status || !path || !out)
        return PW_ERR_PRECONDITION;
    if (*rest != '\\' || out_bytes < 2u) {
        *status = PW_NT_OBJECT_NAME_INVALID;
        return PW_ERR_NOT_FOUND;
    }
    out[0] = '\\';
    ++rest;
    while (*rest != '\0') {
        size_t component = 0u;

        if (*rest == '\\') {
            *status = PW_NT_OBJECT_NAME_INVALID;   /* empty component */
            return PW_ERR_MALFORMED;
        }
        while (rest[component] != '\0' && rest[component] != '\\') {
            const unsigned char character = (unsigned char)rest[component];

            if (character < 0x20u || character > 0x7eu || character == '/' ||
                character == ':') {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            if (length + 1u >= out_bytes) {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            out[length++] = pw_wine_path_lower((char)character);
            ++component;
        }
        if ((component == 1u && rest[0] == '.') ||
            (component == 2u && rest[0] == '.' && rest[1] == '.')) {
            *status = PW_NT_OBJECT_NAME_INVALID;
            return PW_ERR_MALFORMED;
        }
        ++components;
        rest += component;
        if (*rest == '\\') {
            if (length + 1u >= out_bytes) {
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
            out[length++] = '\\';
            ++rest;
            if (*rest == '\0') {                /* trailing separator */
                *status = PW_NT_OBJECT_NAME_INVALID;
                return PW_ERR_MALFORMED;
            }
        }
    }
    if (components == 0u) {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_NOT_FOUND;
    }
    out[length] = '\0';
    return PW_OK;
}
