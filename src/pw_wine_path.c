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
 * lower-case path whose components are all validated: no control character
 * and no separator, no colon and no "." or ".." component, so nothing the
 * guest writes can turn into a different path inside the host's registry
 * profile. Units outside ASCII arrive as their UTF-8 encoding and are carried
 * through unchanged.
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

            if (character < 0x20u || character == 0x7fu || character == '/' ||
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
 * Translates a guest DOS/NT path into a canonical file name inside one of the
 * two roots a Wine loader names - the runtime distribution under C:\windows
 * and the application's own directory under the root of C: - or fails. The
 * root the name belongs to is reported to the caller, the remainder must be a
 * single path component, and the result is lower-cased, so ".." or an absolute
 * host path cannot reach the service.
 */
int pw_wine_path_runtime(const char *path, char *out, size_t out_bytes,
                                  PwFileNamespace *file_namespace,
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
    if (!file_namespace)
        return PW_ERR_PRECONDITION;
    *file_namespace = PW_FILE_RUNTIME;
    if (pw_wine_path_prefix(rest, "\\??\\", &used))
        rest += used;
    /*
     * The two roots a Windows loader names. A path under the Windows directory
     * is the runtime distribution's, and a single component directly under the
     * root of C: is the application's - the directory the process's own image
     * and the modules next to it live in. Neither root falls back into the
     * other: the namespace a name belongs to is decided by the name, so the
     * service that finally opens it never has to guess. A prefix only names a
     * directory when a separator or the end of the string follows it, so
     * "C:\windowsfoo" is a component of the root, exactly as Windows reads it.
     */
    if ((pw_wine_path_prefix(rest, "C:\\windows\\system32", &used) ||
         pw_wine_path_prefix(rest, "C:\\windows", &used)) &&
        (rest[used] == '\\' || rest[used] == '\0')) {
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
    } else if (pw_wine_path_prefix(rest, "C:\\", &used)) {
        /*
         * A single component directly under the root of C: is the
         * application's own: the process image and the modules next to it. The
         * bare root is that directory itself.
         */
        rest += used;
        *file_namespace = PW_FILE_APPLICATION;
        if (*rest == '\0')
            directory = 1;
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

/* How many bytes this code point takes in UTF-8. */
static unsigned utf8_bytes(uint32_t code)
{
    if (code < 0x80u)
        return 1u;
    if (code < 0x800u)
        return 2u;
    if (code < 0x10000u)
        return 3u;
    return 4u;
}

/* Writes one code point as UTF-8 and reports how many bytes it took. */
static unsigned write_utf8(uint32_t code, char *out)
{
    if (code < 0x80u) {
        out[0] = (char)code;
        return 1u;
    }
    if (code < 0x800u) {
        out[0] = (char)(0xc0u | (code >> 6));
        out[1] = (char)(0x80u | (code & 0x3fu));
        return 2u;
    }
    if (code < 0x10000u) {
        out[0] = (char)(0xe0u | (code >> 12));
        out[1] = (char)(0x80u | ((code >> 6) & 0x3fu));
        out[2] = (char)(0x80u | (code & 0x3fu));
        return 3u;
    }
    out[0] = (char)(0xf0u | (code >> 18));
    out[1] = (char)(0x80u | ((code >> 12) & 0x3fu));
    out[2] = (char)(0x80u | ((code >> 6) & 0x3fu));
    out[3] = (char)(0x80u | (code & 0x3fu));
    return 4u;
}

/*
 * Reads a guest UNICODE_STRING and converts it to a canonical UTF-8 string.
 *
 * The runtime's own names are not ASCII: kernelbase keeps its locale cache in
 * a subkey literally named the emoji sequence dlls/kernelbase/locale.c:54
 * calls world_subkey, and a name this translation cannot carry is a key the
 * runtime cannot create. Units below 0x80 are one byte, the rest of the BMP
 * two or three, and a surrogate pair combines into the single code point it
 * stands for. A lone low surrogate, an unpaired high one, or a destination
 * without room for the encoded name is refused rather than folded into
 * something the guest did not write.
 */
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
    {
        const uint32_t units = length / 2u;
        size_t used = 0u;

        for (uint32_t index = 0u; index < units; ++index) {
            uint16_t unit = 0u;
            uint32_t code;
            unsigned bytes;

            if (guest(context, buffer + (uint32_t)index * 2u, &unit, 2u, 0) !=
                PW_OK)
                return PW_ERR_MALFORMED;
            if (unit >= 0xd800u && unit <= 0xdbffu) {
                uint16_t low = 0u;

                if (index + 1u >= units ||
                    guest(context, buffer + (uint32_t)(index + 1u) * 2u, &low,
                          2u, 0) != PW_OK || low < 0xdc00u || low > 0xdfffu)
                    return PW_ERR_MALFORMED;
                code = 0x10000u + (((uint32_t)unit - 0xd800u) << 10) +
                       ((uint32_t)low - 0xdc00u);
                index++;
            } else if (unit >= 0xdc00u && unit <= 0xdfffu) {
                /* A low surrogate with nothing before it is not a name. */
                return PW_ERR_MALFORMED;
            } else {
                code = unit;
            }
            bytes = utf8_bytes(code);
            if (used + bytes + 1u > out_bytes)
                return PW_ERR_MALFORMED;
            used += write_utf8(code, out + used);
        }
        out[used] = '\0';
    }
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
