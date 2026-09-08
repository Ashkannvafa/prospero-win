#include "pw_module_name.h"

#include <string.h>

static char ascii_lower(char value)
{
    return (value >= 'A' && value <= 'Z') ? (char)(value + ('a' - 'A'))
                                          : value;
}

/*
 * Windows modules prospero-win must provide itself. Anything absent from
 * this table is treated as third-party code to manually map, which is the
 * correct default: a missing entry produces a loud PW_ERR_NOT_FOUND naming
 * the module, never a silent stub.
 */
static const char *const system_modules[] = {
    "advapi32.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "d3d10.dll",
    "d3d11.dll",
    "d3d8.dll",
    "d3d9.dll",
    "d3dim.dll",
    "ddraw.dll",
    "dinput.dll",
    "dinput8.dll",
    "dsound.dll",
    "dxgi.dll",
    "gdi32.dll",
    "glu32.dll",
    "imm32.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "msacm32.dll",
    "msimg32.dll",
    "msvcrt.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleaut32.dll",
    "opengl32.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "secur32.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ucrtbase.dll",
    "user32.dll",
    "version.dll",
    "wininet.dll",
    "winmm.dll",
    "ws2_32.dll",
    "wsock32.dll",
};

enum {
    SYSTEM_MODULE_COUNT =
        (uint32_t)(sizeof(system_modules) / sizeof(system_modules[0])),
};

int pw_module_name_canonical(char *out, size_t out_bytes, const char *name)
{
    size_t length = 0;
    size_t index;
    int has_extension = 0;

    if (!out || out_bytes == 0u || !name)
        return PW_ERR_PRECONDITION;
    out[0] = '\0';
    while (name[length] != '\0') {
        const unsigned char value = (unsigned char)name[length];

        if (value < 0x20u || value > 0x7eu)
            return PW_ERR_MALFORMED;
        /* A dependency name is a bare file name, never a path. */
        if (value == '/' || value == '\\' || value == ':')
            return PW_ERR_MALFORMED;
        ++length;
        if (length > PW_MODULE_NAME_MAX)
            return PW_ERR_LIMIT;
    }
    if (length == 0u)
        return PW_ERR_MALFORMED;

    for (index = length; index > 0u; --index) {
        if (name[index - 1u] == '.') {
            has_extension = index != length;   /* a trailing dot is not one */
            break;
        }
    }

    const size_t needed = has_extension ? length + 1u : length + 5u;
    if (needed > out_bytes)
        return PW_ERR_LIMIT;
    for (index = 0; index < length; ++index)
        out[index] = ascii_lower(name[index]);
    if (!has_extension) {
        memcpy(out + length, ".dll", 4);
        length += 4u;
    }
    out[length] = '\0';
    return PW_OK;
}

int pw_module_name_equal(const char *left, const char *right)
{
    size_t index = 0;

    if (!left || !right)
        return 0;
    for (;;) {
        const char a = ascii_lower(left[index]);
        const char b = ascii_lower(right[index]);

        if (a != b)
            return 0;
        if (a == '\0')
            return 1;
        ++index;
    }
}

int pw_module_is_system(const char *canonical_name)
{
    uint32_t low = 0u;
    uint32_t high = SYSTEM_MODULE_COUNT;

    if (!canonical_name)
        return 0;
    /* system_modules is kept sorted; a test asserts that it stays sorted. */
    while (low < high) {
        const uint32_t middle = low + (high - low) / 2u;
        const int order = strcmp(canonical_name, system_modules[middle]);

        if (order == 0)
            return 1;
        if (order < 0)
            high = middle;
        else
            low = middle + 1u;
    }
    return 0;
}

uint32_t pw_module_system_count(void)
{
    return SYSTEM_MODULE_COUNT;
}

const char *pw_module_system_name(uint32_t index)
{
    return index < SYSTEM_MODULE_COUNT ? system_modules[index] : NULL;
}
