/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_module_name.h"

#include <assert.h>
#include <string.h>

static void test_canonicalises(void)
{
    char out[PW_MODULE_NAME_MAX + 1];

    assert(pw_module_name_canonical(out, sizeof(out), "KERNEL32.dll") == PW_OK);
    assert(strcmp(out, "kernel32.dll") == 0);
    assert(pw_module_name_canonical(out, sizeof(out), "BINKW32.DLL") == PW_OK);
    assert(strcmp(out, "binkw32.dll") == 0);
    assert(pw_module_name_canonical(out, sizeof(out), "Game.exe") == PW_OK);
    assert(strcmp(out, "game.exe") == 0);

    /* A bare name gains the implicit extension the PE loader assumes. */
    assert(pw_module_name_canonical(out, sizeof(out), "MSS32") == PW_OK);
    assert(strcmp(out, "mss32.dll") == 0);
    /* A trailing dot is not an extension. */
    assert(pw_module_name_canonical(out, sizeof(out), "weird.") == PW_OK);
    assert(strcmp(out, "weird..dll") == 0);
    assert(pw_module_name_canonical(out, sizeof(out), "a.b.dll") == PW_OK);
    assert(strcmp(out, "a.b.dll") == 0);
}

static void test_rejects_paths_and_junk(void)
{
    char out[PW_MODULE_NAME_MAX + 1];
    char long_name[PW_MODULE_NAME_MAX + 8];

    /* A dependency name is a file name; a path would escape the app dir. */
    assert(pw_module_name_canonical(out, sizeof(out), "..\\evil.dll") ==
           PW_ERR_MALFORMED);
    assert(pw_module_name_canonical(out, sizeof(out), "sub/dir.dll") ==
           PW_ERR_MALFORMED);
    assert(pw_module_name_canonical(out, sizeof(out), "c:evil.dll") ==
           PW_ERR_MALFORMED);
    assert(pw_module_name_canonical(out, sizeof(out), "bad\tname.dll") ==
           PW_ERR_MALFORMED);
    assert(pw_module_name_canonical(out, sizeof(out), "") == PW_ERR_MALFORMED);
    assert(pw_module_name_canonical(out, 4u, "kernel32.dll") == PW_ERR_LIMIT);
    assert(pw_module_name_canonical(NULL, sizeof(out), "a.dll") ==
           PW_ERR_PRECONDITION);
    assert(pw_module_name_canonical(out, sizeof(out), NULL) ==
           PW_ERR_PRECONDITION);

    memset(long_name, 'a', sizeof(long_name) - 1u);
    long_name[sizeof(long_name) - 1u] = '\0';
    assert(pw_module_name_canonical(out, sizeof(out), long_name) ==
           PW_ERR_LIMIT);
}

static void test_case_insensitive_equality(void)
{
    assert(pw_module_name_equal("kernel32.dll", "KERNEL32.DLL"));
    assert(pw_module_name_equal("BinkW32.dll", "binkw32.dll"));
    assert(!pw_module_name_equal("kernel32.dll", "kernel33.dll"));
    assert(!pw_module_name_equal("kernel32.dll", "kernel32"));
    assert(!pw_module_name_equal(NULL, "a"));
    assert(!pw_module_name_equal("a", NULL));
}

static void test_system_classification(void)
{
    /* The Win32 surface prospero-win implements itself. */
    assert(pw_module_is_system("kernel32.dll"));
    assert(pw_module_is_system("user32.dll"));
    assert(pw_module_is_system("ddraw.dll"));
    assert(pw_module_is_system("d3d9.dll"));
    assert(pw_module_is_system("ws2_32.dll"));
    assert(pw_module_is_system("ntdll.dll"));

    /* Third-party code that must actually be mapped. */
    assert(!pw_module_is_system("binkw32.dll"));
    assert(!pw_module_is_system("mss32.dll"));
    assert(!pw_module_is_system("game.exe"));
    assert(!pw_module_is_system("smackw32.dll"));
    assert(!pw_module_is_system(NULL));

    /* The table is searched by binary search, so order is a correctness
     * property, not a style preference. */
    assert(pw_module_system_count() > 20u);
    for (uint32_t index = 1; index < pw_module_system_count(); ++index) {
        const char *previous = pw_module_system_name(index - 1u);
        const char *current = pw_module_system_name(index);

        assert(previous && current);
        assert(strcmp(previous, current) < 0);
    }
    assert(pw_module_system_name(pw_module_system_count()) == NULL);

    /* Every listed name must be findable through the public predicate. */
    for (uint32_t index = 0; index < pw_module_system_count(); ++index)
        assert(pw_module_is_system(pw_module_system_name(index)));
}

int main(void)
{
    test_canonicalises();
    test_rejects_paths_and_junk();
    test_case_insensitive_equality();
    test_system_classification();
    return 0;
}
