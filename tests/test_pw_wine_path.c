/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The name-translation unit on its own.
 *
 * This is the code that decides which names a guest can make a platform
 * service look at, so the interesting half of every case is the refusal: ".."
 * components, embedded separators, colons, device paths, a component that is
 * too long, a UNICODE_STRING whose length disagrees with its buffer, a guest
 * pointer outside the memory the accessor allows. None of it needs a mapping
 * or a service - the unit is pure - so each case is asserted directly, with the
 * NTSTATUS the caller would return, because a refusal that reports the wrong
 * status is a different bug from a refusal that reports none.
 */
#include "../src/pw_wine_path.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* A fake guest window: reads and writes outside it are refused, exactly like
 * the dispatcher's accessor refuses a span it has not validated. */
typedef struct FakeGuest {
    uint8_t bytes[64];
    uint32_t size;
    unsigned reads;
    unsigned writes;
} FakeGuest;

static int fake_access(void *context, uint32_t address, void *out,
                       uint32_t length, int write)
{
    FakeGuest *guest = context;

    if (address > guest->size || length > guest->size - address)
        return PW_ERR_MALFORMED;
    if (write) {
        guest->writes++;
        memcpy(&guest->bytes[address], out, length);
    } else {
        guest->reads++;
        memcpy(out, &guest->bytes[address], length);
    }
    return PW_OK;
}

/* Writes a UNICODE_STRING {Length, MaximumLength, Buffer} plus its text. */
static void put_string(FakeGuest *guest, uint16_t length, uint32_t buffer,
                       const char *text)
{
    memcpy(&guest->bytes[0], &length, 2u);
    memcpy(&guest->bytes[4], &buffer, 4u);
    for (uint16_t index = 0; index < length / 2u && text[index]; ++index) {
        const uint16_t unit = (uint8_t)text[index];
        const uint32_t address = buffer + index * 2u;

        /* A buffer outside the fake window is deliberately not written: the
         * case exists to prove the reader refuses it, and the test must not
         * touch memory the fake guest does not have either. */
        if (address + 2u > guest->size)
            return;
        memcpy(&guest->bytes[address], &unit, 2u);
    }
}

static void test_prefix(void)
{
    size_t used = 0u;

    assert(pw_wine_path_prefix("C:\\Windows\\System32\\kernel32.dll",
                               "c:\\windows", &used) == 1);
    assert(used == 10u);
    assert(pw_wine_path_prefix("\\??\\C:\\windows", "\\??\\", &used) == 1);
    assert(used == 4u);
    assert(pw_wine_path_prefix("D:\\windows", "c:\\windows", &used) == 0);
    assert(pw_wine_path_lower('A') == 'a');
    assert(pw_wine_path_lower('z') == 'z');
    assert(pw_wine_path_lower('0') == '0');
}

static void test_registry(void)
{
    char out[192];
    uint32_t status = 0u;
    static const struct {
        const char *path;
        int result;
        uint32_t refused_with;
        const char *canonical;
    } cases[] = {
        { "\\Registry\\Machine\\Software\\Wine", PW_OK, 0u,
          "\\registry\\machine\\software\\wine" },
        { "\\Registry\\Machine", PW_OK, 0u, "\\registry\\machine" },
        { "\\registry\\user\\S-1-5-21-0-0-0-1000", PW_OK, 0u,
          "\\registry\\user\\s-1-5-21-0-0-0-1000" },
        /* A path that is not in this namespace at all is invalid, and one
         * that is inside it but not under a served root is not found: the two
         * are different refusals and the caller answers differently. */
        { "\\Device\\HarddiskVolume1", PW_ERR_NOT_FOUND,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "/Registry/Machine", PW_ERR_NOT_FOUND,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Something", PW_ERR_NOT_FOUND,
          PW_NT_OBJECT_NAME_NOT_FOUND, NULL },
        { "\\Registry\\", PW_ERR_NOT_FOUND, PW_NT_OBJECT_NAME_NOT_FOUND,
          NULL },
        /* Empty, traversing, separating and trailing components are refused. */
        { "\\Registry\\Machine\\\\Wine", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Machine\\..\\User", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Machine\\.", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Machine\\Wine\\", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Machine\\a/b", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\Registry\\Machine\\a:b", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        memset(out, 0, sizeof(out));
        const int result = pw_wine_path_registry(cases[index].path, out,
                                                 sizeof(out), &status);

        assert(result == cases[index].result);
        if (result == PW_OK)
            assert(strcmp(out, cases[index].canonical) == 0);
        else
            assert(status == cases[index].refused_with);
    }
    /* A component that does not fit is a refusal, not a truncated path. */
    {
        char small[16];

        assert(pw_wine_path_registry("\\Registry\\Machine\\averylongcomponent",
                                     small, sizeof(small), &status) ==
               PW_ERR_MALFORMED);
        assert(status == PW_NT_OBJECT_NAME_INVALID);
    }
    assert(pw_wine_path_registry_root("\\registry\\machine",
                                      "\\registry\\machine") == 1);
    assert(pw_wine_path_registry_root("\\registry\\machinemanager",
                                      "\\registry\\machine") == 0);
}

static void test_runtime(void)
{
    char out[192];
    uint32_t status = 0u;
    int directory = -1;
    static const struct {
        const char *path;
        int result;
        uint32_t refused_with;
        const char *canonical;
        int is_directory;
    } cases[] = {
        { "\\??\\C:\\windows\\system32\\kernel32.dll", PW_OK, 0u,
          "kernel32.dll", 0 },
        { "C:\\WINDOWS\\KernelBase.DLL", PW_OK, 0u, "kernelbase.dll", 0 },
        { "C:\\windows", PW_OK, 0u, "", 1 },
        { "C:\\windows\\system32\\", PW_OK, 0u, "", 1 },
        /* Two components, another drive and a drive-relative path. */
        { "C:\\windows\\system32\\sub\\file.dll", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_NOT_FOUND, NULL, 0 },
        { "\\??\\D:\\windows\\x", PW_ERR_NOT_FOUND,
          PW_NT_OBJECT_NAME_NOT_FOUND, NULL, 0 },
        { "\\windows\\x", PW_ERR_NOT_FOUND, PW_NT_OBJECT_NAME_NOT_FOUND,
          NULL, 0 },
        /* Traversal, an alternate data stream and a prefix that only looks
         * like the Windows directory. */
        { "C:\\windows\\..", PW_ERR_MALFORMED, PW_NT_OBJECT_NAME_NOT_FOUND,
          NULL, 0 },
        { "C:\\windows\\system32\\a.dll:stream", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_NOT_FOUND, NULL, 0 },
        { "C:\\windowsfoo", PW_ERR_NOT_FOUND, PW_NT_OBJECT_NAME_NOT_FOUND,
          NULL, 0 },
        { "C:\\windows\\system32\\a/b.dll", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_NOT_FOUND, NULL, 0 },
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        memset(out, 0, sizeof(out));
        const int result = pw_wine_path_runtime(cases[index].path, out,
                                                sizeof(out), &directory,
                                                &status);

        assert(result == cases[index].result);
        if (result == PW_OK) {
            assert(strcmp(out, cases[index].canonical) == 0);
            assert(directory == cases[index].is_directory);
        } else {
            assert(status == cases[index].refused_with);
        }
    }
}

static void test_object(void)
{
    char out[192];
    uint32_t status = 0u;
    static const struct {
        const char *path;
        int result;
        uint32_t refused_with;
        const char *canonical;
    } cases[] = {
        { "\\KnownDlls", PW_OK, 0u, "\\knowndlls" },
        { "\\KnownDlls\\kernel32.dll", PW_OK, 0u,
          "\\knowndlls\\kernel32.dll" },
        /* A relative name is resolved against a handle, not here. */
        { "KnownDlls", PW_ERR_NOT_FOUND, PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\", PW_ERR_NOT_FOUND, PW_NT_OBJECT_NAME_NOT_FOUND, NULL },
        { "\\KnownDlls\\", PW_ERR_MALFORMED, PW_NT_OBJECT_NAME_INVALID,
          NULL },
        { "\\KnownDlls\\..\\BaseNamedObjects", PW_ERR_MALFORMED,
          PW_NT_OBJECT_NAME_INVALID, NULL },
        { "\\KnownDlls\\a.b:c", PW_ERR_MALFORMED, PW_NT_OBJECT_NAME_INVALID,
          NULL },
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        memset(out, 0, sizeof(out));
        const int result = pw_wine_path_object(cases[index].path, out,
                                               sizeof(out), &status);

        assert(result == cases[index].result);
        if (result == PW_OK)
            assert(strcmp(out, cases[index].canonical) == 0);
        else
            assert(status == cases[index].refused_with);
    }
}

static void test_value_name(void)
{
    char out[192];
    uint32_t status = 0u;

    assert(pw_wine_path_value("DisplayName", out, sizeof(out), &status) ==
           PW_OK);
    assert(strcmp(out, "displayname") == 0);
    /* The empty name is the key's default value, which is a value. */
    assert(pw_wine_path_value("", out, sizeof(out), &status) == PW_OK);
    assert(out[0] == '\0');
    assert(pw_wine_path_value("@", out, sizeof(out), &status) == PW_OK);
    assert(pw_wine_path_value("a\\b", out, sizeof(out), &status) ==
           PW_ERR_MALFORMED);
    assert(status == PW_NT_OBJECT_NAME_INVALID);
    assert(pw_wine_path_value("a/b", out, sizeof(out), &status) ==
           PW_ERR_MALFORMED);
    assert(pw_wine_path_value("a:b", out, sizeof(out), &status) ==
           PW_ERR_MALFORMED);
    {
        char small[4];

        assert(pw_wine_path_value("abcdef", small, sizeof(small), &status) ==
               PW_ERR_MALFORMED);
    }
}

static void test_guest_strings(void)
{
    FakeGuest guest;
    char out[64];

    memset(&guest, 0, sizeof(guest));
    guest.size = sizeof(guest.bytes);
    put_string(&guest, 14u, 16u, "FOO.dll");
    /* The reader preserves the guest's case; the namespace translators are
     * what lower-case a name. */
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out,
                                     sizeof(out)) == PW_OK);
    assert(strcmp(out, "FOO.dll") == 0);
    assert(pw_wine_path_value_name(fake_access, &guest, 0u, out,
                                   sizeof(out)) == PW_OK);
    assert(strcmp(out, "FOO.dll") == 0);
    assert(guest.writes == 0u);

    /* An odd byte length cannot be a UTF-16 string. */
    put_string(&guest, 7u, 16u, "FOO.dll");
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out,
                                     sizeof(out)) == PW_ERR_MALFORMED);
    /* A zero-length name is the default value, not a malformed string. */
    put_string(&guest, 0u, 16u, "");
    assert(pw_wine_path_value_name(fake_access, &guest, 0u, out,
                                   sizeof(out)) == PW_OK);
    assert(out[0] == '\0');
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out,
                                     sizeof(out)) == PW_ERR_MALFORMED);
    /* A non-ASCII unit is refused rather than folded into a host name. */
    put_string(&guest, 2u, 16u, "");
    {
        const uint16_t unit = 0x00e9u;

        memcpy(&guest.bytes[16], &unit, 2u);
    }
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out,
                                     sizeof(out)) == PW_ERR_UNSUPPORTED);
    /* A buffer outside the guest window, and a destination too small to hold
     * the name with its terminator. */
    put_string(&guest, 14u, 200u, "FOO.dll");
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out,
                                     sizeof(out)) == PW_ERR_MALFORMED);
    put_string(&guest, 14u, 16u, "FOO.dll");
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out, 4u) ==
           PW_ERR_MALFORMED);
    /* The header itself has to be inside the window. */
    assert(pw_wine_path_read_unicode(fake_access, &guest, 60u, out,
                                     sizeof(out)) == PW_ERR_MALFORMED);
}

/*
 * The declared boundaries. Every function here takes an explicit output size
 * and a set of required pointers, and the final review found paths that wrote
 * or read before proving either: the registry prefix copied before the size
 * was checked, a root check reading an unterminated buffer, and prefix
 * matching reading past a shorter string. These cases pin the rules, under the
 * sanitizers as well as here.
 */
static void test_boundaries(void)
{
    FakeGuest guest;
    char out[8];
    char canary[8];
    uint32_t status = 0u;
    size_t used = 0u;
    int directory = 0;

    memset(&guest, 0, sizeof(guest));
    guest.size = sizeof(guest.bytes);

    /* Required pointers are refused, not dereferenced. */
    assert(pw_wine_path_prefix(NULL, "a", &used) == 0);
    assert(pw_wine_path_prefix("a", NULL, &used) == 0);
    assert(pw_wine_path_registry(NULL, out, sizeof(out), &status) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_registry("\\Registry\\Machine", NULL, sizeof(out),
                                 &status) == PW_ERR_PRECONDITION);
    assert(pw_wine_path_registry("\\Registry\\Machine", out, sizeof(out),
                                 NULL) == PW_ERR_PRECONDITION);
    assert(pw_wine_path_value(NULL, out, sizeof(out), &status) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_value("a", NULL, sizeof(out), &status) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_value("a", out, sizeof(out), NULL) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_runtime(NULL, out, sizeof(out), &directory,
                                &status) == PW_ERR_PRECONDITION);
    assert(pw_wine_path_object(NULL, out, sizeof(out), &status) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_object("\\KnownDlls", NULL, sizeof(out), &status) ==
           PW_ERR_PRECONDITION);
    assert(pw_wine_path_read_unicode(NULL, NULL, 0u, out, sizeof(out)) ==
           PW_ERR_MALFORMED);
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, NULL,
                                     sizeof(out)) == PW_ERR_MALFORMED);
    assert(pw_wine_path_value_name(NULL, NULL, 0u, out, sizeof(out)) ==
           PW_ERR_MALFORMED);
    assert(pw_wine_path_value_name(fake_access, &guest, 0u, NULL,
                                   sizeof(out)) == PW_ERR_MALFORMED);

    /* A zero-capacity output is refused before anything is written. */
    assert(pw_wine_path_registry("\\Registry\\Machine", out, 0u, &status) ==
           PW_ERR_MALFORMED);
    assert(pw_wine_path_value("", out, 0u, &status) == PW_ERR_MALFORMED);
    assert(pw_wine_path_runtime("C:\\windows", out, 0u, &directory,
                                &status) == PW_ERR_MALFORMED);
    assert(pw_wine_path_object("\\KnownDlls", out, 0u, &status) ==
           PW_ERR_NOT_FOUND);
    assert(pw_wine_path_read_unicode(fake_access, &guest, 0u, out, 0u) ==
           PW_ERR_MALFORMED);
    assert(pw_wine_path_value_name(fake_access, &guest, 0u, out, 0u) ==
           PW_ERR_MALFORMED);

    /* An output too small for the namespace prefix is refused before the copy:
     * the canary bytes are untouched. */
    memset(canary, 0x5a, sizeof(canary));
    assert(pw_wine_path_registry("\\Registry\\Machine", canary, 4u, &status) ==
           PW_ERR_MALFORMED);
    for (size_t index = 0u; index < sizeof(canary); ++index)
        assert((unsigned char)canary[index] == 0x5a);

    /* A string shorter than the prefix is not read past its terminator. */
    assert(pw_wine_path_prefix("\\Reg", "\\registry\\", &used) == 0);
    assert(pw_wine_path_prefix("", "\\registry\\", &used) == 0);
    assert(pw_wine_path_prefix("C:\\wind", "C:\\windows\\system32",
                               &used) == 0);

    /* The exact boundary fits; one byte less is refused rather than
     * truncated. "\\Registry\\Machine\\" is 18 bytes, so a 20-byte path needs
     * exactly 21 bytes with its terminator. */
    {
        char path[32];
        char exact[21];
        char short_buffer[20];

        memcpy(path, "\\Registry\\Machine\\xy", 21);
        assert(pw_wine_path_registry(path, exact, sizeof(exact), &status) ==
               PW_OK);
        assert(strcmp(exact, "\\registry\\machine\\xy") == 0);
        assert(pw_wine_path_registry(path, short_buffer, sizeof(short_buffer),
                                     &status) == PW_ERR_MALFORMED);
        assert(status == PW_NT_OBJECT_NAME_INVALID);
    }
    /* The same boundary for a value name: three characters need four bytes. */
    {
        char exact[4];
        char short_buffer[3];

        assert(pw_wine_path_value("Abc", exact, sizeof(exact), &status) ==
               PW_OK);
        assert(strcmp(exact, "abc") == 0);
        assert(pw_wine_path_value("Abc", short_buffer, sizeof(short_buffer),
                                  &status) == PW_ERR_MALFORMED);
        assert(status == PW_NT_OBJECT_NAME_INVALID);
    }
    /* A component of exactly the runtime buffer's size, and one over. */
    {
        char path[32];
        char exact[8];

        memcpy(path, "C:\\windows\\abcdefg", 19);
        assert(pw_wine_path_runtime(path, exact, sizeof(exact), &directory,
                                    &status) == PW_OK);
        assert(strcmp(exact, "abcdefg") == 0 && directory == 0);
        path[18] = 'h';                       /* one byte longer than `exact` */
        assert(pw_wine_path_runtime(path, exact, sizeof(exact), &directory,
                                    &status) == PW_ERR_MALFORMED);
    }
}

int main(void)
{
    test_prefix();
    test_registry();
    test_runtime();
    test_object();
    test_value_name();
    test_guest_strings();
    test_boundaries();
    printf("wine name translation passed: prefix, registry, runtime, object, "
           "value, guest-string and buffer-boundary rules\n");
    return 0;
}
