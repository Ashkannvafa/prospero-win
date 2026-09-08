/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pw_loader.h"
#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <string.h>

enum {
    MAX_FILES = 8,
    IMAGE_CAPACITY = 64 * 1024,
};

static uint8_t images[MAX_FILES][IMAGE_CAPACITY];
static const uint8_t code[64] = {0x48, 0x31, 0xc0, 0xc3};

typedef struct FakeFile {
    const char *name;
    const uint8_t *bytes;
    size_t size;
} FakeFile;

static FakeFile files[MAX_FILES];
static uint32_t file_count;
static uint32_t open_calls;
static uint32_t close_calls;

/* A provider over an in-memory table: host tests touch no filesystem. */
static int fake_open(void *context, const char *canonical_name,
                     PwFileSpan *out)
{
    (void)context;
    ++open_calls;
    for (uint32_t index = 0; index < file_count; ++index) {
        if (!pw_module_name_equal(files[index].name, canonical_name))
            continue;
        out->bytes = files[index].bytes;
        out->size = files[index].size;
        out->handle = NULL;
        memset(out->path, 0, sizeof(out->path));
        memcpy(out->path, "/app0/win/", 10);
        memcpy(out->path + 10, canonical_name, strlen(canonical_name));
        return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}

static void fake_close(void *context, PwFileSpan *span)
{
    (void)context;
    ++close_calls;
    span->bytes = NULL;
    span->size = 0u;
}

static void provider_reset(void)
{
    file_count = 0u;
    open_calls = 0u;
    close_calls = 0u;
    memset(files, 0, sizeof(files));
}

/* Builds one synthetic module and registers it with the fake provider. */
static size_t add_module(const char *name, int dll, uint16_t machine,
                         const char *const *imports, uint32_t import_count,
                         int publish)
{
    PeFixtureSpec spec;
    const uint32_t slot = file_count;
    size_t size;

    assert(slot < MAX_FILES);
    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 1;
    spec.machine = machine;
    spec.dll = dll;
    spec.image_base = 0x180000000ull + (uint64_t)slot * 0x100000ull;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = code;
    spec.sections[1].data_bytes = 32u;
    spec.entry_point = 0x1000u;
    /* Every module is relocatable; nothing can be mapped at its own base. */
    spec.reloc_count = 1u;
    spec.relocs[0].rva = 0x2000u;
    spec.relocs[0].type = PE_RELOC_DIR64;
    for (uint32_t index = 0; index < import_count; ++index) {
        spec.imports[index].dll = imports[index];
        spec.imports[index].names[0] = "Entry";
    }
    spec.import_count = import_count;

    size = pe_fixture_build(images[slot], IMAGE_CAPACITY, &spec);
    assert(size != 0u);
    if (publish) {
        files[slot].name = name;
        files[slot].bytes = images[slot];
        files[slot].size = size;
        ++file_count;
    } else {
        /* Reserve the slot so a later module does not overwrite the bytes. */
        files[slot].name = "";
        files[slot].bytes = images[slot];
        files[slot].size = size;
        ++file_count;
    }
    return size;
}

static PwFileProvider provider = {NULL, fake_open, fake_close};
static PwVmBackend backend;
static PwLoader loader;                 /* far too large for the stack */

static void test_resolves_third_party_chain(void)
{
    static const char *const root_imports[] = {"BINKW32.dll", "KERNEL32.dll"};
    static const char *const bink_imports[] = {"msvcrt.dll", "helper.dll"};
    static const char *const helper_imports[] = {"KERNEL32.dll"};
    size_t root_size;
    const PwModule *module;

    provider_reset();
    /* Slot 0 holds the root; it is passed in directly, not through the
     * provider, exactly as an executable is on the console. */
    root_size = add_module("", 0, 0, root_imports, 2u, 0);
    (void)add_module("binkw32.dll", 1, 0, bink_imports, 2u, 1);
    (void)add_module("helper.dll", 1, 0, helper_imports, 1u, 1);

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    assert(pw_loader_load(&loader, images[0], root_size, "GAME.EXE") == PW_OK);

    /*
     * game.exe -> binkw32.dll -> {msvcrt.dll, helper.dll}
     *                            helper.dll -> kernel32.dll
     * Two third-party images are mapped; two Win32 modules become host
     * bindings and are never read from disk.
     */
    assert(loader.module_count == 5u);
    assert(loader.local_count == 2u);
    assert(loader.host_count == 2u);
    assert(loader.machine == PE_MACHINE_AMD64);
    assert(loader.max_depth == 2u);
    assert(loader.cycle_edges == 0u);
    /* Only the two local dependencies were ever opened. */
    assert(open_calls == 2u);

    module = pw_loader_module(&loader, 0u);
    assert(module && strcmp(module->name, "game.exe") == 0);
    assert(module->kind == PW_MODULE_ROOT);
    assert(module->is_dll == 0u);
    assert(module->machine_native == 1u);
    assert(module->mapped_ok == 1u);
    assert(module->depth == 0u);
    assert(module->dependency_count == 2u);
    assert(module->import_symbols == 2u);

    const int bink = pw_loader_find(&loader, "binkw32.dll");
    assert(bink == 1);
    module = pw_loader_module(&loader, (uint32_t)bink);
    assert(module->kind == PW_MODULE_LOCAL);
    assert(module->is_dll == 1u);
    assert(module->depth == 1u);
    assert(module->mapped_ok == 1u);
    assert(module->mapped.relocs.applied == 1u);
    assert(module->verify.headers_present == 1u);
    assert(module->verify.raw_mismatches == 0u);
    assert(strcmp(module->path, "/app0/win/binkw32.dll") == 0);

    const int kernel = pw_loader_find(&loader, "KERNEL32.DLL");
    assert(kernel == 2);
    module = pw_loader_module(&loader, (uint32_t)kernel);
    assert(module->kind == PW_MODULE_HOST);
    assert(module->mapped_ok == 0u);        /* never loaded from disk */
    assert(module->path[0] == '\0');
    assert(module->depth == 1u);

    module = pw_loader_module(&loader, 3u);
    assert(strcmp(module->name, "msvcrt.dll") == 0);
    assert(module->kind == PW_MODULE_HOST);
    module = pw_loader_module(&loader, 4u);
    assert(strcmp(module->name, "helper.dll") == 0);
    assert(module->kind == PW_MODULE_LOCAL);
    assert(module->depth == 2u);
    assert(pw_loader_module(&loader, 5u) == NULL);

    /* kernel32 is reached twice and registered once. */
    module = pw_loader_module(&loader, 4u);
    assert(module->dependency_count == 1u);
    assert(module->dependencies[0] == 2u);

    /* Dependencies precede dependents; the root is last. */
    assert(loader.order_count == 5u);
    assert(loader.order[4] == 0u);
    for (uint32_t index = 0; index < loader.order_count; ++index) {
        const PwModule *current =
            pw_loader_module(&loader, loader.order[index]);
        for (uint32_t edge = 0; edge < current->dependency_count; ++edge) {
            uint32_t position = loader.order_count;

            for (uint32_t scan = 0; scan < loader.order_count; ++scan) {
                if (loader.order[scan] == current->dependencies[edge])
                    position = scan;
            }
            assert(position < index);
        }
    }

    /* Reserved bytes account for the mapped images only. */
    assert(loader.reserved_bytes ==
           pw_loader_module(&loader, 0u)->mapped.region.bytes +
           pw_loader_module(&loader, 1u)->mapped.region.bytes +
           pw_loader_module(&loader, 4u)->mapped.region.bytes);

    assert(pw_loader_finalize(&loader) == PW_OK);
    assert(pw_loader_module(&loader, 0u)->mapped.protections_applied == 1u);
    assert(pw_loader_module(&loader, 2u)->mapped.protections_applied == 0u);

    assert(pw_loader_release(&loader) == PW_OK);
    assert(loader.module_count == 0u);
    assert(loader.reserved_bytes == 0u);
    /* Every span the loader opened was closed. */
    assert(close_calls == 2u);
}

static void test_reports_missing_dependency(void)
{
    static const char *const root_imports[] = {"mss32.dll"};
    size_t root_size;

    provider_reset();
    root_size = add_module("", 0, 0, root_imports, 1u, 0);

    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    /*
     * mss32.dll is third-party, so it must be staged next to the
     * executable. Absent, the loader names it instead of stubbing it.
     */
    assert(pw_loader_load(&loader, images[0], root_size, "game.exe") ==
           PW_ERR_NOT_FOUND);
    assert(strcmp(loader.missing, "mss32.dll") == 0);
    /* The failed load released the root reservation it had already made. */
    assert(loader.module_count == 0u);
    assert(loader.reserved_bytes == 0u);
}

static void test_refuses_mixed_machines(void)
{
    static const char *const root_imports[] = {"helper.dll"};
    size_t root_size;

    provider_reset();
    root_size = add_module("", 0, PE_MACHINE_AMD64, root_imports, 1u, 0);
    (void)add_module("helper.dll", 1, PE_MACHINE_I386, NULL, 0u, 1);

    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    /* One process cannot hold both instruction sets. */
    assert(pw_loader_load(&loader, images[0], root_size, "game.exe") ==
           PW_ERR_UNSUPPORTED);
    assert(loader.module_count == 0u);
}

static void test_tolerates_import_cycles(void)
{
    static const char *const root_imports[] = {"a.dll"};
    static const char *const a_imports[] = {"b.dll"};
    static const char *const b_imports[] = {"a.dll"};
    size_t root_size;

    provider_reset();
    root_size = add_module("", 0, 0, root_imports, 1u, 0);
    (void)add_module("a.dll", 1, 0, a_imports, 1u, 1);
    (void)add_module("b.dll", 1, 0, b_imports, 1u, 1);

    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    /* A mutual import is normal in PE and must not be an error. */
    assert(pw_loader_load(&loader, images[0], root_size, "game.exe") == PW_OK);
    assert(loader.module_count == 3u);
    assert(loader.local_count == 2u);
    assert(loader.cycle_edges == 1u);
    assert(loader.order_count == 3u);
    assert(loader.order[2] == 0u);
    assert(pw_loader_release(&loader) == PW_OK);
}

static void test_root_without_imports(void)
{
    size_t root_size;

    provider_reset();
    root_size = add_module("", 0, 0, NULL, 0u, 0);

    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    assert(pw_loader_load(&loader, images[0], root_size, "solo.exe") == PW_OK);
    assert(loader.module_count == 1u);
    assert(loader.host_count == 0u);
    assert(open_calls == 0u);
    /* A second load into a live loader is a state error, not a leak. */
    assert(pw_loader_load(&loader, images[0], root_size, "solo.exe") ==
           PW_ERR_STATE);
    assert(pw_loader_release(&loader) == PW_OK);
}

static void test_preconditions(void)
{
    size_t root_size;

    provider_reset();
    root_size = add_module("", 0, 0, NULL, 0u, 0);

    assert(pw_loader_init(NULL, &provider, &backend) == PW_ERR_PRECONDITION);
    assert(pw_loader_init(&loader, NULL, &backend) == PW_ERR_PRECONDITION);
    assert(pw_loader_init(&loader, &provider, NULL) == PW_ERR_PRECONDITION);

    PwFileProvider broken = provider;
    broken.open = NULL;
    assert(!pw_file_provider_valid(&broken));
    assert(!pw_file_provider_valid(NULL));
    assert(pw_loader_init(&loader, &broken, &backend) == PW_ERR_PRECONDITION);

    assert(pw_loader_init(&loader, &provider, &backend) == PW_OK);
    assert(pw_loader_load(&loader, NULL, root_size, "a.exe") ==
           PW_ERR_PRECONDITION);
    assert(pw_loader_load(&loader, images[0], root_size, NULL) ==
           PW_ERR_PRECONDITION);
    /* A path is not a module name. */
    assert(pw_loader_load(&loader, images[0], root_size, "..\\a.exe") ==
           PW_ERR_MALFORMED);
    assert(pw_loader_find(&loader, "absent.dll") == PW_ERR_NOT_FOUND);
    assert(pw_loader_find(NULL, "a") == PW_ERR_PRECONDITION);
    assert(pw_loader_module(NULL, 0u) == NULL);
    assert(pw_loader_compute_order(&loader) == PW_ERR_PRECONDITION);
    assert(pw_loader_finalize(&loader) == PW_ERR_PRECONDITION);
    assert(pw_loader_release(NULL) == PW_ERR_PRECONDITION);

    assert(strcmp(pw_module_kind_name(PW_MODULE_ROOT), "root") == 0);
    assert(strcmp(pw_module_kind_name(PW_MODULE_LOCAL), "local") == 0);
    assert(strcmp(pw_module_kind_name(PW_MODULE_HOST), "host") == 0);
    assert(strcmp(pw_module_kind_name(99u), "unknown") == 0);
}

int main(void)
{
    /* The registry is deliberately large: keep it out of automatic storage. */
    assert(sizeof(PwLoader) > 64u * 1024u);
    assert(sizeof(PwLoader) < 1024u * 1024u);

    test_resolves_third_party_chain();
    test_reports_missing_dependency();
    test_refuses_mixed_machines();
    test_tolerates_import_cycles();
    test_root_without_imports();
    test_preconditions();
    return 0;
}
