/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pw_export.h"
#include "../src/pw_import_bind.h"
#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <string.h>

enum {
    MAX_FILES = 8,
    IMAGE_CAPACITY = 64 * 1024,
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    NTDLL_ORDINAL = 101,
};

static uint8_t images[MAX_FILES][IMAGE_CAPACITY];
static uint8_t root_bytes[IMAGE_CAPACITY];

static const uint8_t code[32] = {0xc3};
static const uint8_t data[32] = {0x11, 0x22, 0x33, 0x44};

typedef struct FakeFile {
    const char *name;
    const uint8_t *bytes;
    size_t size;
} FakeFile;

static FakeFile files[MAX_FILES];
static uint32_t file_count;

static int fake_open(void *context, const char *canonical_name,
                     PwFileSpan *out)
{
    (void)context;
    for (uint32_t index = 0; index < file_count; ++index) {
        if (!pw_module_name_equal(files[index].name, canonical_name))
            continue;
        out->bytes = files[index].bytes;
        out->size = files[index].size;
        out->handle = NULL;
        memset(out->path, 0, sizeof(out->path));
        memcpy(out->path, "runtime/", 8);
        memcpy(out->path + 8, files[index].name, strlen(files[index].name));
        return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}

static void fake_close(void *context, PwFileSpan *span)
{
    (void)context;
    span->bytes = NULL;
    span->size = 0u;
}

static int fake_open_namespace(void *context, PwFileNamespace file_namespace,
                               const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_open(context, canonical_name, out);
}

static const PwFileProvider provider = {
    .context = NULL,
    .open = fake_open,
    .close = fake_close,
    .open_namespace = fake_open_namespace,
};

/*
 * Registers one synthetic i386 module. Each module gets its own image base
 * so a resolved address identifies the module it came from.
 */
static void add_module(const char *name, uint32_t slot,
                       const PeFixtureExport *exports, uint32_t export_count,
                       const PeFixtureImport *imports, uint32_t import_count)
{
    PeFixtureSpec spec;
    size_t size;

    assert(file_count < MAX_FILES);
    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = 0x10000000ull + (uint64_t)slot * 0x100000ull;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".rdata";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ;
    spec.sections[1].data = data;
    spec.sections[1].data_bytes = (uint32_t)sizeof(data);
    spec.entry_point = TEXT_RVA;
    spec.export_base = 1u;
    spec.export_module_name = name;
    spec.export_count = export_count;
    for (uint32_t index = 0; index < export_count; ++index)
        spec.exports[index] = exports[index];
    spec.import_count = import_count;
    for (uint32_t index = 0; index < import_count; ++index)
        spec.imports[index] = imports[index];
    size = pe_fixture_build(images[slot], IMAGE_CAPACITY, &spec);
    assert(size != 0u);
    files[file_count].name = name;
    files[file_count].bytes = images[slot];
    files[file_count].size = size;
    ++file_count;
}

/*
 * The graph under test:
 *
 *   kernel32.dll  CreateFileA -> KERNELBASE.CreateFileA
 *                 Chain       -> KERNELBASE.Chain2
 *                 ForwardedData -> NTDLL.DataThing
 *                 Missing     -> NOSUCHMODULE.Thing
 *                 Cycle       -> KERNELBASE.Cycle2
 *   kernelbase.dll CreateFileA -> NTDLL.#101
 *                  Chain2      -> NTDLL.Chain3
 *                  Cycle2      -> KERNEL32.Cycle
 *                  Sparse      -> NTDLL.#7
 *   ntdll.dll      #101 and "Primary" share one RVA in .text
 *                  Chain3      -> NTDLL.Final
 *                  Final, DataThing, ZeroFill
 *   empty.dll      no export directory
 */
static const PeFixtureExport kernel32_exports[] = {
    {"CreateFileA", 1u, 0u, "KERNELBASE.CreateFileA"},
    {"Chain", 2u, 0u, "KERNELBASE.Chain2"},
    {"ForwardedData", 3u, 0u, "NTDLL.DataThing"},
    {"Missing", 4u, 0u, "NOSUCHMODULE.Thing"},
    {"Cycle", 5u, 0u, "KERNELBASE.Cycle2"},
    {"Direct", 6u, TEXT_RVA, NULL},
};

static const PeFixtureExport kernelbase_exports[] = {
    {"CreateFileA", 1u, 0u, "NTDLL.#101"},
    {"Chain2", 2u, 0u, "NTDLL.Chain3"},
    {"Cycle2", 3u, 0u, "KERNEL32.Cycle"},
    {"Sparse", 4u, 0u, "NTDLL.#7"},
};

static const PeFixtureExport ntdll_exports[] = {
    {"Primary", 1u, TEXT_RVA, NULL},
    {"Chain3", 2u, 0u, "NTDLL.Final"},
    {"Final", 3u, TEXT_RVA + 4u, NULL},
    {"DataThing", 4u, DATA_RVA, NULL},
    {"ZeroFill", 5u, 0u, NULL},         /* sparse: rva 0 */
    {NULL, NTDLL_ORDINAL, TEXT_RVA, NULL},
};

static PwLoader loader;
static PwVmBackend vm;
static PwExportResolver resolver;
static const PwModulePolicy wine_policy = {
    .context = NULL,
    .classify = pw_loader_wine_policy,
};

static void load_graph(void)
{
    PeFixtureSpec spec;
    size_t size;

    file_count = 0u;
    /* Mirror the real graph shape: kernel32 imports kernelbase, and
     * kernelbase imports ntdll, so both modules are reachable. */
    {
        static const PeFixtureImport kernel32_imports[1] = {
            {"kernelbase.dll", {"CreateFileA", NULL}, {0}},
        };
        static const PeFixtureImport kernelbase_imports[1] = {
            {"ntdll.dll", {"Primary", NULL}, {0}},
        };

    add_module("kernel32.dll", 0u, kernel32_exports,
               (uint32_t)(sizeof(kernel32_exports) / sizeof(kernel32_exports[0])),
               kernel32_imports, 1u);
    add_module("kernelbase.dll", 1u, kernelbase_exports,
               (uint32_t)(sizeof(kernelbase_exports) / sizeof(kernelbase_exports[0])),
               kernelbase_imports, 1u);
    }
    add_module("ntdll.dll", 2u, ntdll_exports,
               (uint32_t)(sizeof(ntdll_exports) / sizeof(ntdll_exports[0])),
               NULL, 0u);
    add_module("empty.dll", 3u, NULL, 0u, NULL, 0u);

    assert(pw_vm_posix_backend(&vm) == PW_OK);
    assert(pw_loader_init(&loader, &provider, &vm) == PW_OK);
    /* The Wine policy maps Windows modules from the runtime namespace
     * instead of treating them as native host interfaces. */
    assert(pw_loader_set_policy(&loader, &wine_policy) == PW_OK);
    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.image_base = 0x00400000u;
    spec.entry_point = TEXT_RVA;
    spec.section_count = 1u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.import_count = 2u;
    spec.imports[0].dll = "kernel32.dll";
    spec.imports[0].names[0] = "CreateFileA";
    spec.imports[0].names[1] = "Chain";
    spec.imports[1].dll = "ntdll.dll";
    spec.imports[1].names[0] = "DataThing";
    spec.imports[1].names[1] = "Primary";
    spec.imports[1].ordinals[0] = NTDLL_ORDINAL;
    size = pe_fixture_build(root_bytes, sizeof(root_bytes), &spec);
    assert(size != 0u);
    assert(pw_loader_load(&loader, root_bytes, size, "app.exe") == PW_OK);
    assert(pw_loader_compute_order(&loader) == PW_OK);
    assert(pw_export_resolver_init(&resolver, &loader, 4u) == PW_OK);
}

static uint32_t module_base(const char *name)
{
    const int index = pw_loader_find(&loader, name);
    const PwModule *module;

    assert(index >= 0);
    module = pw_loader_module(&loader, (uint32_t)index);
    assert(module != NULL);
    return (uint32_t)module->mapped.actual_base;
}

static void test_name_ordinal_and_data(void)
{
    PwExportTarget target;

    assert(pw_export_resolve(&resolver, "kernel32.dll", "Direct", 0u, 0,
                             &target) == PW_OK);
    assert(target.address == module_base("kernel32.dll") + TEXT_RVA);
    assert(target.is_data == 0u);
    assert(target.forwarded == 0u);
    assert(strcmp(target.module, "kernel32.dll") == 0);

    /* A forwarder to a name resolves through kernelbase to ntdll. */
    assert(pw_export_resolve(&resolver, "kErNeL32", "CreateFileA", 0u, 0,
                             &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA);
    assert(target.forwarded == 1u);
    assert(target.forwards == 2u);
    assert(strcmp(target.module, "ntdll.dll") == 0);
    assert(target.is_data == 0u);

    /* The same address through an ordinal forwarder and a direct ordinal
     * lookup: name and ordinal agree. */
    assert(pw_export_resolve(&resolver, "ntdll.dll", NULL, NTDLL_ORDINAL, 1,
                             &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA);
    assert(target.by_ordinal == 1u);
    assert(pw_export_resolve(&resolver, "ntdll.dll", "Primary", 0u, 0,
                             &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA);

    /* Exported data stays data across a forwarder. */
    assert(pw_export_resolve(&resolver, "kernel32.dll", "ForwardedData", 0u, 0,
                             &target) == PW_OK);
    assert(target.is_data == 1u);
    assert(target.address == module_base("ntdll.dll") + DATA_RVA);
    assert(pw_export_resolve(&resolver, "ntdll.dll", "DataThing", 0u, 0,
                             &target) == PW_OK);
    assert(target.is_data == 1u);

    /* Requests use the forwarder spelling too. */
    assert(pw_export_resolve_request(&resolver, "KERNEL32.CreateFileA",
                                     &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA);
    assert(pw_export_resolve_request(&resolver, "NTDLL.#101", &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA);
    assert(pw_export_resolve_request(&resolver, "NTDLL.NotThere", &target) ==
           PW_ERR_NOT_FOUND);
    assert(pw_export_resolve_request(&resolver, "NoSeparator", &target) ==
           PW_ERR_MALFORMED);
    assert(pw_export_resolve_request(&resolver, "NTDLL.#0", &target) ==
           PW_ERR_MALFORMED);
    assert(pw_export_resolve_request(&resolver, "NTDLL.#99999", &target) ==
           PW_ERR_MALFORMED);
    assert(pw_export_resolve_request(&resolver, "NTDLL.#12x", &target) ==
           PW_ERR_MALFORMED);
}

static void test_three_module_chain(void)
{
    PwExportTarget target;

    assert(pw_export_resolve(&resolver, "kernel32.dll", "Chain", 0u, 0,
                             &target) == PW_OK);
    assert(target.address == module_base("ntdll.dll") + TEXT_RVA + 4u);
    assert(target.forwards == 3u);
    assert(strcmp(target.module, "ntdll.dll") == 0);
    assert(strcmp(target.symbol, "Final") == 0);
}

static void test_failures_are_closed(void)
{
    PwExportTarget target;
    const uint64_t misses = resolver.misses;

    memset(&target, 0xab, sizeof(target));
    /* Forwarder into a module that was never mapped. */
    assert(pw_export_resolve(&resolver, "kernel32.dll", "Missing", 0u, 0,
                             &target) == PW_ERR_NOT_FOUND);
    assert(resolver.misses == misses + 1u);
    assert(strcmp(resolver.request_module, "kernel32.dll") == 0);
    assert(strcmp(resolver.request_symbol, "Missing") == 0);
    assert(strcmp(resolver.failed_module, "nosuchmodule.dll") == 0);
    assert(target.address == 0u);

    /* A sparse function slot reached through a forwarder ordinal. */
    assert(pw_export_resolve(&resolver, "kernelbase.dll", "Sparse", 0u, 0,
                             &target) == PW_ERR_NOT_FOUND);
    assert(resolver.misses == misses + 2u);
    assert(strcmp(resolver.failed_module, "ntdll.dll") == 0);

    /* A sparse slot inside ntdll itself. */
    assert(pw_export_resolve_request(&resolver, "NTDLL.ZeroFill", &target) ==
           PW_ERR_NOT_FOUND);
    /* A module with no export directory. */
    assert(pw_export_resolve(&resolver, "empty.dll", "Anything", 0u, 0,
                             &target) == PW_ERR_NOT_FOUND);
    /* An unreachable ordinal. */
    assert(pw_export_resolve(&resolver, "ntdll.dll", NULL, 4000u, 1,
                             &target) == PW_ERR_NOT_FOUND);
    /* Case-sensitive symbol names. */
    assert(pw_export_resolve(&resolver, "ntdll.dll", "primary", 0u, 0,
                             &target) == PW_ERR_NOT_FOUND);
    assert(target.address == 0u);

    /* Precondition failures never write a target. */
    assert(pw_export_resolve(&resolver, "ntdll.dll", NULL, 0u, 0, &target) ==
           PW_ERR_PRECONDITION);
    assert(pw_export_resolve(&resolver, "", "Primary", 0u, 0, &target) ==
           PW_ERR_PRECONDITION);
    assert(pw_export_resolve(&resolver, "ntdll.dll", "Primary", 0u, 0, NULL) ==
           PW_ERR_PRECONDITION);
    assert(target.address == 0u);
}

static void test_cycle_and_depth(void)
{
    PwExportTarget target;
    PwExportResolver shallow;

    assert(pw_export_resolve(&resolver, "kernel32.dll", "Cycle", 0u, 0,
                             &target) == PW_ERR_MALFORMED);
    assert(resolver.cycles == 1u);
    assert(strcmp(resolver.request_symbol, "Cycle") == 0);
    assert(target.address == 0u);

    /* Depth 4 is exactly enough for the three-module chain. */
    assert(pw_export_resolver_init(&shallow, &loader, 1u) == PW_OK);
    assert(pw_export_resolve(&shallow, "kernel32.dll", "Chain", 0u, 0,
                             &target) == PW_ERR_LIMIT);
    assert(shallow.depth_exhausted == 1u);
    assert(shallow.max_observed_depth == 1u);
    /* The identity is still the caller's, not the abandoned hop. */
    assert(strcmp(shallow.request_module, "kernel32.dll") == 0);
    assert(strcmp(shallow.request_symbol, "Chain") == 0);
    assert(target.address == 0u);
    assert(pw_export_resolver_init(&resolver, &loader, 0u) ==
           PW_ERR_PRECONDITION);
    assert(pw_export_resolver_init(&resolver, &loader,
                                   PW_EXPORT_MAX_DEPTH + 1u) ==
           PW_ERR_PRECONDITION);
}

static void test_import_binding_uses_one_resolver(void)
{
    PwImportBindWorkspace workspace;
    PwImportBindReport report;
    const int ntdll = pw_loader_find(&loader, "ntdll.dll");
    PwModule *module;

    assert(ntdll >= 0);
    module = (PwModule *)pw_loader_module(&loader, (uint32_t)ntdll);
    assert(module != NULL);
    assert(pw_import_bind32(&module->image, &module->mapped,
                            pw_export_import_resolver, &resolver, &workspace,
                            &report) == PW_OK);
    /* ntdll imports nothing in this fixture, so every slot must have been
     * resolved by its own module instead; the report is still well formed. */
    assert(report.total == 0u);

    /* The root executable binds its runtime imports through the resolver. */
    {
        const int root = 0;
        PwModule *app = (PwModule *)pw_loader_module(&loader, (uint32_t)root);
        uint32_t value = 0u;

        assert(app != NULL);
        assert(app->import_symbols == 5u);
        assert(pw_import_bind32(&app->image, &app->mapped,
                                pw_export_import_resolver, &resolver,
                                &workspace, &report) == PW_OK);
        assert(report.total == 5u);
        assert(report.functions == 4u);
        assert(report.data == 1u);
        /* CreateFileA forwards kernel32 -> kernelbase -> ntdll.#101. */
        memcpy(&value, workspace.writes[0].slot, 4u);
        assert(value == module_base("ntdll.dll") + TEXT_RVA);
        assert(workspace.writes[0].kind == PW_IMPORT_FUNCTION);
        /* Chain forwards through all three modules. */
        memcpy(&value, workspace.writes[1].slot, 4u);
        assert(value == module_base("ntdll.dll") + TEXT_RVA + 4u);
        /* DataThing is a data import. */
        assert(workspace.writes[2].kind == PW_IMPORT_DATA);
        memcpy(&value, workspace.writes[2].slot, 4u);
        assert(value == module_base("ntdll.dll") + DATA_RVA);
        /* Primary and the ordinal import resolve to the same code address. */
        memcpy(&value, workspace.writes[3].slot, 4u);
        assert(value == module_base("ntdll.dll") + TEXT_RVA);
        memcpy(&value, workspace.writes[4].slot, 4u);
        assert(value == module_base("ntdll.dll") + TEXT_RVA);
    }
    assert(pw_loader_release(&loader) == PW_OK);
}

int main(void)
{
    load_graph();
    test_name_ordinal_and_data();
    test_three_module_chain();
    test_failures_are_closed();
    test_cycle_and_depth();
    test_import_binding_uses_one_resolver();
    return 0;
}
