/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the Wine ntdll entry gate.
 *
 * The real acceptance evidence needs the staged Wine runtime, which is a
 * build artifact. This test builds two synthetic modules shaped the way Wine
 * shapes them - a data export for the dispatcher slot, the single
 * "jmp dword ptr [slot]" thunk, and a syscall stub that names its call and
 * jumps through that thunk - so the gate's boundary detection, entry
 * decoding, stop classification and cleanup are exercised by `make test`
 * without any third-party binary.
 */
#include "pe_fixture.h"

#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"

#include <assert.h>
#include <string.h>

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    THUNK_RVA = TEXT_RVA + 16,
    ROOT_TEXT_RVA = 0x1000,
    SYSCALL_ID = 0x0f,
};

static uint8_t ntdll_bytes[64 * 1024];
static uint8_t root_bytes[64 * 1024];

static int fake_open(void *context, const char *canonical_name,
                     PwFileSpan *out)
{
    (void)context;
    if (pw_module_name_equal(canonical_name, "ntdll.dll")) {
        out->bytes = ntdll_bytes;
        out->size = sizeof(ntdll_bytes);
    } else if (pw_module_name_equal(canonical_name, "kernelbase.dll")) {
        out->bytes = root_bytes;
        out->size = sizeof(root_bytes);
    } else {
        return PW_ERR_NOT_FOUND;
    }
    out->handle = NULL;
    memset(out->path, 0, sizeof(out->path));
    memcpy(out->path, "runtime/", 8);
    memcpy(out->path + 8, canonical_name, strlen(canonical_name));
    return PW_OK;
}

static void fake_close(void *context, PwFileSpan *span)
{
    (void)context;
    (void)span;
}

static const PwFileProvider provider = {
    .context = NULL,
    .open = fake_open,
    .close = fake_close,
    .open_namespace = NULL,
};

static int fake_open_namespace(void *context, PwFileNamespace file_namespace,
                               const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_open(context, canonical_name, out);
}

/*
 * The synthetic ntdll:
 *   .text  mov eax,0x0f ; mov edx,caller-relative thunk ; call edx ; ret 4
 *          jmp dword ptr [dispatcher slot]
 *   .data  the dispatcher slot itself (uninitialised in real Wine, so a
 *          plain data address with no file bytes is what the parser must
 *          accept)
 */
static size_t build_ntdll(void)
{
    static const uint8_t text[32] = {
        0xb8, SYSCALL_ID, 0x00, 0x00, 0x00,           /* mov eax, 0x0f */
        /* "mov edx, 0x7bc01010" and "jmp dword ptr [0x7bc02000]": the
         * linked addresses of the thunk and the dispatcher slot at the
         * preferred base 0x7bc00000. Both operands carry a HIGHLOW
         * relocation, so the mapper rewrites them for the load address. */
        0xba, 0x10, 0x10, 0xc0, 0x7b,
        0xff, 0xd2,                                   /* call edx */
        0xc2, 0x04, 0x00,                             /* ret 4 */
        0x90,
        0xff, 0x25, 0x00, 0x20, 0xc0, 0x7b,           /* jmp [slot] */
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };
    static const uint8_t data[4] = {0, 0, 0, 0};
    PeFixtureSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = 0x7bc00000u;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = TEXT_RVA;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = text;
    spec.sections[0].data_bytes = (uint32_t)sizeof(text);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = data;
    spec.sections[1].data_bytes = (uint32_t)sizeof(data);
    spec.export_base = 1u;
    spec.export_module_name = "ntdll.dll";
    spec.export_count = 2u;
    spec.exports[0].name = "__wine_syscall_dispatcher";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = DATA_RVA;
    spec.exports[1].name = "NtClose";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = TEXT_RVA;
    /* Both absolute operands are relocated when the module is mapped. */
    spec.reloc_count = 2u;
    spec.relocs[0].rva = TEXT_RVA + 6u;
    spec.relocs[0].type = PE_RELOC_HIGHLOW;
    spec.relocs[1].rva = THUNK_RVA + 2u;
    spec.relocs[1].type = PE_RELOC_HIGHLOW;
    return pe_fixture_build(ntdll_bytes, sizeof(ntdll_bytes), &spec);
}

/* The root imports the stub the gate enters, so binding is exercised. */
static size_t build_root(void)
{
    static const uint8_t text[8] = {0xc3, 0xc3, 0xc3, 0xc3,
                                    0xc3, 0xc3, 0xc3, 0xc3};
    PeFixtureSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = 0x7b800000u;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = ROOT_TEXT_RVA;
    spec.section_count = 1u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = text;
    spec.sections[0].data_bytes = (uint32_t)sizeof(text);
    spec.import_count = 1u;
    spec.imports[0].dll = "ntdll.dll";
    spec.imports[0].names[0] = "NtClose";
    return pe_fixture_build(root_bytes, sizeof(root_bytes), &spec);
}

int main(void)
{
    PwFileProvider namespaced = provider;
    PwWineGateConfig config;
    PwWineGateReport report;
    PwVmBackend vm;
    const char *modules[] = {"ntdll.dll", "kernelbase.dll"};
    int status;

    namespaced.open_namespace = fake_open_namespace;
    assert(build_ntdll() != 0u);
    assert(build_root() != 0u);
    assert(pw_vm_posix_backend(&vm) == PW_OK);

    memset(&config, 0, sizeof(config));
    config.provider = &namespaced;
    config.backend = &vm;
    config.root_module = "kernelbase.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "NtClose";
    config.modules[0] = modules[0];
    config.modules[1] = modules[1];
    config.module_count = 2u;
    status = pw_wine_gate_run(&config, &report);
    assert(status == PW_OK);
    assert(pw_wine_stop_is_acceptance(report.stop));
    assert(strcmp(pw_wine_stop_name(report.stop),
                  "wine-unix-call-boundary") == 0);

    /* Module identity comes from hashing the bytes the provider handed over. */
    assert(report.module_count == 2u);
    assert(strcmp(report.modules[0].name, "ntdll.dll") == 0);
    assert(report.modules[0].loaded == 1u);
    assert(report.modules[0].size == sizeof(ntdll_bytes));
    assert(strlen(report.modules[0].sha256) == 64u);
    assert(report.modules[0].machine == PE_MACHINE_I386);
    assert(report.modules[0].base != 0u);
    assert((uint64_t)report.modules[0].base +
           report.modules[0].image_bytes <= 0x100000000ull);

    /* The boundary is the data export and the thunk that references it. */
    assert(report.boundary_slot_rva == DATA_RVA);
    assert(report.boundary_count == 1u);
    assert(report.boundary_thunk_rva == THUNK_RVA);
    assert(report.boundary_thunk_va ==
           report.modules[0].base + THUNK_RVA);
    assert(report.boundary_slot_va == report.modules[0].base + DATA_RVA);

    /* The entry is the exported stub, and its encoded id is the syscall. */
    assert(report.bound_functions == 1u);
    assert(report.bound_modules == 1u);
    assert(report.bind_failures == 0u);
    assert(report.entry_rva == TEXT_RVA);
    assert(report.entry_eip == report.modules[0].base + TEXT_RVA);
    assert(report.entry_pe_rva == TEXT_RVA);
    assert(report.stub_syscall_id == SYSCALL_ID);
    assert(report.first_eip == report.entry_eip);
    assert(report.last_eip == report.boundary_thunk_va);
    assert(report.stop_address == report.boundary_thunk_va);
    assert(report.observed_syscall_id == SYSCALL_ID);
    /* mov, mov, call: three real guest instructions, nothing else. */
    assert(report.retired == 3u);
    assert(report.translated_blocks == 1u);
    assert(report.host_calls == 0u);
    assert(report.cleanup_modules == 2u);
    assert(report.cleanup_translations == 1u);

    /* A wrong entry symbol is refused rather than silently accepted. */
    config.entry_symbol = "NotExported";
    memset(&report, 0, sizeof(report));
    assert(pw_wine_gate_run(&config, &report) != PW_OK);
    assert(!pw_wine_stop_is_acceptance(report.stop));

    /* A backend whose PE32 images cannot be reached by the guest is refused
     * by the mapper rather than executed at a truncated address. */
    config.entry_symbol = "NtClose";
    config.provider = NULL;
    assert(pw_wine_gate_run(&config, &report) == PW_ERR_PRECONDITION);
    return 0;
}
