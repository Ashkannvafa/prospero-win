/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the object-namespace side of the Unix-call bridge.
 *
 * One synthetic module plays the part of a Wine loader: it opens the
 * \KnownDlls directory the loader opens once at startup, looks for a section
 * in it the way open_known_dll does (absolute and relative to that handle),
 * and is refused a traversal and a name outside the namespace. The service is
 * an in-memory profile that declares exactly one directory, so the loader's
 * fall-back path is what the test proves: a name the profile does not have is
 * a real NTSTATUS, not a silence.
 */
#include "pe_fixture.h"
#include "pw_unhandled_call.h"

#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"
#include "../src/pw_wine_runner.h"

#include <assert.h>
#include <string.h>

/* The run's own workspace; two of these are independent. */
static PwWineRunner test_runner;

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,                    /* __wine_syscall_dispatcher */
    KNOWN_TEXT_RVA = DATA_RVA + 0x040,      /* "\KnownDlls" */
    KNOWN_RVA = DATA_RVA + 0x080,           /* its UNICODE_STRING */
    KNOWN_ATTRS_RVA = DATA_RVA + 0x090,
    KNOWN_HANDLE_RVA = DATA_RVA + 0x0B0,
    SECTION_TEXT_RVA = DATA_RVA + 0x0C0,    /* "\KnownDlls\kernel32.dll" */
    SECTION_RVA = DATA_RVA + 0x100,
    SECTION_ATTRS_RVA = DATA_RVA + 0x110,
    SECTION_HANDLE_RVA = DATA_RVA + 0x130,
    RELATIVE_TEXT_RVA = DATA_RVA + 0x140,   /* "ntdll.dll" */
    RELATIVE_RVA = DATA_RVA + 0x160,
    RELATIVE_ATTRS_RVA = DATA_RVA + 0x170,  /* RootDirectory set at run time */
    RELATIVE_HANDLE_RVA = DATA_RVA + 0x190,
    TRAVERSAL_TEXT_RVA = DATA_RVA + 0x1A0,  /* "\KnownDlls\..\x" */
    TRAVERSAL_RVA = DATA_RVA + 0x1C0,
    TRAVERSAL_ATTRS_RVA = DATA_RVA + 0x1D0,
    TRAVERSAL_HANDLE_RVA = DATA_RVA + 0x1F0,
    PLAIN_TEXT_RVA = DATA_RVA + 0x200,      /* "no-leading-separator" */
    PLAIN_RVA = DATA_RVA + 0x240,
    PLAIN_ATTRS_RVA = DATA_RVA + 0x250,
    PLAIN_HANDLE_RVA = DATA_RVA + 0x270,
    STATUS_RVA = DATA_RVA + 0x280,          /* five status slots */
    HANDLE_COPY_RVA = DATA_RVA + 0x2A0,
    STOP_RESULT_RVA = DATA_RVA + 0x2B0,
    THUNK_RVA = TEXT_RVA + 0x200,
    STUB_DIRECTORY_RVA = TEXT_RVA + 0x210,  /* NtOpenDirectoryObject, 0x58 */
    STUB_SECTION_RVA = TEXT_RVA + 0x220,    /* NtOpenSection, 0x37 */
    STUB_CLOSE_RVA = TEXT_RVA + 0x230,      /* NtClose, 0x0f */
    STUB_STOP_RVA = TEXT_RVA + 0x240,       /* NtQueryInformationProcess, 0x19 */
    CALLER_RVA = TEXT_RVA,
};

/*
 * The hand-written data layout is checked region by region, so a string that
 * grows into a header or a slot that moves inside a string is a compile error.
 */
_Static_assert(KNOWN_TEXT_RVA + 22u <= KNOWN_RVA,
               "KnownDlls text overlaps its UNICODE_STRING");
_Static_assert(KNOWN_RVA + 32u <= KNOWN_HANDLE_RVA,
               "KnownDlls header overlaps its handle slot");
_Static_assert(SECTION_TEXT_RVA + 46u <= SECTION_RVA,
               "section text overlaps its UNICODE_STRING");
_Static_assert(SECTION_RVA + 32u <= SECTION_HANDLE_RVA,
               "section header overlaps its handle slot");
_Static_assert(RELATIVE_TEXT_RVA + 22u <= RELATIVE_RVA,
               "relative text overlaps its UNICODE_STRING");
_Static_assert(RELATIVE_RVA + 32u <= RELATIVE_HANDLE_RVA,
               "relative header overlaps its handle slot");
_Static_assert(TRAVERSAL_TEXT_RVA + 32u <= TRAVERSAL_RVA,
               "traversal text overlaps its UNICODE_STRING");
_Static_assert(TRAVERSAL_RVA + 32u <= TRAVERSAL_HANDLE_RVA,
               "traversal header overlaps its handle slot");
_Static_assert(PLAIN_TEXT_RVA + 44u <= PLAIN_RVA,
               "plain text overlaps its UNICODE_STRING");
_Static_assert(PLAIN_RVA + 32u <= PLAIN_HANDLE_RVA,
               "plain header overlaps its handle slot");
_Static_assert(PLAIN_HANDLE_RVA + 16u <= STATUS_RVA,
               "plain handle overlaps the status slots");
_Static_assert(STATUS_RVA + 20u <= HANDLE_COPY_RVA,
               "status slots overlap the handle copy");
_Static_assert(HANDLE_COPY_RVA + 16u <= STOP_RESULT_RVA,
               "handle copy overlaps the stop result");

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[0x400];
static PeFixtureReloc relocs[64];
static uint32_t reloc_count;

static void emit_byte(uint8_t value)
{
    assert(text_bytes < sizeof(text));
    text[text_bytes++] = value;
}

static void emit_u32(uint32_t value)
{
    emit_byte((uint8_t)(value & 0xffu));
    emit_byte((uint8_t)((value >> 8) & 0xffu));
    emit_byte((uint8_t)((value >> 16) & 0xffu));
    emit_byte((uint8_t)((value >> 24) & 0xffu));
}

static void emit_absolute(uint32_t rva)
{
    assert(reloc_count < sizeof(relocs) / sizeof(relocs[0]));
    relocs[reloc_count].rva = TEXT_RVA + text_bytes;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    emit_u32(IMAGE_BASE + rva);
}

static void emit_data_reloc(uint32_t rva)
{
    assert(reloc_count < sizeof(relocs) / sizeof(relocs[0]));
    relocs[reloc_count].rva = rva;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
}

static void emit_push_absolute(uint32_t rva)
{
    emit_byte(0x68);
    emit_absolute(rva);
}

static void emit_push_imm8(uint8_t value)
{
    emit_byte(0x6a);
    emit_byte(value);
}

static void emit_push_imm32(uint32_t value)
{
    emit_byte(0x68);
    emit_u32(value);
}

static void emit_call(uint32_t target_rva)
{
    const uint32_t next = TEXT_RVA + text_bytes + 5u;

    emit_byte(0xe8);
    emit_u32(target_rva - next);
}

static void emit_load_eax(uint32_t rva)
{
    emit_byte(0xa1);
    emit_absolute(rva);
}

static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

static void emit_stub(uint32_t index, uint32_t id, uint16_t arg_bytes)
{
    while (text_bytes < (uint32_t)index - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xb8);
    emit_u32(id);
    emit_byte(0xba);
    emit_absolute(THUNK_RVA);
    emit_byte(0xff); emit_byte(0xd2);
    emit_byte(0xc2);
    emit_byte((uint8_t)(arg_bytes & 0xffu));
    emit_byte((uint8_t)((arg_bytes >> 8) & 0xffu));
    emit_byte(0x90);
}

static void put_unicode_string(uint32_t header, uint32_t text_offset,
                               const char *text_ascii)
{
    const uint16_t length = (uint16_t)(strlen(text_ascii) * 2u);
    const uint32_t buffer = IMAGE_BASE + text_offset;
    uint32_t index = 0u;

    header -= DATA_RVA;
    text_offset -= DATA_RVA;
    while (text_ascii[index] != '\0') {
        data[text_offset + index * 2u] = (uint8_t)text_ascii[index];
        data[text_offset + index * 2u + 1u] = 0u;
        ++index;
    }
    data[text_offset + index * 2u] = 0u;
    data[text_offset + index * 2u + 1u] = 0u;
    memcpy(data + header, &length, 2u);
    memcpy(data + header + 2u, &length, 2u);
    memcpy(data + header + 4u, &buffer, 4u);
}

static void put_attributes(uint32_t attributes, uint32_t name_header)
{
    const uint32_t length = 24u;
    const uint32_t name_pointer = IMAGE_BASE + name_header;

    memcpy(data + (attributes - DATA_RVA), &length, 4u);
    memcpy(data + (attributes - DATA_RVA) + 8u, &name_pointer, 4u);
}

/* NtOpenDirectoryObject / NtOpenSection(&handle, access, &attributes) */
static void emit_open_object(uint32_t stub_rva, uint32_t attributes_rva,
                             uint32_t handle_rva, uint32_t status_rva)
{
    emit_push_absolute(attributes_rva);
    emit_push_imm32(0x000f000fu);
    emit_push_absolute(handle_rva);
    emit_call(stub_rva);
    emit_store_eax(status_rva);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));
    put_unicode_string(KNOWN_RVA, KNOWN_TEXT_RVA, "\\KnownDlls");
    put_unicode_string(SECTION_RVA, SECTION_TEXT_RVA,
                       "\\KnownDlls\\kernel32.dll");
    put_unicode_string(RELATIVE_RVA, RELATIVE_TEXT_RVA, "ntdll.dll");
    put_unicode_string(TRAVERSAL_RVA, TRAVERSAL_TEXT_RVA,
                       "\\KnownDlls\\..\\x");
    put_unicode_string(PLAIN_RVA, PLAIN_TEXT_RVA, "no-leading-separator");
    put_attributes(KNOWN_ATTRS_RVA, KNOWN_RVA);
    put_attributes(SECTION_ATTRS_RVA, SECTION_RVA);
    put_attributes(RELATIVE_ATTRS_RVA, RELATIVE_RVA);   /* RootDirectory set below */
    put_attributes(TRAVERSAL_ATTRS_RVA, TRAVERSAL_RVA);
    put_attributes(PLAIN_ATTRS_RVA, PLAIN_RVA);

    /* The directory the loader opens once, and the handle it keeps. */
    emit_open_object(STUB_DIRECTORY_RVA, KNOWN_ATTRS_RVA, KNOWN_HANDLE_RVA,
                     STATUS_RVA);
    emit_load_eax(KNOWN_HANDLE_RVA);
    emit_store_eax(HANDLE_COPY_RVA);
    /* A section by absolute name, and the same directory's own name. */
    emit_open_object(STUB_SECTION_RVA, SECTION_ATTRS_RVA, SECTION_HANDLE_RVA,
                     STATUS_RVA + 4u);
    /* open_known_dll's shape: the directory handle plus the DLL name. */
    emit_load_eax(KNOWN_HANDLE_RVA);
    emit_store_eax(RELATIVE_ATTRS_RVA + 4u);            /* RootDirectory */
    emit_open_object(STUB_SECTION_RVA, RELATIVE_ATTRS_RVA, RELATIVE_HANDLE_RVA,
                     STATUS_RVA + 8u);
    /* A traversal, and a name that is not absolute at all. */
    emit_open_object(STUB_DIRECTORY_RVA, TRAVERSAL_ATTRS_RVA,
                     TRAVERSAL_HANDLE_RVA, STATUS_RVA + 12u);
    emit_open_object(STUB_DIRECTORY_RVA, PLAIN_ATTRS_RVA, PLAIN_HANDLE_RVA,
                     STATUS_RVA + 16u);
    /* The directory handle is closed again. */
    emit_load_eax(KNOWN_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);

    /*
     * A call with no handler stops the run, and its arguments are the values
     * the guest loaded out of its own memory: the handle the gate wrote back
     * for the directory, and the status the section lookup produced.
     */
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_load_eax(STATUS_RVA + 4u);
    emit_byte(0x50);
    emit_load_eax(HANDLE_COPY_RVA);
    emit_byte(0x50);
    emit_call(STUB_STOP_RVA);
    emit_store_eax(STOP_RESULT_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_DIRECTORY_RVA, 0x0058u, 12u);
    emit_stub(STUB_SECTION_RVA, 0x0037u, 12u);
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);
    /* A call this bridge has no handler for. */
    emit_stub(STUB_STOP_RVA, PW_TEST_UNHANDLED_CALL_ID,
              PW_TEST_UNHANDLED_CALL_ARGS);
    emit_byte(0xc3);

    emit_data_reloc(KNOWN_RVA + 4u);
    emit_data_reloc(KNOWN_ATTRS_RVA + 8u);
    emit_data_reloc(SECTION_RVA + 4u);
    emit_data_reloc(SECTION_ATTRS_RVA + 8u);
    emit_data_reloc(RELATIVE_RVA + 4u);
    emit_data_reloc(RELATIVE_ATTRS_RVA + 8u);
    emit_data_reloc(TRAVERSAL_RVA + 4u);
    emit_data_reloc(TRAVERSAL_ATTRS_RVA + 8u);
    emit_data_reloc(PLAIN_RVA + 4u);
    emit_data_reloc(PLAIN_ATTRS_RVA + 8u);

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = IMAGE_BASE;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = CALLER_RVA;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = text;
    spec.sections[0].data_bytes = text_bytes;
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
    spec.exports[0].rva = SLOT_RVA;
    spec.exports[1].name = "TestEntry";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = CALLER_RVA;
    spec.reloc_count = reloc_count;
    for (uint32_t index = 0; index < reloc_count; ++index)
        spec.relocs[index] = relocs[index];
    return pe_fixture_build(image, sizeof(image), &spec);
}

/*
 * The profile this test supplies: one directory object, and no sections in
 * it. Every section lookup therefore answers NOT_FOUND, which is the fall-back
 * path a loader takes when a DLL is not a known DLL.
 */
static uint32_t fake_opens;
static uint32_t fake_closes;
static char fake_paths[8][PW_WINE_GATE_MAX_PATH + 1];
static PwWineObjectKind fake_kinds[8];

static PwWineObjectStatus fake_object_open(void *context, PwWineObjectKind kind,
                                           const char *path, void **token)
{
    (void)context;
    if (fake_opens < sizeof(fake_paths) / sizeof(fake_paths[0])) {
        memcpy(fake_paths[fake_opens], path, strlen(path) + 1u);
        fake_kinds[fake_opens] = kind;
    }
    fake_opens++;
    if (kind == PW_WINE_OBJECT_DIRECTORY && strcmp(path, "\\knowndlls") == 0) {
        *token = (void *)(uintptr_t)path;
        return PW_WINE_OBJECT_OK;
    }
    return PW_WINE_OBJECT_NOT_FOUND;
}

static void fake_object_close(void *context, void *token)
{
    (void)context;
    (void)token;
    fake_closes++;
}

static PwFileSpan span;

static int fake_provider_open(void *context, const char *canonical_name,
                              PwFileSpan *out)
{
    (void)context;
    if (!pw_module_name_equal(canonical_name, "ntdll.dll"))
        return PW_ERR_NOT_FOUND;
    *out = span;
    return PW_OK;
}

static void fake_provider_close(void *context, PwFileSpan *closed)
{
    (void)context;
    (void)closed;
}

static int fake_provider_namespace(void *context, PwFileNamespace file_namespace,
                                   const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_provider_open(context, canonical_name, out);
}

int main(void)
{
    const PwFileProvider provider = {
        .context = NULL, .open = fake_provider_open,
        .close = fake_provider_close, .open_namespace = fake_provider_namespace,
    };
    const PwWineObjectService objects = {
        .context = NULL, .open = fake_object_open, .close = fake_object_close,
    };
    PwWineGateConfig config;
    PwWineGateReport report;
    PwVmBackend vm;
    const char *modules[] = {"ntdll.dll"};
    const size_t size = build_module();

    assert(size != 0u);
    span.bytes = image;
    span.size = size;
    span.handle = NULL;
    memset(span.path, 0, sizeof(span.path));
    assert(pw_vm_posix_backend(&vm) == PW_OK);

    memset(&config, 0, sizeof(config));
    pw_wine_runner_init(&test_runner);
    config.runner = &test_runner;
    config.provider = &provider;
    config.backend = &vm;
    config.objects = &objects;
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    (void)pw_wine_gate_run(&config, &report);
    assert(report.objects_configured == 1u);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(report.observed_syscall_id == PW_TEST_UNHANDLED_CALL_ID);
    assert(report.calls.records == 7u);
    assert(report.calls.handled == 6u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);

    /* The directory the loader opens: one open, one handle, one path. */
    assert(report.calls.sequence[0].id == 0x0058u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    assert(report.object_opens == 1u);
    assert(strcmp(fake_paths[0], "\\knowndlls") == 0);
    assert(fake_kinds[0] == PW_WINE_OBJECT_DIRECTORY);

    /* A section lookup by absolute name, and one relative to that directory:
     * both answer NOT_FOUND, and both reached the service with a canonical
     * path - the relative one composed from the handle. */
    assert(report.calls.sequence[1].id == 0x0037u);
    assert(report.calls.sequence[1].status == PW_NT_OBJECT_NAME_NOT_FOUND);
    assert(report.calls.sequence[2].status == PW_NT_OBJECT_NAME_NOT_FOUND);
    assert(strcmp(fake_paths[1], "\\knowndlls\\kernel32.dll") == 0);
    assert(strcmp(fake_paths[2], "\\knowndlls\\ntdll.dll") == 0);
    assert(fake_kinds[1] == PW_WINE_OBJECT_SECTION &&
           fake_kinds[2] == PW_WINE_OBJECT_SECTION);

    /* A traversal and a name that is not absolute: refused by the gate, so the
     * service never sees them. */
    assert(report.calls.sequence[3].status == PW_NT_OBJECT_NAME_INVALID);
    assert(report.calls.sequence[4].status == PW_NT_OBJECT_NAME_INVALID);
    assert(strcmp(report.last_object, "no-leading-separator") == 0);
    assert(report.object_refusals == 4u);
    assert(fake_opens == 3u);

    /* The directory handle the guest closed is the one it was given. */
    assert(report.calls.sequence[5].id == 0x000fu);
    assert(report.calls.sequence[5].status == PW_NT_SUCCESS);
    assert(fake_closes == 1u);

    /*
     * The stop call's arguments are the handle the gate wrote back (a
     * gate-owned index, so never zero) and the status the section lookup
     * produced, both loaded from the guest's own memory.
     */
    assert(report.calls.sequence[6].id == PW_TEST_UNHANDLED_CALL_ID);
    assert(report.calls.sequence[6].outcome == PW_UNIX_CALL_UNIMPLEMENTED);
    assert(report.calls.sequence[6].args[0] == 0x100u);
    assert(report.calls.sequence[6].args[1] == PW_NT_OBJECT_NAME_NOT_FOUND);
    return 0;
}
