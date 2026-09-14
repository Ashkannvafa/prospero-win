/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the process-information side of the Unix-call
 * bridge.
 *
 * One synthetic module plays the part of a Wine loader: it asks
 * NtQueryInformationProcess for ProcessImageInformation - which is what
 * build_main_module does before it decides whether the module the process was
 * handed is an executable - and then ends its own process with
 * NtTerminateProcess, passing what it read back as the exit status. The
 * assertions are about the values the guest itself loaded out of its own
 * memory, so they can only be right if the answer the gate wrote really is
 * the image's own PE header data.
 */
#include "pe_fixture.h"

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
    INFO_RVA = DATA_RVA + 0x040,            /* 48-byte SECTION_IMAGE_INFORMATION */
    INFO_RET_RVA = DATA_RVA + 0x080,
    TRANSFER_COPY_RVA = DATA_RVA + 0x090,
    CHARACTERISTICS_COPY_RVA = DATA_RVA + 0x0A0,
    STATUS_RVA = DATA_RVA + 0x0B0,          /* four status slots */
    THUNK_RVA = TEXT_RVA + 0x200,
    STUB_QUERY_RVA = TEXT_RVA + 0x210,      /* NtQueryInformationProcess, 0x19 */
    STUB_TERMINATE_RVA = TEXT_RVA + 0x220,  /* NtTerminateProcess, 0x2c */
    CALLER_RVA = TEXT_RVA,
    /* The fixture's own entry point, which is what the gate must report. */
    FIXTURE_ENTRY_RVA = CALLER_RVA,
};

_Static_assert(INFO_RVA + 48u <= INFO_RET_RVA,
               "image information overlaps its result slot");
_Static_assert(INFO_RET_RVA + 16u <= TRANSFER_COPY_RVA,
               "result slot overlaps the transfer copy");
_Static_assert(STATUS_RVA + 16u <= DATA_RVA + 0x400u,
               "status slots run past the data section");

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[0x400];
static PeFixtureReloc relocs[32];
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

/* "movzx eax, word ptr [disp32]" */
static void emit_load_u16(uint32_t rva)
{
    emit_byte(0x0f);
    emit_byte(0xb7);
    emit_byte(0x05);
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

/* NtQueryInformationProcess(-1, class, buffer, length, &result) */
static void emit_query(uint32_t information_class, uint32_t length,
                       uint32_t buffer_rva, uint32_t status_rva)
{
    emit_push_absolute(INFO_RET_RVA);
    emit_push_imm32(length);
    emit_push_absolute(buffer_rva);
    emit_push_imm8((uint8_t)information_class);
    emit_push_imm8(0xff);
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(status_rva);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));

    /* The image information the loader asks about the process image. */
    emit_query(0x25u, 0x30u, INFO_RVA, STATUS_RVA);
    /* Read the transfer address and the characteristics back, so the calls
     * below carry values the guest loaded out of its own buffer. */
    emit_load_eax(INFO_RVA);
    emit_store_eax(TRANSFER_COPY_RVA);
    emit_load_u16(INFO_RVA + 28u);
    emit_store_eax(CHARACTERISTICS_COPY_RVA);
    /* A buffer that cannot hold the answer: a real length mismatch. */
    emit_query(0x25u, 0x20u, INFO_RVA, STATUS_RVA + 4u);
    /* A class with no meaning here, and a handle that is not this process.
     * The class is refused before the buffer is looked at, so the transfer
     * address the guest read back can travel as that argument. */
    emit_push_absolute(INFO_RET_RVA);
    emit_push_imm32(0x30u);
    emit_load_eax(TRANSFER_COPY_RVA);
    emit_byte(0x50);
    emit_push_imm8(0x00);
    emit_push_imm8(0xff);
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(STATUS_RVA + 8u);
    emit_push_absolute(INFO_RET_RVA);
    emit_push_imm32(0x30u);
    emit_push_absolute(INFO_RVA);
    emit_push_imm8(0x25);
    emit_push_imm32(0x00001234u);
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(STATUS_RVA + 12u);
    /* Now end the process, reporting the image characteristics as the exit
     * status: ntdll's own loader does this when the image is not an
     * executable, and the gate stops because there is nothing left to run. */
    emit_load_eax(CHARACTERISTICS_COPY_RVA);
    emit_byte(0x50);
    emit_push_imm8(0xff);
    emit_call(STUB_TERMINATE_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_QUERY_RVA, 0x0019u, 20u);
    emit_stub(STUB_TERMINATE_RVA, 0x002cu, 8u);
    emit_byte(0xc3);

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = IMAGE_BASE;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = FIXTURE_ENTRY_RVA;
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
    PwWineGateConfig config;
    PwWineGateReport report;
    PwVmBackend vm;
    const char *modules[] = {"ntdll.dll"};
    const size_t size = build_module();
    /* The gate reports the transfer address at the address the module was
     * actually loaded at, which is not its preferred base. */
    uint32_t expected_transfer = 0u;
    /* IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL
     * is what the fixture's own header carries. */
    const uint16_t expected_characteristics = 0x2102u;

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
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    (void)pw_wine_gate_run(&config, &report);
    expected_transfer = report.modules[0].base + FIXTURE_ENTRY_RVA;
    /*
     * The run ends because the guest ended its own process, and the gate
     * reports exactly that rather than a broken stop.
     */
    assert(report.stop == PW_WINE_STOP_PROCESS_TERMINATED);
    assert(strcmp(pw_wine_stop_name(report.stop), "process-terminated") == 0);
    assert(report.calls.records == 5u);
    assert(report.calls.handled == 5u);
    assert(report.calls.unimplemented == 0u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);

    /* The image information: served, and the gate recorded what it described. */
    assert(report.calls.sequence[0].id == 0x0019u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    /* Two of the four queries name the class this bridge answers; the other
     * two are refused before the query is counted. */
    assert(report.process_queries == 2u);
    assert(report.process_image_characteristics == expected_characteristics);

    /* A buffer that cannot hold the answer, a class with no meaning here and a
     * handle that is not this process. */
    assert(report.calls.sequence[1].status == PW_NT_INFO_LENGTH_MISMATCH);
    assert(report.calls.sequence[2].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[3].status == PW_NT_INVALID_HANDLE);

    /*
     * The class-refused call carries the transfer address the guest read out
     * of the buffer the gate wrote, and the terminating call carries the image
     * characteristics it read the same way: both can only be right if the
     * answer really landed in guest memory.
     */
    assert(report.calls.sequence[2].args[2] == expected_transfer);
    assert(report.calls.sequence[4].id == 0x002cu);
    assert(report.calls.sequence[4].args[0] == 0xffffffffu);
    assert(report.calls.sequence[4].args[1] == expected_characteristics);
    assert(report.calls.sequence[4].status == PW_NT_SUCCESS);
    return 0;
}
