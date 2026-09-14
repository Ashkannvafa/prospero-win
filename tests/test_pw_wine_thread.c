/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The thread list the loader walks while it gives modules their TLS slots.
 *
 * alloc_tls_slot (dlls/ntdll/loader.c:1331) enumerates the process's threads
 * with NtGetNextThread and asks each one where its TEB is with
 * NtQueryInformationThread(ThreadBasicInformation), so this is the shape the
 * gate has to answer: the next thread of the list with a handle to it, the
 * end of the list as STATUS_NO_MORE_ENTRIES with a null handle, and a TEB
 * address that is the one the process actually runs on.
 *
 * Everything the guest learns here is carried out through the transcript, not
 * asserted from this file's opinion of what it should have been: the process
 * and thread ids and the TEB address the guest read out of its own answer
 * travel as the arguments of the refusals below, and the exit status is the
 * TEB address it read.
 */
#include "pe_fixture.h"

#include "../src/pw_guest_process.h"
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
    HANDLE_RVA = DATA_RVA + 0x020,          /* the handle NtGetNextThread wrote */
    HANDLE2_RVA = DATA_RVA + 0x028,         /* the second enumeration's handle */
    STATUS_RVA = DATA_RVA + 0x030,          /* six status slots */
    INFO_RVA = DATA_RVA + 0x060,            /* the 28-byte answer buffer */
    WRITTEN_RVA = DATA_RVA + 0x090,         /* its return length */
    LOADED_TEB_RVA = DATA_RVA + 0x0A0,      /* TebBaseAddress the guest read */
    LOADED_PID_RVA = DATA_RVA + 0x0B0,      /* ClientId.UniqueProcess */
    LOADED_TID_RVA = DATA_RVA + 0x0C0,      /* ClientId.UniqueThread */
    CARRY_RVA = DATA_RVA + 0x0D0,           /* what the carries returned */
    THUNK_RVA = TEXT_RVA + 0x200,
    STUB_NEXT_RVA = TEXT_RVA + 0x210,       /* NtGetNextThread, 0xa0 */
    STUB_QUERY_RVA = TEXT_RVA + 0x220,      /* NtQueryInformationThread, 0x25 */
    STUB_CLOSE_RVA = TEXT_RVA + 0x230,      /* NtClose, 0x0f */
    STUB_TERMINATE_RVA = TEXT_RVA + 0x240,  /* NtTerminateProcess, 0x2c */
    CALLER_RVA = TEXT_RVA,
    FIXTURE_ENTRY_RVA = CALLER_RVA,
};

enum {
    THREAD_BASIC_INFORMATION = 0u,
    INVALID_CLASS = 4u,
    THREAD_QUERY_LIMITED_INFORMATION = 0x0800u,
    THREAD_BASIC_BYTES = 28u,
};

_Static_assert(STATUS_RVA + 6u * 4u <= INFO_RVA,
               "the status slots overlap the answer buffer");
_Static_assert(INFO_RVA + THREAD_BASIC_BYTES <= WRITTEN_RVA,
               "the answer overlaps the return length");
_Static_assert(CARRY_RVA + 4u * 4u <= DATA_RVA + 0x200u,
               "the carry slots run past the data section");

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[0x200];
static PeFixtureReloc relocs[128];
static uint32_t reloc_count;
static PwFileSpan span;

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

static void emit_call(uint32_t rva)
{
    emit_byte(0xe8);
    emit_u32(rva - (TEXT_RVA + text_bytes + 4u));
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

/* NtGetNextThread(-1, [last], access, 0, 0, [out]) */
static void emit_next(uint32_t last_rva, uint32_t out_rva, uint32_t status_rva)
{
    emit_push_absolute(out_rva);
    emit_push_imm8(0u);
    emit_push_imm8(0u);
    emit_push_imm32(THREAD_QUERY_LIMITED_INFORMATION);
    if (last_rva != 0u) {
        emit_byte(0xff); emit_byte(0x35);
        emit_absolute(last_rva);            /* push dword [last] */
    } else {
        emit_push_imm8(0u);
    }
    emit_push_imm8(0xff);
    emit_call(STUB_NEXT_RVA);
    emit_store_eax(status_rva);
}

/* NtQueryInformationThread(<handle>, <class>, [INFO_RVA], size, NULL). Both the
 * handle and the class can come out of a slot instead of being constants, so a
 * value the guest read can travel in a call that is refused before it is
 * looked at. */
static void emit_query(uint32_t handle_rva, uint32_t class_value,
                       uint32_t class_rva, uint32_t status_rva)
{
    emit_push_imm32(0u);
    emit_push_imm32(THREAD_BASIC_BYTES);
    emit_push_absolute(INFO_RVA);
    if (class_rva != 0u) {
        emit_byte(0xff); emit_byte(0x35);
        emit_absolute(class_rva);
    } else {
        emit_push_imm8((uint8_t)class_value);
    }
    emit_load_eax(handle_rva);
    emit_byte(0x50);
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(status_rva);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));

    /* The thread the loader enumerates: a handle, then its TEB. */
    emit_next(0u, HANDLE_RVA, STATUS_RVA);
    emit_query(HANDLE_RVA, THREAD_BASIC_INFORMATION, 0u, STATUS_RVA + 4u);
    emit_load_eax(INFO_RVA + 4u);           /* TebBaseAddress */
    emit_store_eax(LOADED_TEB_RVA);
    emit_load_eax(INFO_RVA + 8u);           /* ClientId.UniqueProcess */
    emit_store_eax(LOADED_PID_RVA);
    emit_load_eax(INFO_RVA + 12u);          /* ClientId.UniqueThread */
    emit_store_eax(LOADED_TID_RVA);

    /* The end of the list: the same call with the handle it just returned. */
    emit_next(HANDLE_RVA, HANDLE2_RVA, STATUS_RVA + 8u);

    /*
     * The values the guest read, carried out as the arguments of refusals: the
     * process id as the handle of a question about a handle this run never
     * handed out, the thread id as the class of a question about one it did,
     * and the TEB address as the "last thread" of another enumeration.
     */
    emit_query(LOADED_PID_RVA, THREAD_BASIC_INFORMATION, 0u, STATUS_RVA + 12u);
    emit_query(HANDLE_RVA, 0u, LOADED_TID_RVA, STATUS_RVA + 16u);
    emit_next(LOADED_TEB_RVA, CARRY_RVA, STATUS_RVA + 20u);

    /* The handle the first call returned is closed by the guest, not by us. */
    emit_load_eax(HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);

    /* End the process, reporting the TEB address the guest read. */
    emit_load_eax(LOADED_TEB_RVA);
    emit_byte(0x50);
    emit_push_imm8(0xff);
    emit_call(STUB_TERMINATE_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_NEXT_RVA, 0x00a0u, 24u);
    emit_stub(STUB_QUERY_RVA, 0x0025u, 20u);
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);
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
    for (uint32_t index = 0u; index < reloc_count; ++index)
        spec.relocs[index] = relocs[index];
    return pe_fixture_build(image, sizeof(image), &spec);
}

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
    uint32_t expected_entry = 0u;

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
    expected_entry = report.modules[0].base + FIXTURE_ENTRY_RVA;

    /* The run ends because the guest ended its own process, with the TEB
     * address it read out of the thread information as its exit status. */
    assert(report.stop == PW_WINE_STOP_PROCESS_TERMINATED);
    assert(report.calls.records == 8u);
    assert(report.calls.handled == 8u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.calls.unimplemented == 0u);
    /* Both enumerations that reached the list: the first thread and the end of
     * it. The third call is refused at its handle, before the list is read. */
    assert(report.thread_enumerations == 2u);
    assert(report.thread_handles == 1u);
    /* One question reached ThreadBasicInformation; the other was refused at
     * the class, and the counter counts the answers of that class. */
    assert(report.thread_queries == 1u);
    assert(report.thread_refusals == 3u);

    /* The first enumeration returned the one thread this run models. */
    assert(report.calls.sequence[0].id == 0x00a0u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    /* The question the loader asks about it: ThreadBasicInformation. */
    assert(report.calls.sequence[1].id == 0x0025u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    /* The end of the list, with a null handle written back. */
    assert(report.calls.sequence[2].id == 0x00a0u);
    assert(report.calls.sequence[2].status == PW_NT_NO_MORE_ENTRIES);
    assert(report.calls.sequence[2].args[1] != 0u);
    /*
     * The carries. The process id the guest read travels as the handle of a
     * question about a handle this run never handed out; the thread id as the
     * class of a question about a handle it did; and the TEB address as the
     * "last thread" of another enumeration, which is not a handle either.
     */
    assert(report.calls.sequence[3].id == 0x0025u);
    assert(report.calls.sequence[3].status == PW_NT_INVALID_HANDLE);
    assert(report.calls.sequence[3].args[0] == PW_GUEST_PROCESS_ID);
    assert(report.calls.sequence[4].id == 0x0025u);
    assert(report.calls.sequence[4].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[4].args[1] == PW_GUEST_THREAD_ID);
    assert(report.calls.sequence[5].id == 0x00a0u);
    assert(report.calls.sequence[5].status == PW_NT_INVALID_HANDLE);
    assert(report.calls.sequence[5].args[1] == report.teb_base);
    /* The handle the guest closed, and then its own process. */
    assert(report.calls.sequence[6].id == 0x000fu);
    assert(report.calls.sequence[6].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[7].id == 0x002cu);
    assert(report.calls.sequence[7].args[1] == report.teb_base);
    assert(report.file_handles == 0u);
    /* The entry point the fixture relocated into its own image, which is what
     * the first enumeration was about: the loader asks about the thread it is
     * running on, and this run is running on the one it published. */
    assert(report.calls.sequence[0].return_pc >= expected_entry);
    return 0;
}
