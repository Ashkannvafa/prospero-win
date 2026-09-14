/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * NtContinue: the call that installs a thread's own context, which is how a
 * Wine thread starts and how a program's clean exit arrives.
 *
 * The kernel builds a register context for the first thread and ntdll's
 * initialization entry hands it to loader_init and then to
 * signal_start_thread, which enters the thread through NtContinue
 * (dlls/ntdll/unix/signal_i386.c:2455-2545). The same call is what a
 * program's exit goes through: the application's entry point returns, kernel32
 * hands the value to RtlExitUserThread, and that calls
 * NtTerminateThread( GetCurrentThread(), status ) and never returns
 * (dlls/ntdll/thread.c:764). Both halves are driven here from the guest.
 *
 * What the guest learns travels out through the transcript, never from this
 * file's opinion: the resumed code reads the stack pointer and the accumulator
 * the context named and hands them, with the two refused contexts' statuses,
 * to a call this run does not serve, so the recorded arguments are the values
 * the guest actually had.
 */
#include "pe_fixture.h"

#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"
#include "../src/pw_wine_runner.h"
#include "../src/pw_wine_thread.h"

#include <assert.h>
#include <string.h>

/* The run's own workspace; two of these are independent. */
static PwWineRunner test_runner;

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,                    /* __wine_syscall_dispatcher */
    STATUS_RVA = DATA_RVA + 0x20,           /* four status slots */
    RAN_RVA = DATA_RVA + 0x40,              /* written only if the state was
                                             * not installed */
    CONTEXT_GOOD_RVA = DATA_RVA + 0x100,
    CONTEXT_BAD_FLAGS_RVA = DATA_RVA + 0x400,
    CONTEXT_BAD_SEGMENT_RVA = DATA_RVA + 0x700,
    CONTEXT_STACK_RVA = DATA_RVA + 0xA00,   /* what the good context's Esp
                                             * points at */
    CONTINUE_CALLER_RVA = TEXT_RVA,
    RESUME_RVA = TEXT_RVA + 0x400,
    THUNK_RVA = TEXT_RVA + 0x600,
    STUB_CONTINUE_RVA = TEXT_RVA + 0x610,   /* NtContinue, 0x43 */
    STUB_SETINFO_RVA = TEXT_RVA + 0x620,    /* NtSetInformationThread: none */
    STUB_EXIT_RVA = TEXT_RVA + 0x630,       /* NtTerminateThread, 0x53 */
    CALLER_RVA = CONTINUE_CALLER_RVA,
};

enum {
    /* The three groups the kernel's own context asks for; the initial set
     * also carries the floating-point and extended groups. */
    CONTEXT_FLAGS_FULL = 0x00010007u,
    USER_CS = 0x1bu,
    USER_SS = 0x23u,
    CONTEXT_EFLAGS = 0x246u,
    /* What the good context must come back with. */
    CONTEXT_EAX = 0x5a5a0001u,
    CONTEXT_STACK_VALUE = 0xcafebabeu,
    NEVER_RAN = 0xdead0000u,
    /* NtSetInformationThread, the call this run does not serve: the carrier. */
    SET_INFORMATION_THREAD = 0x000du,
    /* The exit status the guest names when it ends its own thread. */
    EXIT_STATUS = 0x1234u,
    NtCurrentThread = 0xfffffffeu,
    NOT_A_THREAD = 0x12345678u,
};

static uint8_t image[64 * 1024];
static uint8_t text[2048];
static uint32_t text_bytes;
static uint8_t data[0x1000];
static PeFixtureReloc relocs[256];
static uint32_t reloc_count;
static PwFileSpan span;
/* Where the second entry point's code ended up: the first caller's length is
 * not a constant, so the export table records what the emitter actually
 * produced instead of an offset this file hopes it kept to. */
static uint32_t exit_caller_rva;

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

/* mov eax, <the virtual address of this rva> */
static void emit_mov_eax_rva(uint32_t rva)
{
    emit_byte(0xb8);
    emit_absolute(rva);
}

/* mov dword [abs], imm32 */
static void emit_store_imm32(uint32_t rva, uint32_t value)
{
    emit_byte(0xc7); emit_byte(0x05);
    emit_absolute(rva);
    emit_u32(value);
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

/* NtContinue(<context>, <test_alert>): what the kernel's own thread start and
 * RtlExitUserThread's neighbours call. */
static void emit_continue(uint32_t context_rva, uint32_t status_rva)
{
    emit_push_imm32(1u);
    emit_push_absolute(context_rva);
    emit_call(STUB_CONTINUE_RVA);
    emit_store_eax(status_rva);
}

/* One context in the guest's own data section: the flags and segments it is
 * validated by, the state it must come back with and where it resumes. Esp is
 * left to the caller, because the stack pointer a thread resumes on is its own
 * stack and the guard says so: a push below a pointer into the data section is
 * refused exactly like any other access outside the stack. */
static void emit_context(uint32_t context_rva, uint32_t flags, uint32_t cs,
                         uint32_t ss, uint32_t eax)
{
    emit_store_imm32(context_rva + PW_WINE_CONTEXT_OFFSET_FLAGS, flags);
    emit_store_imm32(context_rva + PW_WINE_CONTEXT_OFFSET_SEG_CS, cs);
    emit_store_imm32(context_rva + PW_WINE_CONTEXT_OFFSET_SEG_SS, ss);
    emit_store_imm32(context_rva + PW_WINE_CONTEXT_OFFSET_EFLAGS,
                     CONTEXT_EFLAGS);
    emit_store_imm32(context_rva + PW_WINE_CONTEXT_OFFSET_EAX, eax);
    emit_mov_eax_rva(RESUME_RVA);
    emit_store_eax(context_rva + PW_WINE_CONTEXT_OFFSET_EIP);
}

/* The stack the resumed code runs on, one frame's worth below the caller's own
 * frame, with the value the resumed code must find there: "mov eax, esp", then
 * the store, then the context's Esp field. */
static void emit_context_stack(uint32_t context_rva)
{
    emit_byte(0x89); emit_byte(0xe0);              /* mov eax, esp */
    emit_byte(0x2d); emit_u32(0x80u);              /* sub eax, 0x80 */
    emit_byte(0xc7); emit_byte(0x00);              /* mov dword [eax], imm32 */
    emit_u32(CONTEXT_STACK_VALUE);
    emit_store_eax(context_rva + PW_WINE_CONTEXT_OFFSET_ESP);
}

/* The code the good context resumes at. It reads the dword the context's Esp
 * names and then hands the context's accumulator and that dword, together with
 * the two refusal statuses, to a call this run does not serve - so the
 * recorded arguments are the state the guest was actually left in. */
static void emit_resume(void)
{
    while (text_bytes < RESUME_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0x8b); emit_byte(0x14); emit_byte(0x24);   /* mov edx, [esp] */
    emit_byte(0x89); emit_byte(0xc1);                    /* mov ecx, eax: the
                                                          * context's own
                                                          * accumulator, kept
                                                          * before the status
                                                          * loads overwrite it */
    emit_load_eax(STATUS_RVA + 4u);
    emit_byte(0x50);                                     /* push eax: status 2 */
    emit_load_eax(STATUS_RVA + 0u);
    emit_byte(0x50);                                     /* push eax: status 1 */
    emit_byte(0x52);                                     /* push edx: [esp] */
    emit_byte(0x51);                                     /* push ecx: the
                                                          * context's Eax */
    emit_call(STUB_SETINFO_RVA);
    emit_store_eax(STATUS_RVA + 8u);
}

/* The first caller: two contexts this run must refuse, then one it must
 * install. The store after the third call is never executed when the state was
 * installed, which is what distinguishes "resumed where the context said" from
 * "returned from the stub". */
static void emit_continue_caller(void)
{
    emit_context(CONTEXT_BAD_FLAGS_RVA, 0x00000001u, USER_CS, USER_SS, 0u);
    emit_context(CONTEXT_BAD_SEGMENT_RVA, CONTEXT_FLAGS_FULL, 0u, USER_SS, 0u);
    emit_context(CONTEXT_GOOD_RVA, CONTEXT_FLAGS_FULL, USER_CS, USER_SS,
                 CONTEXT_EAX);
    emit_context_stack(CONTEXT_GOOD_RVA);

    emit_continue(CONTEXT_BAD_FLAGS_RVA, STATUS_RVA + 0u);
    emit_continue(CONTEXT_BAD_SEGMENT_RVA, STATUS_RVA + 4u);
    emit_continue(CONTEXT_GOOD_RVA, STATUS_RVA + 12u);
    /*
     * Only reached if NtContinue synthesized the stub's own return over the
     * state it was handed: the test asserts this slot is still zero.
     */
    emit_store_imm32(RAN_RVA, NEVER_RAN);
}

/* The second caller: the handle check of NtTerminateThread, then the call that
 * ends the process with the status the guest names. */
static void emit_exit_caller(void)
{
    exit_caller_rva = TEXT_RVA + text_bytes;
    emit_push_imm32(EXIT_STATUS);
    emit_push_imm32(NOT_A_THREAD);
    emit_call(STUB_EXIT_RVA);
    emit_store_eax(STATUS_RVA + 0u);
    emit_push_imm32(EXIT_STATUS);
    emit_push_imm32(NtCurrentThread);
    emit_call(STUB_EXIT_RVA);
    emit_store_eax(STATUS_RVA + 4u);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));

    emit_continue_caller();
    emit_exit_caller();
    emit_resume();
    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_CONTINUE_RVA, 0x0043u, 8u);          /* NtContinue */
    emit_stub(STUB_SETINFO_RVA, SET_INFORMATION_THREAD, 16u);
    emit_stub(STUB_EXIT_RVA, 0x0053u, 8u);              /* NtTerminateThread */
    emit_byte(0xc3);

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
    spec.export_count = 3u;
    spec.exports[0].name = "__wine_syscall_dispatcher";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = SLOT_RVA;
    spec.exports[1].name = "TestEntry";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = CONTINUE_CALLER_RVA;
    spec.exports[2].name = "TestEntryExit";
    spec.exports[2].ordinal = 3u;
    spec.exports[2].rva = exit_caller_rva;
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

    /* The first run: two refused contexts, one installed, and the state it
     * installed carried out through a call this run does not serve. */
    (void)pw_wine_gate_run(&config, &report);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(report.context_restores == 1u);
    assert(report.context_restore_refusals == 2u);
    /* Nothing ended the process: the run stopped on a call with no handler. */
    assert(report.exit_call_id == 0u && report.exit_status == 0u);
    assert(report.calls.records == 4u);
    assert(report.calls.handled == 3u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);

    /* The two contexts this run cannot run in, each refused at the field it
     * failed on, and the one it installed. */
    assert(report.calls.sequence[0].id == 0x0043u);
    assert(report.calls.sequence[0].status == PW_NT_INVALID_PARAMETER);
    assert(report.calls.sequence[1].id == 0x0043u);
    assert(report.calls.sequence[1].status == PW_NT_INVALID_PARAMETER);
    assert(report.calls.sequence[2].id == 0x0043u);
    assert(report.calls.sequence[2].status == PW_NT_SUCCESS);
    /* The carrier: NtSetInformationThread, with no handler, still read. */
    assert(report.calls.sequence[3].id == SET_INFORMATION_THREAD);
    assert(report.calls.sequence[3].status == PW_NT_NOT_IMPLEMENTED);

    /*
     * The transcript: the carrier's arguments are the state the installed
     * context left the guest in. The accumulator is the context's own, the
     * stack argument is the dword at the address the context named as Esp -
     * so both were installed - and the last two are the statuses the two
     * refused contexts answered with.
     */
    assert(report.stop_call_args[0] == CONTEXT_EAX);
    assert(report.stop_call_args[1] == CONTEXT_STACK_VALUE);
    assert(report.stop_call_args[2] == PW_NT_INVALID_PARAMETER);
    assert(report.stop_call_args[3] == PW_NT_INVALID_PARAMETER);
    /* The store after the installed call never ran: the run resumed where the
     * context said instead of returning from the stub. */
    {
        const uint32_t ran = 0u;

        memcpy((void *)&ran, data + (RAN_RVA - DATA_RVA), 4u);
        assert(ran == 0u);
    }
    /* The gate built the first thread's context itself, with the root image's
     * transfer address as the routine this fixture does not export a thread
     * entry for. */
    assert(report.main_entry_eip == report.modules[0].base + CALLER_RVA);

    /* The second run: NtTerminateThread refuses a handle this run never handed
     * out, and the current thread's own termination ends the process with the
     * status the guest named. */
    pw_wine_runner_init(&test_runner);
    memset(&config, 0, sizeof(config));
    config.runner = &test_runner;
    config.provider = &provider;
    config.backend = &vm;
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntryExit";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;
    (void)pw_wine_gate_run(&config, &report);
    assert(report.stop == PW_WINE_STOP_PROCESS_TERMINATED);
    assert(report.exit_call_id == 0x0053u);
    assert(report.exit_status == EXIT_STATUS);
    assert(report.calls.records == 2u);
    assert(report.calls.sequence[0].id == 0x0053u);
    assert(report.calls.sequence[0].status == PW_NT_INVALID_HANDLE);
    assert(report.calls.sequence[0].args[0] == NOT_A_THREAD);
    assert(report.calls.sequence[1].id == 0x0053u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[1].args[0] == NtCurrentThread);
    assert(report.calls.sequence[1].args[1] == EXIT_STATUS);
    return 0;
}
