/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the Unix-call bridge.
 *
 * The real evidence needs the staged Wine runtime. This test builds one
 * synthetic module shaped like Wine's ntdll: a caller that pushes a stdcall
 * frame and calls a syscall stub, stubs that load a call number and reach the
 * dispatcher through the single "jmp dword ptr [slot]" thunk, and a data
 * export for the dispatcher slot. Running the gate over it proves, without
 * any third-party binary, that:
 *
 *   - the first call is serviced (NtAllocateVirtualMemory), the guest memory
 *     it asks for becomes addressable and the base/size are written back;
 *   - the guest resumes in the caller with the NTSTATUS in EAX, which is only
 *     true if the two-level frame was unwound correctly;
 *   - the second, unimplemented call is named exactly and stops the run;
 *   - the allocation this run made is released at cleanup.
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
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,            /* __wine_syscall_dispatcher */
    BASE_SLOT_RVA = DATA_RVA + 4,   /* *BaseAddress for the first call */
    SIZE_SLOT_RVA = DATA_RVA + 8,   /* *RegionSize, pre-set below */
    RESULT0_RVA = DATA_RVA + 12,    /* where the caller stores the status */
    RESULT1_RVA = DATA_RVA + 16,
    THUNK_RVA = TEXT_RVA + 0x40,
    STUB0_RVA = TEXT_RVA + 0x50,    /* NtAllocateVirtualMemory, 0x18 */
    STUB1_RVA = TEXT_RVA + 0x60,    /* NtQueryInformationProcess, 0x19 */
    CALLER_RVA = TEXT_RVA,
    ALLOCATION_SIZE = 0x4000,
};

static uint8_t image[64 * 1024];
static uint8_t text[256];
static uint32_t text_bytes;
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

/* An absolute operand of the guest address `rva`, with its relocation. */
static void emit_absolute(uint32_t rva)
{
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

/* "mov [disp32], eax", the shape a caller uses to keep the NTSTATUS. */
static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

static void emit_stub(uint32_t id, uint16_t arg_bytes)
{
    emit_byte(0xb8);                 /* mov eax, id */
    emit_u32(id);
    emit_byte(0xba);                 /* mov edx, <thunk> */
    emit_absolute(THUNK_RVA);
    emit_byte(0xff); emit_byte(0xd2);/* call edx */
    emit_byte(0xc2);                 /* ret imm16 */
    emit_byte((uint8_t)(arg_bytes & 0xffu));
    emit_byte((uint8_t)((arg_bytes >> 8) & 0xffu));
    emit_byte(0x90);                 /* pad to a clean slot */
}

static size_t build_module(void)
{
    PeFixtureSpec spec;
    /* The guest pre-fills *RegionSize with the block it wants. */
    static const uint8_t data[32] = {
        0x00, 0x00, 0x00, 0x00,             /* dispatcher slot */
        0x00, 0x00, 0x00, 0x00,             /* *BaseAddress */
        0x00, 0x40, 0x00, 0x00,             /* *RegionSize = 0x4000 */
    };

    /* The caller: six stdcall arguments, then the stub, then the next call. */
    text_bytes = 0u;
    reloc_count = 0u;
    assert(CALLER_RVA == TEXT_RVA);
    emit_push_imm8(0x04);              /* Protect: PAGE_READWRITE */
    emit_push_imm32(0x2000u);          /* AllocationType: MEM_RESERVE */
    emit_push_absolute(SIZE_SLOT_RVA); /* *RegionSize */
    emit_push_imm8(0x00);              /* ZeroBits */
    emit_push_absolute(BASE_SLOT_RVA); /* *BaseAddress */
    emit_push_imm8(0xff);              /* ProcessHandle: NtCurrentProcess */
    emit_call(STUB0_RVA);
    emit_store_eax(RESULT0_RVA);
    /* The second call: an unimplemented number, reached only if the first
     * one really returned to this caller. Its first argument is read from
     * the slot the bridge wrote the allocated base into, so the reported
     * argument proves the guest saw the write-back. */
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);                  /* mov eax, [BASE_SLOT] */
    emit_absolute(BASE_SLOT_RVA);
    emit_byte(0x50);                  /* push eax */
    emit_call(STUB1_RVA);
    emit_store_eax(RESULT1_RVA);
    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    /* The dispatcher thunk: the single jmp that references the slot. */
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    while (text_bytes < STUB0_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_stub(0x0018u, 24u);           /* NtAllocateVirtualMemory */
    while (text_bytes < STUB1_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_stub(0x0019u, 20u);           /* NtQueryInformationProcess */
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

static int fake_open(void *context, const char *canonical_name,
                     PwFileSpan *out)
{
    (void)context;
    if (!pw_module_name_equal(canonical_name, "ntdll.dll"))
        return PW_ERR_NOT_FOUND;
    *out = span;
    return PW_OK;
}

static void fake_close(void *context, PwFileSpan *closed)
{
    (void)context;
    (void)closed;
}

static int fake_open_namespace(void *context, PwFileNamespace file_namespace,
                               const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_open(context, canonical_name, out);
}

int main(void)
{
    const PwFileProvider provider = {
        .context = NULL, .open = fake_open, .close = fake_close,
        .open_namespace = fake_open_namespace,
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
    memcpy(span.path, "runtime/ntdll.dll", 18);
    assert(pw_vm_posix_backend(&vm) == PW_OK);

    memset(&config, 0, sizeof(config));
    config.provider = &provider;
    config.backend = &vm;
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    /* The run stops at the second, unimplemented call, which is a refusal
     * the gate reports rather than a successful acceptance. */
    assert(pw_wine_gate_run(&config, &report) == PW_ERR_UNSUPPORTED);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(strcmp(pw_wine_stop_name(report.stop),
                  "unix-call-unimplemented") == 0);
    assert(report.observed_syscall_id == 0x0019u);
    assert(report.calls.handled == 1u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.unknown == 0u && report.calls.rejected == 0u);
    assert(report.calls_serviced == 1u);
    assert(report.calls.records == 2u);

    /* The first call was recognised by number and by the table's name. */
    assert(report.calls.sequence[0].id == 0x0018u);
    assert(strcmp(report.calls.sequence[0].name,
                  "NtAllocateVirtualMemory") == 0);
    assert(report.calls.sequence[0].arg_bytes == 24u);
    assert(strcmp(pw_unix_call_outcome_name(report.calls.sequence[0].outcome),
                  "handled") == 0);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    /* Its six arguments came from the two-level frame, in order. */
    assert(report.calls.sequence[0].args[0] == 0xffffffffu);
    assert(report.calls.sequence[0].args[1] ==
           report.modules[0].base + BASE_SLOT_RVA);
    assert(report.calls.sequence[0].args[2] == 0u);
    assert(report.calls.sequence[0].args[3] ==
           report.modules[0].base + SIZE_SLOT_RVA);
    assert(report.calls.sequence[0].args[4] == 0x2000u);
    assert(report.calls.sequence[0].args[5] == 0x04u);
    assert(report.calls.sequence[0].stub_return_pc ==
           report.modules[0].base + STUB0_RVA + 12u);
    assert(report.calls.sequence[0].return_pc ==
           report.modules[0].base + CALLER_RVA + 26u);

    /* The guest really continued: its allocation request was answered, its
     * own store of the NTSTATUS ran, and the second call was reached. */
    assert(report.calls.sequence[1].id == 0x0019u);
    assert(strcmp(report.calls.sequence[1].name,
                  "NtQueryInformationProcess") == 0);
    assert(report.calls.sequence[1].outcome == PW_UNIX_CALL_UNIMPLEMENTED);
    assert(report.allocations == 1u);
    assert(report.allocated_bytes == ALLOCATION_SIZE);
    assert(report.call_regions == 1u);
    /* The gate populated a process-parameters structure: the loader reads the
     * current directory, the DLL and image paths and the environment from
     * it, and a zeroed page is what used to make it fault. */
    assert(report.parameters_length > 0x100u);
    assert(report.parameters_base == 0x0c000000u);
    /*
     * The second call's first argument was loaded by the guest from the slot
     * the bridge filled in, so this value can only be right if the write-back
     * landed in guest memory the guest could then read. The run itself
     * reaching that call is the proof that the first call returned to the
     * caller with a correct stack.
     */
    assert(report.calls.sequence[1].args[0] == 0x20000000u);
    /* The region it was given is addressable for the guest. */
    assert(report.guest_regions >= 4u);
    /* ... and the run released it again. */
    assert(report.cleanup_modules == 1u);
    assert(report.cleanup_mappings >= 4u);
    return 0;
}
