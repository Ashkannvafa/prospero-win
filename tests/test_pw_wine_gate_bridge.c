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
 *   - the guest releases that block (NtFreeVirtualMemory, MEM_RELEASE), the
 *     mapping goes back to the backend, the block stops being addressable
 *     and the released size is written back into the guest's own variable;
 *   - the guest resumes in the caller with the NTSTATUS in EAX, which is only
 *     true if the two-level frame was unwound correctly;
 *   - the third, unimplemented call is named exactly and stops the run.
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
    SLOT_RVA = DATA_RVA,            /* __wine_syscall_dispatcher */
    BASE_SLOT_RVA = DATA_RVA + 4,   /* *BaseAddress for the first call */
    SIZE_SLOT_RVA = DATA_RVA + 8,   /* *RegionSize, pre-set below */
    RESULT0_RVA = DATA_RVA + 12,    /* where the caller stores the status */
    RESULT1_RVA = DATA_RVA + 16,
    THUNK_RVA = TEXT_RVA + 0x100,
    STUB0_RVA = TEXT_RVA + 0x110,   /* NtAllocateVirtualMemory, 0x18 */
    STUB1_RVA = TEXT_RVA + 0x120,   /* NtFreeVirtualMemory, 0x1e */
    /* A call this bridge has no handler for: the run must stop and name it
     * exactly. Update it when the handler lands. */
    STUB2_RVA = TEXT_RVA + 0x130,   /* NtProtectVirtualMemory, 0x50 */
    CALLER_RVA = TEXT_RVA,
    ALLOCATION_SIZE = 0x4000,
};

static uint8_t image[64 * 1024];
static uint8_t text[512];
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

/* Fault injection: which part of the caller hands the bridge a span it cannot
 * write. Each variant is a self-contained run, because a rejected call is
 * where the run stops. */
enum PwBridgeFault {
    PW_BRIDGE_NO_FAULT = 0,
    PW_BRIDGE_ALLOC_SIZE_OUTPUT = 1,    /* *RegionSize unwritable */
    PW_BRIDGE_ALLOC_BASE_OUTPUT = 2,    /* *BaseAddress unwritable */
    PW_BRIDGE_FREE_BASE_OUTPUT = 3,     /* the release's *BaseAddress */
};

static size_t build_module(enum PwBridgeFault fault)
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
    if (fault == PW_BRIDGE_ALLOC_SIZE_OUTPUT)
        emit_push_imm32(0x50000000u);  /* a span no region covers */
    else
        emit_push_absolute(SIZE_SLOT_RVA); /* *RegionSize */
    emit_push_imm8(0x00);              /* ZeroBits */
    if (fault == PW_BRIDGE_ALLOC_BASE_OUTPUT)
        emit_push_imm32(0x50000000u);
    else
        emit_push_absolute(BASE_SLOT_RVA); /* *BaseAddress */
    emit_push_imm8(0xff);              /* ProcessHandle: NtCurrentProcess */
    emit_call(STUB0_RVA);
    emit_store_eax(RESULT0_RVA);
    /* The guest releases the block the bridge just gave it, asking for a
     * whole-region release the way Wine's own cleanup path does: *RegionSize
     * is set to zero first, so the value the free writes back (the size of
     * the region it released) can only appear if the bridge really wrote it
     * into guest memory. */
    emit_byte(0xc7); emit_byte(0x05);   /* mov dword ptr [SIZE_SLOT], 0 */
    emit_absolute(SIZE_SLOT_RVA);
    emit_u32(0u);
    emit_push_imm32(0x8000u);         /* FreeType: MEM_RELEASE */
    emit_push_absolute(SIZE_SLOT_RVA); /* *RegionSize */
    if (fault == PW_BRIDGE_FREE_BASE_OUTPUT)
        emit_push_imm32(0x50000000u);
    else
        emit_push_absolute(BASE_SLOT_RVA); /* *BaseAddress */
    emit_push_imm8(0xff);             /* ProcessHandle: NtCurrentProcess */
    emit_call(STUB1_RVA);
    emit_store_eax(RESULT1_RVA);
    /* The third call: an unimplemented number, reached only if the two
     * serviced calls really returned to this caller. Its first argument is
     * the size the free wrote back and its second the base the allocation
     * wrote back, so the reported arguments prove the guest saw both. */
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);                  /* mov eax, [BASE_SLOT] */
    emit_absolute(BASE_SLOT_RVA);
    emit_byte(0x50);                  /* push eax: second argument */
    emit_byte(0xa1);                  /* mov eax, [SIZE_SLOT] */
    emit_absolute(SIZE_SLOT_RVA);
    emit_byte(0x50);                  /* push eax: first argument */
    emit_call(STUB2_RVA);
    emit_store_eax(RESULT1_RVA + 4u);
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
    emit_stub(0x001eu, 16u);           /* NtFreeVirtualMemory */
    while (text_bytes < STUB2_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_stub(PW_TEST_UNHANDLED_CALL_ID, PW_TEST_UNHANDLED_CALL_ARGS);
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
    const size_t size = build_module(PW_BRIDGE_NO_FAULT);

    assert(size != 0u);
    span.bytes = image;
    span.size = size;
    span.handle = NULL;
    memset(span.path, 0, sizeof(span.path));
    memcpy(span.path, "runtime/ntdll.dll", 18);
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

    /* The run stops at the third, unimplemented call, which is a refusal
     * the gate reports rather than a successful acceptance. */
    assert(pw_wine_gate_run(&config, &report) == PW_ERR_UNSUPPORTED);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(strcmp(pw_wine_stop_name(report.stop),
                  "unix-call-unimplemented") == 0);
    assert(report.observed_syscall_id == PW_TEST_UNHANDLED_CALL_ID);
    assert(report.calls.handled == 2u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.unknown == 0u && report.calls.rejected == 0u);
    assert(report.calls_serviced == 2u);
    assert(report.calls.records == 3u);

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
     * own store of the NTSTATUS ran, and the release was reached. */
    assert(report.calls.sequence[1].id == 0x001eu);
    assert(strcmp(report.calls.sequence[1].name, "NtFreeVirtualMemory") == 0);
    assert(report.calls.sequence[1].outcome == PW_UNIX_CALL_HANDLED);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[1].args[0] == 0xffffffffu);
    assert(report.calls.sequence[1].args[3] == 0x8000u);   /* MEM_RELEASE */
    assert(report.calls.sequence[2].id == PW_TEST_UNHANDLED_CALL_ID);
    assert(strcmp(report.calls.sequence[2].name,
                  PW_TEST_UNHANDLED_CALL_NAME) == 0);
    assert(report.calls.sequence[2].outcome == PW_UNIX_CALL_UNIMPLEMENTED);
    assert(report.allocations == 1u);
    assert(report.releases == 1u);
    /* Nothing the guest allocated is still live, and the one region that
     * remains registered is the process-parameters block, which the gate
     * plays the parent for. */
    assert(report.allocated_bytes == 0u);
    assert(report.call_regions == 1u);
    /* The gate populated a process-parameters structure: the loader reads the
     * current directory, the DLL and image paths and the environment from
     * it, and a zeroed page is what used to make it fault. */
    assert(report.parameters_length > 0x100u);
    assert(report.parameters_base == 0x0c000000u);
    /*
     * The third call's arguments were loaded by the guest from the slots the
     * two serviced calls filled in, so these values can only be right if both
     * write-backs landed in guest memory the guest could then read: the base
     * the allocation returned, and the size the release wrote back.
     */
    assert(report.calls.sequence[2].args[0] == ALLOCATION_SIZE);
    assert(report.calls.sequence[2].args[1] == 0x20000000u);
    /* The region it was given is addressable for the guest. */
    assert(report.guest_regions >= 4u);
    /* Cleanup has the window, the TEB, the PEB and the process parameters to
     * release; the NT allocation is not among them any more. */
    assert(report.cleanup_modules == 1u);
    assert(report.cleanup_mappings >= 4u);
    {
        const uint32_t baseline_mappings = report.cleanup_mappings;

        /*
         * Fault injection. Both platform calls write guest outputs, so every
         * output span is preflighted before anything is reserved, committed,
         * released or accounted: a span the guest cannot write must leave the
         * run's state exactly as it was. Each variant is its own run, because
         * a rejected call is where that run stops.
         */
        const struct {
            enum PwBridgeFault fault;
            uint32_t argument_index;
            uint32_t allocations;
            uint32_t live_regions;
            uint32_t allocated_bytes;
            uint32_t cleanup_mappings;
        } cases[] = {
            /* *RegionSize cannot be written: nothing was allocated at all. */
            { PW_BRIDGE_ALLOC_SIZE_OUTPUT, 4u, 0u, 1u, 0u, baseline_mappings },
            /* *BaseAddress cannot be written: same, nothing was allocated. */
            { PW_BRIDGE_ALLOC_BASE_OUTPUT, 2u, 0u, 1u, 0u, baseline_mappings },
            /* The release's *BaseAddress cannot be written: the block the
             * guest already owns stays live and accounted, and cleanup has one
             * more mapping to release than the clean run had. */
            { PW_BRIDGE_FREE_BASE_OUTPUT, 2u, 1u, 2u, ALLOCATION_SIZE,
              baseline_mappings + 1u },
        };

        for (unsigned index = 0; index < sizeof(cases) / sizeof(cases[0]);
             ++index) {
            PwWineGateReport faulted;
            const size_t faulted_size = build_module(cases[index].fault);
            PwWineGateConfig fault_config = config;

            assert(faulted_size != 0u);
            span.size = faulted_size;
            memset(&faulted, 0, sizeof(faulted));
            assert(pw_wine_gate_run(&fault_config, &faulted) ==
                   PW_ERR_UNSUPPORTED);
            assert(faulted.stop == PW_WINE_STOP_UNIX_CALL_REJECTED);
            assert(faulted.calls.rejected == 1u);
            /* The rejected call is the last one in the run. */
            assert(faulted.calls.records >= 1u);
            assert(faulted.calls.sequence[faulted.calls.records - 1u]
                       .argument_index == cases[index].argument_index);
            /* The state the call would have changed is exactly as it was. */
            assert(faulted.allocations == cases[index].allocations);
            assert(faulted.call_regions == cases[index].live_regions);
            assert(faulted.allocated_bytes == cases[index].allocated_bytes);
            assert(faulted.cleanup_mappings == cases[index].cleanup_mappings);
            assert(faulted.cleanup_translations == 1u);
            assert(faulted.cleanup_modules == 1u);
        }
    }
    return 0;
}
