/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the virtual-memory query side of the Unix-call
 * bridge.
 *
 * One synthetic module plays the part of a Wine loader: it asks
 * NtQueryVirtualMemory for MemoryBasicInformation about its own entry point -
 * which is what build_ntdll_module does before any module record for ntdll
 * exists, and the reason the query has to come out of this run's own mappings
 * - and about its own stack, and then reads both answers back out of the
 * buffer the gate wrote.
 *
 * Every assertion about an answer is about a value the guest itself loaded out
 * of that buffer and passed on as an argument of a later call, so an answer
 * that never landed in guest memory cannot pass, and neither can one that
 * landed with the wrong fields.
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
    ADDRESS_RVA = DATA_RVA + 0x020,         /* the address under test */
    MBI_RVA = DATA_RVA + 0x040,             /* the 28-byte answer buffer */
    LOADED_BASE_RVA = DATA_RVA + 0x080,     /* AllocationBase the guest read */
    LOADED_SIZE_RVA = DATA_RVA + 0x090,     /* RegionSize the guest read */
    LOADED_TYPE_RVA = DATA_RVA + 0x0A0,     /* Type the guest read */
    STACK_BASE_RVA = DATA_RVA + 0x0B0,      /* the stack's AllocationBase */
    STATUS_RVA = DATA_RVA + 0x100,          /* six status slots */
    COMPARE_STATUS_RVA = DATA_RVA + 0x140,  /* five slots: the comparisons */
    THUNK_RVA = TEXT_RVA + 0x200,
    STUB_QUERY_RVA = TEXT_RVA + 0x210,      /* NtQueryVirtualMemory, 0x23 */
    STUB_TERMINATE_RVA = TEXT_RVA + 0x220,  /* NtTerminateProcess, 0x2c */
    STUB_COMPARE_RVA = TEXT_RVA + 0x230,    /* NtAreMappedFilesTheSame, 0x72 */
    CALLER_RVA = TEXT_RVA,
    /* The fixture's own entry point, which is what the guest measures. */
    FIXTURE_ENTRY_RVA = CALLER_RVA,
};

/* The values the guest asks about, and the classes it must not be answered. */
enum {
    MEMORY_MAPPED_FILENAME_INFORMATION = 4u,
    UNMAPPED_ADDRESS = 0x70000000u,
    MEM_IMAGE = 0x01000000u,
    MBI_BYTES = 28u,
    SHORT_BUFFER = 0x10u,
};

_Static_assert(ADDRESS_RVA + 4u <= MBI_RVA, "the address slot overlaps the answer");
_Static_assert(MBI_RVA + MBI_BYTES <= LOADED_BASE_RVA,
               "the answer overlaps the slots the guest copies out of it");
_Static_assert(STATUS_RVA + 6u * 4u <= DATA_RVA + 0x400u,
               "status slots run past the data section");
_Static_assert(COMPARE_STATUS_RVA + 5u * 4u <= DATA_RVA + 0x400u,
               "comparison slots run past the data section");

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[0x400];
static PeFixtureReloc relocs[128];
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

/* An image address as the loader will relocate it, not as it is stored. */
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

/* "mov eax, imm32" with the image's own reloc: the *address* of an RVA, which
 * is what the guest asks about, as opposed to emit_load_eax's "the value
 * stored at that address". */
static void emit_mov_eax_absolute(uint32_t rva)
{
    emit_byte(0xb8);
    emit_absolute(rva);
}

static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

/* "mov eax, esp": the guest's own stack pointer, an address it cannot name
 * any other way and does not have to guess. */
static void emit_load_esp(void)
{
    emit_byte(0x89);
    emit_byte(0xe0);
}

static void emit_push_eax(void)
{
    emit_byte(0x50);
}

/* NtQueryVirtualMemory(-1, [ADDRESS_RVA], class, MBI_RVA, length, NULL). */
static void emit_query(uint32_t information_class, uint32_t length,
                       uint32_t status_rva)
{
    emit_push_imm32(0u);                        /* return length: not wanted */
    emit_push_imm32(length);
    emit_push_absolute(MBI_RVA);
    emit_push_imm8((uint8_t)information_class);
    emit_load_eax(ADDRESS_RVA);
    emit_push_eax();
    emit_push_imm8(0xff);                       /* this process */
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(status_rva);
}

/* The answer buffer the guest copies a field out of, as a value it then passes
 * as an argument of a call that is refused before it looks at that argument. */
static void emit_copy_field_to_slot(uint32_t field_offset, uint32_t slot_rva)
{
    emit_load_eax(MBI_RVA + field_offset);
    emit_store_eax(slot_rva);
}

/* NtAreMappedFilesTheSame(addr1 in eax, addr2 in edx), the question ntdll's
 * loader asks itself when it wants to know whether an image it has just mapped
 * is one it already has. Both addresses are guest addresses it owns. */
static void emit_compare_eax_edx(uint32_t status_rva)
{
    emit_byte(0x52);                        /* push edx: the second address */
    emit_push_eax();                        /* push eax: the first address */
    emit_call(STUB_COMPARE_RVA);
    emit_store_eax(status_rva);
}

/* "mov edx, [abs]" */
static void emit_load_edx(uint32_t rva)
{
    emit_byte(0x8b);
    emit_byte(0x15);
    emit_absolute(rva);
}

/* "mov edx, imm32": the immediate is an address of ours, so it needs the same
 * base relocation an absolute operand in the code does. */
static void emit_mov_edx_absolute(uint32_t rva)
{
    emit_byte(0xba);
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

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));

    /* The image address the loader relocated into this module, which is what
     * the guest asks about first. */
    emit_mov_eax_absolute(CALLER_RVA);
    emit_store_eax(ADDRESS_RVA);
    emit_query(0u, MBI_BYTES, STATUS_RVA);
    emit_copy_field_to_slot(4u, LOADED_BASE_RVA);
    emit_copy_field_to_slot(12u, LOADED_SIZE_RVA);
    emit_copy_field_to_slot(24u, LOADED_TYPE_RVA);

    /* Its own stack, an address it knows without naming the module. */
    emit_load_esp();
    emit_store_eax(ADDRESS_RVA);
    emit_query(0u, MBI_BYTES, STATUS_RVA + 4u);
    emit_copy_field_to_slot(4u, STACK_BASE_RVA);

    /* A buffer that cannot hold the answer; the address argument carries the
     * stack allocation base the guest just read back. */
    emit_load_eax(STACK_BASE_RVA);
    emit_store_eax(ADDRESS_RVA);
    emit_query(0u, SHORT_BUFFER, STATUS_RVA + 8u);

    /* A class this bridge does not answer, refused before the address is
     * looked at, so the image region size can travel as that argument. */
    emit_load_eax(LOADED_SIZE_RVA);
    emit_store_eax(ADDRESS_RVA);
    emit_query(MEMORY_MAPPED_FILENAME_INFORMATION, MBI_BYTES, STATUS_RVA + 12u);

    /* A handle that is not this process, refused before the class is read, so
     * the region type can travel as that argument. */
    emit_push_imm32(0u);
    emit_push_imm32(MBI_BYTES);
    emit_push_absolute(MBI_RVA);
    emit_push_imm8(0u);
    emit_load_eax(ADDRESS_RVA);
    emit_push_eax();
    emit_load_eax(LOADED_TYPE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(STATUS_RVA + 16u);

    /* A page this run never mapped. */
    emit_byte(0xb8);
    emit_u32(UNMAPPED_ADDRESS);
    emit_store_eax(ADDRESS_RVA);
    emit_query(0u, MBI_BYTES, STATUS_RVA + 20u);

    /*
     * NtAreMappedFilesTheSame, the question ntdll's loader asks itself when it
     * wants to know whether an image it has just mapped is one it already has
     * (dlls/ntdll/loader.c:2798 compares the base of a module record with the
     * new image, address against address). Three shapes are asked here: two
     * addresses inside one image, which is one view; the image against the
     * private page the process runs on, which is not a file view; and the
     * image against a page this run never mapped.
     */
    emit_mov_eax_absolute(CALLER_RVA);      /* the fixture's own entry point */
    emit_mov_edx_absolute(MBI_RVA);         /* another address in the same image */
    emit_compare_eax_edx(COMPARE_STATUS_RVA);

    emit_load_esp();                        /* the process's own stack page */
    emit_byte(0x89); emit_byte(0xc2);       /* mov edx, eax */
    emit_mov_eax_absolute(CALLER_RVA);
    emit_compare_eax_edx(COMPARE_STATUS_RVA + 4u);

    emit_mov_eax_absolute(CALLER_RVA);
    emit_byte(0xba);                        /* mov edx, a page with nothing on it */
    emit_u32(UNMAPPED_ADDRESS);
    emit_compare_eax_edx(COMPARE_STATUS_RVA + 8u);

    /*
     * The three answers travel as arguments of two more comparisons, which are
     * refused before they look at an address: the transcript, not this test,
     * carries what the guest actually saw.
     */
    emit_load_eax(COMPARE_STATUS_RVA);
    emit_load_edx(COMPARE_STATUS_RVA + 4u);
    emit_compare_eax_edx(COMPARE_STATUS_RVA + 12u);
    emit_load_eax(COMPARE_STATUS_RVA + 8u);
    emit_load_edx(LOADED_BASE_RVA);
    emit_compare_eax_edx(COMPARE_STATUS_RVA + 16u);

    /* Now end the process, reporting the image allocation base the guest read
     * out of the first answer as the exit status. */
    emit_load_eax(LOADED_BASE_RVA);
    emit_push_eax();
    emit_push_imm8(0xff);
    emit_call(STUB_TERMINATE_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_QUERY_RVA, 0x0023u, 24u);
    emit_stub(STUB_TERMINATE_RVA, 0x002cu, 8u);
    emit_stub(STUB_COMPARE_RVA, 0x0072u, 8u);
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
    uint32_t expected_entry = 0u;
    uint32_t expected_region_size = 0u;

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
    /* The queried page is the module's entry page, so the region the answer
     * describes runs from there to the end of the image. */
    expected_region_size = report.modules[0].image_bytes - FIXTURE_ENTRY_RVA;

    /* The run ends because the guest ended its own process, with the allocation
     * base it read out of the answer as its exit status. */
    assert(report.stop == PW_WINE_STOP_PROCESS_TERMINATED);
    assert(report.calls.records == 12u);
    assert(report.calls.handled == 12u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.calls.unimplemented == 0u);
    /* Four of the six queries name the class this bridge answers and a handle
     * it accepts; the other two are refused before the query is counted. */
    assert(report.virtual_queries == 4u);

    for (uint32_t index = 0u; index < 6u; ++index)
        assert(report.calls.sequence[index].id == 0x0023u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[2].status == PW_NT_INFO_LENGTH_MISMATCH);
    assert(report.calls.sequence[3].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[4].status == PW_NT_INVALID_HANDLE);
    assert(report.calls.sequence[5].status == PW_NT_INVALID_PARAMETER);

    /* The first query asked about the entry point the guest relocated into its
     * own image, which is the address the fake loader measured. */
    assert(report.calls.sequence[0].args[1] == expected_entry);
    /* The refused class carries the image region size the guest read: the page
     * it asked about is the entry page, and the region runs to the image end. */
    assert(report.calls.sequence[3].args[1] == expected_region_size);
    /* The refused handle carries the region type the guest read. */
    assert(report.calls.sequence[4].args[0] == MEM_IMAGE);
    /* The refused short buffer carries the stack allocation base the guest
     * read, which is the region this run declared for the process stack. */
    assert(report.calls.sequence[2].args[1] == report.stack_base);
    /* The query about an unmapped page reached the handler and was refused. */
    assert(report.calls.sequence[5].args[1] == UNMAPPED_ADDRESS);
    /* The image allocation base the guest read is what it exited with. */
    assert(report.calls.sequence[11].id == 0x002cu);
    assert(report.calls.sequence[11].args[1] == report.modules[0].base);
    /*
     * The address comparisons, in the order the guest asked them. Two
     * addresses inside one image are one view - and the two arguments are
     * different addresses, so the answer cannot be address equality. The
     * process's own stack page is mapped but is not a file view, which is the
     * case Wine answers with STATUS_CONFLICTING_ADDRESSES, and a page this run
     * never mapped is refused rather than guessed at.
     */
    assert(report.address_comparisons == 5u);
    assert(report.address_comparison_refusals == 4u);
    for (uint32_t index = 6u; index < 11u; ++index)
        assert(report.calls.sequence[index].id == 0x0072u);
    assert(report.calls.sequence[6].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[6].args[0] != report.calls.sequence[6].args[1]);
    assert(report.calls.sequence[7].status == PW_NT_CONFLICTING_ADDRESSES);
    /* The private address is the guest's own stack pointer, which lies inside
     * the stack region this run declared for it, not at its base. */
    assert(report.calls.sequence[7].args[0] == expected_entry);
    assert(report.calls.sequence[7].args[1] >= report.stack_base);
    assert(report.calls.sequence[7].args[1] <
           report.stack_base + report.stack_bytes);
    assert(report.calls.sequence[8].status == PW_NT_INVALID_ADDRESS);
    assert(report.calls.sequence[8].args[0] == expected_entry);
    assert(report.calls.sequence[8].args[1] == UNMAPPED_ADDRESS);
    /* The two refused carries: the answers the guest read back travel as the
     * addresses of the next comparison, so their values are in the record. */
    assert(report.calls.sequence[9].status == PW_NT_INVALID_ADDRESS);
    assert(report.calls.sequence[9].args[0] == PW_NT_SUCCESS);
    assert(report.calls.sequence[9].args[1] == PW_NT_CONFLICTING_ADDRESSES);
    assert(report.calls.sequence[10].status == PW_NT_INVALID_ADDRESS);
    assert(report.calls.sequence[10].args[0] == PW_NT_INVALID_ADDRESS);
    assert(report.calls.sequence[10].args[1] == report.modules[0].base);
    return 0;
}
