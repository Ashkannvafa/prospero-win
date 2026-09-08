/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pe_layout.h"
#include "../src/pe_reloc.h"

#include <assert.h>
#include <string.h>

static uint8_t buffer[128 * 1024];
static const uint8_t payload[256] = {0x48, 0x31, 0xc0, 0xc3};

static size_t section_table_offset(const PeImage *image)
{
    return image->nt_offset + 4u + PE_FILE_HEADER_BYTES +
           image->optional_header_bytes;
}

static void write_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    bytes[3] = (uint8_t)((value >> 24) & 0xffu);
}

static size_t build(PeFixtureSpec *spec)
{
    memset(spec, 0, sizeof(*spec));
    spec->pe32plus = 1;
    spec->image_base = 0x140000000ull;
    spec->dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec->section_count = 3u;
    spec->sections[0].name = ".text";
    spec->sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec->sections[0].data = payload;
    spec->sections[0].data_bytes = (uint32_t)sizeof(payload);
    spec->sections[1].name = ".data";
    spec->sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec->sections[1].data = payload;
    spec->sections[1].data_bytes = 32u;
    spec->sections[1].virtual_size = 0x1800u;    /* spills into a second page */
    spec->sections[2].name = ".bss";
    spec->sections[2].characteristics = PE_SCN_CNT_UNINITIALIZED_DATA |
                                        PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec->sections[2].virtual_size = 0x4000u;    /* no bytes on disk at all */
    spec->entry_point = 0x1000u;
    return pe_fixture_build(buffer, sizeof(buffer), spec);
}

static void test_plans_basic_layout(void)
{
    PeFixtureSpec spec;
    const size_t size = build(&spec);
    PeImage image;
    PeLayout layout;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);

    assert(layout.preferred_base == 0x140000000ull);
    assert(layout.section_alignment == 0x1000u);
    assert(layout.entry_point == 0x1000u);
    assert(layout.section_count == 3u);
    assert(layout.dynamic_base == 1u);
    assert(layout.nx_compat == 1u);
    assert(layout.relocatable == 0u);           /* no .reloc in this spec */
    assert(layout.header_bytes == image.size_of_headers);

    /* .text: one page, code copied, rest zeroed. */
    assert(strcmp(layout.sections[0].name, ".text") == 0);
    assert(layout.sections[0].rva == 0x1000u);
    assert(layout.sections[0].mapped_bytes == 0x1000u);
    assert(layout.sections[0].raw_bytes == sizeof(payload));
    assert(layout.sections[0].zero_bytes == 0x1000u - sizeof(payload));
    assert(layout.sections[0].protection == (PW_PROT_READ | PW_PROT_EXEC));
    assert(layout.sections[0].derived_protection == 0u);

    /*
     * .data: VirtualSize 0x1800 rounds up to two pages, and SizeOfRawData
     * is the file-aligned 0x200, so the copy carries the linker's padding
     * exactly as Windows does.
     */
    assert(layout.sections[1].rva == 0x2000u);
    assert(layout.sections[1].virtual_bytes == 0x1800u);
    assert(layout.sections[1].mapped_bytes == 0x2000u);
    assert(layout.sections[1].raw_bytes == 0x200u);
    assert(layout.sections[1].protection == (PW_PROT_READ | PW_PROT_WRITE));

    /* .bss: entirely zero filled. */
    assert(layout.sections[2].rva == 0x4000u);
    assert(layout.sections[2].raw_bytes == 0u);
    assert(layout.sections[2].mapped_bytes == 0x4000u);
    assert(layout.sections[2].zero_bytes == 0x4000u);
    assert(layout.sections[2].uninitialized == 1u);

    assert(layout.image_bytes == 0x8000u);
    assert(layout.exec_bytes == 0x1000u);
    assert(layout.write_bytes == 0x2000u + 0x4000u);
    assert(layout.copy_bytes == sizeof(payload) + 0x200u);
    assert(layout.zero_bytes ==
           (0x1000u - sizeof(payload)) + (0x2000u - 0x200u) + 0x4000u);
}

static void test_protection_derivation(void)
{
    int derived = 0;

    assert(pe_layout_protection(PE_SCN_MEM_READ, &derived) == PW_PROT_READ);
    assert(derived == 0);
    assert(pe_layout_protection(PE_SCN_MEM_READ | PE_SCN_MEM_WRITE |
                                PE_SCN_MEM_EXECUTE, &derived) ==
           (PW_PROT_READ | PW_PROT_WRITE | PW_PROT_EXEC));
    assert(derived == 0);

    /* No access bits at all: normalised, and the fact is recorded. */
    assert(pe_layout_protection(PE_SCN_CNT_CODE, &derived) ==
           (PW_PROT_READ | PW_PROT_EXEC));
    assert(derived == 1);
    assert(pe_layout_protection(PE_SCN_CNT_INITIALIZED_DATA, &derived) ==
           PW_PROT_READ);
    assert(derived == 1);
    assert(pe_layout_protection(0u, &derived) == PW_PROT_NONE);
    assert(derived == 1);
    assert(pe_layout_protection(PE_SCN_MEM_READ, NULL) == PW_PROT_READ);
}

static void test_rejects_small_section_alignment(void)
{
    PeFixtureSpec spec;
    size_t size;
    PeImage image;
    PeLayout layout;

    (void)build(&spec);
    spec.section_alignment = 0x200u;
    spec.file_alignment = 0x200u;
    spec.sections[1].virtual_size = 0x400u;
    spec.sections[2].virtual_size = 0x400u;
    spec.entry_point = 0x200u;
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    /* A raw-mapped image is well formed but deliberately not handled. */
    assert(pe_layout_plan(&layout, &image) == PW_ERR_UNSUPPORTED);
}

static void test_rejects_misaligned_image_base(void)
{
    PeFixtureSpec spec;
    size_t size;
    PeImage image;
    PeLayout layout;

    (void)build(&spec);
    spec.image_base = 0x140000800ull;
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_ERR_MALFORMED);
}

static void test_rejects_overlapping_sections(void)
{
    PeFixtureSpec spec;
    const size_t size = build(&spec);
    PeImage image;
    PeLayout layout;
    size_t table;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    table = section_table_offset(&image);

    /* Point .data back inside .text. */
    write_u32(buffer + table + PE_SECTION_HEADER_BYTES + 12u, 0x1000u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_ERR_MALFORMED);
}

static void test_rejects_misaligned_section_rva(void)
{
    PeFixtureSpec spec;
    const size_t size = build(&spec);
    PeImage image;
    PeLayout layout;
    size_t table;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    table = section_table_offset(&image);
    write_u32(buffer + table + 12u, 0x1100u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_ERR_MALFORMED);
}

static void test_rejects_section_past_image(void)
{
    PeFixtureSpec spec;
    const size_t size = build(&spec);
    PeImage image;
    PeLayout layout;
    size_t table;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    table = section_table_offset(&image);
    /* Move .bss beyond SizeOfImage. */
    write_u32(buffer + table + 2u * PE_SECTION_HEADER_BYTES + 12u, 0x40000u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_ERR_MALFORMED);
}

static void test_reports_relocatable(void)
{
    PeFixtureSpec spec;
    size_t size;
    PeImage image;
    PeLayout layout;

    (void)build(&spec);
    spec.reloc_count = 2u;
    spec.relocs[0].rva = 0x1010u;
    spec.relocs[0].type = PE_RELOC_DIR64;
    spec.relocs[1].rva = 0x1020u;
    spec.relocs[1].type = PE_RELOC_DIR64;
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    assert(layout.relocatable == 1u);
    assert(pe_layout_plan(NULL, &image) == PW_ERR_PRECONDITION);
    assert(pe_layout_plan(&layout, NULL) == PW_ERR_PRECONDITION);
}

int main(void)
{
    test_plans_basic_layout();
    test_protection_derivation();
    test_rejects_small_section_alignment();
    test_rejects_misaligned_image_base();
    test_rejects_overlapping_sections();
    test_rejects_misaligned_section_rva();
    test_rejects_section_past_image();
    test_reports_relocatable();
    return 0;
}
