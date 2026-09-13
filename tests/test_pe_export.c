/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pe_export.h"

#include <assert.h>
#include <string.h>

static uint8_t buffer[128 * 1024];
static const uint8_t code[16] = {0xc3};
static const uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/*
 * The generated .edata section is appended after the caller's sections, so
 * the exported-code and exported-data RVAs are fixed by the section
 * alignment. The tests assert the parsed layout below rather than trusting
 * these constants.
 */
enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
};

static void base_spec(PeFixtureSpec *spec, int pe32plus)
{
    memset(spec, 0, sizeof(*spec));
    spec->pe32plus = pe32plus;
    spec->image_base = pe32plus ? 0x180000000ull : 0x400000ull;
    spec->section_count = 2u;
    spec->sections[0].name = ".text";
    spec->sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec->sections[0].data = code;
    spec->sections[0].data_bytes = (uint32_t)sizeof(code);
    spec->sections[1].name = ".rdata";
    spec->sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ;
    spec->sections[1].data = data;
    spec->sections[1].data_bytes = (uint32_t)sizeof(data);
    spec->entry_point = TEXT_RVA;
    spec->export_base = 1u;
    spec->export_module_name = "fixture.dll";
}

static size_t build(PeFixtureSpec *spec, PeImage *image)
{
    const size_t size = pe_fixture_build(buffer, sizeof(buffer), spec);

    assert(size != 0u);
    assert(pe_image_parse(image, buffer, size) == PW_OK);
    assert(image->sections[0].virtual_address == TEXT_RVA);
    assert(image->sections[1].virtual_address == DATA_RVA);
    assert(image->machine == (spec->pe32plus ? PE_MACHINE_AMD64 : PE_MACHINE_I386));
    return size;
}

static const PeSection *section_named(const PeImage *image, const char *name)
{
    for (uint32_t index = 0; index < image->section_count; ++index)
        if (strcmp(image->sections[index].name, name) == 0)
            return &image->sections[index];
    return NULL;
}

/* The export directory lives in the generated .edata section. */
static uint32_t forwarder_string_rva(const PeImage *image, const char *text)
{
    const PeSection *section = section_named(image, ".edata");
    size_t offset;
    const size_t length = strlen(text);

    assert(section != NULL);
    assert(pe_image_file_offset(image, section->virtual_address, 1u, &offset) ==
           PW_OK);
    for (uint32_t rva = section->virtual_address;
         (uint64_t)rva + length < (uint64_t)section->virtual_address +
                               section->virtual_size;
         ++rva) {
        if (pe_image_file_offset(image, rva, (uint32_t)length + 1u, &offset) !=
            PW_OK)
            break;
        if (memcmp(image->bytes + offset, text, length + 1u) == 0)
            return rva;
    }
    assert(0 && "forwarder string not found in .edata");
    return 0u;
}

static void test_no_export_directory(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;

    base_spec(&spec, 0);
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(directory.function_count == 0u);
    assert(directory.name_count == 0u);
    /* An export-less image is legal; every lookup fails closed. */
    assert(pe_export_find_name(&image, &directory, "Anything", &symbol) ==
           PW_ERR_NOT_FOUND);
    assert(pe_export_find_ordinal(&image, &directory, 1u, &symbol) ==
           PW_ERR_NOT_FOUND);
}

static void test_name_and_ordinal_share_one_rva(int pe32plus)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol by_name;
    PeExportSymbol by_ordinal;

    base_spec(&spec, pe32plus);
    spec.export_count = 3u;
    /* One entry published by name and ordinal, one ordinal-only, one named
     * with a gap before it so index 1 stays sparse. */
    spec.exports[0].name = "Same";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = TEXT_RVA;
    spec.exports[1].name = NULL;
    spec.exports[1].ordinal = 3u;
    spec.exports[1].rva = TEXT_RVA + 4u;
    spec.exports[2].name = "SparseBelow";
    spec.exports[2].ordinal = 4u;
    spec.exports[2].rva = DATA_RVA;
    (void)build(&spec, &image);

    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(strcmp(directory.module_name, "fixture.dll") == 0);
    assert(directory.ordinal_base == 1u);
    assert(directory.function_count == 4u);
    assert(directory.name_count == 2u);

    assert(pe_export_find_name(&image, &directory, "Same", &by_name) == PW_OK);
    assert(by_name.rva == TEXT_RVA);
    assert(by_name.ordinal == 1u);
    assert(by_name.is_code == 1u);
    assert(by_name.is_forwarder == 0u);
    assert(pe_export_find_ordinal(&image, &directory, 1u, &by_ordinal) == PW_OK);
    assert(by_ordinal.rva == by_name.rva);
    assert(by_ordinal.by_ordinal == 1u);
    assert(strcmp(by_ordinal.name, "Same") == 0);

    /* Export names are exact ASCII, not case-folded. */
    assert(pe_export_find_name(&image, &directory, "same", &by_name) ==
           PW_ERR_NOT_FOUND);
    assert(pe_export_find_name(&image, &directory, "Samex", &by_name) ==
           PW_ERR_NOT_FOUND);

    /* Ordinal-only slots carry no name but do resolve. */
    assert(pe_export_find_ordinal(&image, &directory, 3u, &by_ordinal) == PW_OK);
    assert(by_ordinal.rva == TEXT_RVA + 4u);
    assert(by_ordinal.name[0] == '\0');

    /* Index 1 has no entry at all: sparse slots fail closed. */
    assert(pe_export_find_ordinal(&image, &directory, 2u, &by_ordinal) ==
           PW_ERR_NOT_FOUND);
    /* Below the base, at the top of the range and past it. */
    assert(pe_export_find_ordinal(&image, &directory, 0u, &by_ordinal) ==
           PW_ERR_NOT_FOUND);
    assert(pe_export_find_ordinal(&image, &directory, 4u, &by_ordinal) == PW_OK);
    assert(pe_export_find_ordinal(&image, &directory, 5u, &by_ordinal) ==
           PW_ERR_NOT_FOUND);
    assert(pe_export_find_ordinal(&image, &directory, 0xffffu, &by_ordinal) ==
           PW_ERR_NOT_FOUND);

    /* Exported data is distinguished from callable code. */
    assert(pe_export_find_name(&image, &directory, "SparseBelow", &by_name) ==
           PW_OK);
    assert(by_name.is_code == 0u);
    assert(by_name.rva == DATA_RVA);
}

static void test_forwarders_and_code_data_rule(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;
    uint32_t forwarder_rva;
    uint32_t in_directory_rva;
    uint32_t plain_code_rva = TEXT_RVA;
    size_t offset;

    base_spec(&spec, 0);
    spec.export_count = 3u;
    spec.exports[0].name = "Forwarded";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].forwarder = "KERNELBASE.CreateFileA";
    spec.exports[1].name = "ForwardedOrdinal";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].forwarder = "NTDLL.#101";
    spec.exports[2].name = "PlainCode";
    spec.exports[2].ordinal = 3u;
    spec.exports[2].rva = TEXT_RVA;
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);

    assert(pe_export_find_name(&image, &directory, "Forwarded", &symbol) ==
           PW_OK);
    assert(symbol.is_forwarder == 1u);
    assert(strcmp(symbol.target, "KERNELBASE.CreateFileA") == 0);
    assert(symbol.forwarder_rva >= directory.directory_rva);
    assert(symbol.is_code == 0u);

    assert(pe_export_find_name(&image, &directory, "ForwardedOrdinal",
                               &symbol) == PW_OK);
    assert(strcmp(symbol.target, "NTDLL.#101") == 0);
    in_directory_rva = symbol.forwarder_rva;
    assert(in_directory_rva >= directory.directory_rva);

    /*
     * A forwarder string is only recognised while its RVA is inside the
     * export directory. Pointing a slot at ordinary .text makes the very
     * same kind of entry a plain code export instead.
     */
    forwarder_rva = forwarder_string_rva(&image, "KERNELBASE.CreateFileA");
    assert(forwarder_rva != 0u);
    assert(forwarder_rva >= directory.directory_rva);
    assert(forwarder_rva != in_directory_rva);
    assert(pe_image_file_offset(&image, directory.functions_rva, 4u, &offset) ==
           PW_OK);
    memcpy(buffer + offset, &plain_code_rva, 4u);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(pe_export_find_name(&image, &directory, "Forwarded", &symbol) ==
           PW_OK);
    assert(symbol.is_forwarder == 0u);
    assert(symbol.is_code == 1u);
    assert(symbol.rva == TEXT_RVA);

    /* Restoring the directory RVA brings the forwarder back. */
    memcpy(buffer + offset, &forwarder_rva, 4u);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(pe_export_find_name(&image, &directory, "Forwarded", &symbol) ==
           PW_OK);
    assert(symbol.is_forwarder == 1u);
    assert(strcmp(symbol.target, "KERNELBASE.CreateFileA") == 0);
    /* The data export stays data. */
    assert(pe_export_find_name(&image, &directory, "PlainCode", &symbol) ==
           PW_OK);
    assert(symbol.is_code == 1u);
}

static void test_malformed_forwarder_fails_closed(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;
    const PeSection *section;
    uint32_t broken;
    size_t offset;

    base_spec(&spec, 0);
    spec.export_count = 1u;
    spec.exports[0].name = "Forwarded";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].forwarder = "KERNELBASE.CreateFileA";
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    section = section_named(&image, ".edata");
    assert(section != NULL);

    /* A forwarder RVA on the directory's last byte with no terminator is
     * malformed, not "an empty string". */
    assert(pe_image_file_offset(&image, section->virtual_address, 1u, &offset) ==
           PW_OK);
    buffer[offset + section->virtual_size - 1u] = 'X';
    broken = section->virtual_address + section->virtual_size - 1u;
    assert(pe_image_file_offset(&image, directory.functions_rva, 4u, &offset) ==
           PW_OK);
    memcpy(buffer + offset, &broken, 4u);
    assert(pe_export_find_name(&image, &directory, "Forwarded", &symbol) ==
           PW_ERR_MALFORMED);
}

static void test_structural_rejections(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;
    size_t offset;
    uint32_t value;

    base_spec(&spec, 0);
    spec.export_count = 2u;
    spec.exports[0].name = "B";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = TEXT_RVA;
    spec.exports[1].name = "A";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = TEXT_RVA + 4u;
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(pe_export_find_name(&image, &directory, "A", &symbol) == PW_OK);
    assert(symbol.rva == TEXT_RVA + 4u);

    /* NumberOfNames above NumberOfFunctions is self-inconsistent. */
    assert(pe_image_file_offset(&image, directory.directory_rva, 40u, &offset) ==
           PW_OK);
    value = 4u;
    memcpy(buffer + offset + 24u, &value, 4u);
    assert(pe_export_parse(&directory, &image) == PW_ERR_MALFORMED);

    /* A base that would push ordinal arithmetic past 16 bits. */
    value = 0xffff0000u;
    memcpy(buffer + offset + 16u, &value, 4u);
    assert(pe_export_parse(&directory, &image) == PW_ERR_MALFORMED);

    /* A function table that runs past the file. */
    value = 0xffff0000u;
    memcpy(buffer + offset + 28u, &value, 4u);
    assert(pe_export_parse(&directory, &image) == PW_ERR_MALFORMED);

    /* An empty module name is not a usable export root. */
    value = 0u;
    memcpy(buffer + offset + 12u, &value, 4u);
    assert(pe_export_parse(&directory, &image) == PW_ERR_MALFORMED);
}

static void test_degenerate_inputs(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;

    base_spec(&spec, 0);
    spec.export_count = 1u;
    spec.exports[0].name = "Only";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = TEXT_RVA;
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    assert(pe_export_parse(NULL, &image) == PW_ERR_PRECONDITION);
    assert(pe_export_parse(&directory, NULL) == PW_ERR_PRECONDITION);
    assert(pe_export_find_name(&image, &directory, NULL, &symbol) ==
           PW_ERR_PRECONDITION);
    assert(pe_export_find_name(&image, &directory, "Only", NULL) ==
           PW_ERR_PRECONDITION);
    assert(pe_export_find_ordinal(&image, NULL, 1u, &symbol) ==
           PW_ERR_PRECONDITION);
    assert(pe_export_read_index(&image, &directory, 1u, &symbol) ==
           PW_ERR_MALFORMED);
}

static void test_duplicate_name_is_conflicting_data(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeExportDirectory directory;
    PeExportSymbol symbol;

    base_spec(&spec, 0);
    spec.export_count = 2u;
    spec.exports[0].name = "Twice";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = TEXT_RVA;
    spec.exports[1].name = "Twice";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = TEXT_RVA + 4u;
    (void)build(&spec, &image);
    assert(pe_export_parse(&directory, &image) == PW_OK);
    /* Two name entries claiming different function slots cannot both be the
     * definition, so the lookup refuses instead of picking one. */
    assert(pe_export_find_name(&image, &directory, "Twice", &symbol) ==
           PW_ERR_MALFORMED);
    /* An ordinal lookup does not consult the name table, so it still works. */
    assert(pe_export_find_ordinal(&image, &directory, 1u, &symbol) == PW_OK);
    assert(symbol.rva == TEXT_RVA);
}

int main(void)
{
    test_no_export_directory();
    test_name_and_ordinal_share_one_rva(0);
    test_name_and_ordinal_share_one_rva(1);
    test_forwarders_and_code_data_rule();
    test_malformed_forwarder_fails_closed();
    test_structural_rejections();
    test_degenerate_inputs();
    test_duplicate_name_is_conflicting_data();
    return 0;
}
