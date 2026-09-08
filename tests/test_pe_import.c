/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include <assert.h>
#include <string.h>

static uint8_t buffer[128 * 1024];
static const uint8_t code[64] = {0xc3};

static void base_spec(PeFixtureSpec *spec, int pe32plus)
{
    memset(spec, 0, sizeof(*spec));
    spec->pe32plus = pe32plus;
    spec->image_base = pe32plus ? 0x140000000ull : 0x400000ull;
    spec->section_count = 1u;
    spec->sections[0].name = ".text";
    spec->sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec->sections[0].data = code;
    spec->sections[0].data_bytes = (uint32_t)sizeof(code);
    spec->entry_point = 0x1000u;
}

static void test_no_import_directory(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeImportTable table;
    size_t size;

    base_spec(&spec, 1);
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    /* An image with no imports is valid, not an error. */
    assert(pe_import_parse(&table, &image) == PW_OK);
    assert(table.module_count == 0u);
    assert(table.symbol_count == 0u);
}

static void test_named_and_ordinal_imports(int pe32plus)
{
    PeFixtureSpec spec;
    PeImage image;
    PeImportTable table;
    PeImportSymbol symbols[8];
    uint32_t count = 0;
    size_t size;

    base_spec(&spec, pe32plus);
    spec.import_count = 2u;
    spec.imports[0].dll = "binkw32.dll";
    spec.imports[0].names[0] = "BinkOpen";
    spec.imports[0].names[1] = "BinkClose";
    spec.imports[0].names[2] = "BinkDoFrame";
    spec.imports[1].dll = "KERNEL32.dll";
    spec.imports[1].names[0] = "CreateFileA";
    spec.imports[1].ordinals[0] = 0x0123u;
    spec.imports[1].ordinals[1] = 0x0456u;
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_import_parse(&table, &image) == PW_OK);

    assert(table.module_count == 2u);
    assert(strcmp(table.modules[0].name, "binkw32.dll") == 0);
    assert(table.modules[0].named_count == 3u);
    assert(table.modules[0].ordinal_count == 0u);
    assert(table.modules[0].lookup_table_rva != 0u);
    assert(table.modules[0].address_table_rva != 0u);
    assert(table.modules[0].bound == 0u);

    /* Case is preserved by the parser; canonicalisation happens elsewhere. */
    assert(strcmp(table.modules[1].name, "KERNEL32.dll") == 0);
    assert(table.modules[1].named_count == 1u);
    assert(table.modules[1].ordinal_count == 2u);
    assert(table.symbol_count == 6u);

    assert(pe_import_enumerate(&image, &table.modules[0], symbols, 8u,
                               &count) == PW_OK);
    assert(count == 3u);
    assert(strcmp(symbols[0].name, "BinkOpen") == 0);
    assert(symbols[0].by_ordinal == 0u);
    assert(symbols[0].hint == 1u);
    assert(symbols[0].thunk_rva == table.modules[0].address_table_rva);
    assert(strcmp(symbols[2].name, "BinkDoFrame") == 0);
    assert(symbols[2].thunk_rva ==
           table.modules[0].address_table_rva + (pe32plus ? 16u : 8u));

    assert(pe_import_enumerate(&image, &table.modules[1], symbols, 8u,
                               &count) == PW_OK);
    assert(count == 3u);
    assert(symbols[0].by_ordinal == 0u);
    assert(strcmp(symbols[0].name, "CreateFileA") == 0);
    assert(symbols[1].by_ordinal == 1u);
    assert(symbols[1].ordinal == 0x0123u);
    assert(symbols[1].name[0] == '\0');
    assert(symbols[2].by_ordinal == 1u);
    assert(symbols[2].ordinal == 0x0456u);

    /* Capacity is a hard bound, not a truncation hint. */
    assert(pe_import_enumerate(&image, &table.modules[1], symbols, 2u,
                               &count) == PW_ERR_LIMIT);
    assert(pe_import_enumerate(&image, NULL, symbols, 8u, &count) ==
           PW_ERR_PRECONDITION);
}

static void test_bound_image_without_lookup_table(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeImportTable table;
    PeImportSymbol symbols[4];
    uint32_t count = 0;
    size_t size;

    base_spec(&spec, 1);
    spec.omit_lookup_table = 1;
    spec.import_count = 1u;
    spec.imports[0].dll = "mss32.dll";
    spec.imports[0].names[0] = "AIL_startup";
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(pe_import_parse(&table, &image) == PW_OK);
    assert(table.module_count == 1u);
    assert(table.modules[0].lookup_table_rva == 0u);
    assert(table.modules[0].named_count == 1u);
    /* With no OriginalFirstThunk the address table is the only source. */
    assert(pe_import_enumerate(&image, &table.modules[0], symbols, 4u,
                               &count) == PW_OK);
    assert(count == 1u);
    assert(strcmp(symbols[0].name, "AIL_startup") == 0);
}

static void test_rejects_malformed_descriptor(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeImportTable table;
    const PeDataDirectory *directory;
    size_t descriptor;
    size_t size;

    base_spec(&spec, 1);
    spec.import_count = 1u;
    spec.imports[0].dll = "binkw32.dll";
    spec.imports[0].names[0] = "BinkOpen";
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    directory = pe_image_directory(&image, PE_DIR_IMPORT);
    assert(directory != NULL);
    assert(pe_image_file_offset(&image, directory->virtual_address,
                                PE_IMPORT_DESCRIPTOR_BYTES, &descriptor) ==
           PW_OK);

    /* A descriptor with a name but no address table is not usable. */
    memset(buffer + descriptor + 16u, 0, 4u);
    assert(pe_import_parse(&table, &image) == PW_ERR_MALFORMED);

    /* A name RVA outside every section fails closed. */
    (void)pe_fixture_build(buffer, sizeof(buffer), &spec);
    buffer[descriptor + 12u] = 0x00u;
    buffer[descriptor + 13u] = 0x00u;
    buffer[descriptor + 14u] = 0x90u;
    buffer[descriptor + 15u] = 0x00u;
    assert(pe_import_parse(&table, &image) == PW_ERR_NOT_FOUND);
}

int main(void)
{
    test_no_import_directory();
    test_named_and_ordinal_imports(1);
    test_named_and_ordinal_imports(0);
    test_bound_image_without_lookup_table();
    test_rejects_malformed_descriptor();
    return 0;
}
