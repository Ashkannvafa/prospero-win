/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include <assert.h>
#include <string.h>

static uint8_t buffer[64 * 1024];

static const uint8_t code[64] = {0x90, 0x90, 0xc3};

static size_t build_basic(int pe32plus, uint16_t machine)
{
    PeFixtureSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = pe32plus;
    spec.machine = machine;
    spec.image_base = pe32plus ? 0x140000000ull : 0x400000ull;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = code;
    spec.sections[1].data_bytes = 16u;
    spec.sections[1].virtual_size = 0x2000u;
    spec.entry_point = 0x1000u;
    return pe_fixture_build(buffer, sizeof(buffer), &spec);
}

static void test_parses_pe32plus(void)
{
    const size_t size = build_basic(1, 0);
    PeImage image;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(image.machine == PE_MACHINE_AMD64);
    assert(pe_image_machine_is_native(&image));
    assert(strcmp(pe_image_machine_name(&image), "amd64") == 0);
    assert(image.optional_magic == PE_OPT_MAGIC_PE32PLUS);
    assert(image.image_base == 0x140000000ull);
    assert(image.section_count == 2u);
    assert(image.section_alignment == 0x1000u);
    assert(image.file_alignment == 0x200u);
    assert(image.entry_point == 0x1000u);
    assert(image.directory_count == PE_DIRECTORY_ENTRIES);
    assert(!pe_image_is_dll(&image));
    assert(strcmp(image.sections[0].name, ".text") == 0);
    assert(strcmp(image.sections[1].name, ".data") == 0);
    assert(image.sections[1].virtual_size == 0x2000u);
    /* File alignment padding makes SizeOfRawData exceed the payload. */
    assert(image.sections[0].raw_size == 0x200u);
}

static void test_parses_pe32(void)
{
    const size_t size = build_basic(0, 0);
    PeImage image;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    assert(image.machine == PE_MACHINE_I386);
    assert(image.optional_magic == PE_OPT_MAGIC_PE32);
    assert(image.image_base == 0x400000u);
    /* An i386 image parses and maps but cannot execute on this hardware. */
    assert(!pe_image_machine_is_native(&image));
    assert(strcmp(pe_image_machine_name(&image), "i386") == 0);
}

static void test_rejects_non_pe(void)
{
    PeImage image;
    uint8_t junk[512];

    memset(junk, 0, sizeof(junk));
    assert(pe_image_parse(&image, junk, 8u) == PW_ERR_TRUNCATED);
    assert(pe_image_parse(&image, junk, sizeof(junk)) == PW_ERR_NOT_PE);

    /* MZ present, PE signature absent. */
    junk[0] = 'M';
    junk[1] = 'Z';
    junk[0x3c] = 0x40;
    assert(pe_image_parse(&image, junk, sizeof(junk)) == PW_ERR_NOT_PE);
    assert(pe_image_parse(&image, NULL, sizeof(junk)) == PW_ERR_PRECONDITION);
}

static void test_rejects_bad_nt_offset(void)
{
    const size_t size = build_basic(1, 0);
    PeImage image;

    assert(size != 0u);
    buffer[0x3c] = 0x41;                    /* misaligned e_lfanew */
    assert(pe_image_parse(&image, buffer, size) == PW_ERR_MALFORMED);

    (void)build_basic(1, 0);
    buffer[0x3c] = 0x08;                    /* inside the DOS header */
    assert(pe_image_parse(&image, buffer, size) == PW_ERR_MALFORMED);

    (void)build_basic(1, 0);
    buffer[0x3c] = 0x00;
    buffer[0x3d] = 0x00;
    buffer[0x3e] = 0x10;
    buffer[0x3f] = 0x00;                    /* 0x100000, past the end */
    assert(pe_image_parse(&image, buffer, size) == PW_ERR_TRUNCATED);
}

static void test_rejects_foreign_machine(void)
{
    const size_t size = build_basic(1, 0xaa64u);    /* arm64 */
    PeImage image;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_ERR_UNSUPPORTED);
}

static void test_rejects_zero_sections(void)
{
    const size_t size = build_basic(1, 0);
    PeImage image;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    /* NumberOfSections lives at nt_offset + 6. */
    buffer[image.nt_offset + 6u] = 0u;
    buffer[image.nt_offset + 7u] = 0u;
    assert(pe_image_parse(&image, buffer, size) == PW_ERR_MALFORMED);
}

static void test_rejects_truncated_section_bytes(void)
{
    const size_t size = build_basic(1, 0);
    PeImage image;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);
    /* The same bytes, declared shorter than the section table claims. */
    assert(pe_image_parse(&image, buffer, size - 1u) == PW_ERR_TRUNCATED);
}

static void test_rva_translation(void)
{
    const size_t size = build_basic(1, 0);
    PeImage image;
    const PeSection *section;
    size_t offset;

    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);

    section = pe_image_section_for_rva(&image, 0x1000u);
    assert(section && strcmp(section->name, ".text") == 0);
    assert(pe_image_section_for_rva(&image, 0x0u) == NULL);
    assert(pe_image_section_for_rva(&image, 0x900000u) == NULL);

    assert(pe_image_file_offset(&image, 0x1000u, 3u, &offset) == PW_OK);
    assert(memcmp(buffer + offset, code, 3u) == 0);

    /* The header region maps one to one onto the file. */
    assert(pe_image_file_offset(&image, 0x40u, 4u, &offset) == PW_OK);
    assert(offset == 0x40u);

    /* An address inside the uninitialised tail has no bytes on disk. */
    assert(pe_image_file_offset(&image, 0x2000u + 0x1000u, 4u, &offset) ==
           PW_ERR_NOT_FOUND);
    assert(pe_image_file_offset(&image, 0x900000u, 4u, &offset) ==
           PW_ERR_NOT_FOUND);
    assert(pe_image_file_offset(&image, 0x1000u, 0u, &offset) ==
           PW_ERR_PRECONDITION);
}

static void test_reads_names(void)
{
    PeFixtureSpec spec;
    PeImage image;
    size_t size;
    char name[PW_MODULE_NAME_MAX + 1];
    const PeDataDirectory *directory;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 1;
    spec.image_base = 0x140000000ull;
    spec.section_count = 1u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.import_count = 1u;
    spec.imports[0].dll = "BINKW32.dll";
    spec.imports[0].names[0] = "BinkOpen";
    size = pe_fixture_build(buffer, sizeof(buffer), &spec);
    assert(size != 0u);
    assert(pe_image_parse(&image, buffer, size) == PW_OK);

    directory = pe_image_directory(&image, PE_DIR_IMPORT);
    assert(directory && directory->virtual_address != 0u);
    assert(pe_image_directory(&image, 99u) == NULL);

    /* The descriptor's Name field is at descriptor + 12. */
    size_t descriptor;
    assert(pe_image_file_offset(&image, directory->virtual_address,
                                PE_IMPORT_DESCRIPTOR_BYTES, &descriptor) ==
           PW_OK);
    const uint32_t name_rva = (uint32_t)buffer[descriptor + 12] |
                              ((uint32_t)buffer[descriptor + 13] << 8) |
                              ((uint32_t)buffer[descriptor + 14] << 16) |
                              ((uint32_t)buffer[descriptor + 15] << 24);
    assert(pe_image_read_name(&image, name_rva, name, sizeof(name)) == PW_OK);
    assert(strcmp(name, "BINKW32.dll") == 0);
    assert(pe_image_read_name(&image, name_rva, name, 4u) == PW_ERR_LIMIT);
    assert(pe_image_read_name(&image, 0x900000u, name, sizeof(name)) ==
           PW_ERR_NOT_FOUND);
}

static void test_result_names(void)
{
    assert(strcmp(pw_result_name(PW_OK), "ok") == 0);
    assert(strcmp(pw_result_name(PW_ERR_NOT_PE), "not-pe") == 0);
    assert(strcmp(pw_result_name(-999), "unknown") == 0);
    assert(strcmp(pw_protection_name(PW_PROT_READ | PW_PROT_EXEC), "r-x") == 0);
    assert(strcmp(pw_protection_name(PW_PROT_NONE), "---") == 0);
    assert(strcmp(pw_protection_name(PW_PROT_READ | PW_PROT_WRITE), "rw-") == 0);
}

int main(void)
{
    test_parses_pe32plus();
    test_parses_pe32();
    test_rejects_non_pe();
    test_rejects_bad_nt_offset();
    test_rejects_foreign_machine();
    test_rejects_zero_sections();
    test_rejects_truncated_section_bytes();
    test_rva_translation();
    test_reads_names();
    test_result_names();
    return 0;
}
