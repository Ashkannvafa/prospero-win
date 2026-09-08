/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pe_reloc.h"

#include <assert.h>
#include <string.h>

enum {
    IMAGE_BYTES = 0x4000u,
    DIR_RVA = 0x2000u,
    TARGET_PAGE = 0x1000u,
};

static uint8_t mapped[IMAGE_BYTES];

static void put_u16(uint32_t offset, uint16_t value)
{
    memcpy(mapped + offset, &value, sizeof(value));
}

static void put_u32(uint32_t offset, uint32_t value)
{
    memcpy(mapped + offset, &value, sizeof(value));
}

static void put_u64(uint32_t offset, uint64_t value)
{
    memcpy(mapped + offset, &value, sizeof(value));
}

static uint32_t get_u32(uint32_t offset)
{
    uint32_t value;

    memcpy(&value, mapped + offset, sizeof(value));
    return value;
}

static uint64_t get_u64(uint32_t offset)
{
    uint64_t value;

    memcpy(&value, mapped + offset, sizeof(value));
    return value;
}

static uint16_t get_u16(uint32_t offset)
{
    uint16_t value;

    memcpy(&value, mapped + offset, sizeof(value));
    return value;
}

/* Writes one relocation block and returns its byte size. */
static uint32_t put_block(uint32_t offset, uint32_t page,
                          const uint16_t *entries, uint32_t count)
{
    const uint32_t bytes = 8u + ((count * 2u + 3u) & ~3u);

    put_u32(offset, page);
    put_u32(offset + 4u, bytes);
    for (uint32_t index = 0; index < count; ++index)
        put_u16(offset + 8u + index * 2u, entries[index]);
    for (uint32_t index = count * 2u; index < bytes - 8u; ++index)
        mapped[offset + 8u + index] = 0u;
    return bytes;
}

static uint16_t entry(uint32_t type, uint32_t offset)
{
    return (uint16_t)((type << 12) | (offset & 0x0fffu));
}

static PeDataDirectory directory(uint32_t size)
{
    PeDataDirectory value;

    value.virtual_address = DIR_RVA;
    value.size = size;
    return value;
}

static void reset(void)
{
    memset(mapped, 0, sizeof(mapped));
}

static void test_applies_dir64_and_highlow(void)
{
    uint16_t table[3];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    put_u64(TARGET_PAGE + 0x10u, 0x140001234ull);
    put_u32(TARGET_PAGE + 0x20u, 0x00401234u);
    table[0] = entry(PE_RELOC_DIR64, 0x10u);
    table[1] = entry(PE_RELOC_HIGHLOW, 0x20u);
    table[2] = entry(PE_RELOC_ABSOLUTE, 0u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 3u);
    dir = directory(bytes);

    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x140000000ull,
                          0x180000000ull, &stats) == PW_OK);
    assert(stats.blocks == 1u);
    /* The block is padded to four bytes, so a fourth ABSOLUTE entry exists. */
    assert(stats.entries == 4u);
    assert(stats.applied == 2u);
    assert(stats.absolute == 2u);
    assert(stats.dir64 == 1u);
    assert(stats.highlow == 1u);
    assert(stats.delta == 0x40000000ull);
    assert(get_u64(TARGET_PAGE + 0x10u) == 0x180001234ull);
    /* HIGHLOW adds only the low 32 bits of the delta. */
    assert(get_u32(TARGET_PAGE + 0x20u) == 0x40401234u);
}

static void test_zero_delta_counts_without_writing(void)
{
    uint16_t table[1];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    put_u64(TARGET_PAGE + 0x10u, 0x140001234ull);
    table[0] = entry(PE_RELOC_DIR64, 0x10u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 1u);
    dir = directory(bytes);

    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x140000000ull,
                          0x140000000ull, &stats) == PW_OK);
    assert(stats.entries == 2u);        /* one real entry plus block padding */
    assert(stats.dir64 == 1u);
    assert(stats.applied == 0u);
    assert(get_u64(TARGET_PAGE + 0x10u) == 0x140001234ull);
}

static void test_applies_high_and_low(void)
{
    uint16_t table[2];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    put_u16(TARGET_PAGE + 0x30u, 0x0040u);
    put_u16(TARGET_PAGE + 0x40u, 0x1234u);
    table[0] = entry(PE_RELOC_HIGH, 0x30u);
    table[1] = entry(PE_RELOC_LOW, 0x40u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 2u);
    dir = directory(bytes);

    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x1500000u,
                          &stats) == PW_OK);
    assert(stats.high_or_low == 2u);
    assert(stats.applied == 2u);
    /* delta is 0x1100000: high half 0x0110, low half 0x0000. */
    assert(get_u16(TARGET_PAGE + 0x30u) == 0x0150u);
    assert(get_u16(TARGET_PAGE + 0x40u) == 0x1234u);
}

static void test_missing_directory(void)
{
    PeRelocStats stats;
    PeDataDirectory dir;

    reset();
    dir.virtual_address = 0u;
    dir.size = 0u;
    /* Nothing to rebase and nothing asked: fine. */
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x140000000ull,
                          0x140000000ull, &stats) == PW_OK);
    /* A rebase without a relocation table cannot be honoured. */
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x140000000ull,
                          0x180000000ull, &stats) == PW_ERR_UNSUPPORTED);
}

/*
 * Found by mutation fuzzing: an image whose data-directory array is too
 * short to contain the base-relocation slot made pe_image_directory()
 * return NULL, and the mapper reported a caller-error precondition for a
 * perfectly well-formed image.
 */
static void test_absent_directory_is_not_a_caller_error(void)
{
    PeRelocStats stats;

    reset();
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, NULL, 0x140000000ull,
                          0x140000000ull, &stats) == PW_OK);
    assert(stats.entries == 0u);
    assert(stats.applied == 0u);
    /* Still unrebaseable, and reported as exactly that. */
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, NULL, 0x140000000ull,
                          0x180000000ull, &stats) == PW_ERR_UNSUPPORTED);
}

static void test_refuses_unknown_types(void)
{
    uint16_t table[1];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    table[0] = entry(PE_RELOC_HIGHADJ, 0x10u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 1u);
    dir = directory(bytes);
    /* HIGHADJ consumes a second word; skipping it would desynchronise. */
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_UNSUPPORTED);

    reset();
    table[0] = entry(9u, 0x10u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 1u);
    dir = directory(bytes);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_UNSUPPORTED);
}

static void test_refuses_malformed_blocks(void)
{
    PeRelocStats stats;
    PeDataDirectory dir;

    reset();
    put_u32(DIR_RVA, TARGET_PAGE);
    put_u32(DIR_RVA + 4u, 7u);              /* smaller than a block header */
    dir = directory(16u);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);

    reset();
    put_u32(DIR_RVA, TARGET_PAGE);
    put_u32(DIR_RVA + 4u, 11u);             /* odd entry area */
    dir = directory(16u);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);

    reset();
    put_u32(DIR_RVA, TARGET_PAGE);
    put_u32(DIR_RVA + 4u, 64u);             /* larger than the directory */
    dir = directory(16u);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);

    reset();
    put_u32(DIR_RVA, IMAGE_BYTES);          /* block page outside the image */
    put_u32(DIR_RVA + 4u, 12u);
    dir = directory(16u);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);
}

static void test_refuses_target_outside_image(void)
{
    uint16_t table[1];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    /* Last page of the image, offset that spills past the end. */
    table[0] = entry(PE_RELOC_DIR64, 0xffcu);
    bytes = put_block(DIR_RVA, IMAGE_BYTES - 0x1000u, table, 1u);
    dir = directory(bytes);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);
}

static void test_directory_outside_image(void)
{
    PeRelocStats stats;
    PeDataDirectory dir;

    reset();
    dir.virtual_address = IMAGE_BYTES - 4u;
    dir.size = 64u;
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x400000u, 0x500000u,
                          &stats) == PW_ERR_MALFORMED);
}

static void test_zero_block_terminates(void)
{
    uint16_t table[1];
    PeRelocStats stats;
    PeDataDirectory dir;
    uint32_t bytes;

    reset();
    put_u64(TARGET_PAGE + 0x10u, 0x140001234ull);
    table[0] = entry(PE_RELOC_DIR64, 0x10u);
    bytes = put_block(DIR_RVA, TARGET_PAGE, table, 1u);
    put_u32(DIR_RVA + bytes, 0u);
    put_u32(DIR_RVA + bytes + 4u, 0u);
    dir = directory(bytes + 32u);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0x140000000ull,
                          0x180000000ull, &stats) == PW_OK);
    assert(stats.blocks == 1u);
    assert(stats.applied == 1u);
}

static void test_preconditions(void)
{
    PeRelocStats stats;
    PeDataDirectory dir = directory(16u);

    assert(pe_reloc_apply(NULL, IMAGE_BYTES, &dir, 0u, 0u, &stats) ==
           PW_ERR_PRECONDITION);
    assert(pe_reloc_apply(mapped, 0u, &dir, 0u, 0u, &stats) ==
           PW_ERR_PRECONDITION);
    assert(pe_reloc_apply(mapped, IMAGE_BYTES, &dir, 0u, 0u, NULL) ==
           PW_ERR_PRECONDITION);
}

int main(void)
{
    test_applies_dir64_and_highlow();
    test_zero_delta_counts_without_writing();
    test_applies_high_and_low();
    test_missing_directory();
    test_absent_directory_is_not_a_caller_error();
    test_refuses_unknown_types();
    test_refuses_malformed_blocks();
    test_refuses_target_outside_image();
    test_directory_outside_image();
    test_zero_block_terminates();
    test_preconditions();
    return 0;
}
