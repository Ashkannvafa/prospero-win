#include "../src/pw_segment.h"

#include <assert.h>

static void test_canonical_encodings(void)
{
    /*
     * These are the architectural values every x86-64 kernel uses for its
     * 32-bit ring-3 segments, so they double as an independent check that
     * the field packing here is right rather than merely self-consistent.
     */
    assert(pw_segment_compat32_code() == 0x00cffb000000ffffull);
    assert(pw_segment_compat32_data() == 0x00cff3000000ffffull);
}

static void test_bit_positions(void)
{
    PwSegmentFields fields = {0};
    uint64_t descriptor;

    /* The L bit is the one that chooses 64-bit over compatibility mode. */
    fields.limit = PW_SEG_LIMIT_4GIB;
    fields.type = PW_SEG_TYPE_CODE_ERA;
    fields.dpl = PW_SEG_RING_USER;
    fields.present = 1u;
    fields.default32 = 1u;
    fields.page_granular = 1u;
    descriptor = pw_segment_encode(&fields);
    assert(descriptor == pw_segment_compat32_code());
    assert(((descriptor >> 53) & 1u) == 0u);        /* L clear   */
    assert(((descriptor >> 54) & 1u) == 1u);        /* D/B set   */
    assert(((descriptor >> 55) & 1u) == 1u);        /* granular  */
    assert(((descriptor >> 47) & 1u) == 1u);        /* present   */
    assert(((descriptor >> 45) & 3u) == 3u);        /* ring 3    */

    fields.long_mode = 1u;
    descriptor = pw_segment_encode(&fields);
    assert(((descriptor >> 53) & 1u) == 1u);
    assert(descriptor != pw_segment_compat32_code());
}

static void test_base_and_limit_split(void)
{
    PwSegmentFields fields = {0};
    PwSegmentFields decoded;
    uint64_t descriptor;

    fields.base = 0xdeadbeefu;
    fields.limit = 0xabcdeu;
    fields.type = PW_SEG_TYPE_DATA_RWA;
    fields.dpl = 2u;
    fields.present = 1u;
    fields.default32 = 1u;
    fields.page_granular = 1u;
    descriptor = pw_segment_encode(&fields);

    /* Base and limit are split across non-adjacent fields; round-trip them. */
    pw_segment_decode(descriptor, &decoded);
    assert(decoded.base == 0xdeadbeefu);
    assert(decoded.limit == 0xabcdeu);
    assert(decoded.type == PW_SEG_TYPE_DATA_RWA);
    assert(decoded.dpl == 2u);
    assert(decoded.present == 1u);
    assert(decoded.long_mode == 0u);
    assert(decoded.default32 == 1u);
    assert(decoded.page_granular == 1u);

    pw_segment_decode(pw_segment_compat32_code(), &decoded);
    assert(decoded.base == 0u);
    assert(decoded.limit == PW_SEG_LIMIT_4GIB);
    assert(decoded.type == PW_SEG_TYPE_CODE_ERA);
}

static void test_rejects_impossible_fields(void)
{
    PwSegmentFields fields = {0};

    fields.limit = 0x100000u;               /* wider than 20 bits */
    assert(pw_segment_encode(&fields) == 0u);
    fields.limit = 0u;
    fields.type = 32u;
    assert(pw_segment_encode(&fields) == 0u);
    fields.type = 0u;
    fields.dpl = 4u;
    assert(pw_segment_encode(&fields) == 0u);
    assert(pw_segment_encode(NULL) == 0u);
    pw_segment_decode(0u, NULL);            /* must not fault */
}

static void test_selectors(void)
{
    /* LSEL(0, 3) and LSEL(1, 3): local table, ring 3. */
    assert(pw_segment_ldt_selector(0u, PW_SEG_RING_USER) == 0x0007u);
    assert(pw_segment_ldt_selector(1u, PW_SEG_RING_USER) == 0x000fu);
    assert(pw_segment_ldt_selector(2u, PW_SEG_RING_USER) == 0x0017u);
    assert(pw_segment_ldt_selector(0u, 0u) == 0x0004u);
}

int main(void)
{
    test_canonical_encodings();
    test_bit_positions();
    test_base_and_limit_split();
    test_rejects_impossible_fields();
    test_selectors();
    return 0;
}
