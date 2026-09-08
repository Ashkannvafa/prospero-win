#include "pw_segment.h"

#include <string.h>

enum {
    SHIFT_LOLIMIT = 0,      /* 16 bits */
    SHIFT_LOBASE = 16,      /* 24 bits */
    SHIFT_TYPE = 40,        /* 5 bits  */
    SHIFT_DPL = 45,         /* 2 bits  */
    SHIFT_PRESENT = 47,
    SHIFT_HILIMIT = 48,     /* 4 bits  */
    SHIFT_LONG = 53,
    SHIFT_DEFAULT32 = 54,
    SHIFT_GRANULAR = 55,
    SHIFT_HIBASE = 56,      /* 8 bits  */
};

uint64_t pw_segment_encode(const PwSegmentFields *fields)
{
    uint64_t descriptor = 0;

    if (!fields || fields->limit > 0xfffffu || fields->type > 31u ||
        fields->dpl > 3u)
        return 0u;

    descriptor |= (uint64_t)(fields->limit & 0xffffu) << SHIFT_LOLIMIT;
    descriptor |= (uint64_t)(fields->base & 0xffffffu) << SHIFT_LOBASE;
    descriptor |= (uint64_t)(fields->type & 0x1fu) << SHIFT_TYPE;
    descriptor |= (uint64_t)(fields->dpl & 3u) << SHIFT_DPL;
    descriptor |= (uint64_t)(fields->present ? 1u : 0u) << SHIFT_PRESENT;
    descriptor |= (uint64_t)((fields->limit >> 16) & 0xfu) << SHIFT_HILIMIT;
    descriptor |= (uint64_t)(fields->long_mode ? 1u : 0u) << SHIFT_LONG;
    descriptor |= (uint64_t)(fields->default32 ? 1u : 0u) << SHIFT_DEFAULT32;
    descriptor |= (uint64_t)(fields->page_granular ? 1u : 0u) << SHIFT_GRANULAR;
    descriptor |= (uint64_t)((fields->base >> 24) & 0xffu) << SHIFT_HIBASE;
    return descriptor;
}

void pw_segment_decode(uint64_t descriptor, PwSegmentFields *fields)
{
    if (!fields)
        return;
    memset(fields, 0, sizeof(*fields));
    fields->limit = (uint32_t)((descriptor >> SHIFT_LOLIMIT) & 0xffffu) |
                    (uint32_t)(((descriptor >> SHIFT_HILIMIT) & 0xfu) << 16);
    fields->base = (uint32_t)((descriptor >> SHIFT_LOBASE) & 0xffffffu) |
                   (uint32_t)(((descriptor >> SHIFT_HIBASE) & 0xffu) << 24);
    fields->type = (unsigned)((descriptor >> SHIFT_TYPE) & 0x1fu);
    fields->dpl = (unsigned)((descriptor >> SHIFT_DPL) & 3u);
    fields->present = (unsigned)((descriptor >> SHIFT_PRESENT) & 1u);
    fields->long_mode = (unsigned)((descriptor >> SHIFT_LONG) & 1u);
    fields->default32 = (unsigned)((descriptor >> SHIFT_DEFAULT32) & 1u);
    fields->page_granular = (unsigned)((descriptor >> SHIFT_GRANULAR) & 1u);
}

uint64_t pw_segment_compat32_code(void)
{
    const PwSegmentFields fields = {
        .base = 0u,
        .limit = PW_SEG_LIMIT_4GIB,
        .type = PW_SEG_TYPE_CODE_ERA,
        .dpl = PW_SEG_RING_USER,
        .present = 1u,
        .long_mode = 0u,        /* L clear is what selects compatibility mode */
        .default32 = 1u,
        .page_granular = 1u,
    };

    return pw_segment_encode(&fields);
}

uint64_t pw_segment_compat32_data(void)
{
    const PwSegmentFields fields = {
        .base = 0u,
        .limit = PW_SEG_LIMIT_4GIB,
        .type = PW_SEG_TYPE_DATA_RWA,
        .dpl = PW_SEG_RING_USER,
        .present = 1u,
        .long_mode = 0u,
        .default32 = 1u,
        .page_granular = 1u,
    };

    return pw_segment_encode(&fields);
}

uint16_t pw_segment_ldt_selector(uint32_t index, unsigned rpl)
{
    return (uint16_t)((index << 3) | PW_SEG_LDT_BIT | (rpl & 3u));
}
