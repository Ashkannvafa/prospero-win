/*
 * x86 segment descriptors, encoded by hand.
 *
 * Reaching 32-bit compatibility mode needs a code descriptor whose L bit
 * is clear and whose D/B bit is set. User code cannot write a descriptor
 * table, but a kernel can install one on its behalf; this file produces the
 * 64-bit descriptor word to hand to whichever call does that, so the
 * encoding is testable without a platform.
 *
 * The layout is the architectural one, matching FreeBSD's
 * `struct user_segment_descriptor` field for field.
 */
#ifndef PROSPERO_WIN_SEGMENT_H
#define PROSPERO_WIN_SEGMENT_H

#include "../include/prospero_win.h"

/* Descriptor types, as FreeBSD's <x86/segments.h> numbers them. */
enum {
    PW_SEG_TYPE_DATA_RW = 18,       /* SDT_MEMRW  */
    PW_SEG_TYPE_DATA_RWA = 19,      /* SDT_MEMRWA */
    PW_SEG_TYPE_CODE_ER = 26,       /* SDT_MEMER  */
    PW_SEG_TYPE_CODE_ERA = 27,      /* SDT_MEMERA */
};

enum {
    PW_SEG_RING_USER = 3,
    PW_SEG_LDT_BIT = 4,             /* SEL_LDT */
    PW_SEG_LIMIT_4GIB = 0xfffffu,   /* with page granularity */
};

typedef struct PwSegmentFields {
    uint32_t base;
    uint32_t limit;                 /* in pages when page_granular */
    unsigned type;
    unsigned dpl;
    unsigned present;
    unsigned long_mode;             /* L: set only for 64-bit code */
    unsigned default32;             /* D/B */
    unsigned page_granular;         /* G */
} PwSegmentFields;

/* Packs fields into one descriptor word; 0 on invalid input. */
uint64_t pw_segment_encode(const PwSegmentFields *fields);

/* Reads a descriptor word back out, for verifying what a kernel installed. */
void pw_segment_decode(uint64_t descriptor, PwSegmentFields *fields);

/* The two descriptors a 32-bit user thunk needs. */
uint64_t pw_segment_compat32_code(void);
uint64_t pw_segment_compat32_data(void);

/* LSEL(index, rpl): a selector naming a local-descriptor-table entry. */
uint16_t pw_segment_ldt_selector(uint32_t index, unsigned rpl);

#endif
