/*
 * Mapped layout: turns a parsed PeImage into the exact reservation,
 * per-section copy/zero spans and page protections a manual mapper needs.
 *
 * This is where an image is accepted or refused as mappable. It performs no
 * allocation and touches no memory outside the caller's PeLayout.
 */
#ifndef PROSPERO_WIN_PE_LAYOUT_H
#define PROSPERO_WIN_PE_LAYOUT_H

#include "pe_image.h"

typedef struct PeLayoutSection {
    char name[PE_SECTION_NAME_BYTES + 1];
    uint32_t rva;
    uint32_t mapped_bytes;      /* section-aligned span reserved for it */
    uint32_t virtual_bytes;     /* effective VirtualSize */
    uint32_t raw_offset;        /* file offset of the initialised bytes */
    uint32_t raw_bytes;         /* bytes copied from the file */
    uint32_t zero_bytes;        /* mapped_bytes - raw_bytes, zero filled */
    uint32_t characteristics;
    uint8_t protection;         /* PW_PROT_* applied after relocation */
    uint8_t uninitialized;      /* .bss style section */
    uint8_t discardable;
    uint8_t derived_protection; /* protection was normalised, not declared */
} PeLayoutSection;

typedef struct PeLayout {
    uint64_t preferred_base;
    uint32_t image_bytes;       /* reservation size */
    uint32_t header_bytes;      /* copied verbatim from file offset 0 */
    uint32_t section_alignment;
    uint32_t entry_point;
    uint32_t section_count;
    uint64_t exec_bytes;
    uint64_t write_bytes;
    uint64_t copy_bytes;
    uint64_t zero_bytes;
    uint8_t relocatable;        /* a non-empty base-relocation directory */
    uint8_t dynamic_base;       /* image opted in to relocation */
    uint8_t nx_compat;
    PeLayoutSection sections[PE_MAX_SECTIONS];
} PeLayout;

/*
 * Refuses, with PW_ERR_UNSUPPORTED or PW_ERR_MALFORMED: a section alignment
 * below one page, overlapping or unordered sections, sections outside
 * SizeOfImage, headers larger than the file and a preferred base that is
 * not section aligned.
 */
int pe_layout_plan(PeLayout *layout, const PeImage *image);

/* PW_PROT_* derived from one section's characteristics. */
unsigned pe_layout_protection(uint32_t characteristics, int *derived);

#endif
