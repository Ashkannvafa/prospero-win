/*
 * Base relocation: rebases an already mapped image when the preferred base
 * was unavailable.
 *
 * The directory is read out of the mapped image, not the file, because
 * .reloc lives inside a section. Unknown and HIGHADJ entry types fail
 * closed: silently skipping a relocation produces a wild pointer whose
 * fault appears far from its cause.
 */
#ifndef PROSPERO_WIN_PE_RELOC_H
#define PROSPERO_WIN_PE_RELOC_H

#include "pe_image.h"

enum {
    PE_RELOC_ABSOLUTE = 0,
    PE_RELOC_HIGH = 1,
    PE_RELOC_LOW = 2,
    PE_RELOC_HIGHLOW = 3,
    PE_RELOC_HIGHADJ = 4,
    PE_RELOC_DIR64 = 10,
};

typedef struct PeRelocStats {
    uint32_t blocks;
    uint32_t entries;       /* every entry walked, padding included */
    uint32_t applied;       /* entries that changed a mapped word */
    uint32_t absolute;      /* padding entries */
    uint32_t highlow;
    uint32_t dir64;
    uint32_t high_or_low;
    uint64_t delta;         /* actual_base - preferred_base, wrapping */
} PeRelocStats;

/*
 * mapped points at the writable alias of the whole image; addresses are
 * computed from actual_base, the address the code will run at, which is the
 * executable alias when the backend uses two mappings.
 */
int pe_reloc_apply(uint8_t *mapped, uint32_t image_bytes,
                   const PeDataDirectory *directory,
                   uint64_t preferred_base, uint64_t actual_base,
                   PeRelocStats *stats);

#endif
