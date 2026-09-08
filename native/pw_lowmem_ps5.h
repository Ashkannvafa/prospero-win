/*
 * Low-address availability, measured from inside the title.
 *
 * A JIT recompilation route for 32-bit guests needs the guest's images,
 * stacks and heap below 4 GiB, so that a 32-bit register used as an address
 * is already the correct 64-bit address — writing a 32-bit register zeroes
 * the upper half, so no address translation is needed at all. If low memory
 * is unobtainable, every memory operand has to be rewritten instead, which
 * changes the cost of that route substantially.
 *
 * An `elfldr` payload can obtain 3 GiB contiguous below 4 GiB and can make
 * it read-execute and read-write-execute. A payload is more privileged than
 * a title, so the number that matters is the one measured here.
 */
#ifndef PROSPERO_WIN_LOWMEM_PS5_H
#define PROSPERO_WIN_LOWMEM_PS5_H

#include "../include/prospero_win.h"

typedef struct PwLowMemResult {
    uint64_t requested_bytes;
    uint64_t address;           /* 0 when the request was declined */
    uint8_t below_four_gib;     /* the whole span, not just its start */
    uint8_t honoured_hint;      /* the address came back as asked */
} PwLowMemResult;

typedef struct PwLowMemReport {
    uint32_t attempts;
    uint64_t largest_low_bytes; /* biggest span obtained entirely below 4 GiB */
    uint64_t largest_low_base;
    int write_read_ok;
    int mprotect_rx;            /* 0 on success, else errno */
    int mprotect_rwx;           /* 0 on success, else errno */
    PwLowMemResult results[8];
} PwLowMemReport;

/*
 * Requests progressively larger spans at a low hint and reports what was
 * granted. Uses hints only: MAP_FIXED replaces live mappings on this
 * firmware and MAP_EXCL is ignored, so it is never used here.
 */
int pw_lowmem_ps5_probe(PwLowMemReport *report);

#endif
