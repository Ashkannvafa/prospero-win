/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_GUEST_HEAP_H
#define PW_GUEST_HEAP_H
#include "../include/prospero_win.h"
typedef struct PwHeapBlock { uint32_t offset,size,requested,used; } PwHeapBlock;
typedef struct PwGuestHeap {
    uint32_t base,bytes,count,capacity;
    PwHeapBlock *blocks;
} PwGuestHeap;
/* Owner supplies live identity-mapped RW memory below 4 GiB and nonoverlapping
 * host metadata. Both outlive the heap. No mapping or locking is performed.
 * 16-byte aligned first-fit blocks; free neighbors coalesce. Zero-size alloc
 * returns a unique freeable block. LIMIT means storage/metadata exhaustion;
 * invalid pointers/state are classified errors. Output unchanged on failure.
 * realloc(p,0) frees; realloc(NULL,n) allocates, including n==0. */
int pw_guest_heap_init(PwGuestHeap *,uint32_t base,uint32_t bytes,PwHeapBlock *,uint32_t capacity);
int pw_guest_heap_validate(const PwGuestHeap *);
int pw_guest_heap_alloc(PwGuestHeap *,uint32_t bytes,uint32_t *address);
int pw_guest_heap_calloc(PwGuestHeap *,uint32_t count,uint32_t bytes,uint32_t *address);
int pw_guest_heap_free(PwGuestHeap *,uint32_t address);
int pw_guest_heap_realloc(PwGuestHeap *,uint32_t address,uint32_t bytes,uint32_t *result);
#endif
