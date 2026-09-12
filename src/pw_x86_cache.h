/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_X86_CACHE_H
#define PW_X86_CACHE_H
#include "pw_x86_block.h"

typedef struct PwX86CacheEntry {
    uint32_t guest_pc,generation;
    size_t code_offset,code_bytes,source_bytes;
    uint32_t instructions;
    uint16_t instruction_ends[32];
    unsigned used;
} PwX86CacheEntry;

typedef struct PwX86Cache {
    PwX86CacheEntry *entries;
    uint32_t capacity,generation;
    size_t arena_bytes,cursor;
    uint64_t hits,misses,publishes,resets,lookup_probes;
    uint32_t max_probe;
} PwX86Cache;

/* Generated code storage and RW/RX transitions remain owner-managed. Entries
 * use open addressing keyed by guest PC, making hot dispatch O(1) average
 * rather than scanning the complete capacity. A generation is valid only
 * while its immutable guest image mapping is alive. */
int pw_x86_cache_init(PwX86Cache *,PwX86CacheEntry *,uint32_t,size_t,uint32_t);
int pw_x86_cache_lookup(PwX86Cache *,uint32_t,const PwX86CacheEntry **);
int pw_x86_cache_publish(PwX86Cache *,uint32_t,const PwX86Block *,size_t,
                         const PwX86CacheEntry **);
int pw_x86_cache_reset(PwX86Cache *,uint32_t);
#endif
