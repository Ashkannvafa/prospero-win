/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x86_cache.h"
#include <string.h>

int pw_x86_cache_init(PwX86Cache *cache,PwX86CacheEntry *entries,uint32_t capacity,
                      size_t arena_bytes,uint32_t generation)
{
    if(!cache || !entries || !capacity || !arena_bytes || !generation)
        return PW_ERR_PRECONDITION;
    memset(entries,0,sizeof(*entries)*capacity);
    *cache=(PwX86Cache){.entries=entries,.capacity=capacity,
                       .generation=generation,.arena_bytes=arena_bytes};
    return PW_OK;
}

int pw_x86_cache_lookup(PwX86Cache *cache,uint32_t guest_pc,const PwX86CacheEntry **entry)
{
    if(!cache || !cache->entries || !cache->generation || !entry)
        return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<cache->capacity;i++)
        if(cache->entries[i].used && cache->entries[i].generation==cache->generation &&
           cache->entries[i].guest_pc==guest_pc) {
            cache->hits++;*entry=&cache->entries[i];return PW_OK;
        }
    cache->misses++;*entry=NULL;return PW_ERR_NOT_FOUND;
}

int pw_x86_cache_publish(PwX86Cache *cache,uint32_t guest_pc,const PwX86Block *block,
                         size_t code_offset,const PwX86CacheEntry **entry)
{
    if(!cache || !cache->entries || !cache->generation || !block || !entry ||
       !block->source_bytes || !block->code_bytes || !block->instructions)
        return PW_ERR_PRECONDITION;
    if(code_offset!=cache->cursor || code_offset>cache->arena_bytes ||
       block->code_bytes>cache->arena_bytes-code_offset)
        return PW_ERR_LIMIT;
    for(uint32_t i=0;i<cache->capacity;i++)
        if(cache->entries[i].used && cache->entries[i].generation==cache->generation &&
           cache->entries[i].guest_pc==guest_pc)return PW_ERR_STATE;
    uint32_t slot=cache->capacity;
    for(uint32_t i=0;i<cache->capacity;i++)if(!cache->entries[i].used){slot=i;break;}
    if(slot==cache->capacity)return PW_ERR_LIMIT;
    cache->entries[slot]=(PwX86CacheEntry){
        .guest_pc=guest_pc,.generation=cache->generation,.code_offset=code_offset,
        .code_bytes=block->code_bytes,.source_bytes=block->source_bytes,
        .instructions=block->instructions,.used=1};
    size_t end=code_offset+block->code_bytes;
    cache->cursor=(end+15)&~(size_t)15;
    if(cache->cursor>cache->arena_bytes)cache->cursor=cache->arena_bytes;
    cache->publishes++;*entry=&cache->entries[slot];return PW_OK;
}

int pw_x86_cache_reset(PwX86Cache *cache,uint32_t generation)
{
    if(!cache || !cache->entries || !cache->capacity || !generation ||
       generation==cache->generation)return PW_ERR_PRECONDITION;
    memset(cache->entries,0,sizeof(*cache->entries)*cache->capacity);
    cache->generation=generation;cache->cursor=0;cache->resets++;return PW_OK;
}
