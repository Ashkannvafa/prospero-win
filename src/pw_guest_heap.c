/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_guest_heap.h"
#include <string.h>
int pw_guest_heap_validate(const PwGuestHeap *h)
{
    if(!h || !h->blocks || !h->base || (h->base&15) || !h->bytes || (h->bytes&15) ||
       (uint64_t)h->base+h->bytes>0x100000000ull || !h->count || h->count>h->capacity)return PW_ERR_STATE;
    uint64_t offset=0;
    for(uint32_t i=0;i<h->count;i++) {
        const PwHeapBlock *b=h->blocks+i;
        if(b->offset!=offset || !b->size || (b->size&15) || b->used>1 || b->requested>b->size ||
           (!b->used && b->requested) || (i && !b->used && !h->blocks[i-1].used))return PW_ERR_STATE;
        offset+=b->size;if(offset>h->bytes)return PW_ERR_STATE;
    }
    return offset==h->bytes?PW_OK:PW_ERR_STATE;
}
int pw_guest_heap_init(PwGuestHeap *h,uint32_t base,uint32_t bytes,PwHeapBlock *blocks,uint32_t capacity)
{
    if(!h || !blocks || !capacity || !base || (base&15) || !bytes || (bytes&15) ||
       (uint64_t)base+bytes>0x100000000ull)return PW_ERR_PRECONDITION;
    blocks[0]=(PwHeapBlock){.size=bytes};*h=(PwGuestHeap){base,bytes,1,capacity,blocks};return PW_OK;
}
static int rounded(uint32_t n,uint32_t *size)
{
    if(n>UINT32_MAX-15)return PW_ERR_LIMIT;
    *size=n?(n+15)&~15u:16;return PW_OK;
}
static void remove_block(PwGuestHeap *h,uint32_t i)
{
    memmove(h->blocks+i,h->blocks+i+1,(h->count-i-1)*sizeof(*h->blocks));
    h->blocks[--h->count]=(PwHeapBlock){0};
}
static void merge_next(PwGuestHeap *h,uint32_t i)
{
    if(i+1<h->count && !h->blocks[i+1].used) {
        h->blocks[i].size+=h->blocks[i+1].size;remove_block(h,i+1);
    }
}
static void shrink(PwGuestHeap *h,uint32_t i,uint32_t size)
{
    PwHeapBlock *b=h->blocks+i;
    if(size==b->size)return;
    uint32_t tail=b->size-size;
    if(i+1<h->count && !h->blocks[i+1].used) {
        h->blocks[i+1].offset-=tail;h->blocks[i+1].size+=tail;b->size=size;
    } else if(h->count<h->capacity) {
        memmove(b+2,b+1,(h->count-i-1)*sizeof(*b));
        b[1]=(PwHeapBlock){.offset=b->offset+size,.size=tail};b->size=size;h->count++;
    } /* Retain excess capacity if no metadata slot is available. */
}
static int find(const PwGuestHeap *h,uint32_t address,uint32_t *index)
{
    if(address<h->base)return PW_ERR_PRECONDITION;
    for(uint32_t i=0;i<h->count;i++)if(h->blocks[i].offset==address-h->base && h->blocks[i].used) {
        *index=i;return PW_OK;
    }
    return PW_ERR_PRECONDITION;
}
int pw_guest_heap_alloc(PwGuestHeap *h,uint32_t n,uint32_t *address)
{
    if(!address)return PW_ERR_PRECONDITION;
    int status=pw_guest_heap_validate(h);if(status!=PW_OK)return status;
    uint32_t size;if((status=rounded(n,&size))!=PW_OK)return status;
    for(uint32_t i=0;i<h->count;i++) {
        PwHeapBlock *b=h->blocks+i;
        if(b->used || b->size<size)continue;
        b->used=1;b->requested=n;shrink(h,i,size);
        *address=h->base+b->offset;return PW_OK;
    }
    return PW_ERR_LIMIT;
}
int pw_guest_heap_free(PwGuestHeap *h,uint32_t address)
{
    int status=pw_guest_heap_validate(h);if(status!=PW_OK)return status;
    if(!address)return PW_OK;
    uint32_t i;if((status=find(h,address,&i))!=PW_OK)return status;
    h->blocks[i].used=0;h->blocks[i].requested=0;merge_next(h,i);
    if(i && !h->blocks[i-1].used)merge_next(h,i-1);
    return PW_OK;
}
int pw_guest_heap_calloc(PwGuestHeap *h,uint32_t count,uint32_t bytes,uint32_t *address)
{
    if(!address)return PW_ERR_PRECONDITION;
    if((uint64_t)count*bytes>UINT32_MAX)return PW_ERR_LIMIT;
    uint32_t p,n=count*bytes;int status=pw_guest_heap_alloc(h,n,&p);
    if(status!=PW_OK)return status;
    if(n)memset((void *)(uintptr_t)p,0,n);
    *address=p;return PW_OK;
}
int pw_guest_heap_realloc(PwGuestHeap *h,uint32_t address,uint32_t n,uint32_t *out)
{
    if(!out)return PW_ERR_PRECONDITION;
    int status=pw_guest_heap_validate(h);if(status!=PW_OK)return status;
    if(!address)return pw_guest_heap_alloc(h,n,out);
    uint32_t i;if((status=find(h,address,&i))!=PW_OK)return status;
    if(!n){status=pw_guest_heap_free(h,address);if(status==PW_OK)*out=0;return status;}
    uint32_t size;if((status=rounded(n,&size))!=PW_OK)return status;
    PwHeapBlock *b=h->blocks+i;uint32_t old=b->requested;
    if(size>b->size && i+1<h->count && !b[1].used && (uint64_t)b->size+b[1].size>=size)merge_next(h,i);
    if(size<=b->size){b->requested=n;shrink(h,i,size);*out=address;return PW_OK;}
    uint32_t p;if((status=pw_guest_heap_alloc(h,n,&p))!=PW_OK)return status;
    memcpy((void *)(uintptr_t)p,(const void *)(uintptr_t)address,old<n?old:n);
    /* The successful allocation can shift indices, but not the old address. */
    status=pw_guest_heap_free(h,address);
    if(status!=PW_OK)return status;
    *out=p;return PW_OK;
}
