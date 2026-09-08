/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_guest_heap.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
static PwHeapBlock blocks[256];
int main(void)
{
    PwVmBackend vm;PwVmRegion region;
    assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(vm.reserve_at(NULL,0x03400000,65536,4096,&region)==PW_OK);
    assert(vm.commit(NULL,&region,0,65536,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    PwGuestHeap h;uint32_t a,b,c,d;
    assert(pw_guest_heap_init(&h,0x03400000,65536,blocks,256)==PW_OK);
    assert(pw_guest_heap_alloc(&h,0,&a)==PW_OK && !(a&15));
    assert(pw_guest_heap_alloc(&h,0,&b)==PW_OK && b!=a);
    assert(pw_guest_heap_free(&h,a)==PW_OK && pw_guest_heap_free(&h,0)==PW_OK);
    assert(pw_guest_heap_free(&h,a)==PW_ERR_PRECONDITION);
    assert(pw_guest_heap_free(&h,b+1)==PW_ERR_PRECONDITION);
    assert(pw_guest_heap_free(&h,b)==PW_OK && h.count==1);
    assert(pw_guest_heap_alloc(&h,36,&a)==PW_OK);
    assert(pw_guest_heap_alloc(&h,48,&b)==PW_OK);
    memset((void *)(uintptr_t)a,0x5a,36);
    assert(pw_guest_heap_realloc(&h,a,200,&c)==PW_OK && c!=a);
    for(unsigned i=0;i<36;i++)assert(*(uint8_t *)(uintptr_t)(c+i)==0x5a);
    assert(pw_guest_heap_realloc(&h,c,16,&d)==PW_OK && d==c);
    assert(pw_guest_heap_realloc(&h,d,128,&c)==PW_OK && c==d);
    uint32_t unchanged=123;PwHeapBlock before[256];memcpy(before,blocks,sizeof(before));
    assert(pw_guest_heap_realloc(&h,c,UINT32_MAX,&unchanged)==PW_ERR_LIMIT && unchanged==123);
    assert(!memcmp(before,blocks,sizeof(before)) && *(uint8_t *)(uintptr_t)c==0x5a);
    assert(pw_guest_heap_realloc(&h,c,65536,&unchanged)==PW_ERR_LIMIT && unchanged==123);
    assert(!memcmp(before,blocks,sizeof(before)) && *(uint8_t *)(uintptr_t)c==0x5a);
    assert(pw_guest_heap_calloc(&h,UINT32_MAX,2,&unchanged)==PW_ERR_LIMIT && unchanged==123);
    assert(!memcmp(before,blocks,sizeof(before)));
    assert(pw_guest_heap_realloc(&h,c,0,&d)==PW_OK && d==0);
    assert(pw_guest_heap_free(&h,b)==PW_OK && h.count==1);
    memset(region.write_base,0xcc,65536);
    assert(pw_guest_heap_calloc(&h,7,5,&a)==PW_OK);
    for(unsigned i=0;i<35;i++)assert(*(uint8_t *)(uintptr_t)(a+i)==0);
    assert(*(uint8_t *)(uintptr_t)(a+35)==0xcc);
    assert(pw_guest_heap_free(&h,a)==PW_OK);
    assert(pw_guest_heap_realloc(&h,0,0,&a)==PW_OK && a);
    assert(pw_guest_heap_free(&h,a)==PW_OK);
    assert(pw_guest_heap_calloc(&h,0,UINT32_MAX,&a)==PW_OK && a);
    assert(pw_guest_heap_free(&h,a)==PW_OK);
    /* Repeated fragmentation: every live allocation keeps its own pattern. */
    uint32_t pointers[64]={0},sizes[64]={0},seed=7;
    for(unsigned step=0;step<4000;step++) {
        seed=seed*1664525u+1013904223u;unsigned slot=(seed>>16)%64;
        if(pointers[slot]) {
            for(unsigned j=0;j<sizes[slot];j++)assert(*(uint8_t *)(uintptr_t)(pointers[slot]+j)==slot);
            if(step&1) {
                unsigned n=(seed>>8)%700+1;uint32_t p;
                int status=pw_guest_heap_realloc(&h,pointers[slot],n,&p);
                assert(status==PW_OK || status==PW_ERR_LIMIT);
                if(status==PW_OK) {
                    for(unsigned j=0;j<(sizes[slot]<n?sizes[slot]:n);j++)assert(*(uint8_t *)(uintptr_t)(p+j)==slot);
                    pointers[slot]=p;sizes[slot]=n;memset((void *)(uintptr_t)p,slot,n);
                }
            } else {assert(pw_guest_heap_free(&h,pointers[slot])==PW_OK);pointers[slot]=0;}
        } else {
            unsigned n=(seed>>8)%700+1;
            int status=pw_guest_heap_alloc(&h,n,pointers+slot);
            assert(status==PW_OK || status==PW_ERR_LIMIT);
            if(status==PW_OK){sizes[slot]=n;memset((void *)(uintptr_t)pointers[slot],slot,n);}
        }
        assert(pw_guest_heap_validate(&h)==PW_OK);
    }
    for(unsigned i=0;i<64;i++)assert(pw_guest_heap_free(&h,pointers[i])==PW_OK);
    assert(h.count==1 && blocks[0].size==65536 && !blocks[0].used);
    assert(pw_guest_heap_alloc(&h,65536,&a)==PW_OK);
    assert(pw_guest_heap_alloc(&h,1,&unchanged)==PW_ERR_LIMIT && unchanged==123);
    assert(pw_guest_heap_free(&h,a)==PW_OK);
    /* Metadata exhaustion retains capacity instead of corrupting the table. */
    assert(pw_guest_heap_init(&h,0x03400000,65536,blocks,1)==PW_OK);
    assert(pw_guest_heap_alloc(&h,1,&a)==PW_OK && blocks[0].size==65536);
    assert(pw_guest_heap_realloc(&h,a,100,&b)==PW_OK && b==a);
    assert(pw_guest_heap_free(&h,a)==PW_OK);
    blocks[0].offset=1;assert(pw_guest_heap_alloc(&h,1,&unchanged)==PW_ERR_STATE && unchanged==123);
    assert(pw_guest_heap_init(&h,0xfffffff0,32,blocks,1)==PW_ERR_PRECONDITION);
    assert(vm.release(NULL,&region)==PW_OK);return 0;
}
