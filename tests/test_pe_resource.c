/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pe_resource.h"
#include <assert.h>
#include <string.h>
static uint8_t bytes[1024];
static void w(unsigned at,uint32_t v){for(unsigned i=0;i<4;i++)bytes[at+i]=(uint8_t)(v>>(i*8));}
static PeImage fixture(void)
{
    memset(bytes,0,sizeof(bytes));
    PeImage im={.bytes=bytes,.size=sizeof(bytes),.directory_count=16,.section_count=1};
    im.sections[0]=(PeSection){.virtual_address=0x1000,.virtual_size=1024,.raw_offset=0,.raw_size=1024};
    im.directories[PE_DIR_RESOURCE]=(PeDataDirectory){0x1000,1024};
    w(12,1u<<16);w(16,6);w(20,0x80000020);
    w(44,1u<<16);w(48,1);w(52,0x80000040);
    w(76,2u<<16);w(80,0);w(84,0x70);w(88,0x409);w(92,0x80);
    w(0x70,0x1100);w(0x74,34);w(0x80,0x1140);w(0x84,34);
    bytes[0x100]=1;bytes[0x102]='N';bytes[0x140]=1;bytes[0x142]='E';
    return im;
}
int main(void)
{
    PeImage im=fixture();PeResource r={0};const uint8_t *text;size_t units;
    assert(pe_resource_find(&im,6,1,0x409,&r)==PW_OK && r.language==0x409 && r.size==34);
    assert(pe_resource_string(&im,0,0x409,&text,&units)==PW_OK && units==1 && text[0]=='E');
    assert(pe_resource_string(&im,0,0x40a,&text,&units)==PW_OK && units==1 && text[0]=='N');
    assert(pe_resource_string(&im,15,0x409,&text,&units)==PW_OK && units==0);
    assert(pe_resource_find(&im,7,1,0,&r)==PW_ERR_NOT_FOUND);
    assert(pe_resource_string(&im,16,0,&text,&units)==PW_ERR_NOT_FOUND);
    w(80,0x407);assert(pe_resource_find(&im,6,1,0x40a,&r)==PW_OK && r.language==0x407);
    w(88,0x407);assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_MALFORMED);
    im=fixture();w(20,0x80000000);assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_MALFORMED);
    im=fixture();w(92,0x800000a0);assert(pe_resource_find(&im,6,1,0x409,&r)==PW_ERR_UNSUPPORTED);
    im=fixture();w(20,0xfffffff0);assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_TRUNCATED);
    im=fixture();w(0x80,0xfffffffe);assert(pe_resource_find(&im,6,1,0x409,&r)!=PW_OK);
    im=fixture();w(0x8c,1);assert(pe_resource_find(&im,6,1,0x409,&r)==PW_ERR_MALFORMED);
    im=fixture();w(0x84,33);text=bytes;units=123;
    assert(pe_resource_string(&im,0,0x409,&text,&units)==PW_ERR_TRUNCATED && text==bytes && units==123);
    im=fixture();bytes[0x140]=0xff;assert(pe_resource_string(&im,0,0x409,&text,&units)==PW_ERR_TRUNCATED);
    im=fixture();w(12,4097u<<16);assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_LIMIT);
    im=fixture();PeResource before={.bytes=bytes,.size=19,.codepage=77,.language=3};r=before;
    im.directories[PE_DIR_RESOURCE].size=15;
    assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_TRUNCATED && !memcmp(&r,&before,sizeof(r)));
    im=fixture();im.directories[PE_DIR_RESOURCE].virtual_address=0;
    assert(pe_resource_find(&im,6,1,0,&r)==PW_ERR_NOT_FOUND);
    im=fixture();
    w(44,1);w(48,0x800000a0);w(52,0x80000040);
    bytes[0xa0]=6;
    const char icon[]="ICON_1";
    for(unsigned i=0;i<6;i++)bytes[0xa2+i*2]=(uint8_t)icon[i];
    assert(pe_resource_find_name(&im,6,"ICON_1",0x409,&r)==PW_OK && r.size==34);
    assert(pe_resource_find_name(&im,6,"icon_1",0x409,&r)==PW_ERR_NOT_FOUND);
    assert(pe_resource_find_name(&im,6,"IC\xff",0x409,&r)==PW_ERR_UNSUPPORTED);
    return 0;
}
