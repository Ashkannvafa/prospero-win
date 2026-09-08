/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_resource.h"
static uint32_t u16(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8;}
static uint32_t u32(const uint8_t *p){return u16(p)|u16(p+2)<<16;}
static int span(const PeImage *im,uint32_t offset,uint32_t n,const uint8_t **p)
{
    const PeDataDirectory *d=pe_image_directory(im,PE_DIR_RESOURCE);
    if(!d || !d->virtual_address || !d->size)return PW_ERR_NOT_FOUND;
    if(offset>d->size || n>d->size-offset)return PW_ERR_TRUNCATED;
    if((uint64_t)d->virtual_address+offset+n>0x100000000ull)return PW_ERR_OVERFLOW;
    size_t file;int status=pe_image_file_offset(im,d->virtual_address+offset,n,&file);
    if(status==PW_OK)*p=im->bytes+file;
    return status;
}
static int entry(const PeImage *im,uint32_t table,uint32_t id,int language,
                 uint32_t *target,uint32_t *selected)
{
    const uint8_t *p;int status=span(im,table,16,&p);
    if(status!=PW_OK)return status;
    unsigned names=u16(p+12),ids=u16(p+14),count=names+ids;
    if(count>4096)return PW_ERR_LIMIT;
    if(table>UINT32_MAX-16)return PW_ERR_OVERFLOW;
    if((status=span(im,table+16,count*8,&p))!=PW_OK)return status;
    uint32_t best=UINT32_MAX,value=0,key=0,last=0;
    for(unsigned i=0;i<count;i++) {
        uint32_t name=u32(p+i*8),offset=u32(p+i*8+4);
        if(i<names){if(!(name&0x80000000u))return PW_ERR_MALFORMED;continue;}
        if(name&0x80000000u || (i>names && name<=last))return PW_ERR_MALFORMED;
        last=name;
        uint32_t score=name==id?0:language?(name==0?1:2):UINT32_MAX;
        if(score<best){best=score;value=offset;key=name;}
    }
    if(best==UINT32_MAX)return PW_ERR_NOT_FOUND;
    *target=value;*selected=key;return PW_OK;
}
int pe_resource_find(const PeImage *im,uint32_t type,uint32_t name,uint16_t lang,PeResource *out)
{
    if(!im || !out || type&0x80000000u || name&0x80000000u)return PW_ERR_PRECONDITION;
    uint32_t table=0,seen[3]={0},key=0,target=0,keys[]={type,name,lang};
    for(unsigned level=0;level<3;level++) {
        for(unsigned i=0;i<level;i++)if(table==seen[i])return PW_ERR_MALFORMED;
        seen[level]=table;
        int status=entry(im,table,keys[level],level==2,&target,&key);
        if(status!=PW_OK)return status;
        if(level<2) {
            if(!(target&0x80000000u))return PW_ERR_UNSUPPORTED;
            table=target&0x7fffffffu;
        } else if(target&0x80000000u)return PW_ERR_UNSUPPORTED;
    }
    const uint8_t *p;int status=span(im,target,16,&p);
    if(status!=PW_OK)return status;
    uint32_t rva=u32(p),size=u32(p+4),cp=u32(p+8);
    if(u32(p+12))return PW_ERR_MALFORMED;
    size_t offset;
    if((status=pe_image_file_offset(im,rva,size,&offset))!=PW_OK)return status;
    *out=(PeResource){im->bytes+offset,size,cp,key};return PW_OK;
}
int pe_resource_string(const PeImage *im,uint32_t id,uint16_t lang,const uint8_t **text,size_t *units)
{
    if(!text || !units || id>0xffff)return PW_ERR_PRECONDITION;
    PeResource r;int status=pe_resource_find(im,6,(id>>4)+1,lang,&r);
    if(status!=PW_OK)return status;
    size_t at=0,length=0;const uint8_t *selected=NULL;
    for(unsigned i=0;i<16;i++) {
        if(at>r.size || r.size-at<2)return PW_ERR_TRUNCATED;
        size_t n=u16(r.bytes+at);at+=2;
        if(n>(r.size-at)/2)return PW_ERR_TRUNCATED;
        if(i==(id&15)){selected=r.bytes+at;length=n;}
        at+=n*2;
    }
    *text=selected;*units=length;return PW_OK;
}
