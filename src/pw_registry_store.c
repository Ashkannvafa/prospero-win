/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_registry_store.h"
#include <string.h>

enum { HEADER_BYTES=24, FORMAT_VERSION=1 };
static const uint8_t magic[4]={'P','W','R','G'};
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put32(uint8_t *p,uint32_t v)
{p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);}
static uint16_t get16(const uint8_t *p){return (uint16_t)p[0]|(uint16_t)p[1]<<8;}
static uint32_t get32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint32_t checksum(const uint8_t *p,uint32_t n)
{uint32_t h=2166136261u;while(n--){h^=*p++;h*=16777619u;}return h;}
static unsigned fold(unsigned c){return c>='A'&&c<='Z'?c+32:c;}
static int same(const char *a,const uint8_t *b,uint16_t n)
{
    size_t length=strlen(a);if(length!=n)return 0;
    for(uint16_t i=0;i<n;i++)if(fold((uint8_t)a[i])!=fold(b[i]))return 0;
    return 1;
}
static int append(uint8_t *out,uint32_t capacity,uint32_t *at,const void *data,uint32_t bytes)
{
    if(*at>capacity || bytes>capacity-*at)return PW_ERR_LIMIT;
    memcpy(out+*at,data,bytes);*at+=bytes;return PW_OK;
}
int pw_registry_encode(const PwRegistry *r,uint8_t *out,uint32_t capacity,uint32_t *written)
{
    if(!r || !r->keys || !r->values || !out || !written)return PW_ERR_PRECONDITION;
    if(capacity<HEADER_BYTES)return PW_ERR_LIMIT;
    memset(out,0,HEADER_BYTES);uint32_t at=HEADER_BYTES,keys=0,values=0;int status;
    for(uint32_t i=0;i<r->key_capacity;i++)if(r->keys[i].used) {
        size_t n=strlen(r->keys[i].path);if(n>PW_REG_PATH_MAX)return PW_ERR_STATE;
        uint8_t header[4];put16(header,(uint16_t)n);put16(header+2,0);
        if((status=append(out,capacity,&at,header,4))!=PW_OK ||
           (status=append(out,capacity,&at,r->keys[i].path,(uint32_t)n))!=PW_OK)return status;
        keys++;
    }
    for(uint32_t i=0;i<r->value_capacity;i++)if(r->values[i].used) {
        const PwRegistryValue *v=&r->values[i];
        if(v->key_index>=r->key_capacity || !r->keys[v->key_index].used ||
           v->size>PW_REG_DATA_MAX)return PW_ERR_STATE;
        size_t pn=strlen(r->keys[v->key_index].path),nn=strlen(v->name);
        if(pn>PW_REG_PATH_MAX || nn>PW_REG_NAME_MAX)return PW_ERR_STATE;
        uint8_t header[12];put16(header,(uint16_t)pn);put16(header+2,(uint16_t)nn);
        put32(header+4,v->type);put32(header+8,v->size);
        if((status=append(out,capacity,&at,header,12))!=PW_OK ||
           (status=append(out,capacity,&at,r->keys[v->key_index].path,(uint32_t)pn))!=PW_OK ||
           (status=append(out,capacity,&at,v->name,(uint32_t)nn))!=PW_OK ||
           (status=append(out,capacity,&at,v->data,v->size))!=PW_OK)return status;
        values++;
    }
    memcpy(out,magic,4);put32(out+4,FORMAT_VERSION);put32(out+8,at);
    put32(out+12,keys);put32(out+16,values);put32(out+20,checksum(out+HEADER_BYTES,at-HEADER_BYTES));
    *written=at;return PW_OK;
}
static int take(uint32_t size,uint32_t *at,uint32_t bytes)
{if(*at>size || bytes>size-*at)return PW_ERR_TRUNCATED;*at+=bytes;return PW_OK;}
int pw_registry_decode(PwRegistry *r,const uint8_t *in,uint32_t size)
{
    if(!r || !r->keys || !r->values || !in)return PW_ERR_PRECONDITION;
    if(size<HEADER_BYTES || memcmp(in,magic,4) || get32(in+4)!=FORMAT_VERSION ||
       get32(in+8)!=size || checksum(in+HEADER_BYTES,size-HEADER_BYTES)!=get32(in+20))
        return PW_ERR_MALFORMED;
    uint32_t key_count=get32(in+12),value_count=get32(in+16),at=HEADER_BYTES;
    if(key_count>r->key_capacity || value_count>r->value_capacity)return PW_ERR_LIMIT;
    for(uint32_t i=0;i<key_count;i++) {
        if(take(size,&at,4)!=PW_OK)return PW_ERR_TRUNCATED;
        uint16_t n=get16(in+at-4);if(!n || n>PW_REG_PATH_MAX || get16(in+at-2))return PW_ERR_MALFORMED;
        if(take(size,&at,n)!=PW_OK || memchr(in+at-n,0,n))return PW_ERR_MALFORMED;
    }
    uint32_t keys_end=at;
    for(uint32_t i=0;i<value_count;i++) {
        if(take(size,&at,12)!=PW_OK)return PW_ERR_TRUNCATED;
        const uint8_t *h=in+at-12;uint16_t pn=get16(h),nn=get16(h+2);
        uint32_t type=get32(h+4),bytes=get32(h+8);
        if(!pn || pn>PW_REG_PATH_MAX || nn>PW_REG_NAME_MAX || bytes>PW_REG_DATA_MAX ||
           (type!=PW_REG_SZ && type!=PW_REG_BINARY && type!=PW_REG_DWORD))return PW_ERR_MALFORMED;
        if(take(size,&at,(uint32_t)pn+nn+bytes)!=PW_OK ||
           memchr(in+at-pn-nn-bytes,0,(size_t)pn+nn))return PW_ERR_MALFORMED;
        unsigned found=0;uint32_t key_at=HEADER_BYTES;
        for(uint32_t k=0;k<key_count;k++) {
            uint16_t n=get16(in+key_at);key_at+=4;
            if(n==pn && !memcmp(in+key_at,in+at-pn-nn-bytes,pn))found=1;
            key_at+=n;
        }
        if(!found)return PW_ERR_MALFORMED;
    }
    if(at!=size)return PW_ERR_MALFORMED;
    memset(r->keys,0,sizeof(*r->keys)*r->key_capacity);
    memset(r->values,0,sizeof(*r->values)*r->value_capacity);at=HEADER_BYTES;
    for(uint32_t i=0;i<key_count;i++) {
        uint16_t n=get16(in+at);at+=4;
        memcpy(r->keys[i].path,in+at,n);r->keys[i].path[n]=0;at+=n;
        r->keys[i].handle=UINT32_C(0xd1000000)+i*16;r->keys[i].used=1;
    }
    at=keys_end;
    for(uint32_t i=0;i<value_count;i++) {
        uint16_t pn=get16(in+at),nn=get16(in+at+2);uint32_t type=get32(in+at+4),bytes=get32(in+at+8);
        at+=12;uint32_t key=0;while(key<key_count && !same(r->keys[key].path,in+at,pn))key++;
        at+=pn;PwRegistryValue *v=&r->values[i];memcpy(v->name,in+at,nn);v->name[nn]=0;at+=nn;
        memcpy(v->data,in+at,bytes);at+=bytes;v->key_index=key;v->type=type;v->size=bytes;v->used=1;
    }
    r->generation=0;return PW_OK;
}
