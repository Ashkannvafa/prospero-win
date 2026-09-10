/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_crt_format.h"
#include <assert.h>
#include <string.h>

typedef struct Fixture { const uint32_t *args;unsigned count; } Fixture;
static int get_u32(void *opaque,unsigned index,uint32_t *value)
{
    Fixture *f=opaque;if(index>=f->count)return PW_ERR_VM;*value=f->args[index];return PW_OK;
}
static int get_string(void *opaque,uint32_t address,char *output,size_t capacity,size_t *length)
{
    (void)opaque;const char *source=address==1?"guest":address==2?"abcdef":NULL;
    if(!source)return PW_ERR_VM;
    size_t n=strlen(source);
    if(n+1>capacity)return PW_ERR_LIMIT;
    memcpy(output,source,n+1);*length=n;return PW_OK;
}
static void check(const char *format,const uint32_t *args,unsigned count,const char *expected)
{
    Fixture fixture={args,count};PwCrtFormatInput input={&fixture,get_u32,get_string};
    char output[128];uint32_t length=99;
    assert(pw_crt_format_ascii(output,sizeof(output),format,&input,&length)==PW_OK);
    assert(!strcmp(output,expected) && length==strlen(expected));
}
int main(void)
{
    uint32_t a[]={7};check("Table%d",a,1,"Table7");
    uint32_t b[]={0xffffffd6u,42,0x2a,9};check("%+06d %-4u %#x %03X",b,4,"-00042 42   0x2a 009");
    uint32_t c[]={1,2};check("%.3s:%8s",c,2,"gue:  abcdef");
    uint32_t d[]={5,'Z'};check("%*c%%",d,2,"    Z%");
    Fixture fixture={a,1};PwCrtFormatInput input={&fixture,get_u32,get_string};
    char tiny[4]="old";uint32_t length=77;
    assert(pw_crt_format_ascii(tiny,sizeof(tiny),"Table%d",&input,&length)==PW_ERR_LIMIT);
    assert(pw_crt_format_ascii(tiny,sizeof(tiny),"%f",&input,&length)==PW_ERR_UNSUPPORTED);
    assert(pw_crt_format_ascii(tiny,sizeof(tiny),"%n",&input,&length)==PW_ERR_UNSUPPORTED);
    return 0;
}
