/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_guest_args.h"
#include "../include/prospero_win.h"
#include <string.h>
static int append(char *text,size_t *n,char value)
{
    if(*n==PW_ARGS_BYTES)return PW_ERR_LIMIT;
    text[(*n)++]=value;return PW_OK;
}
int pw_guest_args_build(const char *line,const char *const *env,unsigned count,
                        uint32_t base,void *output,size_t capacity,PwGuestArgs *report)
{
    if(!line || !base || !output || !report || (count && !env))return PW_ERR_PRECONDITION;
    if(count>PW_ARGS_LIMIT)return PW_ERR_LIMIT;
    char text[PW_ARGS_BYTES];uint32_t offsets[PW_ARGS_LIMIT],env_offsets[PW_ARGS_LIMIT];
    size_t n=0;unsigned argc=0;
    const char *p=line;
    do {
        if(argc==PW_ARGS_LIMIT)return PW_ERR_LIMIT;
        offsets[argc]=(uint32_t)n;unsigned quoted=0;
        while(*p && (quoted || (*p!=' ' && *p!='\t'))) {
            if(!argc) { /* argv[0] has pathname quoting, not argument escaping. */
                if(*p=='"'){quoted=!quoted;p++;continue;}
            } else if(*p=='\\') {
                unsigned slashes=0;while(*p=='\\'){slashes++;p++;}
                unsigned literal=*p=='"'?slashes/2:slashes;
                for(unsigned i=0;i<literal;i++)if(append(text,&n,'\\')!=PW_OK)return PW_ERR_LIMIT;
                if(*p=='"' && (slashes&1)) {
                    if(append(text,&n,'"')!=PW_OK)return PW_ERR_LIMIT;
                    p++;continue;
                }
                if(*p!='"')continue;
            }
            if(*p=='"') {
                p++;
                if(quoted && *p=='"'){p++;if(append(text,&n,'"')!=PW_OK)return PW_ERR_LIMIT;}
                else quoted=!quoted;
            } else if(append(text,&n,*p++)!=PW_OK)return PW_ERR_LIMIT;
        }
        if(append(text,&n,0)!=PW_OK)return PW_ERR_LIMIT;
        argc++;while(*p==' ' || *p=='\t')p++;
    } while(*p);
    for(unsigned i=0;i<count;i++) {
        if(!env[i])return PW_ERR_PRECONDITION;
        env_offsets[i]=(uint32_t)n;
        const char *e=env[i];do {if(append(text,&n,*e)!=PW_OK)return PW_ERR_LIMIT;}while(*e++);
    }
    size_t tables=(argc+count+2)*4,total=tables+n;
    if(total>capacity || (uint64_t)base+total>0x100000000ull)return PW_ERR_LIMIT;
    /* All fallible operations precede publication; byte copies avoid alignment assumptions. */
    uint8_t *dst=output;uint32_t zero=0;
    for(unsigned i=0;i<argc;i++){uint32_t ptr=base+(uint32_t)tables+offsets[i];memcpy(dst+i*4,&ptr,4);}
    memcpy(dst+argc*4,&zero,4);
    for(unsigned i=0;i<count;i++){uint32_t ptr=base+(uint32_t)tables+env_offsets[i];memcpy(dst+(argc+1+i)*4,&ptr,4);}
    memcpy(dst+(argc+count+1)*4,&zero,4);memcpy(dst+tables,text,n);
    *report=(PwGuestArgs){argc,base,base+(argc+1)*4,total};return PW_OK;
}
