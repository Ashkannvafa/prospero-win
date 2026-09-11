/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_ini.h"
#include <limits.h>
#include <string.h>

static unsigned lower(unsigned value)
{return value>='A'&&value<='Z'?value+('a'-'A'):value;}
static int equal(const uint8_t *text,size_t length,const char *wanted)
{
    size_t wanted_length=strlen(wanted);if(length!=wanted_length)return 0;
    for(size_t i=0;i<length;i++)if(lower(text[i])!=lower((uint8_t)wanted[i]))return 0;
    return 1;
}
static void trim(const uint8_t **begin,const uint8_t **end)
{
    while(*begin<*end && (**begin==' '||**begin=='\t'))(*begin)++;
    while(*end>*begin && ((*end)[-1]==' '||(*end)[-1]=='\t'))(*end)--;
}
static int parse(const uint8_t *begin,const uint8_t *end,uint32_t *value)
{
    trim(&begin,&end);int negative=0;if(begin<end && (*begin=='+'||*begin=='-'))
        {negative=*begin=='-';begin++;}
    unsigned base=10;if(end-begin>=2 && begin[0]=='0' && (begin[1]=='x'||begin[1]=='X'))
        {base=16;begin+=2;}
    if(begin==end)return 0;
    uint32_t number=0;unsigned digits=0;
    while(begin<end) {
        unsigned digit;if(*begin>='0'&&*begin<='9')digit=*begin-'0';
        else if(base==16 && lower(*begin)>='a'&&lower(*begin)<='f')digit=lower(*begin)-'a'+10;
        else break;
        if(number>(UINT32_MAX-digit)/base)return 0;
        number=number*base+digit;digits++;begin++;
    }
    while(begin<end && (*begin==' '||*begin=='\t'))begin++;
    if(!digits || (begin<end && *begin!=';'))return 0;
    *value=negative?(uint32_t)(0u-number):number;return 1;
}
int pw_ini_get_int(const uint8_t *bytes,size_t length,const char *section,
                   const char *key,uint32_t fallback,uint32_t *value)
{
    if(!bytes || !section || !*section || !key || !*key || !value)
        return PW_ERR_PRECONDITION;
    *value=fallback;unsigned in_section=0;size_t cursor=0;
    while(cursor<length) {
        size_t start=cursor;while(cursor<length && bytes[cursor]!='\n' && bytes[cursor]!='\r')cursor++;
        const uint8_t *begin=bytes+start,*end=bytes+cursor;trim(&begin,&end);
        while(cursor<length && (bytes[cursor]=='\n'||bytes[cursor]=='\r'))cursor++;
        if(begin==end || *begin==';' || *begin=='#')continue;
        if(*begin=='[' && end-begin>=2 && end[-1]==']') {
            begin++;end--;trim(&begin,&end);in_section=equal(begin,(size_t)(end-begin),section);continue;
        }
        if(!in_section)continue;
        const uint8_t *equals=begin;while(equals<end && *equals!='=')equals++;
        if(equals==end)continue;
        const uint8_t *name_end=equals;trim(&begin,&name_end);
        if(!equal(begin,(size_t)(name_end-begin),key))continue;
        uint32_t parsed;if(parse(equals+1,end,&parsed))*value=parsed;
        return PW_OK;
    }
    return PW_OK;
}
