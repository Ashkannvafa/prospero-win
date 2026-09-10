/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_crt_format.h"
#include <string.h>

typedef struct Writer { char *p;size_t n,capacity;int failed; } Writer;
static void put(Writer *w,char c)
{
    if(w->n+1>=w->capacity){w->failed=1;return;}
    w->p[w->n++]=c;
}
static void repeat(Writer *w,char c,unsigned count){while(count--)put(w,c);}
static int argument(const PwCrtFormatInput *input,unsigned *index,uint32_t *value)
{
    int status=input->u32(input->opaque,*index,value);
    if(status==PW_OK)(*index)++;
    return status;
}
static unsigned digits(uint32_t value,unsigned base,unsigned upper,char out[32])
{
    const char *alphabet=upper?"0123456789ABCDEF":"0123456789abcdef";unsigned n=0;
    do{out[n++]=alphabet[value%base];value/=base;}while(value);
    return n;
}

int pw_crt_format_ascii(char *output,size_t capacity,const char *format,
                        const PwCrtFormatInput *input,uint32_t *length)
{
    if(!output || !capacity || !format || !input || !input->u32 ||
       !input->string || !length)return PW_ERR_PRECONDITION;
    Writer w={output,0,capacity,0};unsigned arg=0;
    for(size_t at=0;format[at];at++) {
        if(format[at]!='%'){put(&w,format[at]);continue;}
        at++;if(!format[at])return PW_ERR_MALFORMED;
        if(format[at]=='%'){put(&w,'%');continue;}
        unsigned left=0,plus=0,space=0,alternate=0,zero=0;
        for(;;) {
            char c=format[at];
            if(c=='-')left=1;else if(c=='+')plus=1;else if(c==' ')space=1;
            else if(c=='#')alternate=1;else if(c=='0')zero=1;else break;
            at++;
        }
        unsigned width=0;int precision=-1;
        if(format[at]=='*') {
            uint32_t value;int status=argument(input,&arg,&value);if(status!=PW_OK)return status;
            int32_t signed_value=(int32_t)value;at++;
            if(signed_value<0){left=1;width=(uint32_t)(0u-value);}else width=value;
        } else while(format[at]>='0' && format[at]<='9') {
            if(width>4096/10)return PW_ERR_LIMIT;
            width=width*10+(unsigned)(format[at++]-'0');
        }
        if(width>4096)return PW_ERR_LIMIT;
        if(format[at]=='.') {
            at++;precision=0;
            if(format[at]=='*') {
                uint32_t value;int status=argument(input,&arg,&value);if(status!=PW_OK)return status;
                at++;precision=(int32_t)value<0?-1:(int)value;
            } else while(format[at]>='0' && format[at]<='9') {
                if(precision>4096/10)return PW_ERR_LIMIT;
                precision=precision*10+(format[at++]-'0');
            }
            if(precision>4096)return PW_ERR_LIMIT;
        }
        unsigned length_kind=0;
        if(format[at]=='h'){length_kind=1;at++;if(format[at]=='h'){length_kind=2;at++;}}
        else if(format[at]=='l'){length_kind=3;at++;if(format[at]=='l')return PW_ERR_UNSUPPORTED;}
        char conversion=format[at];
        if(conversion=='s') {
            if(length_kind)return PW_ERR_UNSUPPORTED;
            uint32_t address;int status=argument(input,&arg,&address);if(status!=PW_OK)return status;
            char text[1024];size_t text_length=0;
            status=input->string(input->opaque,address,text,sizeof(text),&text_length);
            if(status!=PW_OK)return status;
            if(precision>=0 && text_length>(unsigned)precision)text_length=(unsigned)precision;
            unsigned padding=width>text_length?width-(unsigned)text_length:0;
            if(!left)repeat(&w,' ',padding);
            for(size_t i=0;i<text_length;i++)put(&w,text[i]);
            if(left)repeat(&w,' ',padding);
            continue;
        }
        if(conversion=='c') {
            if(length_kind)return PW_ERR_UNSUPPORTED;
            uint32_t value;int status=argument(input,&arg,&value);if(status!=PW_OK)return status;
            unsigned padding=width>1?width-1:0;if(!left)repeat(&w,' ',padding);
            put(&w,(char)value);if(left)repeat(&w,' ',padding);continue;
        }
        unsigned base,upper=0,signed_conversion=0;
        if(conversion=='d' || conversion=='i'){base=10;signed_conversion=1;}
        else if(conversion=='u')base=10;
        else if(conversion=='o')base=8;
        else if(conversion=='x' || conversion=='X'){base=16;upper=conversion=='X';}
        else return PW_ERR_UNSUPPORTED;
        uint32_t value;int status=argument(input,&arg,&value);if(status!=PW_OK)return status;
        if(length_kind==1)value=(uint32_t)(uint16_t)value;
        else if(length_kind==2)value=(uint32_t)(uint8_t)value;
        unsigned negative=0;
        if(signed_conversion) {
            int32_t signed_value=length_kind==1?(int16_t)value:
                                 length_kind==2?(int8_t)value:(int32_t)value;
            if(signed_value<0){negative=1;value=0u-(uint32_t)signed_value;}
            else value=(uint32_t)signed_value;
        }
        char number[32];unsigned number_length=digits(value,base,upper,number);
        if(precision==0 && value==0)number_length=0;
        unsigned precision_zero=precision>(int)number_length?(unsigned)precision-number_length:0;
        char prefix[3];unsigned prefix_length=0;
        if(negative)prefix[prefix_length++]='-';else if(plus)prefix[prefix_length++]='+';else if(space)prefix[prefix_length++]=' ';
        if(alternate && base==16 && value){prefix[prefix_length++]='0';prefix[prefix_length++]=upper?'X':'x';}
        else if(alternate && base==8 && (!number_length || number[number_length-1]!='0'))prefix[prefix_length++]='0';
        unsigned total=prefix_length+precision_zero+number_length;
        unsigned padding=width>total?width-total:0;
        if(!left && (!zero || precision>=0))repeat(&w,' ',padding);
        for(unsigned i=0;i<prefix_length;i++)put(&w,prefix[i]);
        if(!left && zero && precision<0)repeat(&w,'0',padding);
        repeat(&w,'0',precision_zero);
        while(number_length)put(&w,number[--number_length]);
        if(left)repeat(&w,' ',padding);
    }
    if(w.failed || w.n>UINT32_MAX)return PW_ERR_LIMIT;
    output[w.n]=0;*length=(uint32_t)w.n;return PW_OK;
}
