/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x87.h"
#include "../include/prospero_win.h"
#include <string.h>

enum { X87_IE=1, X87_DE=2, X87_OE=8, X87_UE=16, X87_PE=32,
       X87_SF=64, X87_C1=0x0200 };

static uint64_t get64(const uint8_t *p)
{
    uint64_t value=0;for(unsigned i=0;i<8;i++)value|=(uint64_t)p[i]<<(8*i);return value;
}
static void put80(uint8_t out[10],uint64_t sig,uint16_t sign_exp)
{
    for(unsigned i=0;i<8;i++)out[i]=(uint8_t)(sig>>(8*i));
    out[8]=(uint8_t)sign_exp;out[9]=(uint8_t)(sign_exp>>8);
}
static unsigned highest64(uint64_t value)
{
    unsigned bit=0;while(value>>1){value>>=1;bit++;}return bit;
}
static int exception(PwGuestFp *fp,unsigned flag)
{
    fp->x87_status=(uint16_t)(fp->x87_status|flag);
    unsigned pending=flag&~fp->x87_control;
    if(!pending)return PW_OK;
    fp->x87_status=(uint16_t)(fp->x87_status|0x80u); /* exception summary */
    fp->x87_pending=(uint16_t)(fp->x87_pending|pending);
    return PW_ERR_X87_TRAP;
}
static int from_binary(PwGuestFp *fp,uint64_t bits,unsigned fraction_bits,
                       unsigned exponent_bits,unsigned bias,uint8_t out[10])
{
    uint64_t fraction_mask=(UINT64_C(1)<<fraction_bits)-1;
    uint64_t fraction=bits&fraction_mask;
    unsigned exponent=(unsigned)((bits>>fraction_bits)&((1u<<exponent_bits)-1));
    unsigned sign=(unsigned)(bits>>(fraction_bits+exponent_bits));
    unsigned exponent_max=(1u<<exponent_bits)-1;
    if(exponent==exponent_max) {
        uint64_t sig=fraction?UINT64_C(0xc000000000000000)|
            (fraction<<(63-fraction_bits)):UINT64_C(0x8000000000000000);
        put80(out,sig,(uint16_t)((sign<<15)|0x7fff));return PW_OK;
    }
    if(!exponent && !fraction){put80(out,0,(uint16_t)(sign<<15));return PW_OK;}
    int unbiased;
    uint64_t sig;
    if(exponent) {
        unbiased=(int)exponent-(int)bias;
        sig=((UINT64_C(1)<<fraction_bits)|fraction)<<(63-fraction_bits);
    } else {
        unsigned high=highest64(fraction);
        unbiased=1-(int)bias-(int)fraction_bits+(int)high;
        sig=fraction<<(63-high);
        int status=exception(fp,X87_DE);if(status!=PW_OK)return status;
    }
    put80(out,sig,(uint16_t)((sign<<15)|(unsigned)(unbiased+16383)));return PW_OK;
}
static void from_i32(int32_t value,uint8_t out[10])
{
    if(!value){memset(out,0,10);return;}
    unsigned sign=value<0;uint32_t magnitude=sign?(uint32_t)(-(int64_t)value):(uint32_t)value;
    unsigned high=highest64(magnitude);
    put80(out,(uint64_t)magnitude<<(63-high),(uint16_t)((sign<<15)|(16383+high)));
}
static unsigned round_up(uint64_t kept,uint64_t remainder,unsigned shift,
                         unsigned sign,unsigned mode)
{
    if(!remainder)return 0;
    if(mode==1)return sign;       /* toward -infinity */
    if(mode==2)return !sign;      /* toward +infinity */
    if(mode==3)return 0;          /* toward zero */
    if(shift>=65)return 0;
    uint64_t half=UINT64_C(1)<<(shift-1);
    return remainder>half || (remainder==half && (kept&1));
}
static uint64_t rounded_shift(uint64_t sig,unsigned shift,unsigned sign,unsigned mode,
                              unsigned *inexact)
{
    if(!shift){*inexact=0;return sig;}
    uint64_t kept=shift<64?sig>>shift:0;
    uint64_t remainder=shift<64?sig&((UINT64_C(1)<<shift)-1):sig;
    *inexact=!!remainder;
    return kept+round_up(kept,remainder,shift,sign,mode);
}
static int to_binary(PwGuestFp *fp,const uint8_t in[10],unsigned fraction_bits,
                     unsigned exponent_bits,unsigned bias,uint64_t *out)
{
    uint64_t sig=get64(in);uint16_t se=(uint16_t)in[8]|(uint16_t)in[9]<<8;
    unsigned sign=se>>15,exponent=se&0x7fff,exponent_max=(1u<<exponent_bits)-1;
    uint64_t sign_bit=(uint64_t)sign<<(fraction_bits+exponent_bits);
    if(exponent==0x7fff) {
        if(sig==UINT64_C(0x8000000000000000)) {
            *out=sign_bit|(uint64_t)exponent_max<<fraction_bits;return PW_OK;
        }
        uint64_t payload=(sig&UINT64_C(0x7fffffffffffffff))>>(63-fraction_bits);
        payload|=UINT64_C(1)<<(fraction_bits-1);
        *out=sign_bit|(uint64_t)exponent_max<<fraction_bits|payload;return PW_OK;
    }
    if(!sig){*out=sign_bit;return PW_OK;}
    int unbiased=exponent?(int)exponent-16383:-16382;
    unsigned high=highest64(sig);
    if(high<63){sig<<=63-high;unbiased-=63-(int)high;}
    int max=(int)exponent_max-1-(int)bias,min=1-(int)bias;
    unsigned mode=(fp->x87_control>>10)&3,inexact=0;
    if(unbiased>max) {
        uint64_t max_finite=((uint64_t)exponent_max-1)<<fraction_bits |
            ((UINT64_C(1)<<fraction_bits)-1);
        unsigned infinity=mode==0 || (mode==1 && sign) || (mode==2 && !sign);
        *out=sign_bit|(infinity?(uint64_t)exponent_max<<fraction_bits:max_finite);
        int status=exception(fp,X87_OE|X87_PE);return status;
    }
    unsigned precision=fraction_bits+1;
    if(unbiased>=min) {
        uint64_t kept=rounded_shift(sig,64-precision,sign,mode,&inexact);
        if(kept==(UINT64_C(1)<<precision)){kept>>=1;if(++unbiased>max) {
            uint64_t max_finite=((uint64_t)exponent_max-1)<<fraction_bits |
                ((UINT64_C(1)<<fraction_bits)-1);
            unsigned infinity=mode==0 || (mode==1 && sign) || (mode==2 && !sign);
            *out=sign_bit|(infinity?(uint64_t)exponent_max<<fraction_bits:max_finite);
            return exception(fp,X87_OE|X87_PE);
        }}
        *out=sign_bit|(uint64_t)(unbiased+(int)bias)<<fraction_bits|
            (kept&((UINT64_C(1)<<fraction_bits)-1));
    } else {
        unsigned extra=(unsigned)(min-unbiased),shift=64-precision+extra;
        uint64_t kept=rounded_shift(sig,shift,sign,mode,&inexact);
        if(kept==(UINT64_C(1)<<fraction_bits))*out=sign_bit|UINT64_C(1)<<fraction_bits;
        else *out=sign_bit|kept;
        if(inexact){int status=exception(fp,X87_UE);if(status!=PW_OK)return status;}
    }
    return inexact?exception(fp,X87_PE):PW_OK;
}
static unsigned top(const PwGuestFp *fp){return (fp->x87_status>>11)&7;}
static unsigned tag(const PwGuestFp *fp,unsigned slot){return (fp->x87_tag>>(slot*2))&3;}
static void set_tag(PwGuestFp *fp,unsigned slot,unsigned value)
{
    fp->x87_tag=(uint16_t)((fp->x87_tag&~(3u<<(slot*2)))|(value<<(slot*2)));
}
static int peek(const PwGuestFp *fp,unsigned logical,uint8_t out[10])
{
    if(logical>=8)return PW_ERR_PRECONDITION;
    unsigned slot=(top(fp)+logical)&7;if(tag(fp,slot)==3)return PW_ERR_NOT_FOUND;
    memcpy(out,fp->x87_st[slot],10);return PW_OK;
}
static int load(PwGuestFp *fp,const uint8_t value[10])
{
    return pw_guest_x87_push(fp,value);
}
static void indefinite80(uint8_t value[10])
{
    put80(value,UINT64_C(0xc000000000000000),0xffff);
}
static void write_logical(PwGuestFp *fp,unsigned logical,const uint8_t value[10])
{
    unsigned slot=(top(fp)+logical)&7;
    memcpy(fp->x87_st[slot],value,10);set_tag(fp,slot,2);
}
static void force_push(PwGuestFp *fp,const uint8_t value[10])
{
    unsigned slot=(top(fp)-1)&7;
    fp->x87_status=(uint16_t)((fp->x87_status&~0x3800u)|(slot<<11));
    memcpy(fp->x87_st[slot],value,10);set_tag(fp,slot,2);
}
static void force_pop(PwGuestFp *fp)
{
    unsigned slot=top(fp);memset(fp->x87_st[slot],0,10);set_tag(fp,slot,3);
    fp->x87_status=(uint16_t)((fp->x87_status&~0x3800u)|(((slot+1)&7)<<11));
}
static int stack_fault(PwGuestFp *fp,PwX87Action action,uintptr_t operand,unsigned overflow)
{
    fp->x87_status=(uint16_t)((fp->x87_status|X87_SF)&~X87_C1);
    if(overflow)fp->x87_status=(uint16_t)(fp->x87_status|X87_C1);
    int status=exception(fp,X87_IE);if(status!=PW_OK)return status;
    uint8_t indefinite[10];indefinite80(indefinite);
    switch(action) {
    case PW_X87_FLD_F32:case PW_X87_FLD_F64:case PW_X87_FILD_I32:
    case PW_X87_FLD_ST:case PW_X87_FLD1:case PW_X87_FLDZ:
        force_push(fp,indefinite);break;
    case PW_X87_FST_F32: {
        uint32_t value=0xffc00000u;memcpy((void *)operand,&value,4);break;
    }
    case PW_X87_FSTP_F32: {
        uint32_t value=0xffc00000u;memcpy((void *)operand,&value,4);force_pop(fp);break;
    }
    case PW_X87_FSTP_F64: {
        uint64_t value=UINT64_C(0xfff8000000000000);
        memcpy((void *)operand,&value,8);force_pop(fp);break;
    }
    case PW_X87_FSTP_ST:
        write_logical(fp,(unsigned)operand,indefinite);force_pop(fp);break;
    case PW_X87_FCOMP_F32:case PW_X87_FCOMP_F64:
        fp->x87_status=(uint16_t)((fp->x87_status&~0x4500u)|0x4500u);force_pop(fp);break;
    case PW_X87_FUCOMPP:
        fp->x87_status=(uint16_t)((fp->x87_status&~0x4500u)|0x4500u);
        force_pop(fp);force_pop(fp);break;
    case PW_X87_FCOM_F32:case PW_X87_FCOM_F64:case PW_X87_FCOM_ST:
        fp->x87_status=(uint16_t)((fp->x87_status&~0x4500u)|0x4500u);break;
    case PW_X87_FADDP_ST:case PW_X87_FDIVP_ST:
        write_logical(fp,(unsigned)operand,indefinite);force_pop(fp);break;
    case PW_X87_FABS:case PW_X87_FSQRT:
    case PW_X87_FADD_F32:case PW_X87_FADD_F64:
    case PW_X87_FMUL_F32:case PW_X87_FMUL_F64:
    case PW_X87_FSUB_F32:case PW_X87_FSUBR_F32:
    case PW_X87_FDIV_F32:case PW_X87_FDIVR_F64:
    case PW_X87_FADD_ST:case PW_X87_FMUL_ST:case PW_X87_FSUB_ST:case PW_X87_FDIV_ST:
        write_logical(fp,0,indefinite);break;
    case PW_X87_FNSTSW_AX:return PW_ERR_STATE;
    }
    return PW_OK;
}
static int stack_preflight(PwGuestFp *fp,PwX87Action action,uintptr_t operand)
{
    unsigned push=action==PW_X87_FLD_F32 || action==PW_X87_FLD_F64 ||
        action==PW_X87_FILD_I32 || action==PW_X87_FLD_ST ||
        action==PW_X87_FLD1 || action==PW_X87_FLDZ;
    if(push) {
        if(action==PW_X87_FLD_ST && tag(fp,(top(fp)+(unsigned)operand)&7)==3) {
            int status=stack_fault(fp,action,operand,0);return status==PW_OK?1:status;
        }
        if(tag(fp,(top(fp)-1)&7)!=3) {
            int status=stack_fault(fp,action,operand,1);return status==PW_OK?1:status;
        }
        return PW_OK;
    }
    if(action==PW_X87_FNSTSW_AX)return PW_OK;
    unsigned logical=0;
    switch(action) {
    case PW_X87_FADD_ST:case PW_X87_FMUL_ST:case PW_X87_FSUB_ST:case PW_X87_FDIV_ST:
    case PW_X87_FADDP_ST:case PW_X87_FDIVP_ST:case PW_X87_FCOM_ST:
        logical=(unsigned)operand;break;
    case PW_X87_FUCOMPP:logical=1;break;
    default:break;
    }
    if(tag(fp,top(fp))==3 || (logical && tag(fp,(top(fp)+logical)&7)==3)) {
        int status=stack_fault(fp,action,operand,0);return status==PW_OK?1:status;
    }
    return PW_OK;
}
static int store_memory(PwGuestFp *fp,uintptr_t operand,unsigned bits,unsigned pop)
{
    uint8_t value[10];int status=peek(fp,0,value);if(status!=PW_OK)return status;
    PwGuestFp after=*fp;uint64_t output=0;
    status=to_binary(&after,value,bits==32?23:52,bits==32?8:11,bits==32?127:1023,&output);
    if(status!=PW_OK){if(status==PW_ERR_X87_TRAP)*fp=after;return status;}
    if(pop && (status=pw_guest_x87_pop(&after,value))!=PW_OK)return status;
    if(bits==32){uint32_t word=(uint32_t)output;memcpy((void *)operand,&word,4);}
    else memcpy((void *)operand,&output,8);
    *fp=after;return PW_OK;
}

typedef struct Soft80 { uint64_t sig;int exp;unsigned sign,kind; } Soft80;
enum { SOFT_ZERO,SOFT_FINITE,SOFT_INFINITY,SOFT_NAN };
static Soft80 unpack80(const uint8_t in[10])
{
    Soft80 value={.sig=get64(in)};
    uint16_t se=(uint16_t)in[8]|(uint16_t)in[9]<<8;unsigned exponent=se&0x7fff;
    value.sign=se>>15;
    if(exponent==0x7fff)value.kind=value.sig==UINT64_C(0x8000000000000000)?SOFT_INFINITY:SOFT_NAN;
    else if(!value.sig)value.kind=SOFT_ZERO;
    else {
        value.kind=SOFT_FINITE;value.exp=exponent?(int)exponent-16383:-16382;
        unsigned high=highest64(value.sig);
        if(high<63){value.sig<<=63-high;value.exp-=63-(int)high;}
    }
    return value;
}
static void pack_special(Soft80 value,uint8_t out[10])
{
    if(value.kind==SOFT_ZERO)put80(out,0,(uint16_t)(value.sign<<15));
    else if(value.kind==SOFT_INFINITY)
        put80(out,UINT64_C(0x8000000000000000),(uint16_t)((value.sign<<15)|0x7fff));
    else put80(out,UINT64_C(0xc000000000000000),(uint16_t)((value.sign<<15)|0x7fff));
}
static unsigned highest128(__uint128_t value)
{
    uint64_t high=(uint64_t)(value>>64);
    return high?64+highest64(high):highest64((uint64_t)value);
}
static int pack_exact(PwGuestFp *fp,unsigned sign,int exponent,
                      __uint128_t magnitude,unsigned top_bit,uint8_t out[10])
{
    unsigned precision=(fp->x87_control&0x300)==0?24:
        (fp->x87_control&0x300)==0x200?53:64;
    unsigned shift=top_bit+1-precision,mode=(fp->x87_control>>10)&3;
    __uint128_t kept=magnitude>>shift;
    __uint128_t mask=shift?(((__uint128_t)1<<shift)-1):0,remainder=magnitude&mask;
    unsigned increment=0;
    if(remainder) {
        if(mode==1)increment=sign;else if(mode==2)increment=!sign;
        else if(mode==0) {
            __uint128_t half=(__uint128_t)1<<(shift-1);
            increment=remainder>half || (remainder==half && (kept&1));
        }
    }
    kept+=increment;
    if(kept==((__uint128_t)1<<precision)){kept>>=1;exponent++;}
    if(exponent>16383) {
        Soft80 infinity={.sign=sign,.kind=SOFT_INFINITY};pack_special(infinity,out);
        return exception(fp,X87_OE|X87_PE);
    }
    if(exponent<-16382)return PW_ERR_UNSUPPORTED; /* binary80 underflow package pending */
    uint64_t sig=(uint64_t)kept<<(64-precision);
    put80(out,sig,(uint16_t)((sign<<15)|(unsigned)(exponent+16383)));
    return remainder?exception(fp,X87_PE):PW_OK;
}
static int invalid_result(PwGuestFp *fp,uint8_t out[10])
{
    int status=exception(fp,X87_IE);
    pack_special((Soft80){.kind=SOFT_NAN},out);return status;
}
static int soft_add(PwGuestFp *fp,Soft80 a,Soft80 b,uint8_t out[10])
{
    if(a.kind==SOFT_NAN || b.kind==SOFT_NAN){pack_special((Soft80){.kind=SOFT_NAN},out);return PW_OK;}
    if(a.kind==SOFT_INFINITY || b.kind==SOFT_INFINITY) {
        if(a.kind==b.kind && a.sign!=b.sign)return invalid_result(fp,out);
        pack_special(a.kind==SOFT_INFINITY?a:b,out);return PW_OK;
    }
    if(a.kind==SOFT_ZERO && b.kind==SOFT_FINITE)
        return pack_exact(fp,b.sign,b.exp,b.sig,63,out);
    if(b.kind==SOFT_ZERO && a.kind==SOFT_FINITE)
        return pack_exact(fp,a.sign,a.exp,a.sig,63,out);
    if(a.kind==SOFT_ZERO){pack_special(b,out);return PW_OK;}
    if(b.kind==SOFT_ZERO){pack_special(a,out);return PW_OK;}
    if(a.exp<b.exp){Soft80 swap=a;a=b;b=swap;}
    unsigned distance=(unsigned)(a.exp-b.exp);__uint128_t left=(__uint128_t)a.sig<<3;
    __uint128_t right=(__uint128_t)b.sig<<3;
    if(distance) {
        if(distance>=127)right=!!right;
        else {__uint128_t lost=right&(((__uint128_t)1<<distance)-1);right=(right>>distance)|!!lost;}
    }
    __uint128_t magnitude;unsigned top_bit;int exponent=a.exp;unsigned sign;
    if(a.sign==b.sign){magnitude=left+right;sign=a.sign;top_bit=highest128(magnitude);}
    else {
        if(left==right){pack_special((Soft80){.kind=SOFT_ZERO,.sign=((fp->x87_control>>10)&3)==1},out);return PW_OK;}
        if(left>right){magnitude=left-right;sign=a.sign;}else{magnitude=right-left;sign=b.sign;}
        top_bit=highest128(magnitude);
    }
    exponent+=(int)top_bit-66;
    if(top_bit<66){magnitude<<=66-top_bit;top_bit=66;}
    return pack_exact(fp,sign,exponent,magnitude,top_bit,out);
}
static int soft_mul(PwGuestFp *fp,Soft80 a,Soft80 b,uint8_t out[10])
{
    unsigned sign=a.sign^b.sign;
    if(a.kind==SOFT_NAN || b.kind==SOFT_NAN){pack_special((Soft80){.kind=SOFT_NAN},out);return PW_OK;}
    if((a.kind==SOFT_INFINITY && b.kind==SOFT_ZERO) ||
       (b.kind==SOFT_INFINITY && a.kind==SOFT_ZERO))return invalid_result(fp,out);
    if(a.kind==SOFT_INFINITY || b.kind==SOFT_INFINITY){pack_special((Soft80){.kind=SOFT_INFINITY,.sign=sign},out);return PW_OK;}
    if(a.kind==SOFT_ZERO || b.kind==SOFT_ZERO){pack_special((Soft80){.kind=SOFT_ZERO,.sign=sign},out);return PW_OK;}
    __uint128_t product=(__uint128_t)a.sig*b.sig;unsigned top_bit=highest128(product);
    int exponent=a.exp+b.exp+(int)top_bit-126;
    return pack_exact(fp,sign,exponent,product,top_bit,out);
}
static int soft_div(PwGuestFp *fp,Soft80 a,Soft80 b,uint8_t out[10])
{
    unsigned sign=a.sign^b.sign;
    if(a.kind==SOFT_NAN || b.kind==SOFT_NAN){pack_special((Soft80){.kind=SOFT_NAN},out);return PW_OK;}
    if((a.kind==SOFT_ZERO && b.kind==SOFT_ZERO) ||
       (a.kind==SOFT_INFINITY && b.kind==SOFT_INFINITY))return invalid_result(fp,out);
    if(b.kind==SOFT_ZERO) {
        int status=exception(fp,4);pack_special((Soft80){.kind=SOFT_INFINITY,.sign=sign},out);return status;
    }
    if(a.kind==SOFT_INFINITY){pack_special((Soft80){.kind=SOFT_INFINITY,.sign=sign},out);return PW_OK;}
    if(a.kind==SOFT_ZERO || b.kind==SOFT_INFINITY){pack_special((Soft80){.kind=SOFT_ZERO,.sign=sign},out);return PW_OK;}
    __uint128_t dividend=(__uint128_t)a.sig<<64;
    __uint128_t quotient=dividend/b.sig,remainder=dividend%b.sig;
    if(remainder)quotient|=1;
    unsigned top_bit=highest128(quotient);
    int exponent=a.exp-b.exp+(int)top_bit-64;
    return pack_exact(fp,sign,exponent,quotient,top_bit,out);
}
static uint64_t integer_sqrt128(__uint128_t value)
{
    uint64_t root=0;
    for(int bit=63;bit>=0;bit--) {
        uint64_t candidate=root|(UINT64_C(1)<<bit);
        if((__uint128_t)candidate*candidate<=value)root=candidate;
    }
    return root;
}
static int soft_sqrt(PwGuestFp *fp,Soft80 value,uint8_t out[10])
{
    if(value.kind==SOFT_NAN){pack_special(value,out);return PW_OK;}
    if(value.sign && value.kind!=SOFT_ZERO)return invalid_result(fp,out);
    if(value.kind!=SOFT_FINITE){pack_special(value,out);return PW_OK;}
    unsigned odd=(unsigned)value.exp&1;
    __uint128_t radicand=(__uint128_t)value.sig<<(63+odd);
    uint64_t root=integer_sqrt128(radicand);
    __uint128_t remainder=radicand-(__uint128_t)root*root;
    unsigned precision=(fp->x87_control&0x300)==0?24:
        (fp->x87_control&0x300)==0x200?53:64;
    unsigned drop=64-precision,mode=(fp->x87_control>>10)&3;
    uint64_t kept=root>>drop,low=drop?root&((UINT64_C(1)<<drop)-1):0;
    unsigned inexact=!!low || !!remainder,increment=0;
    if(inexact) {
        if(mode==2)increment=1;
        else if(mode==0) {
            if(!drop)increment=remainder>root;
            else {
                uint64_t half=UINT64_C(1)<<(drop-1);
                increment=low>half || (low==half && (remainder || (kept&1)));
            }
        }
    }
    unsigned carry=precision==64?increment && kept==UINT64_MAX:
        kept+increment==(UINT64_C(1)<<precision);
    int exponent=(value.exp-(int)odd)/2;
    if(carry){kept=UINT64_C(1)<<(precision-1);exponent++;}else kept+=increment;
    put80(out,kept<<(64-precision),(uint16_t)(exponent+16383));
    return inexact?exception(fp,X87_PE):PW_OK;
}
static int replace_st(PwGuestFp *fp,unsigned logical,const uint8_t value[10])
{
    if(logical>=8)return PW_ERR_PRECONDITION;
    unsigned slot=(top(fp)+logical)&7;
    if(tag(fp,slot)==3)return PW_ERR_NOT_FOUND;
    memcpy(fp->x87_st[slot],value,10);set_tag(fp,slot,unpack80(value).kind==SOFT_ZERO?1:
        unpack80(value).kind==SOFT_FINITE?0:2);return PW_OK;
}
static int binary(PwGuestFp *fp,Soft80 rhs,unsigned operation,unsigned reverse,
                  unsigned destination,unsigned pop)
{
    uint8_t left_raw[10],result[10];int status=peek(fp,0,left_raw);if(status!=PW_OK)return status;
    Soft80 left=unpack80(left_raw);
    if(reverse){Soft80 swap=left;left=rhs;rhs=swap;}
    PwGuestFp after=*fp;
    status=operation==0?soft_add(&after,left,rhs,result):
        operation==1?soft_mul(&after,left,rhs,result):
        operation==2?soft_add(&after,left,(Soft80){.sig=rhs.sig,.exp=rhs.exp,.sign=!rhs.sign,.kind=rhs.kind},result):
        soft_div(&after,left,rhs,result);
    if(status!=PW_OK){if(status==PW_ERR_X87_TRAP)*fp=after;return status;}
    if((status=replace_st(&after,destination,result))!=PW_OK)return status;
    if(pop && (status=pw_guest_x87_pop(&after,left_raw))!=PW_OK)return status;
    *fp=after;return PW_OK;
}
static int memory_operand(PwGuestFp *fp,uintptr_t operand,unsigned bits,Soft80 *value)
{
    uint8_t raw[10];int status;uint32_t u32;uint64_t u64;PwGuestFp copy=*fp;
    if(bits==32){memcpy(&u32,(const void *)operand,4);status=from_binary(&copy,u32,23,8,127,raw);}
    else {memcpy(&u64,(const void *)operand,8);status=from_binary(&copy,u64,52,11,1023,raw);}
    if(status!=PW_OK){if(status==PW_ERR_X87_TRAP)*fp=copy;return status;}
    *fp=copy;*value=unpack80(raw);return PW_OK;
}
static int compare(PwGuestFp *fp,Soft80 rhs,unsigned pop_count)
{
    uint8_t left_raw[10];int status=peek(fp,0,left_raw);if(status!=PW_OK)return status;
    Soft80 left=unpack80(left_raw);PwGuestFp after=*fp;unsigned flags;
    if(left.kind==SOFT_NAN || rhs.kind==SOFT_NAN){flags=0x4500;if((status=exception(&after,X87_IE))!=PW_OK){*fp=after;return status;}}
    else if(left.kind==SOFT_ZERO && rhs.kind==SOFT_ZERO)flags=0x4000;
    else if(left.kind==SOFT_ZERO)flags=rhs.sign?0:0x0100;
    else if(rhs.kind==SOFT_ZERO)flags=left.sign?0x0100:0;
    else if(left.sign!=rhs.sign)flags=left.sign?0x0100:0;
    else {
        int order=left.kind==SOFT_INFINITY?(rhs.kind==SOFT_INFINITY?0:1):
            rhs.kind==SOFT_INFINITY?-1:left.exp<rhs.exp?-1:left.exp>rhs.exp?1:
            left.sig<rhs.sig?-1:left.sig>rhs.sig?1:0;
        if(left.sign)order=-order;
        flags=order<0?0x0100:order==0?0x4000:0;
    }
    after.x87_status=(uint16_t)((after.x87_status&~0x4500u)|flags);
    while(pop_count--)if((status=pw_guest_x87_pop(&after,left_raw))!=PW_OK)return status;
    *fp=after;return PW_OK;
}

int pw_x87_execute(PwGuestFp *fp,PwX87Action action,uintptr_t operand,uint16_t *ax)
{
    if(!fp || !fp->initialized)return fp?PW_ERR_STATE:PW_ERR_PRECONDITION;
    if((unsigned)action>PW_X87_FUCOMPP)return PW_ERR_UNSUPPORTED;
    switch(action) {
    case PW_X87_FLD_ST:case PW_X87_FSTP_ST:
    case PW_X87_FADD_ST:case PW_X87_FMUL_ST:case PW_X87_FSUB_ST:case PW_X87_FDIV_ST:
    case PW_X87_FADDP_ST:case PW_X87_FDIVP_ST:case PW_X87_FCOM_ST:
        if(operand>=8)return PW_ERR_PRECONDITION;
        break;
    default:break;
    }
    int preflight=stack_preflight(fp,action,operand);
    if(preflight<0)return preflight;
    if(preflight>0)return PW_OK;
    uint8_t value[10];uint32_t u32;uint64_t u64;int status;
    switch(action) {
    case PW_X87_FLD_F32:
        memcpy(&u32,(const void *)operand,4);if((status=from_binary(fp,u32,23,8,127,value))!=PW_OK)return status;
        return load(fp,value);
    case PW_X87_FLD_F64:
        memcpy(&u64,(const void *)operand,8);if((status=from_binary(fp,u64,52,11,1023,value))!=PW_OK)return status;
        return load(fp,value);
    case PW_X87_FILD_I32:
        memcpy(&u32,(const void *)operand,4);from_i32((int32_t)u32,value);return load(fp,value);
    case PW_X87_FLD_ST:
        if((status=peek(fp,(unsigned)operand,value))!=PW_OK)return status;
        return load(fp,value);
    case PW_X87_FLD1:
        put80(value,UINT64_C(0x8000000000000000),0x3fff);return load(fp,value);
    case PW_X87_FLDZ:
        memset(value,0,10);return load(fp,value);
    case PW_X87_FST_F32:return store_memory(fp,operand,32,0);
    case PW_X87_FSTP_F32:return store_memory(fp,operand,32,1);
    case PW_X87_FSTP_F64:return store_memory(fp,operand,64,1);
    case PW_X87_FSTP_ST: {
        unsigned logical=(unsigned)operand;if(logical>=8)return PW_ERR_PRECONDITION;
        if((status=peek(fp,0,value))!=PW_OK)return status;
        PwGuestFp after=*fp;unsigned slot=(top(&after)+logical)&7;
        memcpy(after.x87_st[slot],value,10);set_tag(&after,slot,tag(&after,top(&after)));
        if((status=pw_guest_x87_pop(&after,value))!=PW_OK)return status;
        *fp=after;return PW_OK;
    }
    case PW_X87_FNSTSW_AX:
        if(!ax)return PW_ERR_PRECONDITION;
        *ax=fp->x87_status;return PW_OK;
    case PW_X87_FABS: {
        if((status=peek(fp,0,value))!=PW_OK)return status;
        value[9]&=0x7f;
        return replace_st(fp,0,value);
    }
    case PW_X87_FSQRT: {
        if((status=peek(fp,0,value))!=PW_OK)return status;
        PwGuestFp after=*fp;uint8_t result[10];
        if((status=soft_sqrt(&after,unpack80(value),result))!=PW_OK){if(status==PW_ERR_X87_TRAP)*fp=after;return status;}
        if((status=replace_st(&after,0,result))!=PW_OK)return status;
        *fp=after;return PW_OK;
    }
    case PW_X87_FADD_F32:case PW_X87_FADD_F64:
    case PW_X87_FMUL_F32:case PW_X87_FMUL_F64:
    case PW_X87_FSUB_F32:case PW_X87_FSUBR_F32:
    case PW_X87_FDIV_F32:case PW_X87_FDIVR_F64: {
        Soft80 rhs;unsigned bits=action==PW_X87_FADD_F64 || action==PW_X87_FMUL_F64 ||
            action==PW_X87_FDIVR_F64?64:32;
        if((status=memory_operand(fp,operand,bits,&rhs))!=PW_OK)return status;
        unsigned op=action==PW_X87_FMUL_F32 || action==PW_X87_FMUL_F64?1:
            action==PW_X87_FSUB_F32 || action==PW_X87_FSUBR_F32?2:
            action==PW_X87_FDIV_F32 || action==PW_X87_FDIVR_F64?3:0;
        return binary(fp,rhs,op,action==PW_X87_FSUBR_F32 || action==PW_X87_FDIVR_F64,0,0);
    }
    case PW_X87_FADD_ST:case PW_X87_FMUL_ST:case PW_X87_FSUB_ST:case PW_X87_FDIV_ST:
    case PW_X87_FADDP_ST:case PW_X87_FDIVP_ST: {
        if((status=peek(fp,(unsigned)operand,value))!=PW_OK)return status;
        unsigned op=action==PW_X87_FMUL_ST?1:action==PW_X87_FSUB_ST?2:
            action==PW_X87_FDIV_ST || action==PW_X87_FDIVP_ST?3:0;
        unsigned pop=action==PW_X87_FADDP_ST || action==PW_X87_FDIVP_ST;
        return binary(fp,unpack80(value),op,action==PW_X87_FDIVP_ST,
                      pop?(unsigned)operand:0,pop);
    }
    case PW_X87_FCOM_F32:case PW_X87_FCOM_F64:
    case PW_X87_FCOMP_F32:case PW_X87_FCOMP_F64: {
        Soft80 rhs;unsigned bits=action==PW_X87_FCOM_F64 || action==PW_X87_FCOMP_F64?64:32;
        if((status=memory_operand(fp,operand,bits,&rhs))!=PW_OK)return status;
        return compare(fp,rhs,action==PW_X87_FCOMP_F32 || action==PW_X87_FCOMP_F64);
    }
    case PW_X87_FCOM_ST:
        if((status=peek(fp,(unsigned)operand,value))!=PW_OK)return status;
        return compare(fp,unpack80(value),0);
    case PW_X87_FUCOMPP:
        if((status=peek(fp,1,value))!=PW_OK)return status;
        return compare(fp,unpack80(value),2);
    }
    return PW_ERR_UNSUPPORTED;
}
