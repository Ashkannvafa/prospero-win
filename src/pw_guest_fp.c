/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_guest_fp.h"
#include "../include/prospero_win.h"
/* MSVCRT flag encodings, reviewed against pinned Wine msvcrt/math.c and
 * include/msvcrt/float.h. This is guest integer state, not host FP calls. */
enum { EM=0x8001f, DENORMAL=0x80000, RC=0x300, PC=0x30000,
       IC=0x40000, DN=0x3000000 };
static const uint32_t exception_bits[]={0x10,0x80000,8,4,2,1};
static uint32_t decode(uint32_t raw,unsigned sse)
{
    uint32_t flags=0;
    for(unsigned i=0;i<6;i++)if(raw&(1u<<(i+(sse?7:0))))flags|=exception_bits[i];
    flags|=((raw>>(sse?13:10))&3)<<8;
    if(sse) {
        unsigned mode=raw&0x8040;
        flags|=mode==0x8040?0x1000000:mode==0x40?0x2000000:mode==0x8000?0x3000000:0;
    } else {
        unsigned precision=raw&0x300;
        flags|=precision==0?0x20000:precision==0x200?0x10000:0;
        if(raw&0x1000)flags|=IC;
    }
    return flags;
}
static uint32_t encode(uint32_t raw,uint32_t flags,unsigned sse)
{
    uint32_t next=raw&~(sse?0xffc0u:0x1f3fu);
    for(unsigned i=0;i<6;i++)if(flags&exception_bits[i])next|=1u<<(i+(sse?7:0));
    next|=((flags>>8)&3)<<(sse?13:10);
    if(sse) {
        unsigned mode=flags&DN;
        next|=mode==0x1000000?0x8040:mode==0x2000000?0x40:mode==0x3000000?0x8000:0;
        if(next!=raw)next&=~0x3fu; /* Wine clears SSE status on control change. */
    } else {
        unsigned precision=flags&PC;
        next|=precision==0?0x300:precision==0x10000?0x200:0;
        if(flags&IC)next|=0x1000;
    }
    return next;
}
void pw_guest_fp_init(PwGuestFp *fp)
{
    if(fp)*fp=(PwGuestFp){.x87_control=0x027f,.mxcsr=0x1f80,.initialized=1};
}
int pw_guest_fp_control(PwGuestFp *fp,uint32_t value,uint32_t mask,uint32_t *result)
{
    if(!fp || !result)return PW_ERR_PRECONDITION;
    if(!fp->initialized)return PW_ERR_STATE;
    mask&=~DENORMAL; /* _controlfp, unlike _control87, cannot change this mask. */
    uint32_t xmask=mask&(EM|RC|PC|IC),smask=mask&(EM|RC|DN);
    uint32_t x=decode(fp->x87_control,0),s=decode(fp->mxcsr,1);
    x=(x&~xmask)|(value&xmask);s=(s&~smask)|(value&smask);
    fp->x87_control=(uint16_t)encode(fp->x87_control,x,0);
    fp->mxcsr=encode(fp->mxcsr,s,1);
    *result=x|s|(((x^s)&(EM|RC))?0x80000000u:0);
    return PW_OK;
}
