/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_guest_fp.h"
#include "../include/prospero_win.h"
#include <assert.h>
#include <string.h>
int main(void)
{
    uint16_t host_cw,after_cw;uint32_t host_sse,after_sse;
    __asm__ volatile("fnstcw %0":"=m"(host_cw));
    __asm__ volatile("stmxcsr %0":"=m"(host_sse));
    PwGuestFp fp={0};uint32_t result=123;
    assert(pw_guest_fp_control(&fp,0,0,&result)==PW_ERR_STATE && result==123);
    pw_guest_fp_init(&fp);
    assert(pw_guest_fp_control(&fp,0,0,&result)==PW_OK && result==0x9001f);
    assert(fp.x87_control==0x027f && fp.mxcsr==0x1f80);
    const unsigned winbits[]={0x10,0x80000,8,4,2,1};
    for(unsigned i=0;i<6;i++) {
        pw_guest_fp_init(&fp);
        assert(pw_guest_fp_control(&fp,0,winbits[i],&result)==PW_OK);
        assert(result==(i==1?0x9001f:0x9001f&~winbits[i]));
        assert(!!(fp.x87_control&(1u<<i))==(i==1));
        assert(!!(fp.mxcsr&(1u<<(i+7)))==(i==1));
    }
    for(unsigned round=0;round<4;round++)for(unsigned precision=0;precision<3;precision++)
    for(unsigned denormal=0;denormal<4;denormal++) {
        pw_guest_fp_init(&fp);fp.mxcsr|=0x21;
        unsigned value=(round<<8)|(precision<<16)|(denormal<<24)|0x40000;
        assert(pw_guest_fp_control(&fp,value,0x3070300,&result)==PW_OK);
        assert((fp.x87_control&0xc00)==round<<10);
        assert((fp.x87_control&0x300)==(precision==0?0x300:precision==1?0x200:0));
        assert(fp.x87_control&0x1000);
        assert((fp.mxcsr&0x6000)==round<<13);
        unsigned modes[]={0,0x8040,0x40,0x8000};
        assert((fp.mxcsr&0x8040)==modes[denormal]);
        assert((fp.mxcsr&0x3f)==(!round && !denormal?0x21:0));
        assert(result==(value|0x8001f));
        uint32_t query;assert(pw_guest_fp_control(&fp,0,0,&query)==PW_OK && query==result);
    }
    pw_guest_fp_init(&fp);fp.mxcsr^=0x2000;
    assert(pw_guest_fp_control(&fp,0,0,&result)==PW_OK && result==0x8009011f);
    PwGuestFp before=fp;
    assert(pw_guest_fp_control(&fp,0,0,NULL)==PW_ERR_PRECONDITION && !memcmp(&fp,&before,sizeof(fp)));
    __asm__ volatile("fnstcw %0":"=m"(after_cw));
    __asm__ volatile("stmxcsr %0":"=m"(after_sse));
    assert(host_cw==after_cw && host_sse==after_sse);
    return 0;
}
