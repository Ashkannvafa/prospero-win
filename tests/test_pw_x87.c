/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_x87.h"
#include "../include/prospero_win.h"
#include <assert.h>
#include <string.h>

int main(void)
{
    PwGuestFp fp;pw_guest_fp_init(&fp);uint16_t ax=0xffff;
    uint32_t one=0x3f800000,negative=0xc0200000,stored=0;
    uint64_t pi=UINT64_C(0x400921fb54442d18),stored64=0;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one,NULL)==PW_OK);
    const uint8_t ext_one[10]={0,0,0,0,0,0,0,0x80,0xff,0x3f};uint8_t got[10];
    assert(pw_guest_x87_peek(&fp,0,got)==PW_OK && !memcmp(got,ext_one,10));
    assert(pw_x87_execute(&fp,PW_X87_FST_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==one);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==one);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F64,(uintptr_t)&pi,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F64,(uintptr_t)&stored64,NULL)==PW_OK && stored64==pi);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&negative,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_ST,0,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==negative);
    int32_t minimum=INT32_MIN;
    assert(pw_x87_execute(&fp,PW_X87_FILD_I32,(uintptr_t)&minimum,NULL)==PW_OK);
    const uint8_t ext_min[10]={0,0,0,0,0,0,0,0x80,0x1e,0xc0};
    assert(pw_guest_x87_peek(&fp,0,got)==PW_OK && !memcmp(got,ext_min,10));
    assert(pw_x87_execute(&fp,PW_X87_FNSTSW_AX,0,&ax)==PW_OK && ax==fp.x87_status);
    assert(pw_guest_x87_pop(&fp,got)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD1,0,NULL)==PW_OK);
    assert(pw_guest_x87_peek(&fp,0,got)==PW_OK && !memcmp(got,ext_one,10));
    assert(pw_x87_execute(&fp,PW_X87_FLDZ,0,NULL)==PW_OK);
    assert(pw_guest_x87_peek(&fp,0,got)==PW_OK && !memcmp(got,(uint8_t[10]){0},10));

    /* Exact halfway float32 conversion obeys all four guest rounding modes. */
    uint8_t half[10]={0,0,0,0,0x80,0,0,0x80,0xff,0x3f};
    pw_guest_fp_init(&fp);assert(pw_guest_x87_push(&fp,half)==PW_OK);
    fp.x87_control=(uint16_t)((fp.x87_control&~0xc00u)|0x800u);
    assert(pw_x87_execute(&fp,PW_X87_FST_F32,(uintptr_t)&stored,NULL)==PW_OK);
    assert(stored==0x3f800001 && (fp.x87_status&32));

    /* Exact arithmetic vectors are expressed as IEEE-754 bit patterns, not
     * evaluated through the host floating-point environment. */
    uint32_t one_half=0x3fc00000,two_quarter=0x40100000,three_quarter=0x40700000;
    pw_guest_fp_init(&fp);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one_half,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADD_F32,(uintptr_t)&two_quarter,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three_quarter);
    uint32_t negative_half=0xbf000000,half32=0x3f000000;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADD_F32,(uintptr_t)&negative_half,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==half32);
    uint32_t two=0x40000000,three=0x40400000,six=0x40c00000;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FMUL_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FDIV_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three);
    uint32_t five=0x40a00000;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSUBR_F32,(uintptr_t)&five,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==two);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&six,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FCOM_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(!(fp.x87_status&0x4500));
    assert(pw_x87_execute(&fp,PW_X87_FCOMP_F32,(uintptr_t)&six,NULL)==PW_OK);
    assert((fp.x87_status&0x4500)==0x4000);
    uint32_t zero32=0;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FDIV_F32,(uintptr_t)&zero32,NULL)==PW_OK);
    assert(fp.x87_status&4);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==0x7f800000);
    uint32_t four=0x40800000;
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&four,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSQRT,0,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==two);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSQRT,0,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==0x3fb504f3);

    uint64_t one64=UINT64_C(0x3ff0000000000000),two64=UINT64_C(0x4000000000000000);
    uint64_t three64=UINT64_C(0x4008000000000000),six64=UINT64_C(0x4018000000000000);
    pw_guest_fp_init(&fp);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F64,(uintptr_t)&one64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADD_F64,(uintptr_t)&two64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F64,(uintptr_t)&stored64,NULL)==PW_OK && stored64==three64);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F64,(uintptr_t)&two64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FMUL_F64,(uintptr_t)&three64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F64,(uintptr_t)&stored64,NULL)==PW_OK && stored64==six64);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADD_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three);
    assert(pw_guest_x87_pop(&fp,got)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&one,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADDP_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FMUL_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==six);
    assert(pw_guest_x87_pop(&fp,got)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSUB_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==one);
    assert(pw_guest_x87_pop(&fp,got)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&six,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FDIV_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three);
    assert(pw_guest_x87_pop(&fp,got)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&six,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FDIVP_ST,1,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==three);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F64,(uintptr_t)&two64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FDIVR_F64,(uintptr_t)&six64,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FCOM_F64,(uintptr_t)&three64,NULL)==PW_OK && (fp.x87_status&0x4500)==0x4000);
    assert(pw_x87_execute(&fp,PW_X87_FCOMP_F64,(uintptr_t)&three64,NULL)==PW_OK && (fp.x87_status&0x4500)==0x4000);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&three,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&two,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FCOM_ST,1,NULL)==PW_OK && (fp.x87_status&0x4500)==0x0100);
    assert(pw_x87_execute(&fp,PW_X87_FUCOMPP,0,NULL)==PW_OK);
    assert(pw_guest_x87_peek(&fp,0,got)==PW_ERR_NOT_FOUND);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&negative_half,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FABS,0,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==half32);
    assert(pw_x87_execute(&fp,PW_X87_FLD_F32,(uintptr_t)&zero32,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FADD_F32,(uintptr_t)&one,NULL)==PW_OK);
    assert(pw_x87_execute(&fp,PW_X87_FCOM_F32,(uintptr_t)&zero32,NULL)==PW_OK && !(fp.x87_status&0x4500));
    assert(pw_x87_execute(&fp,PW_X87_FSTP_F32,(uintptr_t)&stored,NULL)==PW_OK && stored==one);
    return 0;
}
