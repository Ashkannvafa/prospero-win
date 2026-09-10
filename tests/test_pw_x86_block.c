/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_x86_block.h"
#include "../src/pw_guest_call.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef int (*BlockFn)(PwX86State *);
static PwVmBackend backend;
static PwVmRegion code, stack;
static PwX86State state;
/* Generated code has no Clang function-type metadata before its entry.
 * Disable only that indirect-call check, not ASan or other UBSan checks. */
#if defined(__clang__)
__attribute__((no_sanitize("function")))
#endif
static int invoke(BlockFn fn, PwX86State *context) { return fn(context); }
static int run(const uint8_t *source, size_t bytes, uint32_t pc)
{
    PwX86Block block;
    assert(backend.protect(NULL,&code,0,code.bytes,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    assert(pw_x86_translate(source,bytes,pc,code.write_base,code.bytes,&block)==PW_OK);
    assert(block.source_bytes == bytes);
    assert(backend.protect(NULL,&code,0,code.bytes,PW_PROT_READ|PW_PROT_EXEC)==PW_OK);
    return invoke((BlockFn)code.exec_base,&state);
}
static void addressing_tests(void)
{
    /* Exercise every 32-bit SIB encoding in all memory displacement modes.
     * Expected arithmetic is C uint32_t, independent from emitted code. */
    for(unsigned mod=0;mod<3;mod++)for(unsigned rm=0;rm<8;rm++)
        for(unsigned sib=0;sib<(rm==4?256u:1u);sib++) {
            for(unsigned i=0;i<8;i++)state.gpr[i]=0xf0000100u+i*17;
            uint32_t before[8];memcpy(before,state.gpr,sizeof(before));
            uint8_t lea[7]={0x8d,(uint8_t)((mod<<6)|(3<<3)|rm)};
            size_t n=2;
            unsigned base=rm, index=4, scale=0;
            if(rm==4) {lea[n++]=(uint8_t)sib;base=sib&7;index=(sib>>3)&7;scale=sib>>6;}
            uint32_t value=(mod==0 && base==5)?0:before[base];
            if(rm==4 && index!=4)value+=before[index]<<scale;
            if(mod==1) {lea[n++]=0xf0;value-=16;}
            else if(mod==2 || (mod==0 && base==5)) {
                lea[n++]=3;lea[n++]=0;lea[n++]=0;lea[n++]=0x80;
                value+=0x80000003u;
            }
            assert(run(lea,n,0x600)==0);
            before[3]=value;
            assert(memcmp(before,state.gpr,sizeof(before))==0);
            assert(state.eip==0x600+n);
            /* Every proper prefix must be rejected as incomplete. */
            uint8_t out[512];PwX86Block block;
            for(size_t len=1;len<n;len++)
                assert(pw_x86_translate(lea,len,0,out,sizeof(out),&block)==PW_ERR_TRUNCATED);
        }
    state.gpr[4]=state.stack_high-64;
    state.gpr[0]=0x12345678;
    const uint8_t save[]={0x89,0x44,0x24,0xfc}; /* [esp-4] = eax */
    const uint8_t load[]={0x8b,0x6c,0x24,0xfc}; /* ebp = [esp-4] */
    assert(run(save,sizeof(save),0x700)==0);
    assert(run(load,sizeof(load),0x704)==0);
    assert(state.gpr[5]==0x12345678);
    /* Absolute disp32 is guest absolute, not host RIP-relative. */
    const uint8_t absolute[]={0x8b,0x15,0xbc,0x0f,0x00,0x03};
    assert(run(absolute,sizeof(absolute),0x710)==0);
    assert(state.gpr[2]==0x12345678);
    state.gpr[4]=state.stack_low;
    assert(run(save,sizeof(save),0x720)==-1 && state.eip==0x720);
    state.gpr[5]=0xabcddcba;
    assert(run(load,sizeof(load),0x730)==-1 && state.gpr[5]==0xabcddcba);
}
static void x87_transfer_tests(void)
{
    pw_guest_fp_init(&state.fp);state.gpr[0]=0xabcd0000;state.eflags=0xad7;
    uint32_t address=state.stack_low,bits=0x3f800000;
    memcpy((void *)(uintptr_t)address,&bits,4);
    uint8_t load_store[]={0xd9,0x05,(uint8_t)address,(uint8_t)(address>>8),
        (uint8_t)(address>>16),(uint8_t)(address>>24),
        0xd9,0x1d,(uint8_t)address,(uint8_t)(address>>8),
        (uint8_t)(address>>16),(uint8_t)(address>>24)};
    assert(run(load_store,sizeof(load_store),0xd400)==0);
    memcpy(&bits,(void *)(uintptr_t)address,4);
    assert(bits==0x3f800000 && pw_guest_x87_peek(&state.fp,0,(uint8_t[10]){0})==PW_ERR_NOT_FOUND);
    assert(state.eflags==0xad7 && state.eip==0xd400+sizeof(load_store));

    int32_t integer=-17;memcpy((void *)(uintptr_t)address,&integer,4);
    uint8_t fild[]={0xdb,0x05,(uint8_t)address,(uint8_t)(address>>8),
        (uint8_t)(address>>16),(uint8_t)(address>>24)};
    assert(run(fild,sizeof(fild),0xd420)==0);
    const uint8_t duplicate_status[]={0xd9,0xc0,0xdd,0xd9,0xdf,0xe0};
    assert(run(duplicate_status,sizeof(duplicate_status),0xd430)==0);
    assert((state.gpr[0]&0xffff)==state.fp.x87_status);
    uint8_t discarded[10];assert(pw_guest_x87_pop(&state.fp,discarded)==PW_OK);

    const uint8_t constants[]={0xd9,0xe8,0xd9,0xee};
    assert(run(constants,sizeof(constants),0xd440)==0);
    uint8_t zero[10];assert(pw_guest_x87_pop(&state.fp,zero)==PW_OK);
    assert(!memcmp(zero,(uint8_t[10]){0},10));
    assert(pw_guest_x87_pop(&state.fp,discarded)==PW_OK);

    /* An eight-byte load that crosses the live boundary faults atomically. */
    state.gpr[1]=state.stack_high-7;PwGuestFp before=state.fp;
    const uint8_t bad[]={0xdd,0x01};
    assert(run(bad,sizeof(bad),0xd450)==-1 && state.eip==0xd450);
    assert(!memcmp(&before,&state.fp,sizeof(before)));
}
static void arithmetic_tests(void)
{
    for(unsigned carry=0;carry<2;carry++) {
        state.gpr[0]=7;state.eflags=0x202|carry;
        const uint8_t sbb[]={0x1b,0xc0};
        assert(run(sbb,sizeof(sbb),0x8f0)==0);
        assert(state.gpr[0]==(carry?0xffffffffu:0));
        assert((state.eflags&1)==carry);
    }
    const uint32_t values[]={0,1,15,16,0x7fffffffu,0x80000000u,0xffffffffu};
    for(unsigned a=0;a<7;a++)for(unsigned b=0;b<7;b++)
        for(unsigned direction=0;direction<2;direction++) {
            uint32_t x=values[a],y=values[b],z=x-y;
            state.gpr[0]=x;state.gpr[1]=y;state.eflags=0x602;
            uint8_t sub[]={direction?0x2b:0x29,direction?0xc1:0xc8};
            assert(run(sub,2,0x900)==0 && state.gpr[0]==z && state.gpr[1]==y);
            uint32_t f=(x<y?1:0) | (z==0?0x40:0) | ((z>>31)?0x80:0);
            f|=((x^y^z)&16);
            f|=(((x^y)&(x^z))>>31)?0x800:0;
            unsigned parity=0;for(unsigned bit=0;bit<8;bit++)parity^=(z>>bit)&1;
            if(!parity)f|=4;
            assert(state.eflags==(0x602|f));
            state.gpr[0]=x;state.gpr[1]=y;state.eflags=0x612;
            const uint8_t logical[]={direction?0x33:0x31,direction?0xc1:0xc8};
            assert(run(logical,2,0x904)==0 && state.gpr[0]==(x^y));
            uint32_t v=x^y,lf=(v==0?0x40:0)|((v>>31)?0x80:0);
            unsigned lp=0;for(unsigned bit=0;bit<8;bit++)lp^=(v>>bit)&1;
            if(!lp)lf|=4;
            assert(state.eflags==(0x612|lf));
            uint32_t before_mov=state.eflags;
            const uint8_t mov[]={0xc7,0xc2,0x12,0x34,0x56,0x78};
            assert(run(mov,sizeof(mov),0x902)==0 && state.gpr[2]==0x78563412);
            assert(state.eflags==before_mov);
        }
    state.gpr[4]=state.stack_high-32;
    const uint8_t write[]={0xc7,0x44,0x24,4,0xff,0xff,0xff,0xff};
    assert(run(write,sizeof(write),0xa00)==0);
    assert(*(uint32_t *)(uintptr_t)(state.gpr[4]+4)==0xffffffffu);
    state.gpr[4]=state.stack_high-4;
    uint32_t flags=state.eflags;
    assert(run(write,sizeof(write),0xa10)==-1 && state.eip==0xa10);
    assert(state.eflags==flags);
}
static void shift_tests(void)
{
    const uint32_t values[]={0,1,0x80000000,0x7fffffff,0xffffffff,0x89abcdef};
    const unsigned kinds[]={4,5,7};
    for(unsigned k=0;k<3;k++)for(unsigned form=0;form<3;form++)
    for(unsigned memory=0;memory<2;memory++)for(unsigned count=0;count<256;count++)
    for(unsigned v=0;v<6;v++) {
        unsigned actual=form==1?1:count,masked=actual&31;
        uint32_t expected=values[v];unsigned long flags;
        if(k==0)__asm__ volatile("shll %%cl,%0; pushfq; popq %1":"+a"(expected),"=r"(flags):"c"(actual):"cc");
        else if(k==1)__asm__ volatile("shrl %%cl,%0; pushfq; popq %1":"+a"(expected),"=r"(flags):"c"(actual):"cc");
        else __asm__ volatile("sarl %%cl,%0; pushfq; popq %1":"+a"(expected),"=r"(flags):"c"(actual):"cc");
        state.gpr[0]=values[v];state.gpr[1]=count;state.gpr[2]=state.stack_high-4;state.eflags=0xad7;
        memcpy((void *)(uintptr_t)state.gpr[2],&values[v],4);
        const uint8_t op[]={(uint8_t)(form==0?0xc1:form==1?0xd1:0xd3),(uint8_t)((memory?2:0xc0)|(kinds[k]<<3)),(uint8_t)count};
        assert(run(op,form==0?3:2,0xd100)==0);
        uint32_t result=state.gpr[0];if(memory)memcpy(&result,(void *)(uintptr_t)state.gpr[2],4);
        unsigned mask=masked?(masked==1?0x8c5:0xc5):0;
        assert(result==expected && state.eflags==((0xad7&~mask)|((unsigned)flags&mask)));
        assert(state.gpr[1]==count && state.gpr[2]==state.stack_high-4);
    }
    /* Destination ECX must use its old CL. A following instruction must run. */
    state.gpr[1]=0x80000021;state.eflags=0x202;
    const uint8_t alias[]={0xd3,0xe9,0xb8,42,0,0,0};
    assert(run(alias,sizeof(alias),0xd200)==0 && state.gpr[1]==0x40000010 && state.gpr[0]==42);
    for(unsigned count=0;count<2;count++) {
        state.gpr[2]=state.stack_high-3;state.eflags=0xad7;
        const uint8_t bad[]={0xc1,0x22,(uint8_t)count};
        assert(run(bad,3,0xd300)==-1 && state.eip==0xd300 && state.eflags==0xad7);
    }
}
static void extension_tests(void)
{
    const uint32_t values[]={0,1,0x7f,0x80,0xff,0x7fff,0x8000,0xffff};
    for(unsigned word=0;word<2;word++)for(unsigned sign=0;sign<2;sign++)
    for(unsigned src=0;src<8;src++)for(unsigned dst=0;dst<8;dst++)for(unsigned v=0;v<8;v++) {
        for(unsigned i=0;i<8;i++)state.gpr[i]=0xaabbccdd;
        unsigned reg=word?src:src&3,shift=word?0:(src>>2)*8,mask=word?0xffff:0xff;
        state.gpr[reg]=(state.gpr[reg]&~(mask<<shift))|((values[v]&mask)<<shift);
        uint32_t before[8];memcpy(before,state.gpr,sizeof(before));state.eflags=0xad7;
        uint32_t expected=values[v]&mask;if(sign && (expected&(word?0x8000:0x80)))expected|=~mask;
        const uint8_t extend[]={0x0f,(uint8_t)(0xb6+word+sign*8),(uint8_t)(0xc0|(dst<<3)|src)};
        assert(run(extend,3,0xd000)==0 && state.eflags==0xad7);
        before[dst]=expected;assert(!memcmp(before,state.gpr,sizeof(before)));
    }
    for(unsigned word=0;word<2;word++)for(unsigned sign=0;sign<2;sign++) {
        state.gpr[1]=state.stack_high-(word?2:1);state.eflags=0xad7;
        uint16_t value=word?0x8000:0x80;memcpy((void *)(uintptr_t)state.gpr[1],&value,word?2:1);
        const uint8_t op[]={0x0f,(uint8_t)(0xb6+word+sign*8),0x01};
        assert(run(op,3,0xd010)==0 && state.gpr[0]==(sign?(word?0xffff8000:0xffffff80):value) && state.eflags==0xad7);
        state.gpr[1]++;uint32_t before=state.gpr[0];
        assert(run(op,3,0xd020)==-1 && state.gpr[0]==before && state.eflags==0xad7);
    }
}
static void ret_cleanup_tests(void)
{
    for(unsigned dec=0;dec<2;dec++)for(unsigned memory=0;memory<2;memory++)for(unsigned carry=0;carry<2;carry++) {
        uint32_t value=dec?0x80000000:0x7fffffff;
        state.gpr[0]=value;state.gpr[1]=state.stack_low;state.eflags=0x202|carry;
        memcpy(stack.write_base,&value,4);
        const uint8_t incdec[]={0xff,(uint8_t)((memory?1:0xc0)|(dec<<3)),0x90};
        assert(run(incdec,3,0xc010)==0 && state.eip==0xc013);
        uint32_t after=state.gpr[0];if(memory)memcpy(&after,stack.write_base,4);
        assert(after==(dec?0x7fffffff:0x80000000));
        assert(state.eflags==((dec?0xa16u:0xa96u)|carry));
    }
    const unsigned pops[]={0,1,4,8,12,13,255,65535};
    for(unsigned i=0;i<sizeof(pops)/sizeof(pops[0]);i++) {
        state.gpr[4]=state.stack_high-16;state.eflags=0xad7;
        uint32_t target=0x1001234;memcpy((void *)(uintptr_t)state.gpr[4],&target,4);
        const uint8_t ret[]={0xc2,(uint8_t)pops[i],(uint8_t)(pops[i]>>8)};
        assert(run(ret,3,0xc000)==(pops[i]<=12?0:-1));
        assert(state.eflags==0xad7);
        assert(state.gpr[4]==state.stack_high-16+(pops[i]<=12?4+pops[i]:0));
        assert(state.eip==(pops[i]<=12?target:0xc000));
    }
    state.gpr[4]=state.stack_high-16;state.eip=0x1003000;
    PwX86State caller=state;PwGuestCallback callback={0};uint32_t args[]={17,23};
    assert(pw_guest_callback_enter(&callback,&state,0x1004000,0xf1000020,args,2,PW_GUEST_STDCALL)==PW_OK);
    const uint8_t guest[]={0xb8,42,0,0,0,0xc2,8,0};
    assert(run(guest,sizeof(guest),0x1004000)==0 && state.eip==0xf1000020);
    uint64_t result;assert(pw_guest_callback_leave(&callback,32,&result)==PW_OK && result==42);
    assert(!memcmp(&caller,&state,sizeof(state)));
}
static void byte_tests(void)
{
    for(unsigned src=0;src<8;src++)for(unsigned dst=0;dst<8;dst++)for(unsigned direction=0;direction<2;direction++) {
        for(unsigned i=0;i<4;i++)state.gpr[i]=0x778899aau+i*0x1101;
        uint32_t before[8];memcpy(before,state.gpr,sizeof(before));state.eflags=0xad7;
        unsigned shift=(dst>>2)*8,source_shift=(src>>2)*8;
        uint32_t value=(before[src&3]>>source_shift)&255;
        const uint8_t mov[]={direction?0x8a:0x88,(uint8_t)(0xc0|((direction?dst:src)<<3)|(direction?src:dst))};
        assert(run(mov,2,0xb000)==0 && state.eflags==0xad7);
        before[dst&3]=(before[dst&3]&~(255u<<shift))|(value<<shift);
        assert(!memcmp(before,state.gpr,sizeof(before)));
    }
    for(unsigned reg=0;reg<8;reg++) {
        unsigned shift=(reg>>2)*8;state.gpr[reg&3]=0x11223344;
        const uint8_t imm[]={(uint8_t)(0xb0+reg),0xfe};
        assert(run(imm,2,0xb010)==0 && state.gpr[reg&3]==((0x11223344u&~(255u<<shift))|(254u<<shift)));
        const uint8_t cmp[]={0x80,(uint8_t)(0xf8|reg),0xfe};state.eflags=0x202;
        assert(run(cmp,3,0xb020)==0 && state.eflags==0x246);
        state.eflags=0xad7;
        const uint8_t test_imm[]={0xf6,(uint8_t)(0xc0|reg),1};
        assert(run(test_imm,3,0xb021)==0 && state.eflags==0x256);
    }
    state.gpr[0]=0x11223380;state.eflags=0xad7;
    const uint8_t test_al[]={0xa8,0xff};
    assert(run(test_al,2,0xb022)==0 && state.gpr[0]==0x11223380 && state.eflags==0x292);
    state.gpr[1]=state.stack_high-1;state.gpr[0]=0x11228044;state.eflags=0xad7;
    const uint8_t store[]={0x88,0x21},load[]={0x8a,0x01}; /* AH -> [ECX], [ECX] -> AL */
    assert(run(store,2,0xb030)==0 && *((uint8_t *)stack.write_base+stack.bytes-1)==0x80);
    const uint8_t test_memory[]={0xf6,0x01,0x80};
    assert(run(test_memory,3,0xb031)==0 && state.eflags==0x292);
    state.eflags=0xad7;
    assert(run(load,2,0xb040)==0 && state.gpr[0]==0x11228080 && state.eflags==0xad7);
    const uint8_t cmp_mem[]={0x80,0x39,0x7f};
    assert(run(cmp_mem,3,0xb050)==0 && state.eflags==0xa12); /* -128 - 127 overflows */
    const uint8_t immediate_store[]={0xc6,0x01,0x7f};
    assert(run(immediate_store,3,0xb060)==0 && *((uint8_t *)stack.write_base+stack.bytes-1)==0x7f);
    const uint8_t reverse[]={0x3a,0x01};
    assert(run(reverse,2,0xb070)==0 && state.eflags==0xa12);
    const uint8_t direct[]={0x38,0x01};
    assert(run(direct,2,0xb080)==0 && state.eflags==0xa87);
    const uint8_t test[]={0x84,0x01};
    assert(run(test,2,0xb090)==0 && state.eflags==0x246);
    state.gpr[1]=state.stack_high;uint32_t old=state.gpr[0];
    assert(run(load,2,0xb0a0)==-1 && state.gpr[0]==old && state.eflags==0x246);
    for(unsigned dec=0;dec<2;dec++)for(unsigned carry=0;carry<2;carry++) {
        state.gpr[6]=dec?0x80000000:0x7fffffff;state.eflags=0x202|carry;
        const uint8_t op[]={(uint8_t)(dec?0x4e:0x46)};
        assert(run(op,1,0xb0b0)==0 && state.gpr[6]==(dec?0x7fffffff:0x80000000));
        assert(state.eflags==((dec?0xa16u:0xa96u)|carry));
    }
}
static void unary_leave_tests(void)
{
    for(unsigned memory=0;memory<2;memory++)for(unsigned negate=0;negate<2;negate++) {
        uint32_t value=0x80000000;memcpy(stack.write_base,&value,4);
        state.gpr[0]=value;state.gpr[1]=state.stack_low;state.eflags=0xad7;
        const uint8_t op[]={0xf7,(uint8_t)((memory?1:0xc0)|((negate?3:2)<<3))};
        assert(run(op,2,0xa000)==0);
        uint32_t result=state.gpr[0];if(memory)memcpy(&result,stack.write_base,4);
        assert(result==(negate?0x80000000:0x7fffffff));
        assert(state.eflags==(negate?0xa87:0xad7));
    }
    uint32_t words[]={0x12345678,0x1002000};
    uint32_t frame=state.stack_high-8;memcpy((void *)(uintptr_t)frame,words,8);
    state.gpr[5]=frame;state.gpr[4]=state.stack_low;state.eflags=0xad7;
    const uint8_t epilogue[]={0xc9,0xc3};
    assert(run(epilogue,2,0xa010)==0 && state.gpr[4]==state.stack_high && state.gpr[5]==words[0] && state.eip==words[1] && state.eflags==0xad7);
    state.gpr[5]=state.stack_high-3;uint32_t esp=state.gpr[4];
    const uint8_t leave[]={0xc9};
    assert(run(leave,1,0xa020)==-1 && state.gpr[4]==esp && state.gpr[5]==state.stack_high-3 && state.eflags==0xad7);
}
static void arithmetic_memory_tests(void)
{
    const unsigned opcodes[]={0x01,0x03,0x29,0x2b,0x31,0x33};
    const uint32_t answers[]={8,8,2,0xfffffffe,6,6};
    const uint32_t flags[]={0x202,0x202,0x202,0x293,0x216,0x216};
    for(unsigned i=0;i<6;i++) {
        uint32_t value=5;memcpy(stack.write_base,&value,4);
        state.gpr[0]=3;state.gpr[1]=state.stack_low;state.eflags=0xad7;
        const uint8_t bytes[]={(uint8_t)opcodes[i],0x01};
        assert(run(bytes,2,0x9000)==0 && state.eflags==flags[i]);
        memcpy(&value,stack.write_base,4);
        assert(state.gpr[0]==(i&1?answers[i]:3) && value==(i&1?5:answers[i]));
        state.gpr[1]=state.stack_high-3;state.eflags=0xad7;uint32_t before=state.gpr[0];
        assert(run(bytes,2,0x9010)==-1 && state.gpr[0]==before && state.eflags==0xad7 && state.eip==0x9010);
    }
    /* Address and destination register may alias. */
    uint32_t value=0x12345678;memcpy(stack.write_base,&value,4);
    state.gpr[0]=state.stack_low;
    const uint8_t alias[]={0x33,0x00};
    assert(run(alias,2,0x9020)==0 && state.gpr[0]==(state.stack_low^value));
}
static void logical_test_tests(void)
{
    const uint32_t values[]={0,1,0x80000000,0x7fffffff,0xffffffff,0xaabbccdd};
    for(unsigned a=0;a<6;a++)for(unsigned b=0;b<6;b++)for(unsigned form=0;form<5;form++) {
        uint32_t left=values[a],right=values[b],result=left&right;
        state.gpr[0]=left;state.gpr[1]=right;state.gpr[2]=state.stack_low;
        memcpy(stack.write_base,&left,4);state.eflags=0xad7;
        unsigned flags=0x212;
        if(!result)flags|=0x40;
        if(result&0x80000000)flags|=0x80;
        unsigned parity=0;for(unsigned i=0;i<8;i++)parity^=(result>>i)&1;
        if(!parity)flags|=4;
        uint8_t bytes[8];size_t n=0;
        if(form<2){bytes[n++]=0x85;bytes[n++]=form?0x0a:0xc8;}
        else {
            bytes[n++]=form==2?0xa9:0xf7;
            if(form!=2)bytes[n++]=form==3?0xc0:0x02;
            for(unsigned i=0;i<4;i++)bytes[n++]=(uint8_t)(right>>(i*8));
        }
        assert(run(bytes,n,0x8000)==0 && state.eflags==flags);
        uint32_t after;memcpy(&after,stack.write_base,4);
        assert(state.gpr[0]==left && state.gpr[1]==right && after==left);
    }
    state.gpr[2]=state.stack_high-3;state.eflags=0xad7;
    const uint8_t bad[]={0x85,0x0a};
    assert(run(bad,2,0x8010)==-1 && state.eflags==0xad7 && state.eip==0x8010);
}
static void push_operand_tests(void)
{
    uint32_t slot=state.stack_high-8,value=0xaabbccdd;
    memcpy((void *)(uintptr_t)slot,&value,4);
    state.gpr[4]=slot;state.eflags=0xad7;
    const uint8_t from_esp[]={0xff,0x34,0x24};
    assert(run(from_esp,3,0x7000)==0 && state.gpr[4]==slot-4 && state.eip==0x7003 && state.eflags==0xad7);
    uint32_t pushed;memcpy(&pushed,(void *)(uintptr_t)(slot-4),4);assert(pushed==value);
    const uint8_t reg_esp[]={0xff,0xf4};state.gpr[4]=slot;
    assert(run(reg_esp,2,0x7010)==0);
    memcpy(&pushed,(void *)(uintptr_t)(slot-4),4);assert(pushed==slot);
    /* Source valid but destination underflows: do not commit ESP or memory. */
    state.gpr[4]=state.stack_low;value=123;memcpy(stack.write_base,&value,4);
    assert(run(from_esp,3,0x7020)==-1 && state.gpr[4]==state.stack_low && state.eflags==0xad7);
    memcpy(&pushed,stack.write_base,4);assert(pushed==123);
    /* Destination valid but source crosses the readable stack boundary. */
    state.gpr[4]=state.stack_high-2;
    assert(run(from_esp,3,0x7030)==-1 && state.gpr[4]==state.stack_high-2 && state.eip==0x7030);
    const uint8_t continuation[]={0xff,0xf0,0x5a};
    state.gpr[4]=slot;state.gpr[0]=42;
    assert(run(continuation,3,0x7040)==0 && state.gpr[2]==42 && state.gpr[4]==slot && state.eip==0x7043);
}
static void absolute_tests(void)
{
    uint32_t low=state.stack_low,high=state.stack_high;
    state.stack_low=state.stack_high=0;state.memory_count=1;
    for(unsigned write=0;write<2;write++)for(unsigned permission=0;permission<4;permission++)
    for(unsigned edge=0;edge<3;edge++) {
        uint32_t address=edge==0?low:edge==1?high-4:high-3;
        state.memory[0]=(PwX86Memory){low,high,permission};
        uint32_t original=0x11223344;memcpy(stack.write_base,&original,4);
        memcpy((uint8_t *)stack.write_base+stack.bytes-4,&original,4);
        state.gpr[0]=0xaabbccdd;state.eflags=0xad7;
        uint8_t instruction[]={write?0xa3:0xa1,(uint8_t)address,(uint8_t)(address>>8),(uint8_t)(address>>16),(uint8_t)(address>>24)};
        unsigned allowed=edge!=2 && (permission&(write?PW_X86_WRITE:PW_X86_READ));
        assert(run(instruction,5,0x6000)==(allowed?0:-1));
        assert(state.eflags==0xad7 && state.eip==(allowed?0x6005:0x6000));
        assert(state.gpr[0]==(allowed && !write?original:0xaabbccdd));
        uint32_t actual;memcpy(&actual,edge?(uint8_t *)stack.write_base+stack.bytes-4:stack.write_base,4);
        assert(actual==(allowed && write?0xaabbccdd:original));
    }
    state.stack_low=low;state.stack_high=high;state.memory_count=0;
}
static void immediate_tests(void)
{
    const uint32_t inputs[]={0,1,5,0x7fff,0x8000,0x7fffffff,0x80000000,0xffffffff};
    for(unsigned width=0;width<2;width++)for(unsigned op=0;op<8;op++)
    for(unsigned cf=0;cf<2;cf++)for(unsigned sample=0;sample<8;sample++)
    for(unsigned memory=0;memory<2;memory++)for(unsigned encoding=0;encoding<3;encoding++) {
        if(memory && encoding==2)continue;
        uint32_t mask=width?0xffff:UINT32_MAX,sign=width?0x8000:0x80000000;
        uint32_t a=inputs[sample]&mask,b=3,result;
        unsigned carry=(op==2 || op==3)?cf:0,logical=op==1 || op==4 || op==6;
        uint64_t wide;
        if(op==0 || op==2){wide=(uint64_t)a+b+carry;result=(uint32_t)wide&mask;}
        else if(op==1){wide=0;result=a|b;}
        else if(op==4){wide=0;result=a&b;}
        else if(op==6){wide=0;result=a^b;}
        else {wide=(uint64_t)b+carry;result=(a-(uint32_t)wide)&mask;}
        unsigned flags=0x202;
        if(logical)flags|=0x10; /* undefined AF retained */
        else {
            unsigned sub=op==3 || op==5 || op==7;
            if(sub?a<wide:wide>mask)flags|=1;
            if((a^b^result)&16)flags|=16;
            if((sub?((a^b)&(a^result)):(~(a^b)&(a^result)))&sign)flags|=0x800;
        }
        if(!result)flags|=0x40;
        if(result&sign)flags|=0x80;
        unsigned parity=0;for(unsigned bit=0;bit<8;bit++)parity^=(result>>bit)&1;
        if(!parity)flags|=4;
        uint32_t initial=inputs[sample];state.gpr[0]=initial;state.gpr[1]=state.stack_low;
        memcpy(stack.write_base,&initial,4);state.eflags=0x212|cf;
        uint8_t bytes[8];size_t n=0;if(width)bytes[n++]=0x66;
        if(encoding==2)bytes[n++]=(uint8_t)(5+op*8);
        else {bytes[n++]=encoding?0x81:0x83;bytes[n++]=(uint8_t)((memory?1:0xc0)|(op<<3));}
        bytes[n++]=3;
        if(encoding){bytes[n++]=0;if(!width){bytes[n++]=0;bytes[n++]=0;}}
        assert(run(bytes,n,0x5000)==0 && state.eflags==flags);
        uint32_t actual=state.gpr[0];if(memory)memcpy(&actual,stack.write_base,4);
        uint32_t expected=op==7?initial:(initial&~mask)|result;
        assert(actual==expected);
    }
    /* RMW requires both permissions, unlike CMP's read-only access. */
    uint32_t low=state.stack_low,high=state.stack_high;
    state.stack_low=state.stack_high=0;state.memory_count=1;
    state.gpr[0]=low;
    const uint8_t update[]={0x83,0x08,1};
    for(unsigned permission=1;permission<=2;permission++) {
        state.memory[0]=(PwX86Memory){low,high,permission};state.eflags=0x246;
        uint32_t before;memcpy(&before,stack.write_base,4);
        assert(run(update,3,0x5100)==-1 && state.eflags==0x246 && state.eip==0x5100);
        uint32_t after;memcpy(&after,stack.write_base,4);assert(after==before);
    }
    state.stack_low=low;state.stack_high=high;state.memory_count=0;
}
static void comparison_tests(void)
{
    for(unsigned flags=0;flags<32;flags++)for(unsigned condition=0;condition<16;condition++) {
        unsigned cf=flags&1,pf=(flags>>1)&1,zf=(flags>>2)&1,sf=(flags>>3)&1,of=(flags>>4)&1;
        unsigned expected[]={of,!of,cf,!cf,zf,!zf,cf||zf,!(cf||zf),sf,!sf,pf,!pf,sf!=of,sf==of,zf||(sf!=of),!zf&&(sf==of)};
        state.eflags=0x202|cf|(pf<<2)|(zf<<6)|(sf<<7)|(of<<11);
        uint32_t saved_flags=state.eflags;
        const uint8_t branch[]={(uint8_t)(0x70+condition),0xfe};
        assert(run(branch,2,0x1000)==0 && state.eip==(expected[condition]?0x1000:0x1002));
        const uint8_t near_branch[]={0x0f,(uint8_t)(0x80+condition),0xfa,0xff,0xff,0xff};
        assert(run(near_branch,6,0x2000)==0 && state.eip==(expected[condition]?0x2000:0x2006));
        for(unsigned reg=0;reg<8;reg++) {
            state.gpr[reg&3]=0xaabbccdd;
            const uint8_t set[]={0x0f,(uint8_t)(0x90+condition),(uint8_t)(0xc0|reg)};
            assert(run(set,3,0x3000)==0);
            unsigned shift=reg>=4?8:0;
            assert(state.gpr[reg&3]==((0xaabbccddu&~(255u<<shift))|(expected[condition]<<shift)));
        }
        assert(state.eflags==saved_flags);
    }
    state.gpr[0]=state.stack_high-2;
    uint16_t word=0xbeef;memcpy((void *)(uintptr_t)state.gpr[0],&word,2);
    uint32_t saved_eax=state.gpr[0];state.eflags=0x202;
    const uint8_t cmp16[]={0x66,0x81,0x38,0xef,0xbe};
    assert(run(cmp16,sizeof(cmp16),0x4000)==0 && state.eflags==0x246 && state.gpr[0]==saved_eax);
    const uint8_t cmp32[]={0x81,0x38,0xef,0xbe,0,0};
    assert(run(cmp32,sizeof(cmp32),0x4010)==-1 && state.eflags==0x246);
    const uint8_t extend[]={0x0f,0xb7,0x10};
    assert(run(extend,3,0x4020)==0 && state.gpr[2]==0xbeef && state.eflags==0x246);
    state.gpr[0]=0xffffffff;
    const uint8_t sign32[]={0x83,0xf8,0xff},sign16[]={0x66,0x83,0xf8,0xff};
    assert(run(sign32,3,0x4030)==0 && state.eflags==0x246);
    assert(run(sign16,4,0x4040)==0 && state.eflags==0x246);
    state.gpr[0]=3;state.gpr[1]=state.stack_low;
    uint32_t five=5;memcpy(stack.write_base,&five,4);
    const uint8_t cmp_reg_mem[]={0x3b,0x01},cmp_mem_reg[]={0x39,0x01};
    assert(run(cmp_reg_mem,2,0x4050)==0 && (state.eflags&1));
    assert(run(cmp_mem_reg,2,0x4060)==0 && !(state.eflags&1));
    for(unsigned direction=0;direction<2;direction++) {
        state.gpr[0]=0xffffffff;state.gpr[1]=1;
        const uint8_t add[]={direction?0x03:0x01,direction?0xc1:0xc8};
        assert(run(add,2,0x4070)==0 && state.gpr[0]==0 && (state.eflags&0x8d5)==0x55);
    }
}
int main(int argc, char **argv)
{
    assert(pw_vm_posix_backend(&backend)==PW_OK);
    assert(backend.reserve(NULL,8192,4096,&code)==PW_OK);
    assert(backend.reserve_at(NULL,0x03000000,4096,4096,&stack)==PW_OK);
    assert(backend.commit(NULL,&stack,0,stack.bytes,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    state.stack_low=0x03000000; state.stack_high=0x03001000;
    state.gpr[4]=state.stack_high;
    /* Independent reference in test_pw_x86_reference.S executes these
     * operations as 32-bit instructions on the host CPU. */
    const uint8_t input[]={0x6a,0xff,0x68,0x44,0x33,0x22,0x11,0xe8,0,0,0,0};
    assert(run(input,sizeof(input),0x01000000)==0);
    assert(state.eip==0x0100000c && state.gpr[4]==state.stack_high-12);
    uint32_t *top=(uint32_t *)(uintptr_t)state.gpr[4];
    assert(top[0]==0x0100000c && top[1]==0x11223344 && top[2]==0xffffffffu);
    if (argc==2 && strcmp(argv[1],"--emit")==0)
        assert(fwrite(top,4,3,stdout)==3);
    const uint8_t address_reference[]={0xb8,0xf0,0xff,0xff,0xff,
        0xb9,3,0,0,0,0x8d,0x54,0xc8,0x20};
    assert(run(address_reference,sizeof(address_reference),0x800)==0);
    assert(state.gpr[2]==0x28);
    if (argc==2 && strcmp(argv[1],"--emit")==0)
        assert(fwrite(&state.gpr[2],4,1,stdout)==1);
    const uint8_t ret[]={0xc3};
    assert(run(ret,1,0x02000000)==0);
    assert(state.eip==0x0100000c && state.gpr[4]==state.stack_high-8);
    state.gpr[4]=state.stack_low;
    memset(stack.write_base,0x5a,stack.bytes);
    assert(run(input,sizeof(input),0x01000000)==-1);
    assert(state.gpr[4]==state.stack_low && state.eip==0x01000000);
    for(size_t i=0;i<stack.bytes;i++)assert(((uint8_t *)stack.write_base)[i]==0x5a);
    state.gpr[4]=state.stack_high;
    assert(run(ret,1,0x02000000)==-1);
    assert(state.gpr[4]==state.stack_high);
    /* Register encodings, preserving all other registers, including ESP. */
    for (unsigned reg=0;reg<8;reg++) {
        state.gpr[4]=state.stack_high;
        for (unsigned i=0;i<8;i++) if(i!=4)state.gpr[i]=0xaabb0000+i;
        uint32_t before[8]; memcpy(before,state.gpr,sizeof(before));
        const uint8_t push[]={(uint8_t)(0x50+reg)};
        assert(run(push,1,0x100)==0);
        assert(*(uint32_t *)(uintptr_t)state.gpr[4]==before[reg]);
        const uint8_t pop[]={(uint8_t)(0x58+reg)};
        assert(run(pop,1,0x101)==0);
        assert(memcmp(before,state.gpr,sizeof(before))==0);
        assert(state.eip==0x102);
    }
    /* POP ESP uses the loaded value, not the old ESP plus four. */
    state.gpr[4]=state.stack_high-4;
    *(uint32_t *)(uintptr_t)state.gpr[4]=state.stack_low+128;
    const uint8_t popesp[]={0x5c};
    assert(run(popesp,1,0x200)==0);
    assert(state.gpr[4]==state.stack_low+128);
    /* Failure after one successful instruction commits exactly that prefix. */
    state.gpr[4]=state.stack_low+4;
    const uint8_t twice[]={0x50,0x51};
    assert(run(twice,2,0x300)==-1);
    assert(state.gpr[4]==state.stack_low && state.eip==0x301);
    assert(*(uint32_t *)stack.write_base==state.gpr[0]);
    /* All register/register MOV combinations, including ESP. */
    for (unsigned direction=0;direction<2;direction++)
        for(unsigned src=0;src<8;src++)for(unsigned dst=0;dst<8;dst++) {
            for(unsigned i=0;i<8;i++)state.gpr[i]=0x12340000+i;
            uint32_t expected[8];memcpy(expected,state.gpr,sizeof(expected));
            expected[dst]=expected[src];
            uint8_t mov[]={direction?0x8b:0x89,
                (uint8_t)(0xc0 | ((direction?dst:src)<<3) | (direction?src:dst))};
            assert(run(mov,2,0x400)==0);
            assert(memcmp(expected,state.gpr,sizeof(expected))==0);
        }
    PwVmRegion thread;
    assert(backend.reserve_at(NULL,0x03002000,4096,4096,&thread)==PW_OK);
    assert(backend.commit(NULL,&thread,0,thread.bytes,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    state.fs_base=0x03002000;state.fs_bytes=4096;
    const uint8_t fsread[]={0x64,0xa1,0,0,0,0};
    const uint8_t fswrite[]={0x64,0xa3,0,0,0,0};
    *(uint32_t *)thread.write_base=0xffffffffu;
    assert(run(fsread,sizeof(fsread),0x500)==0);
    assert(state.gpr[0]==0xffffffffu && state.eip==0x506);
    state.gpr[0]=0x03000100;
    assert(run(fswrite,sizeof(fswrite),0x510)==0);
    assert(*(uint32_t *)thread.write_base==0x03000100);
    uint8_t last[]={0x64,0xa3,0xfc,0x0f,0,0};
    assert(run(last,sizeof(last),0x520)==0);
    assert(*(uint32_t *)((uint8_t *)thread.write_base+4092)==state.gpr[0]);
    last[2]=0xfd;
    assert(run(last,sizeof(last),0x530)==-1 && state.eip==0x530);
    assert(state.gpr[0]==0x03000100);
    state.fs_bytes=3;
    assert(run(fsread,sizeof(fsread),0x540)==-1);
    assert(state.gpr[0]==0x03000100);
    state.fs_base=0xfffffffdu;state.fs_bytes=4096;
    assert(run(fsread,sizeof(fsread),0x550)==-1);
    /* Base+offset overflow fails before dereferencing address zero. */
    const uint8_t overflow[]={0x64,0xa1,4,0,0,0};
    assert(run(overflow,sizeof(overflow),0x560)==-1);
    /* General MOV memory uses explicit read/write permissions, not merely
     * presence of a live mapping. */
    state.memory_count=1;
    state.memory[0]=(PwX86Memory){0x03002000,0x03003000,PW_X86_READ};
    const uint8_t read_region[]={0x8b,0x05,0,0x20,0,3};
    const uint8_t write_region[]={0x89,0x05,0,0x20,0,3};
    assert(run(read_region,sizeof(read_region),0xb00)==0);
    uint32_t saved=*(uint32_t *)thread.write_base;
    state.gpr[0]=0x12345678;
    assert(run(write_region,sizeof(write_region),0xb10)==-1);
    assert(*(uint32_t *)thread.write_base==saved);
    state.memory[0].permissions=PW_X86_WRITE;
    assert(run(write_region,sizeof(write_region),0xb20)==0);
    assert(*(uint32_t *)thread.write_base==0x12345678);
    assert(run(read_region,sizeof(read_region),0xb30)==-1);
    state.memory[0].permissions=PW_X86_READ;
    state.memory[0].high=0x03002003;
    assert(run(read_region,sizeof(read_region),0xb40)==-1);
    state.memory_count=PW_X86_MEMORY_REGIONS+1;
    assert(run(read_region,sizeof(read_region),0xb50)==-1);
    state.memory_count=0;
    assert(run(read_region,sizeof(read_region),0xb60)==-1);
    assert(backend.release(NULL,&thread)==PW_OK);
    x87_transfer_tests();
    addressing_tests();
    arithmetic_tests();
    comparison_tests();
    immediate_tests();
    absolute_tests();
    push_operand_tests();
    logical_test_tests();
    arithmetic_memory_tests();
    unary_leave_tests();
    byte_tests();
    ret_cleanup_tests();
    extension_tests();
    shift_tests();
    /* Enter an actual translated guest callback, then restore its caller. */
    state.gpr[4]=state.stack_high-16;state.eip=0xf0000010;
    PwX86State caller=state;PwGuestCallback callback={0};
    assert(pw_guest_callback_enter(&callback,&state,0x1000,0xf1000010,NULL,0,PW_GUEST_CDECL)==PW_OK);
    const uint8_t callback_code[]={0xb8,42,0,0,0,0xc3};
    assert(run(callback_code,sizeof(callback_code),0x1000)==0);
    uint64_t callback_result=0;
    assert(pw_guest_callback_leave(&callback,32,&callback_result)==PW_OK);
    assert(callback_result==42 && memcmp(&caller,&state,sizeof(state))==0);
    state.gpr[4]=state.stack_high;state.gpr[7]=0xe0000120;
    const uint8_t indirect_call[]={0xff,0xd7};
    assert(run(indirect_call,2,0x2000)==0);
    assert(state.eip==0xe0000120 && state.gpr[4]==state.stack_high-4);
    assert(*(uint32_t *)(uintptr_t)state.gpr[4]==0x2002);
    state.gpr[0]=state.gpr[4];
    const uint8_t indirect_jump[]={0xff,0x20};
    assert(run(indirect_jump,2,0x2100)==0 && state.eip==0x2002);
    assert(state.gpr[4]==state.stack_high-4);
    state.gpr[4]=state.stack_low;
    assert(run(indirect_call,2,0x2200)==-1 && state.eip==0x2200);
    uint8_t scratch[4096]; PwX86Block block;
    const uint8_t fs[]={0x64,0x90};
    assert(pw_x86_translate(fs,sizeof(fs),0,scratch,sizeof(scratch),&block)==PW_ERR_UNSUPPORTED);
    assert(block.code_bytes==0);
    assert(pw_x86_translate(fsread,5,0,scratch,sizeof(scratch),&block)==PW_ERR_TRUNCATED);
    assert(pw_x86_translate(input,1,0,scratch,sizeof(scratch),&block)==PW_ERR_TRUNCATED);
    assert(pw_x86_translate(input,sizeof(input),0,scratch,1,&block)==PW_ERR_LIMIT);
    assert(backend.release(NULL,&code)==PW_OK);
    assert(backend.release(NULL,&stack)==PW_OK);
    return 0;
}
