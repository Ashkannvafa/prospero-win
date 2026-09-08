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
static void arithmetic_tests(void)
{
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
    addressing_tests();
    arithmetic_tests();
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
