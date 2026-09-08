/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_x86_block.h"
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
    assert(backend.release(NULL,&thread)==PW_OK);
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
