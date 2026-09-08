/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_win32.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
#if defined(__clang__)
__attribute__((no_sanitize("function")))
#endif
static int invoke(void *code,PwX86State *s){return ((int (*)(PwX86State *))code)(s);}
static void frame(PwX86State *s,uint32_t token,uint32_t start,uint32_t end,uint32_t ret)
{
    s->gpr[4]-=12;s->eip=token;
    uint32_t words[]={ret,start,end};memcpy((void *)(uintptr_t)s->gpr[4],words,12);
}
int main(void)
{
    PwVmBackend vm;PwVmRegion region,code;
    assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(vm.reserve_at(NULL,0x03000000,8192,4096,&region)==PW_OK);
    assert(vm.commit(NULL,&region,0,8192,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    assert(vm.reserve(NULL,8192,4096,&code)==PW_OK);
    assert(vm.commit(NULL,&code,0,8192,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    PwWin32 r;assert(pw_win32_init(&r,0x1000000,0x03000000,"test")==PW_OK);
    PeImportSymbol symbol={0};strcpy(symbol.name,"_initterm");PwImportTarget t;
    assert(pw_win32_resolve(&r,"msvcrt.dll",&symbol,&t)==PW_OK);
    PwX86State s={.stack_low=0x03001000,.stack_high=0x03002000,.memory_count=1};
    s.memory[0]=(PwX86Memory){0x03000000,0x03001000,PW_X86_READ|PW_X86_WRITE};
    uint32_t table[]={0,0x01002000,0,0x01003000};
    memcpy((void *)0x03000100,table,sizeof(table));s.gpr[4]=s.stack_high;s.eflags=0x246;
    frame(&s,(uint32_t)t.address,0x03000100,0x03000110,0x01004000);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && r.callback_pending && s.eip==table[1] && r.calls==0);
    /* Nested empty initializer returns to the outer callback, not the app. */
    uint32_t outer_esp=s.gpr[4];
    frame(&s,(uint32_t)t.address,0,0,table[1]);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && !r.callback_pending && r.init_depth==1 && s.eip==table[1]);
    s.gpr[4]+=8;assert(s.gpr[4]==outer_esp); /* guest cdecl caller cleanup */
    const uint8_t callback[]={0x83,0x05,0x00,0x02,0x00,0x03,1,0xc3}; /* increment guest word; RET */
    PwX86Block block;
    assert(pw_x86_translate(callback,sizeof(callback),table[1],code.write_base,code.bytes,&block)==PW_OK);
    assert(vm.protect(NULL,&code,0,code.bytes,PW_PROT_READ|PW_PROT_EXEC)==PW_OK);
    assert(invoke(code.exec_base,&s)==0 && s.eip==PW_WIN32_CALLBACK_BASE);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && r.callback_pending && s.eip==table[3]);
    assert(invoke(code.exec_base,&s)==0 && s.eip==PW_WIN32_CALLBACK_BASE);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && !r.callback_pending && !r.init_depth);
    assert(s.eip==0x01004000 && s.gpr[4]==s.stack_high-8 && s.eflags==0x246 && r.calls==2);
    uint32_t count;memcpy(&count,(void *)0x03000200,4);assert(count==2);
    s.gpr[4]=s.stack_high;
    frame(&s,(uint32_t)t.address,0x03000104,0x03000108,0x01004000);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && r.init_depth==1);
    frame(&s,(uint32_t)t.address,0x0300010c,0x03000110,table[1]);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && r.init_depth==2);
    assert(invoke(code.exec_base,&s)==0 && s.eip==PW_WIN32_CALLBACK_BASE+16);
    s.gpr[3]=123;PwX86State corrupt=s;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_STATE && !memcmp(&s,&corrupt,sizeof(s)) && r.init_depth==2);
    s.gpr[3]=0;
    assert(pw_win32_dispatch(&r,&s)==PW_OK && r.init_depth==1 && !r.callback_pending);
    s.gpr[4]+=8;
    assert(invoke(code.exec_base,&s)==0 && s.eip==PW_WIN32_CALLBACK_BASE);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && !r.init_depth && r.calls==4);
    memcpy(&count,(void *)0x03000200,4);assert(count==4);
    s.eip=PW_WIN32_CALLBACK_BASE;PwX86State before=s;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_STATE && !memcmp(&s,&before,sizeof(s)));
    for(unsigned bad=0;bad<3;bad++) {
        s.gpr[4]=s.stack_high;
        frame(&s,(uint32_t)t.address,bad==0?0x03000101:0x04000000,bad==0?0x03000104:bad==1?0x04000004:0x04002000,0x01004000);
        before=s;
        assert(pw_win32_dispatch(&r,&s)==(bad==0?PW_ERR_UNSUPPORTED:bad==1?PW_ERR_VM:PW_ERR_LIMIT));
        assert(!r.init_depth && !memcmp(&s,&before,sizeof(s)));
    }
    assert(vm.release(NULL,&code)==PW_OK);assert(vm.release(NULL,&region)==PW_OK);return 0;
}
