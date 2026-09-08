/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_win32.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
typedef struct Clock { uint64_t ns; PwClockDomain domain; unsigned calls; int result; } Clock;
static int sample(void *opaque,PwClockDomain domain,uint64_t *ns)
{ Clock *c=opaque;c->domain=domain;c->calls++;*ns=c->ns;return c->result; }
static void call(PwWin32 *r,PwX86State *s,const char *dll,const char *name,uint32_t out)
{
    PeImportSymbol symbol={0};strcpy(symbol.name,name);PwImportTarget target;
    assert(pw_win32_resolve(r,dll,&symbol,&target)==PW_OK);
    s->eip=(uint32_t)target.address;s->gpr[4]=s->stack_high-16;s->gpr[0]=0x11223344;s->eflags=0xad7;
    uint32_t frame[]={0x1001000,out};memcpy((void *)(uintptr_t)s->gpr[4],frame,8);
}
int main(void)
{
    PwVmBackend vm;PwVmRegion memory;
    assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(vm.reserve_at(NULL,0x03000000,8192,4096,&memory)==PW_OK);
    assert(vm.commit(NULL,&memory,0,8192,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    PwWin32 r;assert(pw_win32_init(&r,0x1000000,0x03000000,"demo")==PW_OK);
    Clock c={.ns=1234567890123};r.services=(PwWin32Services){&c,sample,17,29};
    PwX86State s={.stack_low=0x03001000,.stack_high=0x03002000};
    uint32_t out=s.stack_low;
    const char *names[]={"GetSystemTimeAsFileTime","QueryPerformanceCounter","GetTickCount","timeGetTime","GetCurrentProcessId","GetCurrentThreadId"};
    for(unsigned i=0;i<6;i++) {
        call(&r,&s,i==3?"winmm.dll":"kernel32.dll",names[i],out);c.calls=0;
        assert(pw_win32_dispatch(&r,&s)==PW_OK && s.eip==0x1001000 && s.eflags==0xad7);
        assert(s.gpr[4]==s.stack_high-(i<2?8:12));
        if(i<2) {
            uint64_t value;memcpy(&value,(void *)(uintptr_t)out,8);
            assert(value==(i?c.ns:c.ns/100+116444736000000000ull));
            assert(s.gpr[0]==(i?1:0x11223344));
        } else assert(s.gpr[0]==(i<4?1234567:i==4?17:29));
        assert(c.calls==(i<4?1:0));
        if(i<4)assert(c.domain==(i==0?PW_CLOCK_UTC:i==1?PW_CLOCK_COUNTER:PW_CLOCK_UPTIME));
    }
    c.ns=((1ull<<32)+17)*1000000;
    call(&r,&s,"kernel32.dll","GetTickCount",0);
    assert(pw_win32_dispatch(&r,&s)==PW_OK && s.gpr[0]==17);
    call(&r,&s,"kernel32.dll","GetSystemTimeAsFileTime",s.stack_high-4);c.calls=0;
    PwX86State before=s;unsigned calls=r.calls;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_VM && !memcmp(&s,&before,sizeof(s)) && !c.calls && r.calls==calls);
    uint64_t sentinel=0x1122334455667788ull;memcpy((void *)(uintptr_t)out,&sentinel,8);
    call(&r,&s,"kernel32.dll","QueryPerformanceCounter",out);before=s;c.result=PW_ERR_STATE;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_STATE && !memcmp(&s,&before,sizeof(s)) && r.calls==calls);
    uint64_t after;memcpy(&after,(void *)(uintptr_t)out,8);assert(after==sentinel);
    c.result=PW_OK;c.ns=UINT64_MAX;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_LIMIT && !memcmp(&s,&before,sizeof(s)));
    r.services.clock_ns=NULL;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_STATE && !memcmp(&s,&before,sizeof(s)));
    r.services.process_id=0;call(&r,&s,"kernel32.dll","GetCurrentProcessId",0);before=s;
    assert(pw_win32_dispatch(&r,&s)==PW_ERR_STATE && !memcmp(&s,&before,sizeof(s)));
    assert(vm.release(NULL,&memory)==PW_OK);return 0;
}
