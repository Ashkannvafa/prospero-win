/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_win32.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
static int string_fixture(void *opaque,uint32_t module,uint32_t id,const uint8_t **text,size_t *units)
{
    (void)opaque;
    static const uint8_t sample[]={'A',0,0xe9,0,0xac,0x20,0x14,0x20};
    static const uint8_t unmapped[]={0,0x4e};
    if(module!=0x01000000)return PW_ERR_UNSUPPORTED;
    if(id==3)return PW_ERR_NOT_FOUND;
    if(id==4)return PW_ERR_TRUNCATED;
    *text=id==2?unmapped:sample;*units=id==1?0:id==2?1:4;return PW_OK;
}
static void string_tests(PwWin32 *r,PwX86State *s)
{
    PeImportSymbol symbol={0};PwImportTarget target;strcpy(symbol.name,"LoadStringA");
    assert(pw_win32_resolve(r,"user32.dll",&symbol,&target)==PW_OK);
    r->services.string_resource=string_fixture;r->services.ansi_codepage=1252;
    uint32_t output=s->stack_low+1;
    const uint8_t converted[]={'A',0xe9,0x80,0x97};
    for(unsigned id=0;id<5;id++)for(unsigned cap=0;cap<7;cap++) {
        memset((void *)(uintptr_t)(output-1),0xcc,12);
        s->eip=(uint32_t)target.address;s->gpr[4]=s->stack_high-20;s->eflags=0xad7;
        uint32_t frame[]={0x01001234,0x01000000,id,output,cap};
        memcpy((void *)(uintptr_t)s->gpr[4],frame,sizeof(frame));PwX86State before=*s;
        int status=pw_win32_dispatch(r,s);
        if(!cap || id==4 || (id==2 && cap>1)) {
            assert(status==(!cap || id==2?PW_ERR_UNSUPPORTED:PW_ERR_TRUNCATED));
            assert(!memcmp(s,&before,sizeof(before)) && *(uint8_t *)(uintptr_t)output==0xcc);
        } else {
            unsigned n=id==0?(cap-1<4?cap-1:4):0;
            assert(status==PW_OK && s->gpr[0]==n && s->eip==frame[0] && s->gpr[4]==s->stack_high && s->eflags==0xad7);
            if(id==3)assert(*(uint8_t *)(uintptr_t)output==0xcc);
            else assert(!memcmp((void *)(uintptr_t)output,converted,n) && *(uint8_t *)(uintptr_t)(output+n)==0);
            assert(*(uint8_t *)(uintptr_t)(output-1)==0xcc && *(uint8_t *)(uintptr_t)(output+n+1)==0xcc);
        }
    }
    s->gpr[4]=s->stack_high-64;s->eip=(uint32_t)target.address;
    uint32_t bad[]={0x01001234,0x01000000,0,s->stack_high-4,5};
    memcpy((void *)(uintptr_t)s->gpr[4],bad,sizeof(bad));PwX86State before=*s;
    assert(pw_win32_dispatch(r,s)==PW_ERR_VM && !memcmp(s,&before,sizeof(before)));
    bad[3]=output;bad[4]=4097;memcpy((void *)(uintptr_t)s->gpr[4],bad,sizeof(bad));
    assert(pw_win32_dispatch(r,s)==PW_ERR_UNSUPPORTED && !memcmp(s,&before,sizeof(before)));
    r->services.ansi_codepage=65001;
    assert(pw_win32_dispatch(r,s)==PW_ERR_UNSUPPORTED);
}
int main(void)
{
    PwVmBackend vm;PwVmRegion data;
    assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(vm.reserve_at(NULL,0x03000000,8192,4096,&data)==PW_OK);
    assert(vm.commit(NULL,&data,0,8192,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    PwWin32 runtime={0};
    assert(pw_win32_init(&runtime,0x01000000,0x03000000,"\"C:\\game\\sample.exe\"")==PW_OK);
    PeImportSymbol symbol={0};PwImportTarget target;
    strcpy(symbol.name,"_acmdln");
    assert(pw_win32_resolve(&runtime,"MSVCRT.DLL",&symbol,&target)==PW_OK && target.kind==PW_IMPORT_DATA);
    uint32_t pointer;memcpy(&pointer,(void *)(uintptr_t)target.address,4);
    assert(!strcmp((char *)(uintptr_t)pointer,"\"C:\\game\\sample.exe\""));
    strcpy(symbol.name,"_adjust_fdiv");
    assert(pw_win32_resolve(&runtime,"msvcrt.dll",&symbol,&target)==PW_OK && target.kind==PW_IMPORT_DATA);
    uint32_t adjust;memcpy(&adjust,(void *)(uintptr_t)target.address,4);assert(adjust==0);
    strcpy(symbol.name,"GetModuleHandleA");
    assert(pw_win32_resolve(&runtime,"KERNEL32.dll",&symbol,&target)==PW_OK && target.kind==PW_IMPORT_FUNCTION);
    PwX86State state={0};state.stack_low=0x03001000;state.stack_high=0x03002000;
    state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;
    uint32_t words[]={0x01001234,0};memcpy((void *)(uintptr_t)state.gpr[4],words,8);
    assert(pw_win32_dispatch(&runtime,&state)==PW_OK);
    assert(state.gpr[0]==0x01000000 && state.eip==words[0] && state.gpr[4]==state.stack_high);
    assert(runtime.calls==1);
    state.gpr[4]-=8;state.eip=(uint32_t)target.address;words[1]=0x03000010;
    memcpy((void *)(uintptr_t)state.gpr[4],words,8);PwX86State before=state;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_UNSUPPORTED);
    assert(memcmp(&state,&before,sizeof(state))==0 && runtime.calls==1);
    strcpy(symbol.name,"GetLastError");
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_OK);
    state.eip=(uint32_t)target.address;before=state;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_UNSUPPORTED);
    assert(!strcmp(runtime.last_name,"GetLastError") && memcmp(&state,&before,sizeof(state))==0);
    const char *crt_names[]={"__set_app_type","__p__fmode","__p__commode"};
    for(unsigned i=0;i<3;i++) {
        strcpy(symbol.name,crt_names[i]);
        assert(pw_win32_resolve(&runtime,"MSVCRT.DLL",&symbol,&target)==PW_OK);
        state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;
        state.gpr[0]=0xaabbccdd;state.eflags=0x246;
        words[1]=2;memcpy((void *)(uintptr_t)state.gpr[4],words,8);
        assert(pw_win32_dispatch(&runtime,&state)==PW_OK);
        assert(state.gpr[4]==state.stack_high-4 && state.eip==words[0] && state.eflags==0x246);
        if(!i)assert(runtime.app_type==2 && state.gpr[0]==0xaabbccdd);
        else {
            assert(state.gpr[0]==runtime.crt_data+(i==1?8:12));
            uint32_t value;memcpy(&value,(void *)(uintptr_t)state.gpr[0],4);
            assert(value==(i==1?0x4000u:0));
            value=123;memcpy((void *)(uintptr_t)state.gpr[0],&value,4);
            state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;
            assert(pw_win32_dispatch(&runtime,&state)==PW_OK);
            memcpy(&value,(void *)(uintptr_t)state.gpr[0],4);assert(value==123);
        }
    }
    strcpy(symbol.name,"__set_app_type");
    assert(pw_win32_resolve(&runtime,"msvcrt.dll",&symbol,&target)==PW_OK);
    state.gpr[4]=state.stack_high-4;state.eip=(uint32_t)target.address;before=state;
    unsigned calls=runtime.calls;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_VM);
    assert(!memcmp(&state,&before,sizeof(state)) && runtime.app_type==2 && runtime.calls==calls);
    strcpy(symbol.name,"_controlfp");
    assert(pw_win32_resolve(&runtime,"msvcrt.dll",&symbol,&target)==PW_OK);
    state.gpr[4]=state.stack_high-12;state.eip=(uint32_t)target.address;
    uint32_t fp_args[]={0x01001234,0x200,0x300};
    memcpy((void *)(uintptr_t)state.gpr[4],fp_args,sizeof(fp_args));before=state;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_STATE && !memcmp(&state,&before,sizeof(state)));
    pw_guest_fp_init(&state.fp);
    assert(pw_win32_dispatch(&runtime,&state)==PW_OK);
    assert(state.gpr[0]==0x9021f && state.gpr[4]==state.stack_high-8 && state.eip==fp_args[0]);
    assert((state.fp.x87_control&0xc00)==0x800 && (state.fp.mxcsr&0x6000)==0x4000);
    state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;before=state;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_VM && !memcmp(&state,&before,sizeof(state)));
    strcpy(symbol.name,"__getmainargs");
    assert(pw_win32_resolve(&runtime,"msvcrt.dll",&symbol,&target)==PW_OK);
    state.gpr[4]=state.stack_high-64;state.eip=(uint32_t)target.address;
    uint32_t main_args[]={0x01001234,state.stack_high-16,state.stack_high-12,state.stack_high-8,0,0};
    memcpy((void *)(uintptr_t)state.gpr[4],main_args,sizeof(main_args));
    assert(pw_win32_dispatch(&runtime,&state)==PW_OK && state.gpr[0]==0 && state.gpr[4]==state.stack_high-60);
    uint32_t outputs[3];memcpy(outputs,(void *)(uintptr_t)(state.stack_high-16),12);
    assert(outputs[0]==1 && outputs[1]==runtime.args.argv && outputs[2]==runtime.args.envp);
    uint32_t arg0;memcpy(&arg0,(void *)(uintptr_t)outputs[1],4);
    assert(!strcmp((char *)(uintptr_t)arg0,"C:\\game\\sample.exe"));
    for(unsigned failure=0;failure<2;failure++) {
        state.gpr[4]=state.stack_high-64;state.eip=(uint32_t)target.address;
        main_args[3]=failure?state.stack_high:state.stack_high-8;main_args[4]=failure?0:1;
        memcpy((void *)(uintptr_t)state.gpr[4],main_args,sizeof(main_args));before=state;
        assert(pw_win32_dispatch(&runtime,&state)==(failure?PW_ERR_VM:PW_ERR_UNSUPPORTED));
        uint32_t after[3];memcpy(after,(void *)(uintptr_t)(state.stack_high-16),12);
        assert(!memcmp(&state,&before,sizeof(state)) && !memcmp(after,outputs,sizeof(after)));
    }
    strcpy(symbol.name,"GetStartupInfoA");
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_OK);
    for(unsigned show=0;show<3;show++) {
        runtime.startup_show=(uint16_t)show;
        uint32_t address=state.stack_low+1; /* unaligned output is supported */
        memset((void *)(uintptr_t)state.stack_low,0xcc,72);
        state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;state.gpr[0]=0xaabbccdd;
        uint32_t startup_frame[]={0x01001234,address};memcpy((void *)(uintptr_t)state.gpr[4],startup_frame,8);
        assert(pw_win32_dispatch(&runtime,&state)==PW_OK && state.gpr[0]==0xaabbccdd && state.gpr[4]==state.stack_high);
        uint8_t expected[68]={0};expected[0]=68;expected[44]=1;expected[48]=(uint8_t)show;
        assert(!memcmp((void *)(uintptr_t)address,expected,68));
        assert(*(uint8_t *)(uintptr_t)state.stack_low==0xcc && *(uint8_t *)(uintptr_t)(address+68)==0xcc);
    }
    state.gpr[4]=state.stack_high-8;state.eip=(uint32_t)target.address;
    uint32_t startup_bad[]={0x01001234,state.stack_high-67};
    memcpy((void *)(uintptr_t)state.gpr[4],startup_bad,8);before=state;
    uint8_t snapshot[67];memcpy(snapshot,(void *)(uintptr_t)startup_bad[1],sizeof(snapshot));
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_VM && !memcmp(&state,&before,sizeof(state)));
    assert(!memcmp(snapshot,(void *)(uintptr_t)startup_bad[1],sizeof(snapshot)));
    runtime.startup_show=10;
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_UNSUPPORTED && !memcmp(&state,&before,sizeof(state)));
    strcpy(symbol.name,"NotInCatalog");
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_ERR_NOT_FOUND);
    symbol.by_ordinal=1;symbol.ordinal=42;
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_ERR_UNSUPPORTED);
    string_tests(&runtime,&state);
    assert(vm.release(NULL,&data)==PW_OK);return 0;
}
