/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_win32.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>
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
    strcpy(symbol.name,"NotInCatalog");
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_ERR_NOT_FOUND);
    symbol.by_ordinal=1;symbol.ordinal=42;
    assert(pw_win32_resolve(&runtime,"kernel32.dll",&symbol,&target)==PW_ERR_UNSUPPORTED);
    assert(vm.release(NULL,&data)==PW_OK);return 0;
}
