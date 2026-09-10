/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "../src/pw_win32.h"
#include "../src/pw_vm_posix.h"
#include <assert.h>
#include <string.h>

static int bitmap_fixture(void *opaque,uint32_t module,uint32_t type,const char *name,
                          const uint8_t **bytes,size_t *size)
{
    (void)opaque;
    static const uint8_t dib[]={40,0,0,0,2,0,0,0,2,0,0,0,1,0,8,0,
        0,0,0,0,8,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,
        1,2,3,0,4,5,6,0,0,1,0,0,1,0,0,0};
    if(module!=0x01000000 || type!=2)return PW_ERR_UNSUPPORTED;
    if(strcmp(name,"SPLASH_BITMAP"))return PW_ERR_NOT_FOUND;
    *bytes=dib;*size=sizeof(dib);return PW_OK;
}

static uint32_t call(PwWin32 *runtime,PwX86State *state,const char *dll,const char *name,
                     const uint32_t *args,unsigned count,int expected)
{
    PeImportSymbol symbol={0};PwImportTarget target;strcpy(symbol.name,name);
    assert(pw_win32_resolve(runtime,dll,&symbol,&target)==PW_OK);
    uint32_t esp=state->stack_high-(count+1)*4,return_pc=0x01001234;
    memcpy((void *)(uintptr_t)esp,&return_pc,4);
    if(count)memcpy((void *)(uintptr_t)(esp+4),args,count*4);
    state->eip=(uint32_t)target.address;state->gpr[4]=esp;state->eflags=0xad7;
    PwX86State before=*state;unsigned calls=runtime->calls;
    int status=pw_win32_dispatch(runtime,state);assert(status==expected);
    if(expected==PW_OK) {
        assert(state->eip==return_pc && state->gpr[4]==state->stack_high &&
               state->eflags==0xad7 && runtime->calls==calls+1);
        for(unsigned i=1;i<8;i++)if(i!=4)assert(state->gpr[i]==before.gpr[i]);
    } else assert(!memcmp(state,&before,sizeof(before)) && runtime->calls==calls);
    return state->gpr[0];
}
int main(void)
{
    PwVmBackend vm;PwVmRegion memory;assert(pw_vm_posix_backend(&vm)==PW_OK);
    assert(vm.reserve_at(NULL,0x03000000,8192,4096,&memory)==PW_OK);
    assert(vm.commit(NULL,&memory,0,memory.bytes,PW_PROT_READ|PW_PROT_WRITE)==PW_OK);
    PwX86State state={.stack_low=0x03001000,.stack_high=0x03002000,.memory_count=1};
    state.memory[0]=(PwX86Memory){0x03000000,0x03001000,PW_X86_READ|PW_X86_WRITE};
    PwWin32 runtime;assert(pw_win32_init(&runtime,0x01000000,0x03000000,"test")==PW_OK);
    PwUser32 user;PwUser32Message messages[1];PwUser32Window windows[1];
    assert(pw_user32_init(&user,messages,1,windows,1)==PW_OK);
    assert(pw_user32_configure_desktop(&user,8,8)==PW_OK);runtime.user32=&user;
    PwGdi gdi;PwGdiDc dcs[4];PwGdiSurface surfaces[4];uint8_t pixels[512];
    assert(pw_gdi_init(&gdi,dcs,4,surfaces,4,pixels,sizeof(pixels))==PW_OK);runtime.gdi=&gdi;
    runtime.services.named_resource=bitmap_fixture;

    uint32_t get_args[]={PW_USER32_DESKTOP_HANDLE};
    uint32_t screen=call(&runtime,&state,"user32.dll","GetDC",get_args,1,PW_OK);
    assert(screen==PW_GDI_HANDLE_FIRST);
    uint32_t dc_args[]={screen};
    assert(call(&runtime,&state,"gdi32.dll","GetLayout",dc_args,1,PW_OK)==0);
    uint32_t layout_args[]={screen,1};
    assert(call(&runtime,&state,"gdi32.dll","SetLayout",layout_args,2,PW_OK)==0);
    assert(call(&runtime,&state,"gdi32.dll","GetLayout",dc_args,1,PW_OK)==1);
    layout_args[1]=0;
    assert(call(&runtime,&state,"gdi32.dll","SetLayout",layout_args,2,PW_OK)==1);
    uint32_t memory_dc=call(&runtime,&state,"gdi32.dll","CreateCompatibleDC",dc_args,1,PW_OK);
    uint32_t caps_args[]={memory_dc,PW_GDI_CAP_RASTERCAPS};
    assert(call(&runtime,&state,"gdi32.dll","GetDeviceCaps",caps_args,2,PW_OK)==PW_GDI_RC_BITBLT);
    caps_args[1]=PW_GDI_CAP_NUMCOLORS;
    assert(call(&runtime,&state,"gdi32.dll","GetDeviceCaps",caps_args,2,PW_OK)==UINT32_MAX);
    uint32_t palette_args[]={memory_dc,0,0};
    assert(call(&runtime,&state,"gdi32.dll","SelectPalette",palette_args,3,PW_OK)==0);
    uint32_t selected_before=dcs[1].selected_bitmap;
    palette_args[1]=0x65726177;
    runtime.last_error=0;
    assert(call(&runtime,&state,"gdi32.dll","SelectPalette",palette_args,3,PW_OK)==0);
    assert(runtime.last_error==6 && dcs[1].selected_bitmap==selected_before);
    palette_args[1]=0;
    uint32_t realize_args[]={memory_dc};
    assert(call(&runtime,&state,"gdi32.dll","RealizePalette",realize_args,1,PW_OK)==0);
    uint32_t bitmap_args[]={screen,4,4};
    uint32_t bitmap=call(&runtime,&state,"gdi32.dll","CreateCompatibleBitmap",bitmap_args,3,PW_OK);
    uint32_t name_address=0x03000100;strcpy((char *)(uintptr_t)name_address,"SPLASH_BITMAP");
    uint32_t load_args[]={0x01000000,name_address};
    uint32_t loaded=call(&runtime,&state,"user32.dll","LoadBitmapA",load_args,2,PW_OK);
    assert(loaded && loaded!=bitmap);
    uint32_t info_address=0x03000140;memset((void *)(uintptr_t)info_address,0xcc,24);
    uint32_t info_args[]={loaded,24,info_address};
    assert(call(&runtime,&state,"gdi32.dll","GetObjectA",info_args,3,PW_OK)==24);
    uint32_t width,height;uint16_t planes,bits;
    memcpy(&width,(void *)(uintptr_t)(info_address+4),4);
    memcpy(&height,(void *)(uintptr_t)(info_address+8),4);
    memcpy(&planes,(void *)(uintptr_t)(info_address+16),2);
    memcpy(&bits,(void *)(uintptr_t)(info_address+18),2);
    assert(width==2 && height==2 && planes==1 && bits==32 &&
           !*(uint32_t *)(uintptr_t)info_address && !*(uint32_t *)(uintptr_t)(info_address+20));
    uint32_t select_args[]={memory_dc,bitmap};
    assert(call(&runtime,&state,"gdi32.dll","SelectObject",select_args,2,PW_OK)==PW_GDI_STOCK_BITMAP);

    PwGdiSurface *source=NULL,*target=NULL;
    for(unsigned i=0;i<4;i++) {
        if(surfaces[i].used && surfaces[i].handle==bitmap)source=&surfaces[i];
        if(surfaces[i].used && surfaces[i].target==PW_USER32_DESKTOP_HANDLE)target=&surfaces[i];
    }
    assert(source && target);memset(pixels+source->offset,0x5a,source->bytes);
    uint32_t blt_args[]={screen,1,2,4,4,memory_dc,0,0,PW_GDI_ROP_SRCCOPY};
    assert(call(&runtime,&state,"gdi32.dll","BitBlt",blt_args,9,PW_OK)==1);
    assert(*(pixels+target->offset+2*target->stride+4)==0x5a);

    uint32_t object_args[]={bitmap};
    assert(call(&runtime,&state,"gdi32.dll","DeleteObject",object_args,1,PW_OK)==0);
    assert(source->used && source->selected_by==1);
    assert(call(&runtime,&state,"gdi32.dll","DeleteDC",dc_args,1,PW_OK)==0);
    uint32_t memory_args[]={memory_dc};
    assert(call(&runtime,&state,"gdi32.dll","DeleteDC",memory_args,1,PW_OK)==1);
    assert(call(&runtime,&state,"gdi32.dll","DeleteObject",object_args,1,PW_OK)==1);
    object_args[0]=loaded;
    assert(call(&runtime,&state,"gdi32.dll","DeleteObject",object_args,1,PW_OK)==1);

    uint32_t mismatched[]={0x10000,screen};
    assert(call(&runtime,&state,"user32.dll","ReleaseDC",mismatched,2,PW_OK)==0);
    uint32_t release[]={PW_USER32_DESKTOP_HANDLE,screen};
    assert(call(&runtime,&state,"user32.dll","ReleaseDC",release,2,PW_OK)==1);
    assert(pw_gdi_validate(&gdi)==PW_OK);
    windows[0]=(PwUser32Window){.handle=0x10000,.wndproc=0x01002000,
        .width=1,.height=1,.used=1};
    uint32_t move_args[]={0x10000,10,20,320,222,0};
    assert(call(&runtime,&state,"user32.dll","MoveWindow",move_args,6,PW_OK)==1);
    assert(windows[0].x==10 && windows[0].y==20 && windows[0].width==320 && windows[0].height==222);
    uint32_t show_args[]={0x10000,8};
    assert(call(&runtime,&state,"user32.dll","ShowWindow",show_args,2,PW_OK)==0);
    uint32_t focus_args[]={0x10000};
    assert(call(&runtime,&state,"user32.dll","SetFocus",focus_args,1,PW_OK)==0 &&
           user.focus_window==0x10000);
    PeImportSymbol update_symbol={0};PwImportTarget update_target;
    strcpy(update_symbol.name,"UpdateWindow");
    assert(pw_win32_resolve(&runtime,"user32.dll",&update_symbol,&update_target)==PW_OK);
    state.eip=(uint32_t)update_target.address;state.gpr[4]=state.stack_high-8;
    uint32_t update_frame[]={0x01001234,0x10000};
    memcpy((void *)(uintptr_t)state.gpr[4],update_frame,sizeof(update_frame));
    assert(pw_win32_dispatch(&runtime,&state)==PW_OK && runtime.callback_pending &&
           runtime.update.active && state.eip==0x01002000 && state.gpr[4]==state.stack_high-28);
    uint32_t callback_frame[5];memcpy(callback_frame,(void *)(uintptr_t)state.gpr[4],20);
    assert(callback_frame[0]==PW_WIN32_UPDATE_CALLBACK && callback_frame[1]==0x10000 &&
           callback_frame[2]==0x0f && !callback_frame[3] && !callback_frame[4]);
    state.gpr[0]=0;state.gpr[4]+=20;state.eip=PW_WIN32_UPDATE_CALLBACK;
    assert(pw_win32_dispatch(&runtime,&state)==PW_OK && !runtime.update.active &&
           state.eip==update_frame[0] && state.gpr[4]==state.stack_high && state.gpr[0]==1 &&
           !windows[0].needs_paint);
    assert(call(&runtime,&state,"user32.dll","UpdateWindow",focus_args,1,PW_OK)==1);

    PeImportSymbol symbol={0};PwImportTarget imported;strcpy(symbol.name,"CreateCompatibleBitmap");
    assert(pw_win32_resolve(&runtime,"gdi32.dll",&symbol,&imported)==PW_OK);
    state.eip=(uint32_t)imported.address;state.gpr[4]=state.stack_high-12;
    uint32_t truncated[]={0x01001234,screen,4};memcpy((void *)(uintptr_t)state.gpr[4],truncated,12);
    PwX86State before=state;PwGdiCounts counts_before,counts_after;
    assert(pw_gdi_counts(&gdi,&counts_before)==PW_OK);
    assert(pw_win32_dispatch(&runtime,&state)==PW_ERR_VM && !memcmp(&state,&before,sizeof(state)));
    assert(pw_gdi_counts(&gdi,&counts_after)==PW_OK &&
           !memcmp(&counts_before,&counts_after,sizeof(counts_before)));
    assert(pw_gdi_reset(&gdi)==PW_OK && pw_gdi_validate(&gdi)==PW_OK);
    assert(vm.release(NULL,&memory)==PW_OK);return 0;
}
