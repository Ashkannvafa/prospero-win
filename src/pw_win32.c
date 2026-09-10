/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_win32.h"
#include "pw_crt_format.h"
#include "pw_module_name.h"
#include <string.h>
#include "pw_win32_catalog.h"
int pw_win32_init(PwWin32 *runtime,uint32_t main,uint32_t data,const char *line)
{
    if(!runtime || !main || !data || !line || (uint64_t)data+4096>UINT32_MAX)
        return PW_ERR_PRECONDITION;
    size_t length=strlen(line);
    if(length>4096-17)return PW_ERR_LIMIT;
    uint8_t buffer[4096]={0};PwGuestArgs args;
    size_t offset=(16+length+1+3)&~(size_t)3;
    if(offset>=sizeof(buffer))return PW_ERR_LIMIT;
    int status=pw_guest_args_build(line,NULL,0,data+(uint32_t)offset,buffer+offset,sizeof(buffer)-offset,&args);
    if(status!=PW_OK)return status;
    uint32_t pointer=data+16,text_mode=0x4000;
    memcpy(buffer,&pointer,4);memcpy(buffer+8,&text_mode,4);
    memcpy(buffer+16,line,length+1);
    memcpy((void *)(uintptr_t)data,buffer,sizeof(buffer));
    *runtime=(PwWin32){.main_base=main,.crt_data=data,.args=args,.startup_show=1};return PW_OK;
}
int pw_win32_resolve(void *opaque,const char *dll,const PeImportSymbol *symbol,PwImportTarget *target)
{
    PwWin32 *r=opaque;
    if(!r || !dll || !symbol || !target)return PW_ERR_PRECONDITION;
    if(!r->main_base || !r->crt_data)return PW_ERR_STATE;
    if(symbol->by_ordinal)return PW_ERR_UNSUPPORTED;
    for(unsigned i=0;i<sizeof(pw_catalog)/sizeof(pw_catalog[0]);i++) {
        if(!pw_module_name_equal(dll,pw_catalog[i].dll) || strcmp(symbol->name,pw_catalog[i].name))continue;
        uint32_t address=PW_WIN32_TOKEN_BASE+i*16;
        if(pw_catalog[i].kind==PW_IMPORT_DATA) {
            if(!strcmp(pw_catalog[i].dll,"msvcrt.dll") && !strcmp(symbol->name,"_acmdln"))address=r->crt_data;
            else if(!strcmp(pw_catalog[i].dll,"msvcrt.dll") && !strcmp(symbol->name,"_adjust_fdiv"))address=r->crt_data+4;
            else return PW_ERR_UNSUPPORTED;
        }
        *target=(PwImportTarget){address,pw_catalog[i].kind};return PW_OK;
    }
    return PW_ERR_NOT_FOUND;
}
static int range_access(PwX86State *s,uint32_t address,size_t bytes,unsigned permission)
{
    if(bytes>UINT32_MAX)return PW_ERR_VM;
    uint64_t end=(uint64_t)address+bytes;
    if(!address || end>0x100000000ull || s->memory_count>PW_X86_MEMORY_REGIONS)return PW_ERR_VM;
    unsigned readable=address>=s->stack_low && end<=s->stack_high;
    for(unsigned i=0;i<s->memory_count;i++) {
        PwX86Memory *m=&s->memory[i];
        if(m->high<=0x100000000ull && address>=m->low && end<=m->high && (m->permissions&permission)==permission)readable=1;
    }
    if(!readable)return PW_ERR_VM;
    return PW_OK;
}
static int word_access(PwX86State *s,uint32_t address,unsigned permission)
{return range_access(s,address,4,permission);}
static int string_length(PwX86State *s,uint32_t address,uint32_t *length)
{
    /* Bounded guest reads only; never hand an unvalidated pointer to strlen. */
    for(uint32_t n=0;n<0x100000;n++) {
        if(address>UINT32_MAX-n)return PW_ERR_VM;
        int status=range_access(s,address+n,1,PW_X86_READ);
        if(status!=PW_OK)return status;
        if(!*(const uint8_t *)(uintptr_t)(address+n)){*length=n;return PW_OK;}
    }
    return PW_ERR_LIMIT;
}
static int guest_string(PwX86State *s,uint32_t address,char *output,size_t capacity,
                        unsigned nullable)
{
    if(!address) {
        if(!nullable)return PW_ERR_VM;
        output[0]=0;return PW_OK;
    }
    uint32_t length;int status=string_length(s,address,&length);
    if(status!=PW_OK)return status;
    if((uint64_t)length+1>capacity)return PW_ERR_LIMIT;
    memcpy(output,(const void *)(uintptr_t)address,(size_t)length+1);return PW_OK;
}
static int writable_capacity(PwX86State *s,uint32_t address,size_t limit,size_t *capacity)
{
    if(!address || !capacity || !limit || s->memory_count>PW_X86_MEMORY_REGIONS)return PW_ERR_VM;
    uint64_t best=0;
    if(address>=s->stack_low && address<s->stack_high)best=s->stack_high-address;
    for(unsigned i=0;i<s->memory_count;i++) {
        const PwX86Memory *m=&s->memory[i];
        if((m->permissions&PW_X86_WRITE) && m->high<=0x100000000ull &&
           address>=m->low && address<m->high && m->high-address>best)best=m->high-address;
    }
    if(!best)return PW_ERR_VM;
    *capacity=(size_t)(best<limit?best:limit);return PW_OK;
}
typedef struct FormatGuest { const PwGuestCall *call;PwX86State *state; } FormatGuest;
static int format_u32(void *opaque,unsigned index,uint32_t *value)
{
    FormatGuest *guest=opaque;
    if(index>(UINT32_MAX-8)/4)return PW_ERR_LIMIT;
    return pw_guest_call_u32(guest->call,8+index*4,value);
}
static int format_string(void *opaque,uint32_t address,char *output,size_t capacity,size_t *length)
{
    FormatGuest *guest=opaque;uint32_t n;int status=string_length(guest->state,address,&n);
    if(status!=PW_OK)return status;
    if((uint64_t)n+1>capacity)return PW_ERR_LIMIT;
    memcpy(output,(const void *)(uintptr_t)address,(size_t)n+1);*length=n;return PW_OK;
}
static int registry_dispatch(PwWin32 *r,PwX86State *state)
{
    if(strcmp(r->last_dll,"advapi32.dll"))return PW_ERR_NOT_FOUND;
    if(!r->registry)return PW_ERR_STATE;
    const char *name=r->last_name;PwGuestCall call={0};uint32_t a[9]={0};
    unsigned count;
    if(!strcmp(name,"RegCreateKeyExA"))count=9;
    else if(!strcmp(name,"RegOpenKeyA"))count=3;
    else if(!strcmp(name,"RegOpenKeyExA"))count=5;
    else if(!strcmp(name,"RegQueryValueA"))count=4;
    else if(!strcmp(name,"RegQueryValueExA") || !strcmp(name,"RegSetValueExA"))count=6;
    else if(!strcmp(name,"RegCloseKey"))count=1;
    else return PW_ERR_UNSUPPORTED;
    int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,count*4,0);
    if(status!=PW_OK)return status;
    for(unsigned i=0;i<count;i++)if((status=pw_guest_call_u32(&call,i*4,&a[i]))!=PW_OK)return status;

    if(!strcmp(name,"RegCloseKey")) {
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=pw_registry_close(r->registry,a[0]);after.gpr[0]=result;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(name,"RegCreateKeyExA")) {
        char key[PW_REG_PATH_MAX+1];
        if(a[2] || a[3] || a[4] || a[6])return PW_ERR_UNSUPPORTED;
        if((status=guest_string(state,a[1],key,sizeof(key),0))!=PW_OK)return status;
        if((status=word_access(state,a[7],PW_X86_WRITE))!=PW_OK)return status;
        if(a[8] && (status=word_access(state,a[8],PW_X86_WRITE))!=PW_OK)return status;
        if(a[8] && (uint64_t)a[7]<a[8]+4ull && (uint64_t)a[8]<a[7]+4ull)
            return PW_ERR_UNSUPPORTED;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t handle=0,disposition=0;
        uint32_t result=pw_registry_create(r->registry,a[0],key,&handle,&disposition);
        after.gpr[0]=result;
        if(!result){memcpy((void *)(uintptr_t)a[7],&handle,4);if(a[8])memcpy((void *)(uintptr_t)a[8],&disposition,4);}
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(name,"RegOpenKeyA") || !strcmp(name,"RegOpenKeyExA")) {
        unsigned extended=!strcmp(name,"RegOpenKeyExA");uint32_t result_pointer=a[extended?4:2];
        if(extended && a[2])return PW_ERR_UNSUPPORTED;
        char key[PW_REG_PATH_MAX+1];
        if((status=guest_string(state,a[1],key,sizeof(key),1))!=PW_OK)return status;
        if((status=word_access(state,result_pointer,PW_X86_WRITE))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t handle=0,result=pw_registry_open(r->registry,a[0],key,&handle);
        after.gpr[0]=result;if(!result)memcpy((void *)(uintptr_t)result_pointer,&handle,4);
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(name,"RegSetValueExA")) {
        if(a[2])return PW_ERR_UNSUPPORTED;
        char value_name[PW_REG_NAME_MAX+1];uint8_t data[PW_REG_DATA_MAX];
        if((status=guest_string(state,a[1],value_name,sizeof(value_name),1))!=PW_OK)return status;
        if(a[5]>sizeof(data))return PW_ERR_UNSUPPORTED;
        if(a[5] && (status=range_access(state,a[4],a[5],PW_X86_READ))!=PW_OK)return status;
        if(a[5])memcpy(data,(const void *)(uintptr_t)a[4],a[5]);
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=pw_registry_set(r->registry,a[0],value_name,a[3],data,a[5]);
        after.gpr[0]=result;*state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(name,"RegQueryValueExA")) {
        if(a[2])return PW_ERR_UNSUPPORTED;
        char value_name[PW_REG_NAME_MAX+1];uint8_t data[PW_REG_DATA_MAX];uint32_t type=0,size;
        if((status=guest_string(state,a[1],value_name,sizeof(value_name),1))!=PW_OK)return status;
        if((status=word_access(state,a[5],PW_X86_READ|PW_X86_WRITE))!=PW_OK)return status;
        memcpy(&size,(const void *)(uintptr_t)a[5],4);
        if(a[3] && (status=word_access(state,a[3],PW_X86_WRITE))!=PW_OK)return status;
        uint32_t result=pw_registry_query(r->registry,a[0],value_name,&type,
                                          a[4]?data:NULL,&size);
        if(!result && a[4] && size && (status=range_access(state,a[4],size,PW_X86_WRITE))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(result!=PW_REG_ERROR_FILE_NOT_FOUND && result!=PW_REG_ERROR_INVALID_HANDLE &&
           result!=PW_REG_ERROR_INVALID_PARAMETER) {
            memcpy((void *)(uintptr_t)a[5],&size,4);
            if(a[3])memcpy((void *)(uintptr_t)a[3],&type,4);
            if(!result && a[4] && size)memcpy((void *)(uintptr_t)a[4],data,size);
        }
        *state=after;r->calls++;return PW_OK;
    }
    /* RegQueryValueA reads the unnamed value of a key or child key. */
    char subkey[PW_REG_PATH_MAX+1];uint8_t data[PW_REG_DATA_MAX];uint32_t size;
    if((status=guest_string(state,a[1],subkey,sizeof(subkey),1))!=PW_OK)return status;
    if((status=word_access(state,a[3],PW_X86_READ|PW_X86_WRITE))!=PW_OK)return status;
    memcpy(&size,(const void *)(uintptr_t)a[3],4);uint32_t handle=a[0],opened=0,result=0;
    if(*subkey){result=pw_registry_open(r->registry,a[0],subkey,&handle);opened=!result;}
    if(!result)result=pw_registry_query(r->registry,handle,"",NULL,a[2]?data:NULL,&size);
    if(opened)(void)pw_registry_close(r->registry,handle);
    if(!result && a[2] && size && (status=range_access(state,a[2],size,PW_X86_WRITE))!=PW_OK)return status;
    PwX86State after=*state;call.state=&after;
    if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
    if(result!=PW_REG_ERROR_FILE_NOT_FOUND && result!=PW_REG_ERROR_INVALID_HANDLE &&
       result!=PW_REG_ERROR_INVALID_PARAMETER) {
        memcpy((void *)(uintptr_t)a[3],&size,4);
        if(!result && a[2] && size)memcpy((void *)(uintptr_t)a[2],data,size);
    }
    *state=after;r->calls++;return PW_OK;
}
static int cp1252(uint32_t c,uint8_t *out)
{
    static const uint16_t high[32]={0x20ac,0,0x201a,0x192,0x201e,0x2026,0x2020,0x2021,
        0x2c6,0x2030,0x160,0x2039,0x152,0,0x17d,0,0,0x2018,0x2019,0x201c,
        0x201d,0x2022,0x2013,0x2014,0x2dc,0x2122,0x161,0x203a,0x153,0,0x17e,0x178};
    if(c<0x80 || (c>=0xa0 && c<=0xff)){*out=(uint8_t)c;return PW_OK;}
    for(unsigned i=0;i<32;i++)if(c==high[i]){*out=(uint8_t)(0x80+i);return PW_OK;}
    return PW_ERR_UNSUPPORTED; /* best-fit/default-character policy not implemented */
}
static int copy_string(PwX86State *s,uint32_t dst,uint32_t src,uint32_t count,
                       unsigned bounded,unsigned append,uint32_t *write_at,uint32_t *length)
{
    uint32_t n=0,prefix=0;int status;
    if(bounded) {
        uint32_t limit=count-1;
        while(n<limit && n<0x100000) {
            if(src>UINT32_MAX-n)return PW_ERR_VM;
            if((status=range_access(s,src+n,1,PW_X86_READ))!=PW_OK)return status;
            if(!*(const uint8_t *)(uintptr_t)(src+n))break;
            n++;
        }
        if(n==0x100000 && n<limit)return PW_ERR_LIMIT;
    } else if((status=string_length(s,src,&n))!=PW_OK)return status;
    if(append && (status=string_length(s,dst,&prefix))!=PW_OK)return status;
    if(dst>UINT32_MAX-prefix)return PW_ERR_VM;
    uint32_t at=dst+prefix;
    if((status=range_access(s,at,(size_t)n+1,PW_X86_WRITE))!=PW_OK)return status;
    /* strcpy follows Wine's memmove behavior. The other two routines have
     * different forward-copy overlap semantics: reject overlapping spans
     * instead of silently implementing memmove for them. */
    uint64_t src_end=(uint64_t)src+n+(bounded?0:1),dst_end=(uint64_t)at+n+1;
    if((bounded || append) && n && src<dst_end && src_end>dst && !(bounded && src==dst))return PW_ERR_UNSUPPORTED;
    *write_at=at;*length=n;return PW_OK;
}
static uint8_t ascii_lower(uint8_t value)
{
    return value>='A' && value<='Z'?(uint8_t)(value+('a'-'A')):value;
}
static int compare_ascii_nocase(PwX86State *s,uint32_t first,uint32_t second,
                                uint32_t count,int32_t *result)
{
    if(!result)return PW_ERR_PRECONDITION;
    *result=0;
    for(uint32_t i=0;i<count;i++) {
        if(first>UINT32_MAX-i || second>UINT32_MAX-i)return PW_ERR_VM;
        int status=range_access(s,first+i,1,PW_X86_READ);
        if(status!=PW_OK)return status;
        if((status=range_access(s,second+i,1,PW_X86_READ))!=PW_OK)return status;
        uint8_t raw_a=*(const uint8_t *)(uintptr_t)(first+i);
        uint8_t raw_b=*(const uint8_t *)(uintptr_t)(second+i);
        uint8_t a=ascii_lower(raw_a),b=ascii_lower(raw_b);
        if(a!=b){*result=a<b?-1:1;return PW_OK;}
        if(!raw_a)return PW_OK;
    }
    return PW_OK;
}
static int table_read(PwX86State *s,uint32_t address,uint32_t *value)
{
    int status=word_access(s,address,PW_X86_READ);
    if(status==PW_OK)memcpy(value,(void *)(uintptr_t)address,4);
    return status;
}
static int init_next(PwWin32 *r,PwX86State *s)
{
    PwWin32Init *f=&r->init[r->init_depth-1];
    while(f->cursor<f->end) {
        uint32_t target;int status=table_read(s,f->cursor,&target);
        if(status!=PW_OK)return status;
        if(target) {
            /* Code permissions are verified by the execution dispatcher. */
            if(target>=PW_WIN32_TOKEN_BASE)return PW_ERR_UNSUPPORTED;
            status=pw_guest_callback_enter(&f->callback,s,target,
                PW_WIN32_CALLBACK_BASE+(r->init_depth-1)*16,NULL,0,PW_GUEST_CDECL);
            if(status!=PW_OK)return status;
            f->cursor+=4;r->callback_pending=1;return PW_OK;
        }
        f->cursor+=4;
    }
    int status=pw_guest_call_finish(&f->call,0,0);
    if(status==PW_OK){memset(f,0,sizeof(*f));r->init_depth--;r->calls++;}
    return status;
}
static int create_callback(PwWin32 *r,PwX86State *s,uint32_t message)
{
    if(!r->create_depth || r->create_depth>PW_WIN32_CREATE_DEPTH)return PW_ERR_STATE;
    unsigned index=r->create_depth-1;PwWin32Create *create=&r->create[index];
    uint32_t args[]={create->handle,message,0,create->create_struct};
    int status=pw_guest_callback_enter(&create->callback,s,create->wndproc,
        PW_WIN32_CREATE_CALLBACK_BASE+index*16,args,4,PW_GUEST_STDCALL);
    if(status==PW_OK)r->callback_pending=1;
    return status;
}
static int create_return(PwWin32 *r,PwX86State *s,unsigned index)
{
    if(!r->create_depth || index!=r->create_depth-1 || index>=PW_WIN32_CREATE_DEPTH)
        return PW_ERR_STATE;
    PwWin32Create *create=&r->create[index];uint64_t result;
    if(!create->active || create->callback.state!=s ||
       create->create_struct+48!=create->call.esp)return PW_ERR_STATE;
    int status=pw_guest_callback_leave(&create->callback,32,&result);
    if(status!=PW_OK)return status;
    if(create->phase==1 && (uint32_t)result) {
        create->phase=2;return create_callback(r,s,1); /* WM_CREATE */
    }
    unsigned commit=create->phase==2 && (uint32_t)result!=UINT32_MAX;
    PwX86State after=*s;after.gpr[4]=create->call.esp;
    PwGuestCall checked=create->call;checked.state=&after;
    if((status=pw_guest_call_finish(&checked,32,commit?create->handle:0))!=PW_OK)
        return status;
    if((status=pw_user32_finish_window(r->user32,create->slot,commit))!=PW_OK)return status;
    *s=after;memset(create,0,sizeof(*create));r->create_depth--;r->calls++;return PW_OK;
}
static int update_return(PwWin32 *r,PwX86State *s)
{
    PwWin32Update *update=&r->update;uint64_t ignored;
    if(!update->active || update->callback.state!=s)return PW_ERR_STATE;
    int status=pw_guest_callback_leave(&update->callback,32,&ignored);
    if(status!=PW_OK)return status;
    PwX86State after=*s;PwGuestCall checked=update->call;checked.state=&after;
    if((status=pw_guest_call_finish(&checked,32,1))!=PW_OK)return status;
    if((status=pw_user32_finish_paint(r->user32,update->handle))!=PW_OK)return status;
    *s=after;memset(update,0,sizeof(*update));r->calls++;return PW_OK;
}
static int gdi_failure(int status,uint32_t *result,uint32_t *error)
{
    if(status==PW_ERR_LIMIT){*result=0;*error=8;return PW_OK;}
    if(status==PW_ERR_NOT_FOUND){*result=0;*error=6;return PW_OK;}
    if(status==PW_ERR_PRECONDITION){*result=0;*error=87;return PW_OK;}
    if(status==PW_ERR_STATE){*result=0;return PW_OK;}
    return status;
}
static int gdi_dispatch(PwWin32 *r,PwX86State *state)
{
    unsigned user=!strcmp(r->last_dll,"user32.dll");
    unsigned gdi=!strcmp(r->last_dll,"gdi32.dll");
    if((!user && !gdi) ||
       (user && strcmp(r->last_name,"GetDC") && strcmp(r->last_name,"ReleaseDC")) ||
       (gdi && strcmp(r->last_name,"CreateCompatibleDC") &&
        strcmp(r->last_name,"CreatePalette") && strcmp(r->last_name,"SetPaletteEntries") &&
        strcmp(r->last_name,"GetStockObject") &&
        strcmp(r->last_name,"CreateCompatibleBitmap") && strcmp(r->last_name,"SelectObject") &&
        strcmp(r->last_name,"DeleteDC") && strcmp(r->last_name,"DeleteObject") &&
        strcmp(r->last_name,"GetLayout") && strcmp(r->last_name,"SetLayout") &&
        strcmp(r->last_name,"GetDeviceCaps") && strcmp(r->last_name,"GetObjectA") &&
        strcmp(r->last_name,"SelectPalette") && strcmp(r->last_name,"RealizePalette") &&
        strcmp(r->last_name,"BitBlt")))return PW_ERR_NOT_FOUND;
    if(!r->gdi || !r->user32)return PW_ERR_STATE;
    if(gdi && !strcmp(r->last_name,"CreatePalette")) {
        PwGuestCall call={0};uint32_t address;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK ||
           (status=range_access(state,address,4,PW_X86_READ))!=PW_OK)return status;
        uint16_t header[2];memcpy(header,(const void *)(uintptr_t)address,4);
        if(header[0]!=0x300 || !header[1] || header[1]>PW_GDI_PALETTE_ENTRIES)
            return PW_ERR_UNSUPPORTED;
        if((status=range_access(state,address+4,(size_t)header[1]*4,PW_X86_READ))!=PW_OK)
            return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=0,error=0;
        status=pw_gdi_create_palette(r->gdi,header[0],header[1],
            (const uint8_t (*)[4])(uintptr_t)(address+4),&result);
        if(status!=PW_OK)status=gdi_failure(status,&result,&error);
        if(status!=PW_OK)return status;
        after.gpr[0]=result;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(gdi && !strcmp(r->last_name,"SetPaletteEntries")) {
        PwGuestCall call={0};uint32_t a[4];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,16,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<4;i++)if((status=pw_guest_call_u32(&call,i*4,&a[i]))!=PW_OK)return status;
        if(a[2] && (status=range_access(state,a[3],(size_t)a[2]*4,PW_X86_READ))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=0,error=0;
        status=a[2]?pw_gdi_set_palette_entries(r->gdi,a[0],a[1],a[2],
            (const uint8_t (*)[4])(uintptr_t)a[3],&result):PW_OK;
        if(status!=PW_OK)status=gdi_failure(status,&result,&error);
        if(status!=PW_OK)return status;
        after.gpr[0]=result;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(gdi && !strcmp(r->last_name,"GetStockObject")) {
        PwGuestCall call={0};uint32_t index,result=0,error=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&index))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        status=pw_gdi_stock_object(index,&result);
        if(status!=PW_OK)status=gdi_failure(status,&result,&error);
        if(status!=PW_OK)return status;
        after.gpr[0]=result;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    unsigned count=!strcmp(r->last_name,"BitBlt")?9:
        (!strcmp(r->last_name,"CreateCompatibleBitmap") || !strcmp(r->last_name,"GetObjectA") ||
         !strcmp(r->last_name,"SelectPalette"))?3:
        (!strcmp(r->last_name,"ReleaseDC") || !strcmp(r->last_name,"SelectObject") ||
         !strcmp(r->last_name,"SetLayout") || !strcmp(r->last_name,"GetDeviceCaps"))?2:1;
    PwGuestCall call={0};uint32_t a[9]={0};
    int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,count*4,0);
    if(status!=PW_OK)return status;
    for(unsigned i=0;i<count;i++)
        if((status=pw_guest_call_u32(&call,i*4,&a[i]))!=PW_OK)return status;
    if(gdi && !strcmp(r->last_name,"GetObjectA")) {
        if(a[1]!=24)return PW_ERR_UNSUPPORTED;
        if((status=range_access(state,a[2],24,PW_X86_WRITE))!=PW_OK)return status;
        PwGdiBitmapInfo info;
        status=pw_gdi_bitmap_info(r->gdi,a[0],&info);
        uint32_t result=status==PW_OK?24:0,error=status==PW_ERR_NOT_FOUND?6:0;
        if(status!=PW_OK && status!=PW_ERR_NOT_FOUND)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(result) {
            uint8_t output[24]={0};
            memcpy(output+4,&info.width,4);memcpy(output+8,&info.height,4);
            memcpy(output+12,&info.stride,4);
            uint16_t planes=(uint16_t)info.planes,bits=(uint16_t)info.bits_per_pixel;
            memcpy(output+16,&planes,2);memcpy(output+18,&bits,2);
            memcpy((void *)(uintptr_t)a[2],output,sizeof(output));
        }
        *state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    PwUser32Rect rect={0};
    if(user && !strcmp(r->last_name,"GetDC")) {
        status=pw_user32_get_window_rect(r->user32,a[0],&rect);
        if(status==PW_ERR_NOT_FOUND || status==PW_ERR_PRECONDITION) {
            PwX86State after=*state;call.state=&after;
            if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
            *state=after;r->last_error=1400;r->calls++;return PW_OK;
        }
        if(status!=PW_OK)return status;
    }
    /* Validate stdcall cleanup before any process-owned GDI mutation. */
    PwX86State after=*state;call.state=&after;
    if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
    uint32_t result=0,error=0;
    if(user && !strcmp(r->last_name,"GetDC")) {
        uint32_t width=(uint32_t)(rect.right-rect.left),height=(uint32_t)(rect.bottom-rect.top);
        status=pw_gdi_get_dc(r->gdi,a[0],width,height,&result);
    } else if(user) {
        status=pw_gdi_release_dc(r->gdi,a[0],a[1]);result=status==PW_OK;
    } else if(!strcmp(r->last_name,"CreateCompatibleDC")) {
        status=pw_gdi_create_compatible_dc(r->gdi,a[0],&result);
    } else if(!strcmp(r->last_name,"CreateCompatibleBitmap")) {
        status=(int32_t)a[1]<=0 || (int32_t)a[2]<=0?PW_ERR_PRECONDITION:
            pw_gdi_create_compatible_bitmap(r->gdi,a[0],a[1],a[2],&result);
    } else if(!strcmp(r->last_name,"SelectObject")) {
        status=pw_gdi_select_bitmap(r->gdi,a[0],a[1],&result);
    } else if(!strcmp(r->last_name,"DeleteDC")) {
        status=pw_gdi_delete_dc(r->gdi,a[0]);result=status==PW_OK;
    } else if(!strcmp(r->last_name,"DeleteObject")) {
        status=pw_gdi_delete_object(r->gdi,a[0]);result=status==PW_OK;
    } else if(!strcmp(r->last_name,"GetLayout")) {
        status=pw_gdi_get_layout(r->gdi,a[0],&result);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;result=UINT32_MAX;error=6;}
    } else if(!strcmp(r->last_name,"SetLayout")) {
        status=pw_gdi_set_layout(r->gdi,a[0],a[1],&result);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;result=UINT32_MAX;error=6;}
    } else if(!strcmp(r->last_name,"GetDeviceCaps")) {
        status=pw_gdi_get_device_caps(r->gdi,a[0],a[1],&result);
    } else if(!strcmp(r->last_name,"SelectPalette")) {
        status=pw_gdi_select_palette(r->gdi,a[0],a[1],a[2],&result);
    } else if(!strcmp(r->last_name,"RealizePalette")) {
        status=pw_gdi_realize_palette(r->gdi,a[0],&result);
    } else {
        status=(int32_t)a[3]<=0 || (int32_t)a[4]<=0?PW_ERR_PRECONDITION:
            pw_gdi_bitblt(r->gdi,a[0],(int32_t)a[1],(int32_t)a[2],a[3],a[4],
                          a[5],(int32_t)a[6],(int32_t)a[7],a[8]);
        result=status==PW_OK;
    }
    if(status!=PW_OK)status=gdi_failure(status,&result,&error);
    if(status!=PW_OK)return status;
    after.gpr[0]=result;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
}
int pw_win32_dispatch(PwWin32 *r,PwX86State *state)
{
    if(!r || !state)return PW_ERR_PRECONDITION;
    if(!r->main_base || !r->crt_data)return PW_ERR_STATE;
    r->callback_pending=0;
    if(state->eip==PW_WIN32_UPDATE_CALLBACK) {
        r->last_dll="user32.dll";r->last_name="UpdateWindow";
        return update_return(r,state);
    }
    if(state->eip>=PW_WIN32_CREATE_CALLBACK_BASE &&
       state->eip<PW_WIN32_CREATE_CALLBACK_BASE+PW_WIN32_CREATE_DEPTH*16 &&
       !((state->eip-PW_WIN32_CREATE_CALLBACK_BASE)%16)) {
        r->last_dll="user32.dll";r->last_name="CreateWindowExA";
        return create_return(r,state,(state->eip-PW_WIN32_CREATE_CALLBACK_BASE)/16);
    }
    if(state->eip>=PW_WIN32_CALLBACK_BASE && state->eip<PW_WIN32_CALLBACK_BASE+PW_WIN32_INIT_DEPTH*16) {
        r->last_dll="msvcrt.dll";r->last_name="_initterm";
        if(!r->init_depth || state->eip!=PW_WIN32_CALLBACK_BASE+(r->init_depth-1)*16)return PW_ERR_STATE;
        PwWin32Init *f=&r->init[r->init_depth-1];
        if(f->callback.state!=state)return PW_ERR_STATE;
        uint64_t ignored;int status=pw_guest_callback_leave(&f->callback,0,&ignored);
        return status==PW_OK?init_next(r,state):status;
    }
    if(state->eip<PW_WIN32_TOKEN_BASE)return PW_ERR_NOT_FOUND;
    uint32_t offset=state->eip-PW_WIN32_TOKEN_BASE,index=offset/16;
    if(offset%16 || index>=sizeof(pw_catalog)/sizeof(pw_catalog[0]) ||
       pw_catalog[index].kind!=PW_IMPORT_FUNCTION)return PW_ERR_NOT_FOUND;
    r->last_dll=pw_catalog[index].dll;r->last_name=pw_catalog[index].name;
    if(!strcmp(r->last_dll,"advapi32.dll"))return registry_dispatch(r,state);
    int gdi_status=gdi_dispatch(r,state);
    if(gdi_status!=PW_ERR_NOT_FOUND)return gdi_status;
    if(!strcmp(r->last_dll,"user32.dll") &&
       (!strcmp(r->last_name,"MapVirtualKeyA") || !strcmp(r->last_name,"GetKeyNameTextA"))) {
        if(!r->user32)return PW_ERR_STATE;
        unsigned key_name=!strcmp(r->last_name,"GetKeyNameTextA");
        unsigned count=key_name?3:2;PwGuestCall call={0};uint32_t a[3]={0};
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,count*4,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<count;i++)
            if((status=pw_guest_call_u32(&call,i*4,&a[i]))!=PW_OK)return status;
        char name[PW_USER32_NAME_MAX+1]={0};uint32_t result=0;
        if(key_name) {
            if(!a[2] || a[2]>sizeof(name))return PW_ERR_UNSUPPORTED;
            if((status=range_access(state,a[1],a[2],PW_X86_WRITE))!=PW_OK)return status;
            if((status=pw_user32_get_key_name(a[0],name,a[2],&result))!=PW_OK)return status;
        } else if((status=pw_user32_map_virtual_key(a[0],a[1],&result))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(key_name)memcpy((void *)(uintptr_t)a[1],name,(size_t)result+1);
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") &&
       (!strcmp(r->last_name,"RegisterWindowMessageA") || !strcmp(r->last_name,"FindWindowA"))) {
        if(!r->user32)return PW_ERR_STATE;
        unsigned find=!strcmp(r->last_name,"FindWindowA");PwGuestCall call={0};uint32_t a[2]={0};
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,find?8:4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&a[0]))!=PW_OK ||
           (find && (status=pw_guest_call_u32(&call,4,&a[1]))!=PW_OK))return status;
        char first[PW_USER32_NAME_MAX+1],second[PW_USER32_NAME_MAX+1];uint32_t result=0;
        if((status=guest_string(state,a[0],first,sizeof(first),find))!=PW_OK)return status;
        if(find && (status=guest_string(state,a[1],second,sizeof(second),1))!=PW_OK)return status;
        /* Validate the return frame before a registration can mutate the
         * process-owned User32 namespace. */
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        if(find)status=pw_user32_find_window(r->user32,a[0]?first:NULL,a[1]?second:NULL,&result);
        else status=pw_user32_register_message(r->user32,first,&result);
        uint32_t error=0;
        if(status==PW_ERR_PRECONDITION || status==PW_ERR_LIMIT){error=status==PW_ERR_LIMIT?8:87;result=0;status=PW_OK;}
        if(status!=PW_OK)return status;
        after.gpr[0]=result;
        *state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"comctl32.dll") && !strcmp(r->last_name,"InitCommonControlsEx")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t address,descriptor[2];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK ||
           (status=range_access(state,address,sizeof(descriptor),PW_X86_READ))!=PW_OK)return status;
        memcpy(descriptor,(const void *)(uintptr_t)address,sizeof(descriptor));
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,1))!=PW_OK)return status;
        status=pw_user32_init_common_controls(r->user32,descriptor[0],descriptor[1]);
        if(status!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") &&
       (!strcmp(r->last_name,"LoadIconA") || !strcmp(r->last_name,"LoadCursorA"))) {
        if(!r->user32 || !r->user32->resources)return PW_ERR_STATE;
        unsigned icon=!strcmp(r->last_name,"LoadIconA");
        PwGuestCall call={0};uint32_t module,resource;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&module))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&resource))!=PW_OK)return status;
        char name[PW_USER32_NAME_MAX+1];const uint8_t *bytes=NULL;size_t size=0;
        if(icon) {
            if(module!=r->main_base || resource<0x10000u || !r->services.named_resource)
                return PW_ERR_UNSUPPORTED;
            if((status=guest_string(state,resource,name,sizeof(name),0))!=PW_OK)return status;
            status=r->services.named_resource(r->services.opaque,module,14,name,&bytes,&size);
            if(status!=PW_OK && status!=PW_ERR_NOT_FOUND)return status;
            if(status==PW_OK && (!bytes || !size || size>UINT32_MAX))return PW_ERR_STATE;
        } else if(module || (resource!=32512u && resource!=32514u)) {
            return PW_ERR_UNSUPPORTED; /* startup uses IDC_ARROW and IDC_WAIT */
        }
        /* Validate the stdcall return before allocating a process object. */
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t handle=0,error=0;
        if(icon && !bytes)error=1814; /* ERROR_RESOURCE_NAME_NOT_FOUND */
        else {
            status=pw_user32_resource(r->user32,
                icon?PW_USER32_ICON:PW_USER32_SYSTEM_CURSOR,
                icon?module:0,icon?14:0,icon?name:NULL,icon?0:resource,
                bytes,(uint32_t)size,&handle);
            if(status==PW_ERR_LIMIT){status=PW_OK;error=8;handle=0;}
            if(status!=PW_OK)return status;
        }
        after.gpr[0]=handle;*state=after;
        if(error)r->last_error=error;
        r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"LoadBitmapA")) {
        if(!r->gdi || !r->services.named_resource)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t module,resource;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&module))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&resource))!=PW_OK)return status;
        if(module!=r->main_base || resource<0x10000u)return PW_ERR_UNSUPPORTED;
        char name[PW_USER32_NAME_MAX+1];
        if((status=guest_string(state,resource,name,sizeof(name),0))!=PW_OK)return status;
        const uint8_t *bytes=NULL;size_t size=0;
        status=r->services.named_resource(r->services.opaque,module,2,name,&bytes,&size);
        if(status!=PW_OK && status!=PW_ERR_NOT_FOUND)return status;
        if(status==PW_OK && (!bytes || !size || size>UINT32_MAX))return PW_ERR_STATE;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t handle=0,error=0;
        if(!bytes)error=1814;
        else {
            status=pw_gdi_create_dib_bitmap(r->gdi,bytes,(uint32_t)size,&handle);
            if(status==PW_ERR_LIMIT){status=PW_OK;error=8;}
            if(status!=PW_OK)return status;
        }
        after.gpr[0]=handle;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"RegisterClassA")) {
        if(!r->user32 || !r->user32->classes || !r->services.code_address)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t address,raw[10];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK ||
           (status=range_access(state,address,sizeof(raw),PW_X86_READ))!=PW_OK)return status;
        memcpy(raw,(const void *)(uintptr_t)address,sizeof(raw));
        if(raw[4]!=r->main_base)return PW_ERR_UNSUPPORTED;
        if((status=r->services.code_address(r->services.opaque,raw[1]))!=PW_OK)return status;
        char menu[PW_USER32_NAME_MAX+1],name[PW_USER32_NAME_MAX+1];
        if((status=guest_string(state,raw[8],menu,sizeof(menu),1))!=PW_OK ||
           (status=guest_string(state,raw[9],name,sizeof(name),0))!=PW_OK)return status;
        unsigned have_icon=!raw[5],have_cursor=!raw[6];
        for(uint32_t i=0;i<r->user32->resource_capacity;i++) {
            const PwUser32Resource *resource=&r->user32->resources[i];
            if(resource->used && resource->handle==raw[5] && resource->kind==PW_USER32_ICON)
                have_icon=1;
            if(resource->used && resource->handle==raw[6] && resource->kind==PW_USER32_SYSTEM_CURSOR)
                have_cursor=1;
        }
        if(!have_icon || !have_cursor)return PW_ERR_UNSUPPORTED;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        PwUser32Class descriptor={0};
        memcpy(descriptor.menu_name,menu,strlen(menu)+1);
        memcpy(descriptor.class_name,name,strlen(name)+1);
        descriptor.style=raw[0];descriptor.wndproc=raw[1];descriptor.class_extra=raw[2];
        descriptor.window_extra=raw[3];descriptor.module=raw[4];descriptor.icon=raw[5];
        descriptor.cursor=raw[6];descriptor.background=raw[7];
        uint16_t atom=0;status=pw_user32_register_class(r->user32,&descriptor,&atom);
        uint32_t error=0;
        if(status==PW_ERR_STATE){status=PW_OK;error=1410;atom=0;}
        else if(status==PW_ERR_LIMIT){status=PW_OK;error=8;atom=0;}
        if(status!=PW_OK)return status;
        after.gpr[0]=atom;*state=after;if(error)r->last_error=error;
        r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"DefWindowProcA")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t args[4];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,16,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<4;i++)if((status=pw_guest_call_u32(&call,i*4,&args[i]))!=PW_OK)return status;
        unsigned known=0;
        for(uint32_t i=0;i<r->user32->window_capacity;i++)
            if(r->user32->windows[i].used && r->user32->windows[i].handle==args[0])known=1;
        if(!known || (args[1]!=0x81 && args[1]!=1))return PW_ERR_UNSUPPORTED;
        status=pw_guest_call_finish(&call,32,args[1]==0x81?1:0);
        if(status==PW_OK)r->calls++;
        return status;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"CreateWindowExA")) {
        if(!r->user32 || !r->user32->classes || r->create_depth>=PW_WIN32_CREATE_DEPTH)
            return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t args[12];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,48,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<12;i++)if((status=pw_guest_call_u32(&call,i*4,&args[i]))!=PW_OK)return status;
        if(args[1]<0x10000u || args[8] || args[9] ||
           args[10]!=r->main_base || args[11])return PW_ERR_UNSUPPORTED;
        char class_name[PW_USER32_NAME_MAX+1],title[PW_USER32_NAME_MAX+1];
        if((status=guest_string(state,args[1],class_name,sizeof(class_name),0))!=PW_OK ||
           (status=guest_string(state,args[2],title,sizeof(title),1))!=PW_OK)return status;
        const PwUser32Class *class_record=NULL;
        if((status=pw_user32_find_class(r->user32,class_name,args[10],&class_record))!=PW_OK) {
            if(status!=PW_ERR_NOT_FOUND)return status;
            PwX86State after=*state;call.state=&after;
            if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
            *state=after;r->last_error=1407;r->calls++;return PW_OK;
        }
        PwX86State finish=*state;PwGuestCall checked=call;checked.state=&finish;
        if((status=pw_guest_call_finish(&checked,32,0))!=PW_OK)return status;
        if(call.esp<state->stack_low+48)return PW_ERR_VM;
        uint32_t scratch=call.esp-48;
        PwUser32Window window={.wndproc=class_record->wndproc,.ex_style=args[0],
            .style=args[3],.x=args[4],.y=args[5],.width=args[6],.height=args[7],
            .parent=args[8],.menu=args[9],.module=args[10],.param=args[11],
            .extra_bytes=class_record->window_extra};
        memcpy(window.class_name,class_name,strlen(class_name)+1);
        memcpy(window.title,title,strlen(title)+1);
        uint32_t slot,handle;
        status=pw_user32_begin_window(r->user32,&window,&slot,&handle);
        if(status==PW_ERR_LIMIT) {
            PwX86State after=*state;call.state=&after;
            if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
            *state=after;r->last_error=8;r->calls++;return PW_OK;
        }
        if(status!=PW_OK)return status;
        uint32_t create_struct[]={args[11],args[10],args[9],args[8],args[7],args[6],
            args[5],args[4],args[3],args[2],args[1],args[0]};
        memcpy((void *)(uintptr_t)scratch,create_struct,sizeof(create_struct));
        state->gpr[4]=scratch;
        unsigned create_index=r->create_depth++;
        r->create[create_index]=(PwWin32Create){.call=call,.slot=slot,.handle=handle,
            .wndproc=class_record->wndproc,.create_struct=scratch,.phase=1,.active=1};
        status=create_callback(r,state,0x81); /* WM_NCCREATE */
        if(status!=PW_OK) {
            (void)pw_user32_finish_window(r->user32,slot,0);
            memset(&r->create[create_index],0,sizeof(r->create[create_index]));
            r->create_depth--;state->gpr[4]=call.esp;
        }
        return status;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"SetWindowLongA")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t args[3];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,12,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<3;i++)
            if((status=pw_guest_call_u32(&call,i*4,&args[i]))!=PW_OK)return status;
        /* Preflight the guest return before mutating per-window storage. */
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t previous=0,error=0;
        status=pw_user32_set_window_long(r->user32,args[0],(int32_t)args[1],args[2],&previous);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;error=1400;} /* ERROR_INVALID_WINDOW_HANDLE */
        else if(status==PW_ERR_PRECONDITION){status=PW_OK;error=1413;} /* ERROR_INVALID_INDEX */
        if(status!=PW_OK)return status;
        after.gpr[0]=previous;*state=after;
        if(error)r->last_error=error;
        r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"GetWindowLongA")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle,index;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&index))!=PW_OK)return status;
        uint32_t result=0,error=0;
        status=pw_user32_get_window_long(r->user32,handle,(int32_t)index,&result);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;error=1400;}
        else if(status==PW_ERR_PRECONDITION){status=PW_OK;error=1413;}
        if(status!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        *state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"GetDesktopWindow")) {
        if(!r->user32 || !r->user32->desktop_configured)return PW_ERR_STATE;
        PwGuestCall call={0};int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,0,0);
        if(status==PW_OK)status=pw_guest_call_finish(&call,32,PW_USER32_DESKTOP_HANDLE);
        if(status==PW_OK)r->calls++;
        return status;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"GetWindowRect")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle,address;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&address))!=PW_OK ||
           (status=range_access(state,address,sizeof(PwUser32Rect),PW_X86_WRITE))!=PW_OK)
            return status;
        PwUser32Rect rect;
        status=pw_user32_get_window_rect(r->user32,handle,&rect);
        uint32_t result=1,error=0;
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;result=0;error=1400;}
        else if(status==PW_ERR_PRECONDITION){status=PW_OK;result=0;error=87;}
        if(status!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(result)memcpy((void *)(uintptr_t)address,&rect,sizeof(rect));
        *state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"MoveWindow")) {
        if(!r->user32 || !r->gdi)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t args[6];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,24,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<6;i++)
            if((status=pw_guest_call_u32(&call,i*4,&args[i]))!=PW_OK)return status;
        if(args[5])return PW_ERR_UNSUPPORTED; /* source-confirmed splash path passes FALSE */
        PwUser32Rect old;
        status=pw_user32_get_window_rect(r->user32,args[0],&old);
        if(status==PW_OK) {
            int64_t right=(int64_t)(int32_t)args[1]+(int32_t)args[3];
            int64_t bottom=(int64_t)(int32_t)args[2]+(int32_t)args[4];
            if((int32_t)args[3]<=0 || (int32_t)args[4]<=0 || right<INT32_MIN ||
               right>INT32_MAX || bottom<INT32_MIN || bottom>INT32_MAX)
                status=PW_ERR_PRECONDITION;
        }
        uint32_t result=status==PW_OK,error=0;
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;error=1400;}
        else if(status==PW_ERR_PRECONDITION || status==PW_ERR_LIMIT){status=PW_OK;error=87;}
        if(status!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(result) {
            status=pw_gdi_resize_target(r->gdi,args[0],args[3],args[4]);
            if(status!=PW_OK)return status;
            status=pw_user32_move_window(r->user32,args[0],(int32_t)args[1],(int32_t)args[2],
                                         args[3],args[4]);
            if(status!=PW_OK)return status;
        }
        *state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") &&
       (!strcmp(r->last_name,"ShowWindow") || !strcmp(r->last_name,"SetFocus"))) {
        if(!r->user32)return PW_ERR_STATE;
        unsigned show=!strcmp(r->last_name,"ShowWindow");PwGuestCall call={0};uint32_t args[2]={0};
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,show?8:4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&args[0]))!=PW_OK ||
           (show && (status=pw_guest_call_u32(&call,4,&args[1]))!=PW_OK))return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=0,error=0;
        status=show?pw_user32_show_window(r->user32,args[0],args[1],&result):
                    pw_user32_set_focus(r->user32,args[0],&result);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;error=1400;result=0;}
        if(status!=PW_OK)return status;
        after.gpr[0]=result;*state=after;if(error)r->last_error=error;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"SetCursor")) {
        if(!r->user32)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t result=0;
        status=pw_user32_set_cursor(r->user32,handle,&result);
        if(status==PW_ERR_NOT_FOUND){status=PW_OK;result=0;r->last_error=6;}
        if(status!=PW_OK)return status;
        after.gpr[0]=result;*state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"UpdateWindow")) {
        if(!r->user32 || r->update.active)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK)return status;
        uint32_t wndproc=0,needed=0;
        status=pw_user32_paint_info(r->user32,handle,&wndproc,&needed);
        if(status==PW_ERR_NOT_FOUND) {
            PwX86State after=*state;call.state=&after;
            if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
            *state=after;r->last_error=1400;r->calls++;return PW_OK;
        }
        if(status!=PW_OK)return status;
        if(!needed) {
            status=pw_guest_call_finish(&call,32,1);if(status==PW_OK)r->calls++;return status;
        }
        uint32_t args[]={handle,0x0f,0,0};
        r->update=(PwWin32Update){.call=call,.handle=handle,.wndproc=wndproc,.active=1};
        status=pw_guest_callback_enter(&r->update.callback,state,wndproc,
                                       PW_WIN32_UPDATE_CALLBACK,args,4,PW_GUEST_STDCALL);
        if(status!=PW_OK){memset(&r->update,0,sizeof(r->update));return status;}
        r->callback_pending=1;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"BeginPaint")) {
        if(!r->user32 || !r->gdi)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle,address;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&address))!=PW_OK ||
           (status=range_access(state,address,64,PW_X86_WRITE))!=PW_OK)return status;
        PwUser32Rect rect;uint32_t wndproc,needed;
        if((status=pw_user32_get_window_rect(r->user32,handle,&rect))!=PW_OK ||
           (status=pw_user32_paint_info(r->user32,handle,&wndproc,&needed))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,0))!=PW_OK)return status;
        uint32_t dc,width=(uint32_t)(rect.right-rect.left),height=(uint32_t)(rect.bottom-rect.top);
        if((status=pw_gdi_get_dc(r->gdi,handle,width,height,&dc))!=PW_OK)return status;
        status=pw_user32_begin_paint(r->user32,handle,dc);
        if(status!=PW_OK){(void)pw_gdi_release_dc(r->gdi,handle,dc);return status;}
        uint8_t output[64]={0};
        memcpy(output,&dc,4);memcpy(output+16,&width,4);memcpy(output+20,&height,4);
        memcpy((void *)(uintptr_t)address,output,sizeof(output));
        after.gpr[0]=dc;*state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"EndPaint")) {
        if(!r->user32 || !r->gdi)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t handle,address,dc;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&handle))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&address))!=PW_OK ||
           (status=range_access(state,address,64,PW_X86_READ))!=PW_OK)return status;
        memcpy(&dc,(const void *)(uintptr_t)address,4);
        if((status=pw_user32_check_paint(r->user32,handle,dc))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,1))!=PW_OK)return status;
        if((status=pw_gdi_release_dc(r->gdi,handle,dc))!=PW_OK ||
           (status=pw_user32_end_paint(r->user32,handle,dc))!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"user32.dll") && !strcmp(r->last_name,"LoadStringA")) {
        if(!r->services.string_resource || r->services.ansi_codepage!=1252)return PW_ERR_UNSUPPORTED;
        PwGuestCall call={0};uint32_t arg[4];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,16,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<4;i++)if((status=pw_guest_call_u32(&call,i*4,&arg[i]))!=PW_OK)return status;
        if(!arg[3] || arg[3]>4096)return PW_ERR_UNSUPPORTED;
        const uint8_t *text=NULL;size_t units=0;
        status=r->services.string_resource(r->services.opaque,arg[0],arg[1],&text,&units);
        if(status!=PW_OK && status!=PW_ERR_NOT_FOUND)return status;
        unsigned missing=status==PW_ERR_NOT_FOUND;
        if(!missing && ((!text && units) || units>65535))return PW_ERR_STATE;
        uint8_t output[4096];size_t n=0;
        if(!missing) {
            while(n<units && n<arg[3]-1) {
                uint32_t c=(uint32_t)text[n*2]|(uint32_t)text[n*2+1]<<8;
                if((status=cp1252(c,output+n))!=PW_OK)return status;
                n++;
            }
            output[n]=0;
            if((status=range_access(state,arg[2],n+1,PW_X86_WRITE))!=PW_OK)return status;
        }
        status=pw_guest_call_finish(&call,32,n);
        if(status!=PW_OK)return status;
        if(!missing)memcpy((void *)(uintptr_t)arg[2],output,n+1);
        r->calls++;return PW_OK;
    }
    unsigned kernel=!strcmp(r->last_dll,"kernel32.dll");
    if(kernel && !strcmp(r->last_name,"GetLastError")) {
        PwGuestCall call={0};int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,0,0);
        if(status==PW_OK)status=pw_guest_call_finish(&call,32,r->last_error);
        if(status==PW_OK)r->calls++;
        return status;
    }
    if(kernel && !strcmp(r->last_name,"GetModuleFileNameA")) {
        PwGuestCall call={0};uint32_t module,destination,capacity;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,12,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&module))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&destination))!=PW_OK ||
           (status=pw_guest_call_u32(&call,8,&capacity))!=PW_OK)return status;
        if(module && module!=r->main_base)return PW_ERR_UNSUPPORTED;
        const char *filename=r->services.main_module_filename;
        if(!filename)return PW_ERR_STATE;
        size_t length=0;
        while(length<=PW_PATH_MAX && filename[length])length++;
        if(length>PW_PATH_MAX)return PW_ERR_LIMIT;
        size_t written=length<capacity?length+1:capacity;
        if(written && (status=range_access(state,destination,written,PW_X86_WRITE))!=PW_OK)
            return status;
        PwX86State after=*state;call.state=&after;
        uint32_t result=length<capacity?(uint32_t)length:capacity;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        if(written)memcpy((void *)(uintptr_t)destination,filename,written);
        *state=after;r->calls++;return PW_OK;
    }
    if(kernel && !strcmp(r->last_name,"GetPrivateProfileIntA")) {
        if(!r->services.profile_int)return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t arg[4];
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,16,0);
        if(status!=PW_OK)return status;
        for(unsigned i=0;i<4;i++)
            if((status=pw_guest_call_u32(&call,i*4,&arg[i]))!=PW_OK)return status;
        char section[128],key[128],filename[PW_PATH_MAX+1];
        if((status=guest_string(state,arg[0],section,sizeof(section),0))!=PW_OK ||
           (status=guest_string(state,arg[1],key,sizeof(key),0))!=PW_OK ||
           (status=guest_string(state,arg[3],filename,sizeof(filename),0))!=PW_OK)
            return status;
        uint32_t result=arg[2];
        status=r->services.profile_int(r->services.opaque,section,key,arg[2],filename,&result);
        if(status!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"msvcrt.dll") && !strcmp(r->last_name,"sprintf")) {
        PwGuestCall call={0};uint32_t destination,format_address;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,8,1);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&destination))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&format_address))!=PW_OK)return status;
        char format[1024],output[4096];
        if((status=guest_string(state,format_address,format,sizeof(format),0))!=PW_OK)return status;
        size_t capacity;
        if((status=writable_capacity(state,destination,sizeof(output),&capacity))!=PW_OK)return status;
        FormatGuest guest={&call,state};PwCrtFormatInput input={&guest,format_u32,format_string};
        uint32_t length;
        if((status=pw_crt_format_ascii(output,capacity,format,&input,&length))!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,length))!=PW_OK)return status;
        memcpy((void *)(uintptr_t)destination,output,(size_t)length+1);
        *state=after;r->calls++;return PW_OK;
    }
    unsigned compare_string=kernel && !strcmp(r->last_name,"lstrcmpA");
    unsigned search_string=!strcmp(r->last_dll,"msvcrt.dll") && !strcmp(r->last_name,"strstr");
    if(compare_string || search_string) {
        PwGuestCall call={0};uint32_t first,second,first_length,second_length;
        int status=pw_guest_call_begin(&call,state,
            compare_string?PW_GUEST_STDCALL:PW_GUEST_CDECL,8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&first))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&second))!=PW_OK ||
           (status=string_length(state,first,&first_length))!=PW_OK ||
           (status=string_length(state,second,&second_length))!=PW_OK)return status;
        const uint8_t *a=(const uint8_t *)(uintptr_t)first;
        const uint8_t *b=(const uint8_t *)(uintptr_t)second;uint32_t result=0;
        if(compare_string) {
            uint32_t common=first_length<second_length?first_length:second_length;int order=0;
            for(uint32_t i=0;i<common && !order;i++)order=a[i]<b[i]?-1:a[i]>b[i]?1:0;
            if(!order)order=first_length<second_length?-1:first_length>second_length?1:0;
            result=(uint32_t)order;
        } else if(!second_length)result=first;
        else if(second_length<=first_length) {
            for(uint32_t i=0;i<=first_length-second_length;i++)
                if(!memcmp(a+i,b,second_length)){result=first+i;break;}
        }
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"msvcrt.dll") && !strcmp(r->last_name,"_strnicmp")) {
        PwGuestCall call={0};uint32_t first,second,count;int32_t result=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,12,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&first))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&second))!=PW_OK ||
           (status=pw_guest_call_u32(&call,8,&count))!=PW_OK ||
           (status=compare_ascii_nocase(state,first,second,count,&result))!=PW_OK)
            return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,(uint32_t)result))!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"msvcrt.dll") &&
       (!strcmp(r->last_name,"fopen") || !strcmp(r->last_name,"fclose"))) {
        unsigned opening=!strcmp(r->last_name,"fopen");
        if((opening && !r->services.file_open) || (!opening && !r->services.file_close))
            return PW_ERR_STATE;
        PwGuestCall call={0};uint32_t a[2]={0};
        int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,opening?8:4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&a[0]))!=PW_OK ||
           (opening && (status=pw_guest_call_u32(&call,4,&a[1]))!=PW_OK))return status;
        uint32_t result=0;
        if(opening) {
            char path[PW_PATH_MAX+1],mode[8];
            if((status=guest_string(state,a[0],path,sizeof(path),0))!=PW_OK ||
               (status=guest_string(state,a[1],mode,sizeof(mode),0))!=PW_OK)return status;
            status=r->services.file_open(r->services.opaque,path,mode,&result);
            if(status==PW_ERR_NOT_FOUND){status=PW_OK;result=0;r->crt_errno=2;}
        } else {
            status=r->services.file_close(r->services.opaque,a[0]);
            result=status==PW_OK?0:UINT32_MAX;
            if(status==PW_ERR_NOT_FOUND){status=PW_OK;r->crt_errno=9;}
        }
        if(status!=PW_OK)return status;
        PwX86State after=*state;call.state=&after;
        if((status=pw_guest_call_finish(&call,32,result))!=PW_OK)return status;
        *state=after;r->calls++;return PW_OK;
    }
    unsigned bounded=kernel && !strcmp(r->last_name,"lstrcpynA");
    unsigned append=kernel && !strcmp(r->last_name,"lstrcatA");
    if(bounded || append || (kernel && !strcmp(r->last_name,"lstrcpyA"))) {
        PwGuestCall call={0};uint32_t dst,src,count=0,at=0,n=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,bounded?12:8,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&dst))!=PW_OK ||
           (status=pw_guest_call_u32(&call,4,&src))!=PW_OK)return status;
        if(bounded && (status=pw_guest_call_u32(&call,8,&count))!=PW_OK)return status;
        if(!bounded || count)status=copy_string(state,dst,src,count,bounded,append,&at,&n);
        unsigned invalid=status==PW_ERR_VM;
        if(status!=PW_OK && !invalid)return status;
        status=pw_guest_call_finish(&call,32,invalid?0:dst);
        if(status!=PW_OK)return status;
        if(invalid)r->last_error=87; /* ERROR_INVALID_PARAMETER, as Wine's bad-pointer path */
        else if(!bounded || count) {
            if(n)memmove((void *)(uintptr_t)at,(const void *)(uintptr_t)src,n);
            *(uint8_t *)(uintptr_t)(at+n)=0;
        }
        r->calls++;return PW_OK;
    }
    if(kernel && !strcmp(r->last_name,"lstrlenA")) {
        PwGuestCall call={0};uint32_t address,length=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK)return status;
        if(address && (status=string_length(state,address,&length))!=PW_OK)return status;
        status=pw_guest_call_finish(&call,32,length);
        if(status==PW_OK)r->calls++;
        return status;
    }
    if(kernel && !strcmp(r->last_name,"GetStartupInfoA")) {
        /* Serialize STARTUPINFOA32, never the host's pointer-sized structure.
         * GUI launch: show policy supplied, no inherited console handles,
         * title/desktop override, geometry override or reserved CRT data. */
        if(r->startup_show>11 || r->startup_show==10)return PW_ERR_UNSUPPORTED;
        PwGuestCall call={0};uint32_t address;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
        if(status!=PW_OK)return status;
        if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK)return status;
        if(address>UINT32_MAX-67)return PW_ERR_VM;
        for(unsigned offset=0;offset<68;offset+=4)
            if((status=word_access(state,address+offset,PW_X86_WRITE))!=PW_OK)return status;
        uint8_t info[68]={0};uint32_t size=68,flags=1;
        memcpy(info,&size,4);memcpy(info+44,&flags,4);memcpy(info+48,&r->startup_show,2);
        status=pw_guest_call_finish(&call,0,0);
        if(status!=PW_OK)return status;
        memcpy((void *)(uintptr_t)address,info,sizeof(info));r->calls++;return PW_OK;
    }
    unsigned wall=kernel && !strcmp(r->last_name,"GetSystemTimeAsFileTime");
    unsigned counter=kernel && !strcmp(r->last_name,"QueryPerformanceCounter");
    unsigned tick=(kernel && !strcmp(r->last_name,"GetTickCount")) ||
        (!strcmp(r->last_dll,"winmm.dll") && !strcmp(r->last_name,"timeGetTime"));
    unsigned pid=kernel && !strcmp(r->last_name,"GetCurrentProcessId");
    unsigned tid=kernel && !strcmp(r->last_name,"GetCurrentThreadId");
    if(wall || counter || tick || pid || tid) {
        PwGuestCall call={0};uint32_t address=0;uint64_t value=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,(wall || counter)?4:0,0);
        if(status!=PW_OK)return status;
        if(wall || counter) {
            if((status=pw_guest_call_u32(&call,0,&address))!=PW_OK)return status;
            if(address>UINT32_MAX-7)return PW_ERR_VM;
            if((status=word_access(state,address,PW_X86_WRITE))!=PW_OK)return status;
            if((status=word_access(state,address+4,PW_X86_WRITE))!=PW_OK)return status;
        }
        if(pid || tid) {
            value=pid?r->services.process_id:r->services.thread_id;
            if(!value)return PW_ERR_STATE;
        } else {
            if(!r->services.clock_ns)return PW_ERR_STATE;
            status=r->services.clock_ns(r->services.opaque,wall?PW_CLOCK_UTC:counter?PW_CLOCK_COUNTER:PW_CLOCK_UPTIME,&value);
            if(status!=PW_OK)return status;
            if(wall)value=value/100+116444736000000000ull;
            else if(tick)value=(uint32_t)(value/1000000);
            else if(value>INT64_MAX)return PW_ERR_LIMIT;
        }
        status=pw_guest_call_finish(&call,wall?0:32,counter?1:value);
        if(status!=PW_OK)return status;
        if(wall || counter)memcpy((void *)(uintptr_t)address,&value,8);
        r->calls++;return PW_OK;
    }
    if(!strcmp(r->last_dll,"msvcrt.dll")) {
        unsigned alloc=!strcmp(r->last_name,"malloc"),zero=!strcmp(r->last_name,"calloc");
        unsigned resize=!strcmp(r->last_name,"realloc"),release=!strcmp(r->last_name,"free");
        if(alloc || zero || resize || release) {
            int status=pw_guest_heap_validate(r->heap);
            if(status!=PW_OK)return status;
            uint64_t end=(uint64_t)r->heap->base+r->heap->bytes;
            if(r->heap->base<state->stack_high && end>state->stack_low)return PW_ERR_STATE;
            if((status=range_access(state,r->heap->base,r->heap->bytes,PW_X86_READ|PW_X86_WRITE))!=PW_OK)return status;
            PwGuestCall call={0};uint32_t first,second=0,address=0;
            status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,(zero || resize)?8:4,0);
            if(status!=PW_OK)return status;
            if((status=pw_guest_call_u32(&call,0,&first))!=PW_OK)return status;
            if((zero || resize) && (status=pw_guest_call_u32(&call,4,&second))!=PW_OK)return status;
            /* Preflight return before allocator side effects. The synchronous
             * heap core never mutates guest registers or calls guest code. */
            PwX86State after=*state;call.state=&after;
            if((status=pw_guest_call_finish(&call,release?0:32,0))!=PW_OK)return status;
            if(alloc)status=pw_guest_heap_alloc(r->heap,first,&address);
            else if(zero)status=pw_guest_heap_calloc(r->heap,first,second,&address);
            else if(resize)status=pw_guest_heap_realloc(r->heap,first,second,&address);
            else status=pw_guest_heap_free(r->heap,first);
            if(status==PW_ERR_LIMIT && !release) {
                /* Default CRT new-handler is absent. No setter is currently
                 * implemented; new_mode alone cannot create a handler. */
                r->crt_errno=12;address=0; /* guest ENOMEM, not host errno */
            } else if(status!=PW_OK)return status;
            if(!release)after.gpr[0]=address;
            *state=after;r->calls++;return PW_OK;
        }
        if(!strcmp(r->last_name,"__getmainargs")) {
            PwGuestCall call={0};uint32_t a[5],mode=r->new_mode;
            int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,20,0);
            if(status!=PW_OK)return status;
            for(unsigned i=0;i<5;i++)if((status=pw_guest_call_u32(&call,i*4,&a[i]))!=PW_OK)return status;
            if(a[3])return PW_ERR_UNSUPPORTED;
            for(unsigned i=0;i<3;i++)if((status=word_access(state,a[i],PW_X86_WRITE))!=PW_OK)return status;
            if(a[4] && (status=table_read(state,a[4],&mode))!=PW_OK)return status;
            if(mode>1)return PW_ERR_UNSUPPORTED;
            status=pw_guest_call_finish(&call,32,0);
            if(status!=PW_OK)return status;
            memcpy((void *)(uintptr_t)a[0],&r->args.argc,4);
            memcpy((void *)(uintptr_t)a[1],&r->args.argv,4);
            memcpy((void *)(uintptr_t)a[2],&r->args.envp,4);
            r->new_mode=mode;r->calls++;return PW_OK;
        }
        if(!strcmp(r->last_name,"_initterm")) {
            if(r->init_depth==PW_WIN32_INIT_DEPTH)return PW_ERR_LIMIT;
            PwWin32Init next={0};
            int status=pw_guest_call_begin(&next.call,state,PW_GUEST_CDECL,8,0);
            if(status!=PW_OK)return status;
            if((status=pw_guest_call_u32(&next.call,0,&next.cursor))!=PW_OK)return status;
            if((status=pw_guest_call_u32(&next.call,4,&next.end))!=PW_OK)return status;
            if((next.cursor&3) || (next.end&3) || next.end<next.cursor)return PW_ERR_UNSUPPORTED;
            if((next.end-next.cursor)/4>PW_WIN32_INIT_ENTRIES)return PW_ERR_LIMIT;
            r->init[r->init_depth++]=next;
            status=init_next(r,state);
            if(status!=PW_OK){memset(&r->init[--r->init_depth],0,sizeof(next));}
            return status;
        }
        if(!strcmp(r->last_name,"_controlfp")) {
            PwGuestCall call={0};uint32_t value,mask,result;
            int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,8,0);
            if(status!=PW_OK)return status;
            if((status=pw_guest_call_u32(&call,0,&value))!=PW_OK)return status;
            if((status=pw_guest_call_u32(&call,4,&mask))!=PW_OK)return status;
            PwGuestFp next=state->fp;
            if((status=pw_guest_fp_control(&next,value,mask,&result))!=PW_OK)return status;
            status=pw_guest_call_finish(&call,32,result);
            if(status==PW_OK){state->fp=next;r->calls++;}
            return status;
        }
        unsigned set_type=!strcmp(r->last_name,"__set_app_type");
        unsigned fmode=!strcmp(r->last_name,"__p__fmode");
        unsigned commode=!strcmp(r->last_name,"__p__commode");
        if(!set_type && !fmode && !commode)return PW_ERR_UNSUPPORTED;
        PwGuestCall call={0};uint32_t type=0;
        int status=pw_guest_call_begin(&call,state,PW_GUEST_CDECL,set_type?4:0,0);
        if(status!=PW_OK)return status;
        if(set_type) {
            status=pw_guest_call_u32(&call,0,&type);
            if(status!=PW_OK)return status;
        }
        status=pw_guest_call_finish(&call,set_type?0:32,r->crt_data+(fmode?8:12));
        if(status==PW_OK) {
            if(set_type)r->app_type=type;
            r->calls++;
        }
        return status;
    }
    if(strcmp(r->last_dll,"kernel32.dll") || strcmp(r->last_name,"GetModuleHandleA"))
        return PW_ERR_UNSUPPORTED;
    PwGuestCall call={0};uint32_t name;
    int status=pw_guest_call_begin(&call,state,PW_GUEST_STDCALL,4,0);
    if(status!=PW_OK)return status;
    status=pw_guest_call_u32(&call,0,&name);
    if(status!=PW_OK)return status;
    if(name)return PW_ERR_UNSUPPORTED;
    status=pw_guest_call_finish(&call,32,r->main_base);
    if(status==PW_OK)r->calls++;
    return status;
}
