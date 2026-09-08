/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_win32.h"
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
    *runtime=(PwWin32){.main_base=main,.crt_data=data,.args=args};return PW_OK;
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
static int word_access(PwX86State *s,uint32_t address,unsigned permission)
{
    uint64_t end=(uint64_t)address+4;
    if(!address || end>0x100000000ull || s->memory_count>PW_X86_MEMORY_REGIONS)return PW_ERR_VM;
    unsigned readable=address>=s->stack_low && end<=s->stack_high;
    for(unsigned i=0;i<s->memory_count;i++) {
        PwX86Memory *m=&s->memory[i];
        if(m->high<=0x100000000ull && address>=m->low && end<=m->high && (m->permissions&permission)==permission)readable=1;
    }
    if(!readable)return PW_ERR_VM;
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
int pw_win32_dispatch(PwWin32 *r,PwX86State *state)
{
    if(!r || !state)return PW_ERR_PRECONDITION;
    if(!r->main_base || !r->crt_data)return PW_ERR_STATE;
    r->callback_pending=0;
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
    unsigned kernel=!strcmp(r->last_dll,"kernel32.dll");
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
