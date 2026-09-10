/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
/* Host-only bounded instruction tracer. Private input is never staged.
 * This is not a complete application loader or Win32 implementation. */
#include "../src/pe_image.h"
#include "../src/pe_resource.h"
#include "../src/pw_map.h"
#include "../src/pw_x86_engine.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_win32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>

static PwImportBindWorkspace binding_work;
static PwHeapBlock heap_blocks[4096];
static PwRegistryKey registry_keys[32];
static PwRegistryValue registry_values[128];
static PwUser32Message user_messages[128];
static PwUser32Window user_windows[128];
static PwUser32Resource user_resources[128];
static PwUser32Class user_classes[128];
static PwGdiDc gdi_dcs[128];
static PwGdiSurface gdi_surfaces[128];
static uint8_t gdi_pixels[32*1024*1024];
static PwX86CacheEntry cache_entries[8192];
typedef struct TraceSource {
    const PeImage *image;const PeLayout *layout;
    char directory[PATH_MAX];FILE *files[8];
} TraceSource;
static int trace_source(void *opaque,uint32_t pc,const uint8_t **source,size_t *bytes)
{
    const TraceSource *view=opaque;
    if(pc<view->image->image_base)return PW_ERR_NOT_FOUND;
    uint32_t rva=pc-(uint32_t)view->image->image_base;
    for(unsigned i=0;i<view->layout->section_count;i++) {
        const PeLayoutSection *section=&view->layout->sections[i];
        uint64_t end=(uint64_t)section->rva+section->mapped_bytes;
        if((section->protection&PW_PROT_EXEC) && rva>=section->rva && (uint64_t)rva<end) {
            *source=(const uint8_t *)(uintptr_t)pc;
            *bytes=(size_t)(end-rva);return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
static int host_string(void *opaque,uint32_t module,uint32_t id,const uint8_t **text,size_t *units)
{
    const TraceSource *view=opaque;const PeImage *im=view->image;
    if(module && module!=im->image_base)return PW_ERR_UNSUPPORTED;
    return pe_resource_string(im,id,0x409,text,units);
}
static int host_named_resource(void *opaque,uint32_t module,uint32_t type,const char *name,
                               const uint8_t **bytes,size_t *size)
{
    const TraceSource *view=opaque;const PeImage *im=view->image;PeResource resource;
    if(module!=im->image_base)return PW_ERR_UNSUPPORTED;
    int status=pe_resource_find_name(im,type,name,0x409,&resource);
    if(status==PW_OK){*bytes=resource.bytes;*size=resource.size;}
    return status;
}
static int host_code_address(void *opaque,uint32_t address)
{
    const TraceSource *view=opaque;const uint8_t *source;size_t bytes;
    return trace_source((void *)view,address,&source,&bytes);
}
static int host_clock(void *opaque,PwClockDomain domain,uint64_t *ns)
{
    (void)opaque;
    clockid_t id;
    if(domain==PW_CLOCK_UTC)id=CLOCK_REALTIME;
    else if(domain==PW_CLOCK_COUNTER)id=CLOCK_MONOTONIC;
    else if(domain==PW_CLOCK_UPTIME)id=CLOCK_BOOTTIME;
    else return PW_ERR_UNSUPPORTED;
    struct timespec value;
    if(clock_gettime(id,&value) || value.tv_sec<0 || value.tv_nsec<0 || value.tv_nsec>=1000000000)
        return PW_ERR_STATE;
    if((uint64_t)value.tv_sec>(UINT64_MAX-(uint64_t)value.tv_nsec)/1000000000)return PW_ERR_LIMIT;
    *ns=(uint64_t)value.tv_sec*1000000000+(uint64_t)value.tv_nsec;return PW_OK;
}
static int host_file_open(void *opaque,const char *path,const char *mode,uint32_t *handle)
{
    TraceSource *view=opaque;
    if(!view || !path || !mode || !handle || (strcmp(mode,"r") && strcmp(mode,"rb")))
        return PW_ERR_UNSUPPORTED;
    const char *base=strrchr(path,'\\');base=base?base+1:path;
    if(!*base || strchr(base,'/') || strchr(base,'\\') || strstr(base,".."))
        return PW_ERR_PRECONDITION;
    unsigned slot=8;for(unsigned i=0;i<8;i++)if(!view->files[i]){slot=i;break;}
    if(slot==8)return PW_ERR_LIMIT;
    char translated[PATH_MAX];int length=snprintf(translated,sizeof(translated),"%s/%s",view->directory,base);
    if(length<0 || (size_t)length>=sizeof(translated))return PW_ERR_LIMIT;
    FILE *file=fopen(translated,mode);if(!file)return PW_ERR_NOT_FOUND;
    view->files[slot]=file;*handle=0x0d000001u+slot;return PW_OK;
}
static int host_file_close(void *opaque,uint32_t handle)
{
    TraceSource *view=opaque;
    if(!view || handle<0x0d000001u || handle>=0x0d000009u)return PW_ERR_NOT_FOUND;
    unsigned slot=handle-0x0d000001u;if(!view->files[slot])return PW_ERR_NOT_FOUND;
    int result=fclose(view->files[slot]);view->files[slot]=NULL;
    return result?PW_ERR_STATE:PW_OK;
}
static int ascii_equal(const char *a,const char *b)
{
    while(*a && *b) {
        if(tolower((unsigned char)*a)!=tolower((unsigned char)*b))return 0;
        a++;b++;
    }
    return !*a && !*b;
}
static int host_profile_int(void *opaque,const char *section,const char *key,
                            uint32_t fallback,const char *filename,uint32_t *value)
{
    TraceSource *view=opaque;
    if(!view || !section || !*section || !key || !*key || !filename || !*filename || !value)
        return PW_ERR_PRECONDITION;
    const char *base=strrchr(filename,'\\');base=base?base+1:filename;
    if(!*base || strchr(base,'/') || strchr(base,'\\') || strstr(base,".."))
        return PW_ERR_PRECONDITION;
    char translated[PATH_MAX];int length=snprintf(translated,sizeof(translated),"%s/%s",view->directory,base);
    if(length<0 || (size_t)length>=sizeof(translated))return PW_ERR_LIMIT;
    FILE *file=fopen(translated,"rb");*value=fallback;
    if(!file)return PW_OK;
    char line[1024];unsigned in_section=0;
    while(fgets(line,sizeof(line),file)) {
        char *p=line;while(isspace((unsigned char)*p))p++;
        char *end=p+strlen(p);while(end>p && isspace((unsigned char)end[-1]))*--end=0;
        if(!*p || *p==';' || *p=='#')continue;
        if(*p=='[') {
            char *close=strchr(p+1,']');
            if(!close){in_section=0;continue;}
            *close=0;in_section=ascii_equal(p+1,section);continue;
        }
        if(!in_section)continue;
        char *equals=strchr(p,'=');if(!equals)continue;
        char *key_end=equals;while(key_end>p && isspace((unsigned char)key_end[-1]))key_end--;
        char saved=*key_end;*key_end=0;unsigned match=ascii_equal(p,key);*key_end=saved;
        if(!match)continue;
        p=equals+1;while(isspace((unsigned char)*p))p++;
        char *number_end=NULL;long parsed=strtol(p,&number_end,0);
        if(number_end!=p)*value=(uint32_t)parsed;
        break;
    }
    int failed=ferror(file);fclose(file);return failed?PW_ERR_STATE:PW_OK;
}

int main(int argc,char **argv)
{
    if(argc<2 || argc>4) {fprintf(stderr,"usage: trace_x86_entry private.exe [max-events:1..65536] [milestone-pc-hex]\n");return 1;}
    unsigned max_events=256;
    if(argc>=3) {
        char *end;unsigned long parsed=strtoul(argv[2],&end,10);
        if(!*argv[2] || *end || parsed<1 || parsed>65536)return 1;
        max_events=(unsigned)parsed;
    }
    uint32_t milestone=0;unsigned milestone_seen=0;
    if(argc==4) {
        char *end;unsigned long parsed=strtoul(argv[3],&end,16);
        if(!*argv[3] || *end || !parsed || parsed>UINT32_MAX)return 1;
        milestone=(uint32_t)parsed;
    }
    int result=1;
    FILE *file=fopen(argv[1],"rb");
    if(!file)return 1;
    if(fseek(file,0,SEEK_END)!=0){fclose(file);return 1;}
    long size=ftell(file);
    if(size<=0 || size>64*1024*1024 || fseek(file,0,SEEK_SET)!=0){fclose(file);return 1;}
    uint8_t *bytes=malloc((size_t)size);
    if(!bytes){fclose(file);return 1;}
    size_t got=fread(bytes,1,(size_t)size,file);fclose(file);
    PeImage image;
    if(got!=(size_t)size || pe_image_parse(&image,bytes,got)!=PW_OK ||
       image.machine!=PE_MACHINE_I386 || image.image_base>UINT32_MAX ||
       image.image_base+image.size_of_image>UINT32_MAX)goto done;
    PwVmBackend vm;
    PwVmRegion stack={0},thread={0},crt={0},heap_region={0};
    PwGuestHeap heap;PwRegistry registry;PwUser32 user32;PwGdi gdi;PwX86Engine engine={0};
    PwMappedImage mapped={0};PeLayout layout;TraceSource trace_view={.image=&image,.layout=&layout};
    const char *slash=strrchr(argv[1],'/');
    size_t directory_length=slash?(size_t)(slash-argv[1]):1;
    if(directory_length>=sizeof(trace_view.directory))goto done;
    if(slash)memcpy(trace_view.directory,argv[1],directory_length);
    else trace_view.directory[0]='.';
    trace_view.directory[directory_length]=0;
    int have_engine=0,have_stack=0,have_thread=0,have_image=0,have_crt=0,have_heap=0,
        have_gdi=0;
    if(pw_vm_posix_backend(&vm)!=PW_OK)goto done;
    if(vm.reserve_at(NULL,0x03000000,0x100000,4096,&stack)!=PW_OK)goto cleanup;
    have_stack=1;
    if(vm.reserve_at(NULL,0x03200000,4096,4096,&thread)!=PW_OK)goto cleanup;
    have_thread=1;
    if(vm.reserve_at(NULL,0x03300000,4096,4096,&crt)!=PW_OK)goto cleanup;
    have_crt=1;
    if(vm.reserve_at(NULL,0x03400000,0x800000,4096,&heap_region)!=PW_OK)goto cleanup;
    have_heap=1;
    if(vm.commit(NULL,&heap_region,0,heap_region.bytes,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK ||
       pw_guest_heap_init(&heap,0x03400000,0x800000,heap_blocks,4096)!=PW_OK)goto cleanup;
    if(vm.commit(NULL,&crt,0,4096,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK)goto cleanup;
    if(vm.commit(NULL,&stack,0,stack.bytes,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK ||
       vm.commit(NULL,&thread,0,thread.bytes,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK)goto cleanup;
    PwX86State state={0};
    pw_guest_fp_init(&state.fp);
    if(pe_layout_plan(&layout,&image)!=PW_OK ||
       layout.section_count+3>PW_X86_MEMORY_REGIONS ||
       image.image_base+image.size_of_image>PW_WIN32_TOKEN_BASE)goto cleanup;
    if(pw_map_image(&mapped,&image,&layout,&vm)!=PW_OK)goto cleanup;
    have_image=1;
    PwMapVerify verified;
    if(mapped.actual_base!=image.image_base || pw_map_verify(&mapped,&image,&layout,&verified)!=PW_OK ||
       verified.raw_mismatches || verified.zero_tail_violations || verified.alias_mismatches)goto cleanup;
    PwWin32 runtime;
    const char *base=strrchr(argv[1],'/');base=base?base+1:argv[1];
    if(strchr(base,'"') || strchr(base,'\\'))goto cleanup;
    char commandline[512];
    int command_bytes=snprintf(commandline,sizeof(commandline),"\"C:\\game\\%s\"",base);
    if(command_bytes<0 || (size_t)command_bytes>=sizeof(commandline))goto cleanup;
    if(pw_win32_init(&runtime,(uint32_t)mapped.actual_base,0x03300000,commandline)!=PW_OK)goto cleanup;
    if(pw_registry_init(&registry,registry_keys,32,registry_values,128)!=PW_OK)goto cleanup;
    if(pw_user32_init(&user32,user_messages,128,user_windows,128)!=PW_OK)goto cleanup;
    if(pw_user32_init_resources(&user32,user_resources,128)!=PW_OK)goto cleanup;
    /* Deterministic virtual display profile for host-only startup tracing. */
    if(pw_user32_configure_desktop(&user32,1920,1080)!=PW_OK)goto cleanup;
    if(pw_gdi_init(&gdi,gdi_dcs,128,gdi_surfaces,128,gdi_pixels,sizeof(gdi_pixels))!=PW_OK)
        goto cleanup;
    have_gdi=1;
    runtime.heap=&heap;runtime.registry=&registry;runtime.user32=&user32;runtime.gdi=&gdi;
    if(pw_user32_init_classes(&user32,user_classes,128)!=PW_OK)goto cleanup;
    runtime.services=(PwWin32Services){.opaque=&trace_view,.clock_ns=host_clock,.process_id=1,.thread_id=2,
        .string_resource=host_string,.named_resource=host_named_resource,
        .code_address=host_code_address,.ansi_codepage=1252,.main_module_filename=commandline+1,
        .file_open=host_file_open,.file_close=host_file_close,.profile_int=host_profile_int};
    commandline[command_bytes-1]=0; /* service path excludes command-line quotes */
    PwImportBindReport binding;
    if(pw_import_bind32(&image,&mapped,pw_win32_resolve,&runtime,&binding_work,&binding)!=PW_OK)goto cleanup;
    printf("kind=host-import-bind total=%u functions=%u data=%u\n",binding.total,binding.functions,binding.data);
    if(pw_map_finalize_protections(&mapped,&layout,&vm)!=PW_OK)goto cleanup;
    state.memory[state.memory_count++]=(PwX86Memory){(uint32_t)mapped.actual_base,
        mapped.actual_base+layout.header_bytes,PW_X86_READ};
    for(unsigned i=0;i<layout.section_count;i++) {
        const PeLayoutSection *s=&layout.sections[i];
        state.memory[state.memory_count++]=(PwX86Memory){(uint32_t)mapped.actual_base+s->rva,
            mapped.actual_base+s->rva+s->mapped_bytes,
            ((s->protection&PW_PROT_READ)?PW_X86_READ:0)|
            ((s->protection&PW_PROT_WRITE)?PW_X86_WRITE:0)};
    }
    state.memory[state.memory_count++]=(PwX86Memory){0x03300000,0x03301000,PW_X86_READ|PW_X86_WRITE};
    state.memory[state.memory_count++]=(PwX86Memory){0x03400000,0x03c00000,PW_X86_READ|PW_X86_WRITE};
    state.stack_low=0x03000000;state.stack_high=0x03100000;
    state.gpr[4]=state.stack_high-4;state.fs_base=0x03200000;state.fs_bytes=4096;
    state.eflags=0x202;state.eip=(uint32_t)image.image_base+image.entry_point;
    *(uint32_t *)thread.write_base=0xffffffffu;
    if(pw_x86_engine_init(&engine,&vm,cache_entries,8192,4*1024*1024,1,
                          trace_source,&trace_view)!=PW_OK)goto cleanup;
    have_engine=1;
    unsigned steps=0,events=0;
    const char *stop="budget";
    for(;events<max_events;events++) {
        if(milestone && !milestone_seen && state.eip==milestone) {
            milestone_seen=1;printf("kind=host-pc-milestone pc=0x%08x\n",milestone);
        }
        int dispatched=pw_win32_dispatch(&runtime,&state);
        if(dispatched==PW_OK) {
            if(runtime.callback_pending)
                printf("kind=host-callback-enter dll=%s name=%s target=0x%08x depth=%u\n",runtime.last_dll,runtime.last_name,state.eip,runtime.init_depth);
            else printf("kind=host-api dll=%s name=%s result=0x%08x\n",runtime.last_dll,runtime.last_name,state.gpr[0]);
            continue;
        }
        if(dispatched!=PW_ERR_NOT_FOUND){
            uint32_t caller=0;
            if(state.gpr[4]>=state.stack_low && state.gpr[4]<=state.stack_high-4)
                memcpy(&caller,(const void *)(uintptr_t)state.gpr[4],sizeof(caller));
            printf("kind=host-api-stop dll=%s name=%s status=%d caller=0x%08x\n",
                   runtime.last_dll?runtime.last_dll:"unknown",
                   runtime.last_name?runtime.last_name:"unknown",dispatched,caller);
            stop=dispatched==PW_ERR_UNSUPPORTED?"unimplemented-api":"api-frame-error";break;
        }
        PwX86StepReport step;int status=pw_x86_engine_step(&engine,&state,&step);
        steps+=step.retired;
        if(status!=PW_OK) {
            stop=status==PW_ERR_UNSUPPORTED?"unsupported":
                 status==PW_ERR_X87_TRAP?"x87-trap":
                 status==PW_ERR_VM?"memory-bounds":
                 status==PW_ERR_LIMIT?"cache-limit":
                 status==PW_ERR_NOT_FOUND?"non-code":"decode-failure";
            break;
        }
    }
    printf("kind=host-entry-trace steps=%u stop=%s eip=0x%08x esp=0x%08x "
           "ebp=0x%08x fs0=0x%08x flags=0x%08x\n",steps,stop,state.eip,
           state.gpr[4],state.gpr[5],*(uint32_t *)thread.write_base,state.eflags);
    printf("kind=host-dbt-cache dispatches=%llu hits=%llu misses=%llu publishes=%llu "
           "retired=%llu code_bytes=%zu generation=%u\n",
           (unsigned long long)engine.dispatches,(unsigned long long)engine.cache.hits,
           (unsigned long long)engine.cache.misses,(unsigned long long)engine.cache.publishes,
           (unsigned long long)engine.retired_instructions,engine.cache.cursor,
           engine.cache.generation);
    if(milestone)printf("kind=host-pc-milestone-summary pc=0x%08x seen=%u\n",
                        milestone,milestone_seen);
    unsigned live=0;uint64_t requested=0;
    for(uint32_t i=0;i<heap.count;i++)if(heap.blocks[i].used){live++;requested+=heap.blocks[i].requested;}
    printf("kind=host-heap-summary blocks=%u live=%u requested=%llu arena=%u valid=%d\n",
           heap.count,live,(unsigned long long)requested,heap.bytes,pw_guest_heap_validate(&heap)==PW_OK);
    PwGdiCounts gdi_counts={0};int gdi_valid=pw_gdi_validate(&gdi)==PW_OK;
    (void)pw_gdi_counts(&gdi,&gdi_counts);
    printf("kind=host-gdi-summary dcs=%u window_dcs=%u memory_dcs=%u surfaces=%u "
           "targets=%u bitmaps=%u pixels=%llu valid=%d\n",gdi_counts.dcs,
           gdi_counts.window_dcs,gdi_counts.memory_dcs,gdi_counts.surfaces,
           gdi_counts.target_surfaces,gdi_counts.bitmaps,
           (unsigned long long)gdi_counts.pixel_bytes,gdi_valid);
    /* A classified stop is evidence, never a successful game startup. */
    result=2;
    if(pw_gdi_reset(&gdi)!=PW_OK || pw_gdi_counts(&gdi,&gdi_counts)!=PW_OK ||
       pw_gdi_validate(&gdi)!=PW_OK)result=1;
    else {
        have_gdi=0;
        printf("kind=host-gdi-cleanup dcs=%u surfaces=%u bitmaps=%u pixels=%llu valid=1\n",
               gdi_counts.dcs,gdi_counts.surfaces,gdi_counts.bitmaps,
               (unsigned long long)gdi_counts.pixel_bytes);
    }
cleanup:
    for(unsigned i=0;i<8;i++)if(trace_view.files[i]){fclose(trace_view.files[i]);trace_view.files[i]=NULL;}
    if(have_gdi && pw_gdi_reset(&gdi)!=PW_OK)result=1;
    if(have_engine && pw_x86_engine_destroy(&engine)!=PW_OK)result=1;
    if(have_heap && vm.release(NULL,&heap_region)!=PW_OK)result=1;
    if(have_crt && vm.release(NULL,&crt)!=PW_OK)result=1;
    if(have_image && pw_map_release(&mapped,&vm)!=PW_OK)result=1;
    if(have_thread && vm.release(NULL,&thread)!=PW_OK)result=1;
    if(have_stack && vm.release(NULL,&stack)!=PW_OK)result=1;
done:
    free(bytes);return result;
}
