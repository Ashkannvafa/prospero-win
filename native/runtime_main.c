/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Native PE32 runtime entry. The Windows image remains private staged input;
 * this executable supplies only independently implemented ABI services. */
#include "../src/pe_image.h"
#include "../src/pe_resource.h"
#include "../src/pw_map.h"
#include "../src/pw_x86_engine.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_win32.h"
#include "pw_audio_ps5.h"
#include "pw_file_ps5.h"
#include "pw_videoout_ps5.h"
#include "ps5log/ps5log.h"
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
#define PW_TITLE_ID "PPSA99995"
#define PW_APP_NAME "prospero-win"
#ifndef PW_STAGE_DIR
#define PW_STAGE_DIR "/app0/win"
#endif
#ifndef PW_ROOT_MODULE
#define PW_ROOT_MODULE "pinball.exe"
#endif

typedef struct NativeServices {
    const PeImage *image;
    const PeLayout *layout;
    PwFilePs5 *files;
    PwAudioPs5 *audio;
    PwUser32 *user32;
    uint64_t waits;
} NativeServices;

static void *scratch(size_t bytes)
{
    void *result=mmap(NULL,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    return result==MAP_FAILED?NULL:result;
}
static uint64_t now_ns(void)
{
    struct timespec value;if(clock_gettime(CLOCK_MONOTONIC,&value))return 0;
    return (uint64_t)value.tv_sec*1000000000ull+(uint64_t)value.tv_nsec;
}
static void fatal_signal(int number,siginfo_t *info,void *context)
{
    const ucontext_t *uc=context;
    PS5LOG_LOG("PW_RUNTIME_SIGNAL sig=%d code=%d addr=%p pc=%p rax=%p rsp=%p",
        number,info?info->si_code:0,info?info->si_addr:NULL,
        uc?(void *)(uintptr_t)uc->uc_mcontext.mc_rip:NULL,
        uc?(void *)(uintptr_t)uc->uc_mcontext.mc_rax:NULL,
        uc?(void *)(uintptr_t)uc->uc_mcontext.mc_rsp:NULL);
    ps5log_close("runtime-signal");_exit(1);
}
static void install_signals(void)
{
    static const int values[]={SIGSEGV,SIGBUS,SIGILL,SIGFPE,SIGABRT,SIGTRAP,SIGSYS};
    struct sigaction action;memset(&action,0,sizeof(action));
    action.sa_sigaction=fatal_signal;action.sa_flags=SA_SIGINFO|SA_RESETHAND;
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++)
        (void)sigaction(values[i],&action,NULL);
}
static int source_view(void *opaque,uint32_t pc,const uint8_t **source,size_t *bytes)
{
    const NativeServices *services=opaque;const PeImage *image=services->image;
    if(pc<image->image_base)return PW_ERR_NOT_FOUND;
    uint32_t rva=pc-(uint32_t)image->image_base;
    for(unsigned i=0;i<services->layout->section_count;i++) {
        const PeLayoutSection *section=&services->layout->sections[i];
        uint64_t end=(uint64_t)section->rva+section->mapped_bytes;
        if((section->protection&PW_PROT_EXEC) && rva>=section->rva && rva<end) {
            *source=(const uint8_t *)(uintptr_t)pc;*bytes=(size_t)(end-rva);return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}
static int string_resource(void *opaque,uint32_t module,uint32_t id,
                           const uint8_t **text,size_t *units)
{
    const NativeServices *s=opaque;
    if(module && module!=s->image->image_base)return PW_ERR_UNSUPPORTED;
    return pe_resource_string(s->image,id,0x409,text,units);
}
static int named_resource(void *opaque,uint32_t module,uint32_t type,const char *name,
                          const uint8_t **bytes,size_t *size)
{
    const NativeServices *s=opaque;PeResource resource;
    if(module!=s->image->image_base)return PW_ERR_UNSUPPORTED;
    int status=pe_resource_find_name(s->image,type,name,0x409,&resource);
    if(status==PW_OK){*bytes=resource.bytes;*size=resource.size;}return status;
}
static int integer_resource(void *opaque,uint32_t module,uint32_t type,uint32_t name,
                            const uint8_t **bytes,size_t *size)
{
    const NativeServices *s=opaque;PeResource resource;
    if(module!=s->image->image_base)return PW_ERR_UNSUPPORTED;
    int status=pe_resource_find(s->image,type,name,0x409,&resource);
    if(status==PW_OK){*bytes=resource.bytes;*size=resource.size;}return status;
}
static int code_address(void *opaque,uint32_t address)
{
    const uint8_t *source;size_t bytes;return source_view(opaque,address,&source,&bytes);
}
static int clock_ns(void *opaque,PwClockDomain domain,uint64_t *value)
{
    (void)opaque;clockid_t id=domain==PW_CLOCK_UTC?CLOCK_REALTIME:CLOCK_MONOTONIC;
    if(domain!=PW_CLOCK_UTC && domain!=PW_CLOCK_UPTIME && domain!=PW_CLOCK_COUNTER)
        return PW_ERR_UNSUPPORTED;
    struct timespec now;if(clock_gettime(id,&now))return PW_ERR_STATE;
    *value=(uint64_t)now.tv_sec*1000000000ull+(uint64_t)now.tv_nsec;return PW_OK;
}
static int file_open(void *opaque,const char *path,const char *mode,uint32_t *handle)
{return pw_file_ps5_stream_open(((NativeServices *)opaque)->files,path,mode,handle);}
static int file_close(void *opaque,uint32_t handle)
{return pw_file_ps5_stream_close(((NativeServices *)opaque)->files,handle);}
static int file_read(void *opaque,uint32_t handle,void *output,uint32_t bytes,uint32_t *got)
{return pw_file_ps5_stream_read(((NativeServices *)opaque)->files,handle,output,bytes,got);}
static int file_seek(void *opaque,uint32_t handle,int32_t offset,uint32_t origin,uint32_t *position)
{return pw_file_ps5_stream_seek(((NativeServices *)opaque)->files,handle,offset,origin,position);}
static int profile_int(void *opaque,const char *section,const char *key,uint32_t fallback,
                       const char *filename,uint32_t *value)
{
    (void)opaque;(void)section;(void)key;(void)filename;
    if(!value)return PW_ERR_PRECONDITION;*value=fallback;return PW_OK;
}
static int message_wait(void *opaque,uint32_t window,PwUser32QueueEntry *message)
{
    NativeServices *services=opaque;if(!window || !message)return PW_ERR_PRECONDITION;
    (void)usleep(16667);uint64_t phase=services->waits++;
    *message=(PwUser32QueueEntry){.window=window};
    if(phase==0) {
        /* A shown top-level window gains focus on Win32.  Deliver that
         * lifecycle transition before deterministic demo commands so the
         * original title enters its active simulation loop. */
        message->message=0x0007; /* WM_SETFOCUS */
        PwUser32QueueEntry new_game={.window=window,.message=0x0111,.wparam=101};
        PwUser32QueueEntry launch_ball={.window=window,.message=0x0111,.wparam=401};
        PwUser32QueueEntry plunger_down={.window=window,.message=0x0100,.wparam=0x20};
        PwUser32QueueEntry plunger_up={.window=window,.message=0x0101,.wparam=0x20};
        PwUser32QueueEntry left_down={.window=window,.message=0x0100,.wparam=0x5a};
        PwUser32QueueEntry left_up={.window=window,.message=0x0101,.wparam=0x5a};
        PwUser32QueueEntry right_down={.window=window,.message=0x0100,.wparam=0xbf};
        PwUser32QueueEntry right_up={.window=window,.message=0x0101,.wparam=0xbf};
        int status=pw_user32_post_message(services->user32,&new_game);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&launch_ball);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&left_down);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&left_up);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&right_down);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&right_up);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&plunger_down);
        if(status==PW_OK)status=pw_user32_post_message(services->user32,&plunger_up);
        if(status!=PW_OK)return status;
    }
    return PW_OK;
}
static int sleep_ms(void *opaque,uint32_t milliseconds)
{
    (void)opaque;
    while(milliseconds) {
        uint32_t chunk=milliseconds>1000?1000:milliseconds;
        if(usleep(chunk*1000u) && errno!=EINTR)return PW_ERR_STATE;
        milliseconds-=chunk;
    }
    return PW_OK;
}
static int audio_open(void *opaque,uint32_t rate,uint16_t channels,uint16_t bits)
{
    int status=pw_audio_ps5_open(((NativeServices *)opaque)->audio,rate,channels,bits);
    PS5LOG_LOG("PW_AUDIO_OPEN status=%s rate=%u channels=%u bits=%u",
               pw_result_name(status),rate,channels,bits);return status;
}
static int audio_submit(void *opaque,const void *pcm,uint32_t bytes)
{
    NativeServices *services=opaque;uint64_t before=services->audio->blocks;
    int status=pw_audio_ps5_submit(services->audio,pcm,bytes);
    if(status==PW_OK && services->audio->blocks!=before &&
       (!before || before/120!=services->audio->blocks/120))
        PS5LOG_LOG("PW_AUDIO_PCM input_bytes=%llu output_frames=%llu blocks=%llu hash=0x%08x",
            (unsigned long long)services->audio->input_bytes,
            (unsigned long long)services->audio->output_frames,
            (unsigned long long)services->audio->blocks,services->audio->input_hash);
    return status;
}
static int audio_control(void *opaque,PwAudioControl control)
{return pw_audio_ps5_control(((NativeServices *)opaque)->audio,control);}

static void abort_runtime(const char *stage,int status)
{
    PS5LOG_LOG("PW_RUNTIME_ABORT stage=%s status=%s",stage,pw_result_name(status));
    ps5log_close(stage);_exit(1);
}

int main(int argc,char **argv)
{
    (void)argc;(void)argv;ps5log_config config;const char *config_path=NULL;
    ps5log_config_defaults(&config);int config_rc=ps5log_load_config(ps5log_default_conf_paths,
        ps5log_default_conf_path_count,&config,&config_path);
    int log_rc=config_rc==0?ps5log_init(&config,PW_TITLE_ID,PW_APP_NAME,now_ns()):config_rc;
    install_signals();PS5LOG_LOG("PW_RUNTIME_BEGIN schema=1 title=%s root=%s config=%d log=%d",
        PW_TITLE_ID,PW_ROOT_MODULE,config_rc,log_rc);

    PwFilePs5 *files=scratch(sizeof(*files));PwFileProvider provider;PwFileSpan root={0};
    if(!files)abort_runtime("files-scratch",PW_ERR_VM);
    int status=pw_file_ps5_init(files,PW_STAGE_DIR);if(status!=PW_OK)abort_runtime("files",status);
    (void)pw_file_ps5_provider(files,&provider);
    status=provider.open(provider.context,PW_ROOT_MODULE,&root);if(status!=PW_OK)abort_runtime("root",status);
    PeImage image;if((status=pe_image_parse(&image,root.bytes,root.size))!=PW_OK ||
       image.machine!=PE_MACHINE_I386)abort_runtime("pe32",status);

    PwVmBackend vm;PwVmRegion stack={0},thread={0},crt={0},heap_region={0};
    if((status=pw_vm_posix_backend(&vm))!=PW_OK)abort_runtime("vm",status);
    if((status=vm.reserve_at(NULL,0x03000000,0x100000,4096,&stack))!=PW_OK ||
       (status=vm.reserve_at(NULL,0x03200000,4096,4096,&thread))!=PW_OK ||
       (status=vm.reserve_at(NULL,0x03300000,4096,4096,&crt))!=PW_OK ||
       (status=vm.reserve_at(NULL,0x03400000,0x4000000,4096,&heap_region))!=PW_OK)
        abort_runtime("guest-reserve",status);
    if((status=vm.commit(NULL,&stack,0,stack.bytes,PW_PROT_READ|PW_PROT_WRITE))!=PW_OK ||
       (status=vm.commit(NULL,&thread,0,thread.bytes,PW_PROT_READ|PW_PROT_WRITE))!=PW_OK ||
       (status=vm.commit(NULL,&crt,0,crt.bytes,PW_PROT_READ|PW_PROT_WRITE))!=PW_OK ||
       (status=vm.commit(NULL,&heap_region,0,heap_region.bytes,PW_PROT_READ|PW_PROT_WRITE))!=PW_OK)
        abort_runtime("guest-commit",status);

    PeLayout layout;PwMappedImage mapped={0};PwMapVerify verify;
    if((status=pe_layout_plan(&layout,&image))!=PW_OK ||
       (status=pw_map_image(&mapped,&image,&layout,&vm))!=PW_OK ||
       (status=pw_map_verify(&mapped,&image,&layout,&verify))!=PW_OK ||
       mapped.actual_base!=image.image_base || verify.raw_mismatches ||
       verify.zero_tail_violations || verify.alias_mismatches)
        abort_runtime("image-map",status);

    PwHeapBlock *heap_blocks=scratch(131072u*sizeof(*heap_blocks));
    PwRegistryKey *registry_keys=scratch(32u*sizeof(*registry_keys));
    PwRegistryValue *registry_values=scratch(128u*sizeof(*registry_values));
    PwUser32Message *messages=scratch(128u*sizeof(*messages));
    PwUser32Window *windows=scratch(128u*sizeof(*windows));
    PwUser32Resource *resources=scratch(128u*sizeof(*resources));
    PwUser32Class *classes=scratch(128u*sizeof(*classes));
    PwGdiDc *dcs=scratch(128u*sizeof(*dcs));PwGdiSurface *surfaces=scratch(128u*sizeof(*surfaces));
    uint8_t *pixels=scratch(32u*1024u*1024u);
    PwX86CacheEntry *cache=scratch(8192u*sizeof(*cache));
    if(!heap_blocks||!registry_keys||!registry_values||!messages||!windows||!resources||
       !classes||!dcs||!surfaces||!pixels||!cache)abort_runtime("runtime-scratch",PW_ERR_VM);
    PwGuestHeap heap;PwRegistry registry;PwUser32 user32;PwGdi gdi;
    if((status=pw_guest_heap_init(&heap,0x03400000,0x4000000,heap_blocks,131072))!=PW_OK ||
       (status=pw_registry_init(&registry,registry_keys,32,registry_values,128))!=PW_OK ||
       (status=pw_user32_init(&user32,messages,128,windows,128))!=PW_OK ||
       (status=pw_user32_init_resources(&user32,resources,128))!=PW_OK ||
       (status=pw_user32_init_classes(&user32,classes,128))!=PW_OK ||
       (status=pw_user32_configure_desktop(&user32,1920,1080))!=PW_OK ||
       (status=pw_gdi_init(&gdi,dcs,128,surfaces,128,pixels,32u*1024u*1024u))!=PW_OK)
        abort_runtime("win32-state",status);

    PwAudioPs5 audio;PwAudioPs5Ops audio_ops;
    if((status=pw_audio_ps5_platform_ops(&audio_ops))!=PW_OK ||
       (status=pw_audio_ps5_init(&audio,&audio_ops))!=PW_OK)abort_runtime("audio",status);
    NativeServices services={.image=&image,.layout=&layout,.files=files,.audio=&audio,
        .user32=&user32};
    PwWin32 runtime;char commandline[64]="\"C:\\game\\" PW_ROOT_MODULE "\"";
    if((status=pw_win32_init(&runtime,(uint32_t)mapped.actual_base,0x03300000,commandline))!=PW_OK)
        abort_runtime("win32-init",status);
    runtime.heap=&heap;runtime.registry=&registry;runtime.user32=&user32;runtime.gdi=&gdi;
    runtime.services=(PwWin32Services){.opaque=&services,.clock_ns=clock_ns,
        .process_id=1,.thread_id=2,.string_resource=string_resource,
        .named_resource=named_resource,.integer_resource=integer_resource,
        .code_address=code_address,.ansi_codepage=1252,
        .main_module_filename="C:\\game\\" PW_ROOT_MODULE,
        .file_open=file_open,.file_close=file_close,.file_read=file_read,.file_seek=file_seek,
        .profile_int=profile_int,.message_wait=message_wait,.sleep_ms=sleep_ms,.audio_open=audio_open,
        .audio_submit=audio_submit,.audio_control=audio_control};
    PwImportBindWorkspace *workspace=scratch(sizeof(*workspace));PwImportBindReport binding;
    if(!workspace || (status=pw_import_bind32(&image,&mapped,pw_win32_resolve,&runtime,
       workspace,&binding))!=PW_OK)abort_runtime("imports",status);
    if((status=pw_map_finalize_protections(&mapped,&layout,&vm))!=PW_OK)
        abort_runtime("protect",status);

    PwX86State state;memset(&state,0,sizeof(state));pw_guest_fp_init(&state.fp);
    state.memory[state.memory_count++]=(PwX86Memory){(uint32_t)mapped.actual_base,
        mapped.actual_base+layout.header_bytes,PW_X86_READ};
    for(unsigned i=0;i<layout.section_count;i++) {
        const PeLayoutSection *section=&layout.sections[i];
        state.memory[state.memory_count++]=(PwX86Memory){(uint32_t)mapped.actual_base+section->rva,
            mapped.actual_base+section->rva+section->mapped_bytes,
            ((section->protection&PW_PROT_READ)?PW_X86_READ:0)|
            ((section->protection&PW_PROT_WRITE)?PW_X86_WRITE:0)};
    }
    state.memory[state.memory_count++]=(PwX86Memory){0x03300000,0x03301000,PW_X86_READ|PW_X86_WRITE};
    state.memory[state.memory_count++]=(PwX86Memory){0x03400000,0x07400000,PW_X86_READ|PW_X86_WRITE};
    state.stack_low=0x03000000;state.stack_high=0x03100000;state.gpr[4]=state.stack_high-4;
    state.fs_base=0x03200000;state.fs_bytes=4096;state.eflags=0x202;
    state.eip=(uint32_t)image.image_base+image.entry_point;*(uint32_t *)thread.write_base=0xffffffffu;
    PwX86Engine engine={0};
    if((status=pw_x86_engine_init(&engine,&vm,cache,8192,4u*1024u*1024u,1,
                                  source_view,&services))!=PW_OK)abort_runtime("dbt",status);
    PwVideoOutPs5 video;
    if((status=pw_videoout_ps5_open(&video))!=PW_OK)abort_runtime("videoout",status);
    PS5LOG_LOG("PW_RUNTIME_READY imports=%u entry=0x%08x image_bytes=%u",
               binding.total,state.eip,image.size_of_image);
    uint64_t events=0,last_heartbeat=now_ns(),last_present=0;uint32_t last_frame_hash=0;
    for(;;events++) {
        status=pw_win32_dispatch(&runtime,&state);
        if(status==PW_ERR_NOT_FOUND) {
            PwX86StepReport report;status=pw_x86_engine_step(&engine,&state,&report);
        }
        if(status!=PW_OK)abort_runtime("execute",status);
        uint64_t now=now_ns();
        if(now-last_present>=33333333ull) {
            PwGdiTargetView best={0};
            for(unsigned i=0;i<128;i++)if(windows[i].used) {
                PwGdiTargetView candidate;
                if(pw_gdi_target_view(&gdi,windows[i].handle,&candidate)==PW_OK &&
                   candidate.width*candidate.height>best.width*best.height)best=candidate;
            }
            if(best.pixels && best.width>=600 && best.height>=400) {
                uint32_t hash=2166136261u;
                for(uint32_t y=0;y<best.height;y++) {
                    const uint8_t *row=best.pixels+(size_t)y*best.stride;
                    for(uint32_t x=0;x<best.width*4u;x++){hash^=row[x];hash*=16777619u;}
                }
                if(hash!=last_frame_hash) {
                    if((status=pw_videoout_ps5_present(&video,&best))!=PW_OK)
                        abort_runtime("present",status);
                    last_frame_hash=hash;
                    if(video.flips==1 || !(video.flips%120))
                        PS5LOG_LOG("PW_VIDEO_FRAME flips=%llu width=%u height=%u hash=0x%08x backend=agc-dma submits=%llu fence=zero",
                            (unsigned long long)video.flips,best.width,best.height,hash,
                            (unsigned long long)video.agc.submits);
                }
            }
            last_present=now;
        }
        if(now-last_heartbeat>=5000000000ull) {
            PwGdiCounts counts;PwGdiTargetView view;unsigned presented=0,window_count=0;
            (void)pw_gdi_counts(&gdi,&counts);
            for(unsigned i=0;i<128;i++)if(windows[i].used) {
                window_count++;
                if(pw_gdi_target_view(&gdi,windows[i].handle,&view)==PW_OK && view.width>=600)
                    presented=1;
            }
            PS5LOG_LOG("PW_RUNTIME_HEARTBEAT events=%llu retired=%llu calls=%u waits=%llu "
                "windows=%u targets=%u visible_source=%u flips=%llu audio_blocks=%llu "
                "audio_bytes=%llu audio_frames=%llu audio_hash=0x%08x",
                (unsigned long long)events,(unsigned long long)engine.retired_instructions,
                runtime.calls,(unsigned long long)services.waits,window_count,
                counts.target_surfaces,presented,(unsigned long long)video.flips,
                (unsigned long long)audio.blocks,(unsigned long long)audio.input_bytes,
                (unsigned long long)audio.output_frames,audio.input_hash);
            last_heartbeat=now;
        }
    }
}
