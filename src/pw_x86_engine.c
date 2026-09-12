/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_x86_engine.h"
#include <string.h>

#if defined(__clang__)
__attribute__((no_sanitize("function")))
#endif
static int invoke(void *entry,PwX86State *state)
{
    return ((int (*)(PwX86State *))entry)(state);
}

static int protection(PwX86Engine *engine,size_t offset,size_t bytes,unsigned value)
{
    int status=engine->backend->protect(engine->backend->context,&engine->code,
                                        offset,bytes,value);
    if(status==PW_OK) {
        engine->protection_calls++;engine->protection_bytes+=bytes;
        engine->sealed=value==(PW_PROT_READ|PW_PROT_EXEC);
    }
    return status;
}

int pw_x86_engine_init(PwX86Engine *engine,const PwVmBackend *backend,
                       PwX86CacheEntry *entries,uint32_t capacity,size_t arena_bytes,
                       uint32_t generation,PwX86SourceView source_view,void *opaque)
{
    if(!engine || !backend || !entries || !capacity || !arena_bytes || !generation ||
       !source_view || !pw_vm_backend_valid(backend) ||
       !(backend->capabilities&PW_VM_CAP_PROTECT))return PW_ERR_PRECONDITION;
    memset(engine,0,sizeof(*engine));
    int status=backend->reserve(backend->context,arena_bytes,backend->page_bytes,&engine->code);
    if(status!=PW_OK)return status;
    status=backend->commit(backend->context,&engine->code,0,engine->code.bytes,
                           PW_PROT_READ|PW_PROT_WRITE);
    if(status!=PW_OK){(void)backend->release(backend->context,&engine->code);return status;}
    status=pw_x86_cache_init(&engine->cache,entries,capacity,engine->code.bytes,generation);
    if(status!=PW_OK){(void)backend->release(backend->context,&engine->code);return status;}
    engine->backend=backend;engine->source_view=source_view;engine->source_opaque=opaque;
    engine->initialized=1;return PW_OK;
}

static int compile(PwX86Engine *engine,uint32_t pc,const PwX86CacheEntry **entry)
{
    const uint8_t *source=NULL;size_t available=0;
    int status=engine->source_view(engine->source_opaque,pc,&source,&available);
    if(status!=PW_OK)return status;
    if(!source || !available)return PW_ERR_NOT_FOUND;
    if(available>PW_X86_ENGINE_MAX_SOURCE)available=PW_X86_ENGINE_MAX_SOURCE;
    uint8_t scratch[PW_X86_ENGINE_MAX_CODE],best_code[PW_X86_ENGINE_MAX_CODE];
    PwX86Block candidate,best={0};int last=PW_ERR_TRUNCATED;
    for(size_t bytes=1;bytes<=available;bytes++) {
        last=pw_x86_translate(source,bytes,pc,scratch,sizeof(scratch),&candidate);
        if(last==PW_OK) {
            best=candidate;memcpy(best_code,scratch,best.code_bytes);
            if(candidate.instructions==32 || candidate.source_bytes<bytes)break;
            continue;
        }
        if(last==PW_ERR_TRUNCATED)continue;
        if(best.instructions)break;
        return last;
    }
    if(!best.instructions)return last==PW_ERR_TRUNCATED?PW_ERR_TRUNCATED:last;
    if(best.code_bytes>engine->cache.arena_bytes-engine->cache.cursor)return PW_ERR_LIMIT;
    size_t page=engine->backend->page_bytes;
    size_t first=(engine->cache.cursor/page)*page;
    size_t tail=engine->cache.cursor+best.code_bytes;
    size_t end=((tail+page-1)/page)*page;
    if(end>engine->code.bytes)end=engine->code.bytes;
    if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK)
        return PW_ERR_VM;
    memcpy((uint8_t *)engine->code.write_base+engine->cache.cursor,best_code,best.code_bytes);
    status=pw_x86_cache_publish(&engine->cache,pc,&best,engine->cache.cursor,entry);
    if(status!=PW_OK) {
        if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_EXEC)!=PW_OK)
            engine->failed=1;
        return status;
    }
    if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_EXEC)!=PW_OK) {
        engine->failed=1;return PW_ERR_VM;
    }
    engine->compiles++;return PW_OK;
}

int pw_x86_engine_step(PwX86Engine *engine,PwX86State *state,PwX86StepReport *report)
{
    if(!engine || !engine->initialized || !state || !report)return PW_ERR_PRECONDITION;
    *report=(PwX86StepReport){.guest_pc=state->eip};
    if(engine->failed)return PW_ERR_STATE;
    const PwX86CacheEntry *entry=NULL;
    int status=pw_x86_cache_lookup(&engine->cache,state->eip,&entry);
    if(status==PW_OK)report->cache_hit=1;
    else if(status==PW_ERR_NOT_FOUND) {
        status=compile(engine,state->eip,&entry);
        if(status!=PW_OK)return status;
    } else return status;
    report->instructions=entry->instructions;report->source_bytes=entry->source_bytes;
    report->code_bytes=entry->code_bytes;engine->dispatches++;
    int invoked=invoke((uint8_t *)engine->code.exec_base+entry->code_offset,state);
    if(!invoked)report->retired=entry->instructions;
    else if(state->eip>=entry->guest_pc &&
            (uint64_t)state->eip<=entry->guest_pc+entry->source_bytes) {
        uint32_t offset=state->eip-entry->guest_pc;
        while(report->retired<entry->instructions &&
              entry->instruction_ends[report->retired]<=offset)report->retired++;
    }
    engine->retired_instructions+=report->retired;
    return invoked==PW_ERR_X87_TRAP?PW_ERR_X87_TRAP:invoked?PW_ERR_VM:PW_OK;
}

int pw_x86_engine_reset(PwX86Engine *engine,uint32_t generation)
{
    if(!engine || !engine->initialized)return PW_ERR_PRECONDITION;
    unsigned was_sealed=engine->sealed;
    if((engine->sealed || engine->failed) &&
       protection(engine,0,engine->code.bytes,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK)
        return PW_ERR_VM;
    int status=pw_x86_cache_reset(&engine->cache,generation);
    if(status!=PW_OK) {
        if(was_sealed && protection(engine,0,engine->code.bytes,
                                    PW_PROT_READ|PW_PROT_EXEC)!=PW_OK)
            engine->failed=1;
        return status;
    }
    memset(engine->code.write_base,0xcc,engine->code.bytes);
    engine->dispatches=0;engine->retired_instructions=0;engine->failed=0;return PW_OK;
}

int pw_x86_engine_destroy(PwX86Engine *engine)
{
    if(!engine || !engine->initialized || !engine->backend)return PW_ERR_PRECONDITION;
    int status=engine->backend->release(engine->backend->context,&engine->code);
    if(status==PW_OK)memset(engine,0,sizeof(*engine));
    return status;
}
