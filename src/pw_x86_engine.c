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
    engine->quantum=PW_X86_ENGINE_DEFAULT_QUANTUM;
    engine->chaining_enabled=0;
    engine->initialized=1;return PW_OK;
}

int pw_x86_engine_set_quantum(PwX86Engine *engine, uint32_t quantum)
{
    if(!engine || !engine->initialized) return PW_ERR_PRECONDITION;
    engine->quantum = quantum;
    return PW_OK;
}

int pw_x86_engine_set_chaining(PwX86Engine *engine, unsigned enabled)
{
    if(!engine || !engine->initialized) return PW_ERR_PRECONDITION;
    engine->chaining_enabled = enabled;
    return PW_OK;
}

static int compile(PwX86Engine *engine,uint32_t pc,const PwX86CacheEntry **entry)
{
    const uint8_t *source=NULL;size_t available=0;
    int status=engine->source_view(engine->source_opaque,pc,&source,&available);
    if(status!=PW_OK)return status;
    if(!source || !available)return PW_ERR_NOT_FOUND;
    if(available>PW_X86_ENGINE_MAX_SOURCE)available=PW_X86_ENGINE_MAX_SOURCE;
    uint8_t scratch[PW_X86_ENGINE_MAX_CODE];
    PwX86Block best = {0};
    int last = pw_x86_translate(source, available, pc, scratch, sizeof(scratch), &best);
    if (last != PW_OK) return last;
    if (!best.instructions) return PW_ERR_TRUNCATED;
    if(best.code_bytes>engine->cache.arena_bytes-engine->cache.cursor)return PW_ERR_LIMIT;

    /* If chaining is enabled and exit is chainable, patch link slot addresses in scratch */
    if(best.exit.chainable && engine->chaining_enabled) {
        uint32_t hash=pc*2654435761u;hash^=hash>>16;
        uint32_t slot=hash%engine->cache.capacity;
        PwX86CacheEntry *cand = NULL;
        for(uint32_t probe=0; probe<engine->cache.capacity; probe++) {
            PwX86CacheEntry *c=&engine->cache.entries[slot];
            if(!c->used || (c->generation==engine->cache.generation && c->guest_pc==pc)) {
                cand = c;
                break;
            }
            slot=(slot+1)%engine->cache.capacity;
        }
        if(cand) {
            uintptr_t taken_slot = (uintptr_t)&cand->link_slots[0].target_code;
            memcpy(scratch + best.exit.target_patch_offset, &taken_slot, sizeof(taken_slot));
            if(best.exit.kind == PW_X86_EXIT_CONDITIONAL) {
                uintptr_t fallthrough_slot = (uintptr_t)&cand->link_slots[1].target_code;
                memcpy(scratch + best.exit.fallthrough_patch_offset, &fallthrough_slot, sizeof(fallthrough_slot));
            }
        }
    }

    size_t page=engine->backend->page_bytes;
    size_t first=(engine->cache.cursor/page)*page;
    size_t tail=engine->cache.cursor+best.code_bytes;
    size_t end=((tail+page-1)/page)*page;
    if(end>engine->code.bytes)end=engine->code.bytes;
    if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_WRITE)!=PW_OK)
        return PW_ERR_VM;
    memcpy((uint8_t *)engine->code.write_base+engine->cache.cursor,scratch,best.code_bytes);
    status=pw_x86_cache_publish(&engine->cache,pc,&best,engine->cache.cursor,entry);
    if(status!=PW_OK) {
        if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_EXEC)!=PW_OK)
            engine->failed=1;
        return status;
    }
    if(protection(engine,first,end-first,PW_PROT_READ|PW_PROT_EXEC)!=PW_OK) {
        engine->failed=1;return PW_ERR_VM;
    }

    /* Initialize link slot stubs */
    PwX86CacheEntry *e_mut = (PwX86CacheEntry *)*entry;
    uint8_t *exec_base = (uint8_t *)engine->code.exec_base;
    if(best.exit.chainable) {
        e_mut->link_slots[0].target_code = exec_base + e_mut->code_offset + best.exit.target_stub_offset;
        e_mut->link_slots[0].target_pc = best.exit.target_pc;
        e_mut->link_slots[0].source_pc = pc;
        e_mut->link_slots[0].is_linked = 0;
        if(best.exit.kind == PW_X86_EXIT_CONDITIONAL) {
            e_mut->link_slots[1].target_code = exec_base + e_mut->code_offset + best.exit.fallthrough_stub_offset;
            e_mut->link_slots[1].target_pc = best.exit.fallthrough_pc;
            e_mut->link_slots[1].source_pc = pc;
            e_mut->link_slots[1].is_linked = 0;
        }

        /* Forward link: connect newly published exits to targets already in cache */
        if(engine->chaining_enabled) {
            PwX86CacheEntry *tgt = NULL;
            if(pw_x86_cache_lookup_mut(&engine->cache, best.exit.target_pc, &tgt) == PW_OK) {
                engine->attempted_links++;
                e_mut->link_slots[0].target_code = exec_base + tgt->code_offset;
                e_mut->link_slots[0].is_linked = 1;
                engine->successful_links++;
            }
            if(best.exit.kind == PW_X86_EXIT_CONDITIONAL) {
                if(pw_x86_cache_lookup_mut(&engine->cache, best.exit.fallthrough_pc, &tgt) == PW_OK) {
                    engine->attempted_links++;
                    e_mut->link_slots[1].target_code = exec_base + tgt->code_offset;
                    e_mut->link_slots[1].is_linked = 1;
                    engine->successful_links++;
                }
            }
        }
    }

    /* Backward link: connect existing unlinked exits targeting this PC */
    if(engine->chaining_enabled) {
        for(uint32_t i=0; i<engine->cache.capacity; i++) {
            PwX86CacheEntry *cand = &engine->cache.entries[i];
            if(cand->used && cand->generation == engine->cache.generation && cand->exit.chainable) {
                if(cand->link_slots[0].target_pc == pc && !cand->link_slots[0].is_linked) {
                    engine->attempted_links++;
                    cand->link_slots[0].target_code = exec_base + e_mut->code_offset;
                    cand->link_slots[0].is_linked = 1;
                    engine->successful_links++;
                }
                if(cand->exit.kind == PW_X86_EXIT_CONDITIONAL &&
                   cand->link_slots[1].target_pc == pc && !cand->link_slots[1].is_linked) {
                    engine->attempted_links++;
                    cand->link_slots[1].target_code = exec_base + e_mut->code_offset;
                    cand->link_slots[1].is_linked = 1;
                    engine->successful_links++;
                }
            }
        }
    }

    engine->compiles++;return PW_OK;
}

int pw_x86_engine_step(PwX86Engine *engine,PwX86State *state,PwX86StepReport *report)
{
    if(!engine || !engine->initialized || !state || !report)return PW_ERR_PRECONDITION;
    *report=(PwX86StepReport){.guest_pc=state->eip};
    if(engine->failed)return PW_ERR_STATE;

    /* Handle pending unlinked exit from previous step */
    if(engine->chaining_enabled && state->last_exit_slot) {
        PwX86LinkSlot *last_slot = (PwX86LinkSlot *)state->last_exit_slot;
        state->last_exit_slot = 0;
        if(last_slot->target_pc == state->eip && !last_slot->is_linked) {
            PwX86CacheEntry *target_entry = NULL;
            if(pw_x86_cache_lookup_mut(&engine->cache, state->eip, &target_entry) == PW_OK) {
                engine->attempted_links++;
                last_slot->target_code = (uint8_t *)engine->code.exec_base + target_entry->code_offset;
                last_slot->is_linked = 1;
                engine->successful_links++;
            }
        }
    }

    const PwX86CacheEntry *entry=NULL;
    int status=pw_x86_cache_lookup(&engine->cache,state->eip,&entry);
    if(status==PW_OK)report->cache_hit=1;
    else if(status==PW_ERR_NOT_FOUND) {
        status=compile(engine,state->eip,&entry);
        if(status!=PW_OK)return status;
    } else return status;

    report->instructions=entry->instructions;report->source_bytes=entry->source_bytes;
    report->code_bytes=entry->code_bytes;engine->dispatches++;

    state->chain_budget = (engine->chaining_enabled && engine->quantum) ? engine->quantum : 1;
    state->step_retired = 0;
    state->step_transitions = 0;
    state->last_exit_slot = 0;

    int invoked=invoke((uint8_t *)engine->code.exec_base+entry->code_offset,state);

    engine->linked_transitions += state->step_transitions;

    if(!invoked) {
        report->retired=state->step_retired;
        if(state->chain_budget == 0) engine->safepoint_returns++;
        else engine->dispatcher_transitions++;
    } else {
        uint32_t intra = 0;
        if(state->eip>=entry->guest_pc &&
           (uint64_t)state->eip<=entry->guest_pc+entry->source_bytes) {
            uint32_t offset=state->eip-entry->guest_pc;
            while(intra<entry->instructions &&
                  entry->instruction_ends[intra]<=offset) intra++;
        }
        report->retired=state->step_retired + intra;
        engine->dispatcher_transitions++;
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

    /* Count unlinks before cache entries are zeroed */
    for(uint32_t i=0; i<engine->cache.capacity; i++) {
        if(engine->cache.entries[i].used) {
            if(engine->cache.entries[i].link_slots[0].is_linked) engine->unlinks++;
            if(engine->cache.entries[i].link_slots[1].is_linked) engine->unlinks++;
        }
    }

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
