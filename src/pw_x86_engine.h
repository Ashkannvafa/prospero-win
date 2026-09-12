/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_X86_ENGINE_H
#define PW_X86_ENGINE_H
#include "pw_x86_cache.h"
#include "../include/prospero_win_vm.h"

enum { PW_X86_ENGINE_MAX_SOURCE=15*32, PW_X86_ENGINE_MAX_CODE=16384 };

/* Return one immutable executable source span beginning at guest_pc. The span
 * remains alive and unchanged for the engine generation. */
typedef int (*PwX86SourceView)(void *opaque,uint32_t guest_pc,
                               const uint8_t **source,size_t *bytes);

typedef struct PwX86StepReport {
    uint32_t guest_pc;
    uint32_t instructions,retired;
    size_t source_bytes,code_bytes;
    unsigned cache_hit;
} PwX86StepReport;

typedef struct PwX86Engine {
    const PwVmBackend *backend;
    PwVmRegion code;
    PwX86Cache cache;
    PwX86SourceView source_view;
    void *source_opaque;
    uint64_t dispatches,retired_instructions,compiles;
    uint64_t protection_calls,protection_bytes;
    unsigned sealed,failed,initialized;
} PwX86Engine;

/* The engine owns its code region but not entries or source memory. It is a
 * single-dispatcher object: reset/destroy require no executing block. Code
 * publication changes protection only on pages touched by the new block. */
int pw_x86_engine_init(PwX86Engine *,const PwVmBackend *,
                       PwX86CacheEntry *,uint32_t,size_t,uint32_t,
                       PwX86SourceView,void *);
int pw_x86_engine_step(PwX86Engine *,PwX86State *,PwX86StepReport *);
int pw_x86_engine_reset(PwX86Engine *,uint32_t);
int pw_x86_engine_destroy(PwX86Engine *);
#endif
