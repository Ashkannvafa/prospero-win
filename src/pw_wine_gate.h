/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Bounded Wine ntdll entry gate.
 *
 * This is the integration milestone for the Wine runtime: map the selected
 * i386 PE modules from the runtime namespace, bind their real import graph,
 * locate the versioned Unix-call boundary inside ntdll, enter one exported
 * ntdll function through the IA-32 DBT and stop at that boundary instead of
 * executing it.
 *
 * The boundary is identified structurally, not guessed. Wine's i386 PE
 * syscall stubs end in "call <__wine_syscall>", and __wine_syscall is the
 * single "jmp dword ptr [__wine_syscall_dispatcher]" thunk that references
 * the exported dispatcher slot. Both the slot and the thunk are located from
 * the mapped image, so the stop point is an address the manifest-hashed
 * ntdll really contains.
 *
 * Nothing here calls a host Wine function, and the gate refuses to widen
 * itself: production Pinball startup does not depend on it.
 */
#ifndef PROSPERO_WIN_PW_WINE_GATE_H
#define PROSPERO_WIN_PW_WINE_GATE_H

#include "pw_export.h"
#include "pw_import_bind.h"
#include "pw_loader.h"
#include "pw_sha256.h"
#include "pw_x86_engine.h"

enum {
    PW_WINE_GATE_MAX_MODULES = 8,
    PW_WINE_GATE_MAX_BOUNDARIES = 8,
    PW_WINE_GATE_DEFAULT_STEPS = 4096,
    PW_WINE_GATE_MAX_STEPS = 1048576,
    PW_WINE_GATE_STACK_BYTES = 64u * 1024u,
    PW_WINE_GATE_CACHE_ENTRIES = 1024,
    PW_WINE_GATE_ARENA_BYTES = 256u * 1024u,
};

typedef enum PwWineStop {
    PW_WINE_STOP_NONE = 0,
    PW_WINE_STOP_UNIX_CALL_BOUNDARY = 1,
    PW_WINE_STOP_UNSUPPORTED_INSTRUCTION = 2,
    PW_WINE_STOP_MEMORY_BOUNDS = 3,
    PW_WINE_STOP_CACHE_LIMIT = 4,
    PW_WINE_STOP_NON_CODE = 5,
    PW_WINE_STOP_DECODE_FAILURE = 6,
    PW_WINE_STOP_X87_TRAP = 7,
    PW_WINE_STOP_STEP_BUDGET = 8,
    PW_WINE_STOP_RETURNED_TO_CALLER = 9,
    PW_WINE_STOP_GATE_ERROR = 10,
} PwWineStop;

typedef struct PwWineModuleRecord {
    char name[PW_MODULE_NAME_MAX + 1];
    char path[PW_PATH_MAX + 1];
    char sha256[PW_SHA256_HEX_BYTES];
    uint32_t size;
    uint32_t machine;
    uint32_t base;                  /* guest load address */
    uint32_t image_bytes;           /* mapped span of the module */
    uint32_t imports;
    uint32_t exports_named;
    uint32_t exports_ordinal;
    uint8_t loaded;
    uint8_t tls_present;
    uint8_t runtime;
} PwWineModuleRecord;

typedef struct PwWineGateConfig {
    const PwFileProvider *provider;
    const PwVmBackend *backend;
    const char *root_module;        /* default "kernelbase.dll" */
    const char *entry_module;       /* default "ntdll.dll" */
    const char *entry_symbol;       /* default "NtClose" */
    const char *dispatcher_symbol;  /* default "__wine_syscall_dispatcher" */
    const char *modules[PW_WINE_GATE_MAX_MODULES];
    uint32_t module_count;
    uint32_t step_budget;           /* 0 uses PW_WINE_GATE_DEFAULT_STEPS */
    uint32_t stack_base;            /* 0 lets the gate choose */
} PwWineGateConfig;

typedef struct PwWineGateReport {
    uint32_t module_count;
    PwWineModuleRecord modules[PW_WINE_GATE_MAX_MODULES];
    uint32_t bound_functions;
    uint32_t bound_data;
    uint32_t bound_modules;
    uint32_t bind_failures;
    uint32_t tls_modules;
    uint32_t boundary_count;
    uint32_t boundary_slot_rva;
    uint32_t boundary_slot_va;
    uint32_t boundary_thunk_rva;
    uint32_t boundary_thunk_va;
    uint32_t entry_rva;
    uint32_t entry_eip;             /* initial guest EIP */
    uint32_t entry_pe_rva;          /* the module's own entry point */
    uint32_t stub_syscall_id;       /* decoded from the stub's first bytes */
    uint32_t observed_syscall_id;   /* EAX when the boundary was reached */
    uint32_t first_eip;
    uint32_t last_eip;
    uint32_t stop_address;
    uint32_t stack_base;
    uint32_t stack_bytes;
    uint64_t dispatches;
    uint64_t retired;
    uint64_t translated_blocks;
    uint64_t translated_bytes;
    uint64_t host_calls;            /* host Wine functions called: must be 0 */
    uint32_t cleanup_modules;
    uint32_t cleanup_mappings;
    uint32_t cleanup_translations;
    PwWineStop stop;
    int status;
} PwWineGateReport;

int pw_wine_gate_run(const PwWineGateConfig *config, PwWineGateReport *report);

const char *pw_wine_stop_name(PwWineStop stop);

/* True when the recorded stop is the accepted acceptance condition. */
int pw_wine_stop_is_acceptance(PwWineStop stop);

#endif
