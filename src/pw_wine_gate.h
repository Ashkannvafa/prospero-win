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
#include "pw_unix_call.h"
#include "pw_x86_engine.h"

enum {
    PW_WINE_GATE_MAX_MODULES = 8,
    PW_WINE_GATE_MAX_BOUNDARIES = 8,
    PW_WINE_GATE_DEFAULT_STEPS = 4096,
    PW_WINE_GATE_MAX_STEPS = 1048576,
    PW_WINE_GATE_STACK_BYTES = 64u * 1024u,
    PW_WINE_GATE_CACHE_ENTRIES = 1024,
    /* ntdll's loader path translates far more code than a title's startup:
     * the arena is the gate's own budget, and running out of it is reported
     * as its own classified stop rather than as a guest fault. */
    PW_WINE_GATE_ARENA_BYTES = 4u * 1024u * 1024u,
    PW_WINE_GATE_DEFAULT_CALLS = 64,
    PW_WINE_GATE_MAX_CALL_REGIONS = 16,
    PW_WINE_GATE_DEFAULT_ALLOCATION_LIMIT = 4u * 1024u * 1024u,
    /* Where the NT allocator hands out guest memory that ntdll asks for. */
    PW_WINE_GATE_HEAP_BASE = 0x20000000u,
    PW_WINE_GATE_HEAP_LIMIT = 0x30000000u,
    PW_WINE_GATE_MAX_HANDLES = 16,
    PW_WINE_GATE_MAX_PATH = 160,
    PW_WINE_GATE_MAX_READ = 64u * 1024u,
};

/*
 * Platform file service below the Unix-call boundary. The gate translates a
 * guest DOS/NT path to a name inside the configured runtime distribution and
 * then asks this service to open, read and close it; the gate itself never
 * touches a host file system call. Everything a handler reads or writes in
 * guest memory still goes through the dispatcher's validated accessor.
 */
typedef enum PwWineFileStatus {
    PW_WINE_FILE_OK = 0,
    PW_WINE_FILE_NOT_FOUND = 1,
    PW_WINE_FILE_DENIED = 2,
    PW_WINE_FILE_ERROR = 3,
} PwWineFileStatus;

typedef struct PwWineFileService {
    void *context;
    /* name is a canonical lower-case file name inside the runtime root. */
    PwWineFileStatus (*open)(void *context, const char *name, uint64_t *size,
                             void **token);
    PwWineFileStatus (*read)(void *context, void *token, uint64_t offset,
                             void *bytes, uint32_t size,
                             uint32_t *read_bytes);
    void (*close)(void *context, void *token);
} PwWineFileService;

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
    PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED = 11,
    PW_WINE_STOP_UNIX_CALL_UNKNOWN = 12,
    PW_WINE_STOP_UNIX_CALL_REJECTED = 13,
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
    const PwWineFileService *files;  /* NULL refuses every open */
    /* Optional per-dispatch trace, so a mode difference can be localised to
     * the block that produced it. */
    void (*trace)(void *context, const PwX86State *state);
    void *trace_context;
    const char *root_module;        /* default "kernelbase.dll" */
    const char *entry_module;       /* default "ntdll.dll" */
    const char *entry_symbol;       /* default "NtClose" */
    const char *dispatcher_symbol;  /* default "__wine_syscall_dispatcher" */
    const char *modules[PW_WINE_GATE_MAX_MODULES];
    uint32_t module_count;
    uint32_t step_budget;           /* 0 uses PW_WINE_GATE_DEFAULT_STEPS */
    uint32_t stack_base;            /* 0 lets the gate choose */
    uint8_t chaining;               /* DBT mode toggles, for parity evidence */
    uint8_t residency;
    uint8_t lazy_flags;
    uint8_t modes_set;              /* 0 keeps the engine defaults */
    uint8_t bridge_calls;           /* service Unix calls instead of stopping */
    uint32_t call_budget;           /* 0 uses PW_WINE_GATE_DEFAULT_CALLS */
    uint32_t allocation_limit;      /* bytes one run may allocate; 0 = default */
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
    uint32_t boundary_return_eip;   /* guest return address at the boundary */
    uint32_t caller_stub_id;        /* id re-read from the stub that called it */
    uint32_t caller_stub_rva;
    uint8_t boundary_return_in_module;
    uint32_t first_eip;
    uint32_t last_eip;
    uint32_t stop_address;
    uint32_t fault_address;         /* memory-bounds identity, when reported */
    uint32_t fault_width;
    uint32_t fault_write;
    uint32_t chaining;
    uint32_t residency;
    uint32_t lazy_flags;
    uint32_t stack_base;
    uint32_t stack_bytes;
    uint32_t guest_regions;         /* declared DBT memory regions */
    uint32_t teb_base;              /* minimal guest TEB (FS base) */
    uint32_t teb_bytes;
    uint32_t peb_base;              /* minimal guest PEB (first argument) */
    uint32_t parameters_base;       /* zeroed process-parameters page */
    uint32_t parameters_length;     /* bytes of the populated structure */
    PwUnixCallTally calls;
    uint32_t calls_serviced;
    uint32_t allocations;
    uint32_t allocated_bytes;
    uint32_t call_regions;          /* guest regions this run mapped for NT */
    uint64_t file_opens;
    uint64_t file_reads;
    uint64_t file_bytes;
    uint64_t file_closes;
    uint64_t file_refusals;
    uint32_t file_handles;
    uint32_t files_configured;
    char last_file[PW_WINE_GATE_MAX_PATH + 1];
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
