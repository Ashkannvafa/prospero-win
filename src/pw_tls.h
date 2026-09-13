/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * PE32 TLS process and thread lifecycle.
 *
 * The loader parses a module's TLS directory (pe_tls.c) and this owner gives
 * it a stable index, per-thread storage and a callback plan. Everything the
 * guest can observe is written through mapped guest memory:
 *
 *   image AddressOfIndex   <- this module's TLS index
 *   TEB + 0x2C             <- guest address of this thread's TLS array
 *   TLS array[index]       <- guest address of this thread's storage
 *
 * Callbacks are scheduled with the DBT's guest-callback mechanism, never as
 * host function pointers, and the plan's order is deterministic: process and
 * thread attach walk modules in dependency order and callbacks forward,
 * detach walks both backwards, as the platform requires.
 *
 * Storage comes from one caller-owned guest arena with a free list, so no
 * allocation happens on an allocator this target does not have and every
 * byte is accounted for: a failed attach rolls its own allocations back and
 * a completed detach returns them.
 */
#ifndef PROSPERO_WIN_PW_TLS_H
#define PROSPERO_WIN_PW_TLS_H

#include "pe_tls.h"
#include "pw_guest_call.h"
#include "pw_map.h"

enum {
    PW_TLS_MAX_MODULES = 16,
    PW_TLS_MAX_THREADS = 8,
    PW_TLS_FREE_RANGES = 32,
    /* TEB->ThreadLocalStoragePointer, the guest's route to its TLS array. */
    PW_TLS_TEB_ARRAY_OFFSET = 0x2cu,
    PW_TLS_ALIGNMENT = 16u,
};

typedef enum PwTlsPhase {
    PW_TLS_PROCESS_ATTACH = 1,
    PW_TLS_THREAD_ATTACH = 2,
    PW_TLS_THREAD_DETACH = 3,
    PW_TLS_PROCESS_DETACH = 4,
} PwTlsPhase;

typedef struct PwTlsModule {
    char name[PW_MODULE_NAME_MAX + 1];
    PeTlsDirectory directory;
    const PeImage *image;           /* borrowed for the runtime's lifetime */
    uint32_t index;
    uint32_t storage_bytes;
    uint32_t index_slot;            /* guest address of AddressOfIndex */
    uint8_t attached;
} PwTlsModule;

typedef struct PwTlsThread {
    uint32_t teb;
    uint32_t array;                 /* guest address of the TLS array */
    uint32_t offset;                /* block start inside the arena */
    uint32_t bytes;                 /* block size */
    uint8_t used;
} PwTlsThread;

typedef struct PwTlsStorage {
    uint32_t offset;
    uint32_t bytes;
    uint8_t used;
} PwTlsStorage;

typedef struct PwTlsPlan {
    PwTlsPhase phase;
    uint32_t thread;
    uint32_t module_cursor;
    uint32_t callback_cursor;
    uint8_t reverse;
    uint8_t active;
} PwTlsPlan;

typedef struct PwTlsRuntime {
    const PwVmBackend *backend;
    PwVmRegion arena;               /* guest RW storage, caller-owned */
    uint32_t arena_cursor;
    uint32_t arena_used;            /* live bytes, for leak accounting */
    uint32_t module_count;
    uint32_t thread_count;
    uint64_t index_writes;
    uint64_t storages_created;
    uint64_t storages_released;
    uint64_t rollbacks;
    uint64_t callbacks_scheduled;
    PwTlsModule modules[PW_TLS_MAX_MODULES];
    PwTlsThread threads[PW_TLS_MAX_THREADS];
    PwTlsStorage storage[PW_TLS_MAX_THREADS];
    PwTlsPlan plan;
} PwTlsRuntime;

int pw_tls_runtime_init(PwTlsRuntime *runtime, const PwVmBackend *backend,
                        PwVmRegion *arena);

/*
 * Registers one mapped module. PW_ERR_NOT_FOUND means the image declares no
 * TLS directory, which is not an error for the caller to ignore silently:
 * it is the honest answer for most modules.
 */
int pw_tls_add_module(PwTlsRuntime *runtime, const char *name,
                      const PeImage *image, PwMappedImage *mapped);

int pw_tls_find_module(const PwTlsRuntime *runtime, const char *name);

/* Creates the thread's array and storage and points the TEB at it. */
int pw_tls_thread_attach(PwTlsRuntime *runtime, uint32_t thread, uint32_t teb,
                         PwX86State *state);

/* Releases the thread's storage and clears its TEB pointer and array. */
int pw_tls_thread_detach(PwTlsRuntime *runtime, uint32_t thread,
                         PwX86State *state);

/* Storage address of one module for one thread, as the guest sees it. */
int pw_tls_slot(const PwTlsRuntime *runtime, uint32_t thread,
                uint32_t module_index, uint32_t *address);

/* The same lookup through guest memory: FS:[0x2C][index]. */
int pw_tls_guest_slot(const PwTlsRuntime *runtime, uint32_t thread,
                      const PwX86State *state, uint32_t module_index,
                      uint32_t *address);

int pw_tls_callback_plan(PwTlsRuntime *runtime, uint32_t thread,
                         PwTlsPhase phase);

/*
 * Schedules the next callback of the active plan through the DBT's guest
 * callback frame. PW_ERR_NOT_FOUND means the plan is exhausted. The caller
 * runs the engine, then calls pw_guest_callback_leave() or
 * pw_tls_callback_failed().
 */
int pw_tls_callback_next(PwTlsRuntime *runtime, PwX86State *state,
                         PwGuestCallback *frame, uint32_t token,
                         uint32_t *callback_address, uint32_t *argument);

/* Rolls back an attach plan, or skips the rest of a detach plan. */
int pw_tls_callback_failed(PwTlsRuntime *runtime, PwX86State *state,
                           int status);

int pw_tls_validate(const PwTlsRuntime *runtime);

#endif
