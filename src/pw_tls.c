/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_tls.h"

#include <string.h>

static uint32_t align_up(uint32_t value, uint32_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static int arena_pointer(const PwTlsRuntime *runtime, uint32_t offset,
                         uint32_t bytes, void **out)
{
    if (!runtime->arena.write_base || !runtime->arena.exec_base)
        return PW_ERR_STATE;
    if (offset > runtime->arena.bytes ||
        bytes > runtime->arena.bytes - offset)
        return PW_ERR_LIMIT;
    *out = (void *)((uint8_t *)runtime->arena.write_base + offset);
    return PW_OK;
}

/* First enclosing free range, else the bump cursor. */
static int allocate_block(PwTlsRuntime *runtime, uint32_t bytes,
                          uint32_t *offset)
{
    for (uint32_t index = 0; index < PW_TLS_MAX_THREADS; ++index) {
        PwTlsStorage *range = &runtime->storage[index];

        /* Only an exact-size free range is reused, so a recycled block never
         * has to be split and the arena stays easy to audit. */
        if (range->used || range->bytes != bytes)
            continue;
        range->used = 1u;
        *offset = range->offset;
        return PW_OK;
    }
    if (runtime->arena_cursor > runtime->arena.bytes ||
        bytes > runtime->arena.bytes - runtime->arena_cursor)
        return PW_ERR_LIMIT;
    *offset = runtime->arena_cursor;
    for (uint32_t slot = 0; slot < PW_TLS_MAX_THREADS; ++slot) {
        if (runtime->storage[slot].used || runtime->storage[slot].bytes != 0u)
            continue;
        runtime->storage[slot] = (PwTlsStorage){*offset, bytes, 1u};
        runtime->arena_cursor += bytes;
        return PW_OK;
    }
    return PW_ERR_LIMIT;
}

static void release_block(PwTlsRuntime *runtime, uint32_t offset,
                          uint32_t bytes)
{
    void *pointer = NULL;

    for (uint32_t index = 0; index < PW_TLS_MAX_THREADS; ++index) {
        PwTlsStorage *range = &runtime->storage[index];

        if (range->used && range->offset == offset && range->bytes == bytes) {
            range->used = 0u;
            break;
        }
    }
    /* Zero before reuse: a recycled block must not leak another thread's
     * template bytes into a fresh TLS slot. */
    if (arena_pointer(runtime, offset, bytes, &pointer) == PW_OK)
        memset(pointer, 0, bytes);
}

static uint32_t block_bytes(const PwTlsRuntime *runtime)
{
    uint32_t total = align_up(runtime->module_count * 4u, PW_TLS_ALIGNMENT);

    for (uint32_t index = 0; index < runtime->module_count; ++index)
        total += align_up(runtime->modules[index].storage_bytes,
                          PW_TLS_ALIGNMENT);
    return total;
}

int pw_tls_runtime_init(PwTlsRuntime *runtime, const PwVmBackend *backend,
                        PwVmRegion *arena)
{
    if (!runtime || !backend || !arena || !arena->write_base ||
        arena->bytes == 0u)
        return PW_ERR_PRECONDITION;
    /* The arena holds PE32 guest addresses. An arena the guest cannot
     * address would be silently truncated, so it is refused instead. */
    if ((uint64_t)(uintptr_t)arena->exec_base + arena->bytes >
        0x100000000ull)
        return PW_ERR_PRECONDITION;
    memset(runtime, 0, sizeof(*runtime));
    runtime->backend = backend;
    runtime->arena = *arena;
    return PW_OK;
}

int pw_tls_find_module(const PwTlsRuntime *runtime, const char *name)
{
    if (!runtime || !name)
        return PW_ERR_PRECONDITION;
    for (uint32_t index = 0; index < runtime->module_count; ++index)
        if (strcmp(runtime->modules[index].name, name) == 0)
            return (int)index;
    return PW_ERR_NOT_FOUND;
}

int pw_tls_add_module(PwTlsRuntime *runtime, const char *name,
                      const PeImage *image, PwMappedImage *mapped)
{
    PeTlsDirectory directory;
    PwTlsModule module;
    uint32_t index;
    uint64_t slot_address;
    void *slot;
    int status;

    if (!runtime || !name || !*name || !image || !mapped)
        return PW_ERR_PRECONDITION;
    if (strlen(name) > PW_MODULE_NAME_MAX)
        return PW_ERR_LIMIT;
    if (runtime->module_count >= PW_TLS_MAX_MODULES)
        return PW_ERR_LIMIT;
    if (pw_tls_find_module(runtime, name) >= 0)
        return PW_ERR_STATE;
    status = pe_tls_parse(&directory, image);
    if (status != PW_OK)
        return status;
    if (directory.directory_rva == 0u)
        return PW_ERR_NOT_FOUND;

    index = runtime->module_count;
    slot = pw_map_writable(mapped, directory.index_rva, 4u);
    if (!slot)
        return PW_ERR_STATE;
    slot_address = pw_map_exec_address(mapped, directory.index_rva);
    if (slot_address == 0u || slot_address > 0xffffffffull)
        return PW_ERR_MALFORMED;
    memcpy(slot, &index, 4u);
    runtime->index_writes++;

    memset(&module, 0, sizeof(module));
    memcpy(module.name, name, strlen(name) + 1u);
    module.directory = directory;
    module.image = image;
    module.index = index;
    module.storage_bytes = directory.storage_bytes;
    module.index_slot = (uint32_t)slot_address;
    runtime->modules[runtime->module_count++] = module;
    return PW_OK;
}

int pw_tls_thread_attach(PwTlsRuntime *runtime, uint32_t thread, uint32_t teb,
                         PwX86State *state)
{
    uint32_t bytes;
    uint32_t offset = 0u;
    uint32_t array;
    uint32_t cursor;
    uint8_t *block = NULL;
    int status;

    if (!runtime || !state)
        return PW_ERR_PRECONDITION;
    if (thread >= PW_TLS_MAX_THREADS || runtime->module_count == 0u)
        return PW_ERR_LIMIT;
    if (runtime->threads[thread].used)
        return PW_ERR_STATE;
    if (teb == 0u || state->fs_base != teb)
        return PW_ERR_VM;
    if (state->fs_bytes < PW_TLS_TEB_ARRAY_OFFSET + 4u)
        return PW_ERR_VM;
    bytes = block_bytes(runtime);
    if (bytes == 0u)
        return PW_ERR_LIMIT;
    status = allocate_block(runtime, bytes, &offset);
    if (status != PW_OK)
        return status;
    status = arena_pointer(runtime, offset, bytes, (void **)&block);
    if (status != PW_OK) {
        release_block(runtime, offset, bytes);
        return status;
    }
    memset(block, 0, bytes);
    array = (uint32_t)(uintptr_t)runtime->arena.exec_base + offset;
    cursor = align_up(runtime->module_count * 4u, PW_TLS_ALIGNMENT);
    for (uint32_t index = 0; index < runtime->module_count; ++index) {
        const PwTlsModule *module = &runtime->modules[index];
        uint32_t slot_address = array + cursor;

        if (module->directory.template_bytes != 0u) {
            const uint8_t *source;
            size_t source_offset;

            status = pe_image_file_offset(module->image,
                                          module->directory.template_rva,
                                          module->directory.template_bytes,
                                          &source_offset);
            if (status != PW_OK) {
                release_block(runtime, offset, bytes);
                return status;
            }
            source = module->image->bytes + source_offset;
            memcpy(block + cursor, source, module->directory.template_bytes);
            runtime->storages_created++;
        }
        /* Template bytes then exactly zero_fill zero bytes: the block was
         * cleared above, so the fill is explicit rather than incidental. */
        memset(block + cursor + module->directory.template_bytes, 0,
               module->directory.zero_fill);
        memcpy(block + index * 4u, &slot_address, 4u);
        cursor += align_up(module->storage_bytes, PW_TLS_ALIGNMENT);
    }
    {
        void *teb_slot = (void *)(uintptr_t)(teb + PW_TLS_TEB_ARRAY_OFFSET);

        memcpy(teb_slot, &array, 4u);
    }
    runtime->threads[thread] = (PwTlsThread){
        .teb = teb, .array = array, .offset = offset, .bytes = bytes, .used = 1u,
    };
    runtime->arena_used += bytes;
    runtime->thread_count++;
    return PW_OK;
}

int pw_tls_thread_detach(PwTlsRuntime *runtime, uint32_t thread,
                         PwX86State *state)
{
    PwTlsThread *entry;
    uint32_t zero = 0u;

    if (!runtime || !state)
        return PW_ERR_PRECONDITION;
    if (thread >= PW_TLS_MAX_THREADS)
        return PW_ERR_PRECONDITION;
    entry = &runtime->threads[thread];
    if (!entry->used)
        return PW_ERR_STATE;
    if (state->fs_base == entry->teb &&
        state->fs_bytes >= PW_TLS_TEB_ARRAY_OFFSET + 4u)
        memcpy((void *)(uintptr_t)(entry->teb + PW_TLS_TEB_ARRAY_OFFSET),
               &zero, 4u);
    release_block(runtime, entry->offset, entry->bytes);
    runtime->storages_released++;
    runtime->arena_used -= entry->bytes;
    *entry = (PwTlsThread){0};
    runtime->thread_count--;
    return PW_OK;
}

int pw_tls_slot(const PwTlsRuntime *runtime, uint32_t thread,
                uint32_t module_index, uint32_t *address)
{
    const PwTlsThread *entry;
    uint32_t value = 0u;
    void *pointer = NULL;

    if (!runtime || !address)
        return PW_ERR_PRECONDITION;
    if (thread >= PW_TLS_MAX_THREADS || module_index >= runtime->module_count)
        return PW_ERR_LIMIT;
    entry = &runtime->threads[thread];
    if (!entry->used)
        return PW_ERR_STATE;
    if (arena_pointer(runtime, entry->offset + module_index * 4u, 4u,
                      &pointer) != PW_OK)
        return PW_ERR_STATE;
    memcpy(&value, pointer, 4u);
    if (value == 0u)
        return PW_ERR_NOT_FOUND;
    *address = value;
    return PW_OK;
}

int pw_tls_guest_slot(const PwTlsRuntime *runtime, uint32_t thread,
                      const PwX86State *state, uint32_t module_index,
                      uint32_t *address)
{
    const PwTlsThread *entry;
    uint32_t array = 0u;
    uint32_t value = 0u;

    if (!runtime || !state || !address)
        return PW_ERR_PRECONDITION;
    if (thread >= PW_TLS_MAX_THREADS || module_index >= runtime->module_count)
        return PW_ERR_LIMIT;
    entry = &runtime->threads[thread];
    if (!entry->used || state->fs_base != entry->teb)
        return PW_ERR_STATE;
    if (state->fs_bytes < PW_TLS_TEB_ARRAY_OFFSET + 4u ||
        (uint64_t)module_index * 4u + 4u > runtime->arena.bytes)
        return PW_ERR_VM;
    /* The guest's own route: FS:[0x2C] is the array, [index] is the slot. */
    memcpy(&array, (const void *)(uintptr_t)(entry->teb +
                                             PW_TLS_TEB_ARRAY_OFFSET), 4u);
    if (array != entry->array)
        return PW_ERR_STATE;
    if (array < (uint32_t)(uintptr_t)runtime->arena.exec_base ||
        (uint64_t)array + module_index * 4u + 4u >
            (uint64_t)(uint32_t)(uintptr_t)runtime->arena.exec_base +
                runtime->arena.bytes)
        return PW_ERR_MALFORMED;
    memcpy(&value, (const void *)(uintptr_t)(array + module_index * 4u), 4u);
    if (value == 0u)
        return PW_ERR_NOT_FOUND;
    *address = value;
    return PW_OK;
}

int pw_tls_callback_plan(PwTlsRuntime *runtime, uint32_t thread,
                         PwTlsPhase phase)
{
    const int reverse = phase == PW_TLS_THREAD_DETACH ||
                        phase == PW_TLS_PROCESS_DETACH;

    if (!runtime)
        return PW_ERR_PRECONDITION;
    if (thread >= PW_TLS_MAX_THREADS)
        return PW_ERR_PRECONDITION;
    if (phase != PW_TLS_PROCESS_ATTACH && phase != PW_TLS_THREAD_ATTACH &&
        phase != PW_TLS_THREAD_DETACH && phase != PW_TLS_PROCESS_DETACH)
        return PW_ERR_PRECONDITION;
    if (!runtime->threads[thread].used)
        return PW_ERR_STATE;
    runtime->plan = (PwTlsPlan){
        .phase = phase,
        .thread = thread,
        .module_cursor = 0u,
        .callback_cursor = reverse ? 0xffffffffu : 0u,
        .reverse = (uint8_t)reverse,
        .active = 1u,
    };
    return PW_OK;
}

int pw_tls_callback_next(PwTlsRuntime *runtime, PwX86State *state,
                         PwGuestCallback *frame, uint32_t token,
                         uint32_t *callback_address, uint32_t *argument)
{
    enum { PW_TLS_CALLBACK_UNSET = 0xffffffffu };

    if (!runtime || !state || !frame || !callback_address || !argument)
        return PW_ERR_PRECONDITION;
    if (!runtime->plan.active)
        return PW_ERR_STATE;
    for (;;) {
        const PwTlsModule *module;
        uint32_t callback_index;
        uint32_t arguments[3];
        int status;

        if (runtime->plan.reverse) {
            if (runtime->plan.module_cursor >= runtime->module_count) {
                runtime->plan.active = 0u;
                return PW_ERR_NOT_FOUND;
            }
            /* Detach walks modules backwards: last registered first. */
            module = &runtime->modules[runtime->module_count - 1u -
                                       runtime->plan.module_cursor];
            if (runtime->plan.callback_cursor == PW_TLS_CALLBACK_UNSET)
                runtime->plan.callback_cursor =
                    module->directory.callback_count;
            if (runtime->plan.callback_cursor == 0u) {
                runtime->plan.module_cursor++;
                runtime->plan.callback_cursor = PW_TLS_CALLBACK_UNSET;
                continue;
            }
            callback_index = --runtime->plan.callback_cursor;
        } else {
            if (runtime->plan.module_cursor >= runtime->module_count) {
                runtime->plan.active = 0u;
                return PW_ERR_NOT_FOUND;
            }
            module = &runtime->modules[runtime->plan.module_cursor];
            if (runtime->plan.callback_cursor >= module->directory.callback_count) {
                runtime->plan.module_cursor++;
                runtime->plan.callback_cursor = 0u;
                continue;
            }
            callback_index = runtime->plan.callback_cursor++;
        }
        arguments[0] = (uint32_t)module->image->image_base;
        arguments[1] = runtime->plan.phase == PW_TLS_PROCESS_ATTACH ? 1u
                     : runtime->plan.phase == PW_TLS_THREAD_ATTACH ? 2u
                     : runtime->plan.phase == PW_TLS_THREAD_DETACH ? 3u : 0u;
        arguments[2] = 0u;
        status = pw_guest_callback_enter(frame, state,
                                         module->directory.callbacks[callback_index].va,
                                         token, arguments, 3u,
                                         PW_GUEST_STDCALL);
        if (status != PW_OK)
            return status;
        runtime->callbacks_scheduled++;
        *callback_address = module->directory.callbacks[callback_index].va;
        *argument = arguments[1];
        return PW_OK;
    }
}

int pw_tls_callback_failed(PwTlsRuntime *runtime, PwX86State *state,
                           int status)
{
    if (!runtime || !state)
        return PW_ERR_PRECONDITION;
    if (!runtime->plan.active)
        return PW_ERR_STATE;
    if (runtime->plan.phase == PW_TLS_PROCESS_ATTACH ||
        runtime->plan.phase == PW_TLS_THREAD_ATTACH) {
        const uint32_t thread = runtime->plan.thread;

        runtime->plan.active = 0u;
        /* Atomic rollback: a thread whose attach callbacks failed does not
         * keep a TLS array, storage or a TEB pointer. */
        if (pw_tls_thread_detach(runtime, thread, state) != PW_OK)
            return PW_ERR_STATE;
        runtime->rollbacks++;
    } else {
        const uint32_t thread = runtime->plan.thread;

        runtime->plan.active = 0u;
        if (pw_tls_thread_detach(runtime, thread, state) != PW_OK)
            return PW_ERR_STATE;
    }
    return status == PW_OK ? PW_ERR_STATE : status;
}

int pw_tls_validate(const PwTlsRuntime *runtime)
{
    uint32_t live = 0u;

    if (!runtime)
        return PW_ERR_PRECONDITION;
    for (uint32_t index = 0; index < runtime->module_count; ++index) {
        const PwTlsModule *module = &runtime->modules[index];

        if (module->index != index || module->index_slot == 0u)
            return PW_ERR_STATE;
    }
    for (uint32_t index = 0; index < PW_TLS_MAX_THREADS; ++index) {
        const PwTlsThread *entry = &runtime->threads[index];

        if (!entry->used)
            continue;
        if (entry->bytes < block_bytes(runtime) ||
            entry->offset + entry->bytes > runtime->arena.bytes ||
            entry->array != (uint32_t)(uintptr_t)runtime->arena.exec_base +
                            entry->offset)
            return PW_ERR_STATE;
        live += entry->bytes;
    }
    if (live != runtime->arena_used)
        return PW_ERR_STATE;
    return PW_OK;
}
