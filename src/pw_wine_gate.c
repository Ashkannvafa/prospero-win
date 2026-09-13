/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_gate.h"

#include "pe_export.h"
#include "pe_reloc.h"
#include "pe_tls.h"
#include "pw_map.h"
#include "pw_module_name.h"
#include "pw_guest_call.h"
#include "../include/prospero_win_vm.h"

#include <string.h>

enum {
    /* Two modules of this distribution are under 5 MiB each. */
    PW_WINE_GATE_LOW_BASE = 0x10000000u,
    PW_WINE_GATE_MAX_IMAGE = 32u * 1024u * 1024u,
};

/*
 * A backend that keeps PE32 runtime modules below the guest's 4 GiB
 * boundary. The portable mapper refuses a PE32 image the guest could not
 * address, and a relocatable Wine DLL would otherwise land wherever mmap
 * chooses, so the gate asks for an exact low reservation first and only
 * falls back to the plain one.
 */
typedef struct PwWineLowBackend {
    PwVmBackend base;
    uint32_t cursor;
} PwWineLowBackend;

static int low_reserve(void *context, size_t bytes, size_t alignment,
                       PwVmRegion *out)
{
    PwWineLowBackend *low = context;
    uint32_t candidate;

    if ((low->base.capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u &&
        bytes != 0u && bytes <= PW_WINE_GATE_MAX_IMAGE) {
        const uint32_t step = alignment != 0u ? (uint32_t)alignment : 0x1000u;
        const uint32_t aligned =
            (low->cursor + step - 1u) & ~(step - 1u);

        for (candidate = aligned;
             (uint64_t)candidate + bytes <= 0x100000000ull &&
             candidate < 0x40000000u;
             candidate += step) {
            if (low->base.reserve_at(low->base.context, candidate, bytes,
                                     alignment, out) == PW_OK) {
                low->cursor = candidate + (uint32_t)bytes;
                return PW_OK;
            }
            if (candidate > 0x40000000u - step)
                break;
        }
        low->cursor = PW_WINE_GATE_LOW_BASE;
    }
    return low->base.reserve(low->base.context, bytes, alignment, out);
}

static void low_backend_init(PwWineLowBackend *low, const PwVmBackend *base)
{
    memset(low, 0, sizeof(*low));
    low->base = *base;
    low->cursor = PW_WINE_GATE_LOW_BASE;
    if ((base->capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u)
        low->base.reserve = low_reserve;
    low->base.context = low;
}

static void copy_text(char *out, size_t out_bytes, const char *text)
{
    size_t length;

    if (!out || out_bytes == 0u)
        return;
    if (!text) {
        out[0] = '\0';
        return;
    }
    length = strlen(text);
    if (length >= out_bytes)
        length = out_bytes - 1u;
    memcpy(out, text, length);
    out[length] = '\0';
}

static PwWineModuleRecord *record_for(PwWineGateReport *report,
                                      const char *canonical)
{
    for (uint32_t index = 0; index < report->module_count; ++index)
        if (strcmp(report->modules[index].name, canonical) == 0)
            return &report->modules[index];
    return NULL;
}

static int hash_module(const PwFileProvider *provider, const char *name,
                       PwWineModuleRecord *record)
{
    PwFileSpan span;
    int status;

    memset(&span, 0, sizeof(span));
    status = provider->open_namespace(provider->context, PW_FILE_RUNTIME, name,
                                      &span);
    if (status != PW_OK)
        return status;
    pw_sha256_hex_span(span.bytes, span.size, record->sha256);
    record->size = (uint32_t)span.size;
    copy_text(record->path, sizeof(record->path), span.path);
    provider->close(provider->context, &span);
    return PW_OK;
}

/* Executable source span for the DBT: only bytes of mapped modules. */
static int gate_source_view(void *opaque, uint32_t pc, const uint8_t **source,
                            size_t *bytes)
{
    const PwLoader *loader = opaque;

    for (uint32_t index = 0; index < loader->module_count; ++index) {
        const PwModule *module = &loader->modules[index];

        if (!module->mapped_ok || pc < module->mapped.actual_base)
            continue;
        for (uint32_t section = 0; section < module->layout.section_count;
             ++section) {
            const PeLayoutSection *entry = &module->layout.sections[section];
            const uint64_t start = module->mapped.actual_base + entry->rva;
            const uint64_t end = start + entry->mapped_bytes;

            if ((entry->protection & PW_PROT_EXEC) == 0u)
                continue;
            if ((uint64_t)pc < start || (uint64_t)pc >= end)
                continue;
            *source = (const uint8_t *)(uintptr_t)pc;
            *bytes = (size_t)(end - pc);
            return PW_OK;
        }
    }
    return PW_ERR_NOT_FOUND;
}

/* "jmp dword ptr [disp32]" entries that reference the dispatcher slot. */
static uint32_t find_dispatcher_thunks(const PwModule *module, uint32_t slot_va,
                                       uint32_t *thunk_rvas, uint32_t capacity)
{
    uint8_t target[4];
    uint32_t found = 0u;

    target[0] = (uint8_t)(slot_va & 0xffu);
    target[1] = (uint8_t)((slot_va >> 8) & 0xffu);
    target[2] = (uint8_t)((slot_va >> 16) & 0xffu);
    target[3] = (uint8_t)((slot_va >> 24) & 0xffu);
    for (uint32_t index = 0; index < module->layout.section_count; ++index) {
        const PeLayoutSection *section = &module->layout.sections[index];
        const uint8_t *bytes;

        if ((section->protection & PW_PROT_EXEC) == 0u)
            continue;
        bytes = (const uint8_t *)(uintptr_t)(module->mapped.actual_base +
                                             section->rva);
        for (uint32_t offset = 0;
             offset + 6u <= section->mapped_bytes; ++offset) {
            if (bytes[offset] != 0xffu || bytes[offset + 1u] != 0x25u)
                continue;
            if (memcmp(bytes + offset + 2u, target, 4u) != 0)
                continue;
            if (found < capacity)
                thunk_rvas[found] = section->rva + offset;
            ++found;
        }
    }
    return found;
}

/* "mov eax, imm32" is how a Wine i386 PE syscall stub names its call. */
static uint32_t decode_stub_syscall(const PwModule *module, uint32_t rva)
{
    const uint8_t *bytes;

    if (rva > module->mapped.image_bytes ||
        module->mapped.image_bytes - rva < 5u)
        return 0u;
    bytes = (const uint8_t *)(uintptr_t)(module->mapped.actual_base + rva);
    if (bytes[0] != 0xb8u)
        return 0u;
    return (uint32_t)bytes[1] | ((uint32_t)bytes[2] << 8) |
           ((uint32_t)bytes[3] << 16) | ((uint32_t)bytes[4] << 24);
}

static PwWineStop classify(int status)
{
    switch (status) {
    case PW_ERR_UNSUPPORTED: return PW_WINE_STOP_UNSUPPORTED_INSTRUCTION;
    case PW_ERR_VM: return PW_WINE_STOP_MEMORY_BOUNDS;
    case PW_ERR_LIMIT: return PW_WINE_STOP_CACHE_LIMIT;
    case PW_ERR_NOT_FOUND: return PW_WINE_STOP_NON_CODE;
    case PW_ERR_X87_TRAP: return PW_WINE_STOP_X87_TRAP;
    default: return PW_WINE_STOP_DECODE_FAILURE;
    }
}

/*
 * Guest memory accessor handed to a Unix-call handler. It applies exactly
 * the rules the dispatcher's own guard applies, so a handler can never read
 * or write an address the DBT would have faulted on: address zero is never
 * valid, the range must lie inside the stack or a declared region, and a
 * write needs that region to be writable.
 */
static int gate_guest_access(void *context, uint32_t address, void *bytes,
                             uint32_t size, int write)
{
    const PwX86State *state = context;
    uint64_t end;

    if (!state || !bytes || size == 0u)
        return PW_ERR_PRECONDITION;
    end = (uint64_t)address + size;
    if (address == 0u || end > 0x100000000ull)
        return PW_ERR_MALFORMED;
    if (address >= state->stack_low && end <= state->stack_high) {
        if (write)
            memcpy((void *)(uintptr_t)address, bytes, size);
        else
            memcpy(bytes, (const void *)(uintptr_t)address, size);
        return PW_OK;
    }
    for (uint32_t index = 0; index < state->memory_count; ++index) {
        const PwX86Memory *region = &state->memory[index];
        const unsigned needed = write ? (PW_X86_READ | PW_X86_WRITE)
                                      : PW_X86_READ;

        if (region->high > 0x100000000ull)
            continue;
        if (address < region->low || end > region->high)
            continue;
        if ((region->permissions & needed) != needed)
            continue;
        if (write)
            memcpy((void *)(uintptr_t)address, bytes, size);
        else
            memcpy(bytes, (const void *)(uintptr_t)address, size);
        return PW_OK;
    }
    return PW_ERR_VM;
}

/*
 * State the NT call handlers need: the gate's low-address allocator, the
 * per-run accounting and the regions this run mapped on the guest's behalf
 * (released at cleanup).
 */
typedef struct PwWineCallContext {
    PwWineLowBackend *low;
    const PwWineGateConfig *config;
    PwWineGateReport *report;
    uint32_t heap_cursor;
    uint32_t limit;
    PwVmRegion regions[PW_WINE_GATE_MAX_CALL_REGIONS];
    /* Whether each region was allocated by an NtAllocateVirtualMemory call
     * the guest made (1) or is a page the gate registered for the guest's
     * benefit (0). Only the first kind counts against the live byte limit. */
    uint8_t region_owned[PW_WINE_GATE_MAX_CALL_REGIONS];
    uint32_t region_count;
    struct PwWineHandle {
        void *token;
        uint64_t size;
        uint64_t offset;
        uint8_t directory;
        uint8_t used;
    } handles[PW_WINE_GATE_MAX_HANDLES];
} PwWineCallContext;

static int reserve_guest_block(PwWineCallContext *calls, uint32_t desired,
                               uint32_t bytes, PwVmRegion *region,
                               uint32_t *base)
{
    const PwVmBackend *backend = &calls->low->base;
    const uint32_t page = (uint32_t)backend->page_bytes;
    const uint32_t aligned = (bytes + page - 1u) & ~(page - 1u);
    int status;

    if (aligned == 0u || (uint64_t)aligned > PW_WINE_GATE_DEFAULT_ALLOCATION_LIMIT)
        return PW_ERR_LIMIT;
    if (calls->region_count >= PW_WINE_GATE_MAX_CALL_REGIONS)
        return PW_ERR_LIMIT;
    if ((backend->capabilities & PW_VM_CAP_EXACT_ADDRESS) == 0u)
        return PW_ERR_UNSUPPORTED;
    if (desired == 0u) {
        uint32_t candidate = (calls->heap_cursor + page - 1u) & ~(page - 1u);

        for (; (uint64_t)candidate + aligned <= PW_WINE_GATE_HEAP_LIMIT;
             candidate += page) {
            status = backend->reserve_at(backend->context, candidate, aligned,
                                         page, region);
            if (status == PW_OK) {
                calls->heap_cursor = candidate + aligned;
                *base = candidate;
                return PW_OK;
            }
        }
        return PW_ERR_VM;
    }
    if ((desired & (page - 1u)) != 0u)
        return PW_ERR_MALFORMED;
    status = backend->reserve_at(backend->context, desired, aligned, page,
                                 region);
    if (status != PW_OK)
        return status;
    *base = desired;
    return PW_OK;
}

/* True when [base, base+bytes) lies entirely inside a region we mapped. */
static int region_covers(const PwWineCallContext *calls, uint32_t base,
                         uint32_t bytes)
{
    for (uint32_t index = 0; index < calls->region_count; ++index) {
        const PwWineCallContext *context = calls;
        const uint32_t low = (uint32_t)(uintptr_t)context->regions[index].exec_base;
        const uint64_t high = low + context->regions[index].bytes;

        if ((uint64_t)base >= low && (uint64_t)base + bytes <= high)
            return 1;
    }
    return 0;
}

/*
 * A returned region must stop being addressable by the guest: the block
 * leaves the dispatcher's declared ranges together with the mapping, so a
 * guest that keeps touching memory it gave back is refused by the same guard
 * that protects every other access.
 */
static void forget_declared_region(PwX86State *state, uint32_t base)
{
    for (uint32_t index = 0; index < state->memory_count; ++index) {
        if (state->memory[index].low != base)
            continue;
        state->memory[index] = state->memory[--state->memory_count];
        return;
    }
}

/*
 * NtAllocateVirtualMemory for the profile a first boot attempt reaches:
 * the current process, no zero bits, MEM_COMMIT|MEM_RESERVE and
 * PAGE_READWRITE. Value errors are answered with an NTSTATUS, because that
 * is what the guest's own contract expects; a guest pointer that does not
 * pass the accessor is a bridge refusal instead, and the argument index is
 * reported so the evidence names it.
 */
static int gate_nt_allocate_virtual_memory(PwWineCallContext *calls,
                                           const PwUnixCallFrame *frame,
                                           PwUnixCallAccess guest_access,
                                           void *access_context,
                                           uint32_t *status,
                                           uint32_t *argument_index)
{
    const uint32_t process_handle = frame->args[0];
    const uint32_t base_pointer = frame->args[1];
    const uint32_t zero_bits = frame->args[2];
    const uint32_t size_pointer = frame->args[3];
    const uint32_t allocation_type = frame->args[4];
    const uint32_t protect = frame->args[5];
    uint32_t base_value = 0u;
    uint32_t size_value = 0u;
    uint32_t base = 0u;
    PwVmRegion region;
    int result;

    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (guest_access(access_context, base_pointer, &base_value, 4u, 0) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (guest_access(access_context, size_pointer, &size_value, 4u, 0) != PW_OK) {
        *argument_index = 4u;
        return PW_ERR_MALFORMED;
    }
    if (zero_bits != 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    /*
     * MEM_RESERVE, MEM_COMMIT and their combination are all accepted; the
     * reserve/commit distinction is not yet modelled, because the dispatcher
     * only knows one kind of guest region. PAGE_READWRITE and the
     * reserve-only "no access yet" value are accepted for the same reason.
     */
    if ((allocation_type != 0x1000u && allocation_type != 0x2000u &&
         allocation_type != 0x3000u) ||
        (protect != 0u && protect != 0x04u) || size_value == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (calls->report->allocated_bytes > calls->limit ||
        size_value > calls->limit - calls->report->allocated_bytes) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    /*
     * MEM_COMMIT on a range this run already mapped is the normal second half
     * of "reserve then commit": it is idempotent, not a new reservation.
     */
    if ((allocation_type == 0x1000u || allocation_type == 0x3000u) &&
        base_value != 0u &&
        region_covers(calls, base_value, (size_value + 0xfffu) & ~0xfffu)) {
        uint32_t rounded = (size_value + 0xfffu) & ~0xfffu;

        if (guest_access(access_context, size_pointer, &rounded, 4u, 1) != PW_OK ||
            guest_access(access_context, base_pointer, &base_value, 4u, 1) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
        *status = PW_NT_SUCCESS;
        return PW_OK;
    }
    memset(&region, 0, sizeof(region));
    result = reserve_guest_block(calls, base_value,
                                 (size_value + 0xfffu) & ~0xfffu, &region,
                                 &base);
    if (result == PW_ERR_LIMIT) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (result != PW_OK) {
        *status = PW_NT_CONFLICTING_ADDRESSES;
        return PW_OK;
    }
    result = calls->low->base.commit(calls->low->base.context, &region, 0u,
                                     region.bytes,
                                     PW_PROT_READ | PW_PROT_WRITE);
    if (result != PW_OK) {
        (void) calls->low->base.release(calls->low->base.context, &region);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    /*
     * The guest must be able to address what it was just given, so the new
     * block joins the dispatcher's declared regions. Without this the very
     * next access to an NT allocation would be classified as out of bounds.
     */
    {
        PwX86State *state = access_context;

        if (state->memory_count >= PW_X86_MEMORY_REGIONS) {
            (void) calls->low->base.release(calls->low->base.context, &region);
            *status = PW_NT_INVALID_PARAMETER;
            return PW_OK;
        }
        state->memory[state->memory_count++] = (PwX86Memory){
            .low = base,
            .high = (uint64_t)base + region.bytes,
            .permissions = PW_X86_READ | PW_X86_WRITE,
        };
    }
    calls->regions[calls->region_count] = region;
    calls->region_owned[calls->region_count] = 1u;
    calls->region_count++;
    calls->report->allocations++;
    calls->report->allocated_bytes += (uint32_t)region.bytes;
    calls->report->call_regions = calls->region_count;
    {
        uint32_t written_size = (uint32_t)region.bytes;

        if (guest_access(access_context, size_pointer, &written_size, 4u, 1) != PW_OK ||
            guest_access(access_context, base_pointer, &base, 4u, 1) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* The two Windows free types, and the shape this bridge can honour. */
enum {
    PW_WINE_MEM_DECOMMIT = 0x4000u,
    PW_WINE_MEM_RELEASE = 0x8000u,
};

/*
 * NtFreeVirtualMemory for the same profile. The bridge models one kind of
 * guest region - a block this run reserved and mapped - so what it can
 * honour is the release of a whole one, which is exactly what a loader's
 * cleanup path asks for. A partial release and a MEM_DECOMMIT are answered
 * with real NTSTATUS values instead of a wrong success, because the
 * reserve/commit distinction is not modelled here. A successful release
 * removes the block from the dispatcher's declared ranges and returns the
 * mapping to the backend, so the guest cannot keep using memory it gave
 * back, and the base and size are written back the way Wine's own
 * implementation does.
 */
static int gate_nt_free_virtual_memory(PwWineCallContext *calls,
                                       const PwUnixCallFrame *frame,
                                       PwUnixCallAccess guest_access,
                                       void *access_context,
                                       uint32_t *status,
                                       uint32_t *argument_index)
{
    const uint32_t process_handle = frame->args[0];
    const uint32_t base_pointer = frame->args[1];
    const uint32_t size_pointer = frame->args[2];
    const uint32_t free_type = frame->args[3];
    uint32_t base_value = 0u;
    uint32_t size_value = 0u;

    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (guest_access(access_context, base_pointer, &base_value, 4u, 0) !=
        PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (guest_access(access_context, size_pointer, &size_value, 4u, 0) !=
        PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (free_type != PW_WINE_MEM_RELEASE) {
        *status = free_type == PW_WINE_MEM_DECOMMIT ? PW_NT_NOT_SUPPORTED
                                                    : PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (base_value == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    for (uint32_t index = 0; index < calls->region_count; ++index) {
        PwVmRegion region = calls->regions[index];
        const uint32_t region_base = (uint32_t)(uintptr_t)region.exec_base;
        const uint32_t released_owned = calls->region_owned[index];
        uint32_t region_bytes = (uint32_t)region.bytes;
        uint32_t released_bytes;
        uint32_t written_base = region_base;

        if (region_base != base_value)
            continue;
        /* A size of zero means "the whole region"; anything shorter is a
         * partial release, which this single-kind allocator cannot split. */
        released_bytes = size_value == 0u
            ? region_bytes
            : (size_value + 0xfffu) & ~0xfffu;
        if (released_bytes < region_bytes) {
            *status = PW_NT_UNABLE_TO_FREE_VM;
            return PW_OK;
        }
        if (calls->low->base.release(calls->low->base.context, &region) !=
            PW_OK) {
            *status = PW_NT_INVALID_PARAMETER;
            return PW_OK;
        }
        calls->regions[index] = calls->regions[--calls->region_count];
        calls->region_owned[index] = calls->region_owned[calls->region_count];
        calls->report->call_regions = calls->region_count;
        forget_declared_region(access_context, region_base);
        /* Wine writes the released base and size back into the guest's own
         * variables; the size becomes the whole region. */
        region_bytes = released_bytes;
        if (guest_access(access_context, base_pointer, &written_base, 4u,
                         1) != PW_OK ||
            guest_access(access_context, size_pointer, &region_bytes, 4u,
                         1) != PW_OK) {
            *argument_index = 2u;
            return PW_ERR_MALFORMED;
        }
        calls->report->releases++;
        /* A registered page (the process-parameters block the gate plays the
         * parent for) was never counted against the guest's live bytes. */
        if (released_owned && calls->report->allocated_bytes >= region_bytes)
            calls->report->allocated_bytes -= region_bytes;
        *status = PW_NT_SUCCESS;
        return PW_OK;
    }
    *status = PW_NT_MEMORY_NOT_ALLOCATED;
    return PW_OK;
}

/*
 * Platform file service plumbing. Handles are gate-owned indices so a guest
 * cannot forge one: the value carries a fixed base and the slot has to be
 * live, and every guest buffer is reached through the dispatcher's validated
 * accessor.
 */
static uint32_t file_handle_value(uint32_t index)
{
    return 0x100u + index;
}

static int file_handle_lookup(PwWineCallContext *calls, uint32_t value,
                              uint32_t *index)
{
    if (value < 0x100u || value - 0x100u >= PW_WINE_GATE_MAX_HANDLES)
        return PW_ERR_NOT_FOUND;
    if (!calls->handles[value - 0x100u].used)
        return PW_ERR_NOT_FOUND;
    *index = value - 0x100u;
    return PW_OK;
}

static int file_handle_alloc(PwWineCallContext *calls, void *token,
                             uint64_t size, int directory, uint32_t *value)
{
    for (uint32_t index = 0; index < PW_WINE_GATE_MAX_HANDLES; ++index) {
        if (calls->handles[index].used)
            continue;
        calls->handles[index] = (struct PwWineHandle){
            .token = token, .size = size, .offset = 0u,
            .directory = (uint8_t)(directory != 0), .used = 1u,
        };
        *value = file_handle_value(index);
        calls->report->file_handles++;
        return PW_OK;
    }
    return PW_ERR_LIMIT;
}

static int file_handle_release(PwWineCallContext *calls, uint32_t value)
{
    uint32_t index = 0u;

    if (file_handle_lookup(calls, value, &index) != PW_OK)
        return PW_ERR_NOT_FOUND;
    if (calls->config->files && calls->handles[index].token)
        calls->config->files->close(calls->config->files->context,
                                    calls->handles[index].token);
    memset(&calls->handles[index], 0, sizeof(calls->handles[index]));
    calls->report->file_closes++;
    if (calls->report->file_handles)
        calls->report->file_handles--;
    return PW_OK;
}

static char ascii_lower(char value)
{
    return value >= 'A' && value <= 'Z' ? (char)(value + 32) : value;
}

static int prefix_matches(const char *text, const char *prefix, size_t *used)
{
    size_t index = 0u;

    for (; prefix[index] != '\0'; ++index) {
        if (ascii_lower(text[index]) != ascii_lower(prefix[index]))
            return 0;
    }
    if (used)
        *used = index;
    return 1;
}

/*
 * Translates a guest DOS/NT path into a canonical file name inside the
 * runtime distribution, or fails. Only the two prefixes a Wine loader uses
 * are accepted, the remainder must be a single path component, and the result
 * is lower-cased, so ".." or an absolute host path cannot reach the service.
 */
static int translate_runtime_path(const char *path, char *out, size_t out_bytes,
                                  int *is_directory, uint32_t *status)
{
    const char *rest = path;
    size_t used = 0u;
    size_t length = 0u;
    int directory = 0;

    if (prefix_matches(rest, "\\??\\", &used))
        rest += used;
    if (prefix_matches(rest, "C:\\windows\\system32", &used) ||
        prefix_matches(rest, "C:\\windows", &used)) {
        rest += used;
        /* The directory itself: a single trailing separator, no component. */
        if (*rest == '\\' && rest[1] == '\0') {
            rest += 1u;
            directory = 1;
        } else if (*rest == '\0') {
            directory = 1;
        } else if (*rest != '\\') {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_NOT_FOUND;
        } else {
            rest += 1u;
        }
    } else {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_NOT_FOUND;
    }
    while (rest[length] != '\0') {
        const char character = rest[length];

        if (character == '\\' || character == '/' || character == ':' ||
            character == '\0' || length + 1u >= out_bytes) {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_MALFORMED;
        }
        out[length] = ascii_lower(character);
        ++length;
    }
    if (length == 0u) {
        if (!directory) {
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            return PW_ERR_MALFORMED;
        }
        out[0] = '\0';
        if (is_directory)
            *is_directory = 1;
        return PW_OK;
    }
    if (length >= 2u && out[length - 1u] == '.' && out[length - 2u] == '.') {
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        return PW_ERR_MALFORMED;
    }
    out[length] = '\0';
    if (is_directory)
        *is_directory = 0;
    return PW_OK;
}

/* Reads a guest UNICODE_STRING and converts it to ASCII. */
static int read_guest_unicode(PwUnixCallAccess guest, void *context,
                              uint32_t address, char *out, size_t out_bytes)
{
    uint8_t header[8];
    uint32_t buffer = 0u;
    uint16_t length = 0u;

    if (guest(context, address, header, sizeof(header), 0) != PW_OK)
        return PW_ERR_MALFORMED;
    memcpy(&length, header, 2u);
    memcpy(&buffer, header + 4u, 4u);
    if (length == 0u || (length & 1u) != 0u || buffer == 0u ||
        length / 2u + 1u > out_bytes)
        return PW_ERR_MALFORMED;
    for (uint32_t index = 0; index < length / 2u; ++index) {
        uint16_t unit = 0u;

        if (guest(context, buffer + index * 2u, &unit, 2u, 0) != PW_OK)
            return PW_ERR_MALFORMED;
        if (unit > 0x7fu)
            return PW_ERR_UNSUPPORTED;   /* the runtime paths are ASCII */
        out[index] = (char)unit;
    }
    out[length / 2u] = '\0';
    return PW_OK;
}

static void write_io_status(PwUnixCallAccess guest, void *context,
                            uint32_t address, uint32_t status,
                            uint64_t information)
{
    uint8_t block[8];

    memcpy(block, &status, 4u);
    memcpy(block + 4u, &information, 4u);
    (void)guest(context, address, block, sizeof(block), 1);
}


/*
 * The Windows directory itself is a gate-owned object. There is no
 * enumeration and no platform token behind it: the loader only needs its
 * existence, and FileStandardInformation reporting Directory = 1.
 */
static int open_directory_handle(PwWineCallContext *calls, const char *reported,
                                 uint32_t handle_pointer, uint32_t io_pointer,
                                 PwUnixCallAccess guest, void *context,
                                 uint32_t *status, uint32_t *argument_index)
{
    uint32_t handle = 0u;

    if (file_handle_alloc(calls, NULL, 0u, 1, &handle) != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)file_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    write_io_status(guest, context, io_pointer, PW_NT_SUCCESS, 0u);
    memcpy(calls->report->last_file, reported, strlen(reported) + 1u);
    calls->report->file_opens++;
    calls->report->file_directories++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtOpenFile for the runtime distribution. The accepted shape is the one a
 * loader uses: an OBJECT_ATTRIBUTES with a UNICODE_STRING name under the
 * Windows directory. Anything else is answered with a real NTSTATUS.
 */
static int gate_nt_open_file(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    uint8_t attributes[24];
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t attributes_pointer = frame->args[2];
    const uint32_t io_pointer = frame->args[3];
    uint32_t name_pointer = 0u;
    char wide[2u * PW_WINE_GATE_MAX_PATH];
    char name[PW_WINE_GATE_MAX_PATH + 1];
    int directory = 0;
    uint64_t size = 0u;
    void *token = NULL;
    uint32_t handle = 0u;

    if (attributes_pointer == 0u || io_pointer == 0u || handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, attributes_pointer, attributes, sizeof(attributes),
              0) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    memcpy(&name_pointer, attributes + 8u, 4u);
    if (name_pointer == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (read_guest_unicode(guest, context, name_pointer, wide, sizeof(wide)) !=
        PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (translate_runtime_path(wide, name, sizeof(name), &directory, status) !=
        PW_OK) {
        const size_t length = strlen(wide);

        if (length <= PW_WINE_GATE_MAX_PATH)
            memcpy(calls->report->last_file, wide, length + 1u);
        calls->report->file_refusals++;
        return PW_OK;
    }
    /*
     * The Windows directory itself is a gate-owned object: there is no
     * enumeration and no platform token behind it, and the loader only needs
     * its existence and Directory = 1 from the standard information.
     */
    if (directory)
        return open_directory_handle(calls, wide, handle_pointer, io_pointer,
                                     guest, context, status, argument_index);
    if (!calls->config->files) {
        *status = PW_NT_NOT_IMPLEMENTED;
        calls->report->file_refusals++;
        return PW_OK;
    }
    switch (calls->config->files->open(calls->config->files->context, name,
                                       &size, &token)) {
    case PW_WINE_FILE_OK:
        break;
    case PW_WINE_FILE_NOT_FOUND:
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        calls->report->file_refusals++;
        return PW_OK;
    case PW_WINE_FILE_DENIED:
        *status = PW_NT_ACCESS_DENIED;
        calls->report->file_refusals++;
        return PW_OK;
    default:
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->file_refusals++;
        return PW_OK;
    }
    if (file_handle_alloc(calls, token, size, 0, &handle) != PW_OK) {
        calls->config->files->close(calls->config->files->context, token);
        *status = PW_NT_INVALID_PARAMETER;
        return PW_OK;
    }
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        (void)file_handle_release(calls, handle);
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    write_io_status(guest, context, io_pointer, PW_NT_SUCCESS, 0u);
    memcpy(calls->report->last_file, name, strlen(name) + 1u);
    calls->report->file_opens++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

static int gate_nt_read_file(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[4];
    const uint32_t buffer = frame->args[5];
    const uint32_t length = frame->args[6];
    const uint32_t offset_pointer = frame->args[7];
    uint32_t index = 0u;
    uint64_t offset = 0u;
    uint8_t staging[PW_WINE_GATE_MAX_READ];
    uint32_t read_bytes = 0u;

    if (file_handle_lookup(calls, handle, &index) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (calls->handles[index].directory) {
        *status = PW_NT_INVALID_DEVICE_REQUEST;
        calls->report->file_refusals++;
        return PW_OK;
    }
    if (io_pointer == 0u || buffer == 0u || length == 0u) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (length > PW_WINE_GATE_MAX_READ) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->file_refusals++;
        return PW_OK;
    }
    offset = calls->handles[index].offset;
    if (offset_pointer != 0u) {
        uint8_t raw[8];
        uint32_t low = 0u, high = 0u;

        if (guest(context, offset_pointer, raw, sizeof(raw), 0) != PW_OK) {
            *argument_index = 7u;
            return PW_ERR_MALFORMED;
        }
        memcpy(&low, raw, 4u);
        memcpy(&high, raw + 4u, 4u);
        offset = (uint64_t)low | ((uint64_t)high << 32);
    }
    if (offset > calls->handles[index].size) {
        write_io_status(guest, context, io_pointer, PW_NT_END_OF_FILE, 0u);
        *status = PW_NT_SUCCESS;
        return PW_OK;
    }
    if (!calls->config->files ||
        calls->config->files->read(calls->config->files->context,
                                   calls->handles[index].token, offset, staging,
                                   length, &read_bytes) != PW_WINE_FILE_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (read_bytes != 0u &&
        guest(context, buffer, staging, read_bytes, 1) != PW_OK) {
        *argument_index = 6u;
        return PW_ERR_MALFORMED;
    }
    calls->handles[index].offset = offset + read_bytes;
    write_io_status(guest, context, io_pointer, PW_NT_SUCCESS, read_bytes);
    calls->report->file_reads++;
    calls->report->file_bytes += read_bytes;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

static int gate_nt_query_information_file(PwWineCallContext *calls,
                                          const PwUnixCallFrame *frame,
                                          PwUnixCallAccess guest, void *context,
                                          uint32_t *status,
                                          uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t information_class = frame->args[4];
    uint8_t block[22];
    uint32_t index = 0u;
    uint32_t written;

    if (file_handle_lookup(calls, handle, &index) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != 5u) {         /* FileStandardInformation */
        *status = PW_NT_INVALID_INFO_CLASS;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, &calls->handles[index].size, 8u);        /* AllocationSize */
    memcpy(block + 8u, &calls->handles[index].size, 8u);   /* EndOfFile */
    block[21] = calls->handles[index].directory;   /* Directory */
    written = length < sizeof(block) ? length : sizeof(block);
    if (written != 0u &&
        (information_pointer == 0u ||
         guest(context, information_pointer, block, written, 1) != PW_OK)) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (io_pointer != 0u)
        write_io_status(guest, context, io_pointer, PW_NT_SUCCESS, written);
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/* FileFsDeviceInformation: FILE_FS_DEVICE_INFORMATION {DeviceType, Characteristics}. */
enum {
    PW_WINE_FS_DEVICE_INFORMATION = 4u,
    PW_WINE_FS_DEVICE_INFORMATION_BYTES = 8u,
    /* FILE_DEVICE_DISK_FILE_SYSTEM: the runtime distribution is a directory
     * tree on a fixed disk, and the gate does not probe the host for it. */
    PW_WINE_DEVICE_DISK_FILE_SYSTEM = 0x00000008u,
};

/*
 * NtQueryVolumeInformationFile for a gate-owned handle. The loader asks one
 * question about the directory it just opened: RtlSetCurrentDirectory_U
 * queries FileFsDeviceInformation and closes the handle again when
 * FILE_REMOVABLE_MEDIA is set. The runtime distribution is a fixed disk, so
 * the answer carries no characteristics; every other information class stays
 * unhandled and the guest is told so with a real NTSTATUS.
 */
static int gate_nt_query_volume_information_file(PwWineCallContext *calls,
                                                 const PwUnixCallFrame *frame,
                                                 PwUnixCallAccess guest,
                                                 void *context,
                                                 uint32_t *status,
                                                 uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t io_pointer = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t information_class = frame->args[4];
    uint32_t index = 0u;
    uint8_t block[8];
    const uint32_t device_type = PW_WINE_DEVICE_DISK_FILE_SYSTEM;
    const uint32_t characteristics = 0u;

    if (file_handle_lookup(calls, handle, &index) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (information_class != PW_WINE_FS_DEVICE_INFORMATION) {
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->file_refusals++;
        return PW_OK;
    }
    if (length < PW_WINE_FS_DEVICE_INFORMATION_BYTES) {
        *status = PW_NT_BUFFER_TOO_SMALL;
        if (io_pointer != 0u)
            write_io_status(guest, context, io_pointer, *status, 0u);
        calls->report->file_refusals++;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, &device_type, 4u);
    memcpy(block + 4u, &characteristics, 4u);
    if (information_pointer == 0u ||
        guest(context, information_pointer, block, sizeof(block), 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (io_pointer != 0u)
        write_io_status(guest, context, io_pointer, PW_NT_SUCCESS,
                        sizeof(block));
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * Services one intercepted Unix call. PW_WINE_STOP_NONE means the guest may
 * continue: the handler's NTSTATUS is in EAX, the stdcall frame is popped and
 * EIP returns to the stub, exactly as Wine's own dispatcher would leave it.
 * Any other value is the reason the run stopped, and the guest state is
 * untouched so the evidence describes the boundary itself.
 */
static PwWineStop service_unix_call(PwWineCallContext *calls, PwX86State *state,
                                    PwWineGateReport *report)
{
    const uint32_t id = state->gpr[0];
    const PwUnixCallInfo *info = pw_unix_call_lookup(id);
    PwUnixCallFrame frame;
    uint32_t argument_index = 0u;
    uint32_t status = PW_NT_NOT_IMPLEMENTED;
    int result;

    report->observed_syscall_id = id;
    if (!info) {
        pw_unix_call_record(&report->calls, NULL, NULL, status, 0u,
                            PW_UNIX_CALL_UNKNOWN);
        return PW_WINE_STOP_UNIX_CALL_UNKNOWN;
    }
    result = pw_unix_call_read(info, gate_guest_access, state, state->gpr[4],
                               &frame, &argument_index);
    if (result != PW_OK) {
        pw_unix_call_record(&report->calls, &frame, info, status,
                            argument_index, PW_UNIX_CALL_REJECTED);
        return PW_WINE_STOP_UNIX_CALL_REJECTED;
    }
    /* The switch below services what has a handler; a known number without
     * one falls through to the unimplemented stop, so the frame is still
     * understood and reported and the guest does not continue past it. */
    switch (info->id) {
    case 0x0018u:
        result = gate_nt_allocate_virtual_memory(calls, &frame,
                                                 gate_guest_access, state,
                                                 &status, &argument_index);
        break;
    case 0x001eu:
        result = gate_nt_free_virtual_memory(calls, &frame, gate_guest_access,
                                             state, &status,
                                             &argument_index);
        break;
    case 0x0033u:
        result = gate_nt_open_file(calls, &frame, gate_guest_access, state,
                                   &status, &argument_index);
        break;
    case 0x0006u:
        result = gate_nt_read_file(calls, &frame, gate_guest_access, state,
                                   &status, &argument_index);
        break;
    case 0x0011u:
        result = gate_nt_query_information_file(calls, &frame,
                                                gate_guest_access, state,
                                                &status, &argument_index);
        break;
    case 0x0049u:
        result = gate_nt_query_volume_information_file(
            calls, &frame, gate_guest_access, state, &status, &argument_index);
        break;
    case 0x000fu:
        if (file_handle_release(calls, frame.args[0]) == PW_OK)
            status = PW_NT_SUCCESS;
        else
            status = PW_NT_INVALID_HANDLE;
        result = PW_OK;
        break;
    default:
        /* A known call number with no handler: it is reported as
         * unimplemented rather than as a refusal of the bridge. */
        status = PW_NT_NOT_IMPLEMENTED;
        result = PW_OK;
        break;
    }
    if (result != PW_OK) {
        pw_unix_call_record(&report->calls, &frame, info, status,
                            argument_index, PW_UNIX_CALL_REJECTED);
        return PW_WINE_STOP_UNIX_CALL_REJECTED;
    }
    if (status == PW_NT_NOT_IMPLEMENTED) {
        pw_unix_call_record(&report->calls, &frame, info, status, 0u,
                            PW_UNIX_CALL_UNIMPLEMENTED);
        return PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED;
    }
    pw_unix_call_record(&report->calls, &frame, info, status,
                        info->arg_bytes / 4u, PW_UNIX_CALL_HANDLED);
    /* Return to the stub with its stdcall frame popped. */
    state->gpr[0] = status;
    /* [esp] is the stub's own return address and [esp+4] the caller's, so
     * resuming means dropping both plus the arguments the stub's ret would
     * have popped. */
    state->gpr[4] += 8u + info->arg_bytes;
    state->eip = frame.return_pc;
    report->calls_serviced++;
    return PW_WINE_STOP_NONE;
}

/*
 * Declares the guest memory the dispatcher may touch. The DBT's guard is
 * region-granular, so each module contributes its whole image as readable
 * plus the union of its writable sections as writable; a write into code is
 * then classified instead of relying on a native fault. Exact page
 * protection is still the mapper's installed protection, which the loader
 * already validated.
 */
static int declare_guest_memory(PwX86State *state, const PwLoader *loader,
                                uint32_t stack_base, uint32_t stack_bytes,
                                const PwVmRegion *thread_block,
                                const PwVmRegion *process_block,
                                const PwVmRegion *parameters_block)
{
    uint32_t used = 0u;

    if (loader->module_count * 2u + 4u > PW_X86_MEMORY_REGIONS)
        return PW_ERR_LIMIT;
    state->stack_low = stack_base;
    state->stack_high = stack_base + stack_bytes;
    state->memory[used++] = (PwX86Memory){
        .low = stack_base, .high = stack_base + stack_bytes,
        .permissions = PW_X86_READ | PW_X86_WRITE,
    };
    if (thread_block && thread_block->write_base) {
        /* The TEB the guest reaches through FS: its own block, writable. */
        state->memory[used++] = (PwX86Memory){
            .low = (uint32_t)(uintptr_t)thread_block->exec_base,
            .high = (uint32_t)((uintptr_t)thread_block->exec_base +
                               thread_block->bytes),
            .permissions = PW_X86_READ | PW_X86_WRITE,
        };
    }
    if (process_block && process_block->write_base) {
        /* The PEB ntdll reaches through TEB->ProcessEnvironmentBlock. */
        state->memory[used++] = (PwX86Memory){
            .low = (uint32_t)(uintptr_t)process_block->exec_base,
            .high = (uint32_t)((uintptr_t)process_block->exec_base +
                               process_block->bytes),
            .permissions = PW_X86_READ | PW_X86_WRITE,
        };
    }
    if (parameters_block && parameters_block->write_base) {
        /* The zeroed process-parameters page PEB->ProcessParameters points at. */
        state->memory[used++] = (PwX86Memory){
            .low = (uint32_t)(uintptr_t)parameters_block->exec_base,
            .high = (uint32_t)((uintptr_t)parameters_block->exec_base +
                               parameters_block->bytes),
            .permissions = PW_X86_READ | PW_X86_WRITE,
        };
    }
    for (uint32_t index = 0; index < loader->module_count; ++index) {
        const PwModule *module = &loader->modules[index];
        uint32_t writable_low = 0u;
        uint32_t writable_high = 0u;

        if (!module->mapped_ok)
            continue;
        state->memory[used++] = (PwX86Memory){
            .low = (uint32_t)module->mapped.actual_base,
            .high = (uint32_t)(module->mapped.actual_base +
                               module->mapped.image_bytes),
            .permissions = PW_X86_READ,
        };
        for (uint32_t section = 0; section < module->layout.section_count;
             ++section) {
            const PeLayoutSection *entry = &module->layout.sections[section];
            const uint32_t low = (uint32_t)module->mapped.actual_base +
                                 entry->rva;
            const uint32_t high = low + entry->mapped_bytes;

            if ((entry->protection & PW_PROT_WRITE) == 0u)
                continue;
            if (writable_low == 0u || low < writable_low)
                writable_low = low;
            if (high > writable_high)
                writable_high = high;
        }
        if (writable_low != 0u && writable_low < writable_high) {
            if (used == PW_X86_MEMORY_REGIONS)
                return PW_ERR_LIMIT;
            state->memory[used++] = (PwX86Memory){
                .low = writable_low, .high = writable_high,
                .permissions = PW_X86_READ | PW_X86_WRITE,
            };
        }
    }
    state->memory_count = used;
    return PW_OK;
}

/*
 * One zeroed guest page, reserved below the 32-bit boundary. The gate uses
 * two: the thread's TEB (what FS points at) and a PEB handed to ntdll's
 * initialization entry as its first argument.
 */
static int allocate_guest_page(const PwWineGateConfig *config,
                               PwWineLowBackend *low, uint32_t base,
                               PwVmRegion *region, uint32_t *address)
{
    int status;

    if ((low->base.capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u)
        status = low->base.reserve_at(low->base.context, base,
                                      PW_WINE_GATE_STACK_BYTES,
                                      low->base.page_bytes, region);
    else
        status = config->backend->reserve(config->backend->context,
                                          PW_WINE_GATE_STACK_BYTES,
                                          config->backend->page_bytes, region);
    if (status != PW_OK)
        return status;
    if ((uint64_t)(uintptr_t)region->exec_base + region->bytes >
        0x100000000ull)
        return PW_ERR_UNSUPPORTED;
    status = config->backend->commit(config->backend->context, region, 0u,
                                     region->bytes,
                                     PW_PROT_READ | PW_PROT_WRITE);
    if (status != PW_OK)
        return status;
    memset(region->write_base, 0, region->bytes);
    *address = (uint32_t)(uintptr_t)region->exec_base;
    return PW_OK;
}

/*
 * A minimal but populated RTL_USER_PROCESS_PARAMETERS: sizes, the current
 * directory, the DLL and image paths, the command line and an environment
 * block, all as UTF-16LE strings inside the same declared page. ntdll reads
 * these during loader and heap initialisation; a zeroed page is what makes it
 * dereference a null Buffer. This is still not a Windows process environment
 * - there is no registry, no NLS data and no drive-letter table - but the
 * fields the loader asks for are present and self-consistent.
 */
static uint32_t write_wide(uint8_t *page, uint32_t *cursor, const char *ascii)
{
    const uint32_t offset = *cursor;

    while (*ascii != '\0') {
        page[*cursor] = (uint8_t)*ascii++;
        page[*cursor + 1u] = 0u;
        *cursor += 2u;
    }
    page[*cursor] = 0u;
    page[*cursor + 1u] = 0u;
    *cursor += 2u;
    return offset;
}

static void set_unicode_string(uint8_t *page, uint32_t field, uint32_t offset,
                               const char *text)
{
    const uint32_t base = (uint32_t)(uintptr_t)page;
    const uint16_t bytes = (uint16_t)(strlen(text) * 2u);

    memcpy(page + field, &bytes, 2u);
    memcpy(page + field + 2u, &bytes, 2u);
    {
        const uint32_t buffer = base + offset;

        memcpy(page + field + 4u, &buffer, 4u);
    }
}

static int populate_process_parameters(uint8_t *page, uint32_t page_bytes,
                                       const char *root_module,
                                       uint32_t *length_out)
{
    uint32_t cursor = 0x100u;
    uint32_t current_offset;
    uint32_t dll_offset;
    uint32_t image_offset;
    uint32_t command_offset;
    uint32_t environment_offset;
    char image_path[128];

    if (!page || page_bytes < 4096u || !root_module)
        return PW_ERR_PRECONDITION;
    if (strlen(root_module) + sizeof("C:\\windows\\system32\\") >
        sizeof(image_path))
        return PW_ERR_LIMIT;
    memcpy(image_path, "C:\\windows\\system32\\",
           sizeof("C:\\windows\\system32\\") - 1u);
    memcpy(image_path + sizeof("C:\\windows\\system32\\") - 1u,
           root_module, strlen(root_module) + 1u);

    current_offset = write_wide(page, &cursor, "C:\\windows");
    dll_offset = write_wide(page, &cursor, "C:\\windows\\system32");
    image_offset = write_wide(page, &cursor, image_path);
    command_offset = write_wide(page, &cursor, image_path);
    environment_offset = write_wide(page, &cursor, "SystemRoot=C:\\windows");
    page[cursor] = 0u;
    page[cursor + 1u] = 0u;
    cursor += 2u;

    set_unicode_string(page, 0x24u, current_offset, "C:\\windows");
    set_unicode_string(page, 0x30u, dll_offset, "C:\\windows\\system32");
    set_unicode_string(page, 0x38u, image_offset, image_path);
    set_unicode_string(page, 0x40u, command_offset, image_path);
    {
        const uint32_t base = (uint32_t)(uintptr_t)page;
        const uint32_t environment = base + environment_offset;

        memcpy(page + 0x48u, &environment, 4u);
    }
    memcpy(page + 0x00u, &cursor, 4u);      /* MaximumLength */
    memcpy(page + 0x04u, &cursor, 4u);      /* Length */
    if (length_out)
        *length_out = cursor;
    return PW_OK;
}

int pw_wine_gate_run(const PwWineGateConfig *config, PwWineGateReport *report)
{
    /* Large by design: the bind workspace holds one module's import table. */
    static PwImportBindWorkspace workspace;
    static PwLoader loader;
    static PwExportResolver resolver;
    static PwX86CacheEntry cache[PW_WINE_GATE_CACHE_ENTRIES];

    PwWineLowBackend low;
    PwX86Engine engine;
    PwImportBindReport bind;
    PeExportDirectory directory;
    PeExportSymbol symbol;
    PwGuestCall call;
    PwFileSpan root_span;
    PwVmRegion stack;
    PwVmRegion teb;
    PwVmRegion peb;
    PwVmRegion parameters;
    PwWineCallContext calls;
    PwX86State state;
    uint32_t thunks[PW_WINE_GATE_MAX_BOUNDARIES];
    const PwModule *entry_module;
    char root_canonical[PW_MODULE_NAME_MAX + 1];
    uint32_t budget;
    int status;
    int have_loader = 0;
    int have_engine = 0;
    int have_stack = 0;
    int have_teb = 0;
    int have_peb = 0;

    if (!config || !report || !config->provider || !config->backend ||
        config->module_count == 0u ||
        config->module_count > PW_WINE_GATE_MAX_MODULES)
        return PW_ERR_PRECONDITION;
    memset(report, 0, sizeof(*report));
    memset(&root_span, 0, sizeof(root_span));
    memset(&teb, 0, sizeof(teb));
    memset(&peb, 0, sizeof(peb));
    memset(&parameters, 0, sizeof(parameters));
    memset(&calls, 0, sizeof(calls));
    memset(&call, 0, sizeof(call));
    budget = config->step_budget != 0u ? config->step_budget
                                       : PW_WINE_GATE_DEFAULT_STEPS;
    if (budget > PW_WINE_GATE_MAX_STEPS)
        return PW_ERR_PRECONDITION;
    report->stop = PW_WINE_STOP_GATE_ERROR;
    low_backend_init(&low, config->backend);

    /* Fingerprint every configured module before mapping anything. */
    for (uint32_t index = 0; index < config->module_count; ++index) {
        PwWineModuleRecord *record = &report->modules[report->module_count];

        if (pw_module_name_canonical(record->name, sizeof(record->name),
                                     config->modules[index]) != PW_OK)
            return PW_ERR_PRECONDITION;
        report->module_count++;
        if (hash_module(config->provider, record->name, record) != PW_OK)
            return PW_ERR_NOT_FOUND;
    }

    status = pw_loader_init(&loader, config->provider, &low.base);
    if (status != PW_OK)
        return status;
    have_loader = 1;
    status = pw_loader_set_policy(&loader, &(PwModulePolicy){
        .context = NULL, .classify = pw_loader_wine_policy,
    });
    if (status != PW_OK)
        goto done;
    {
        const char *root = config->root_module ? config->root_module
                                               : "kernelbase.dll";

        status = pw_module_name_canonical(root_canonical,
                                          sizeof(root_canonical), root);
        if (status != PW_OK)
            goto done;
        status = config->provider->open_namespace(config->provider->context,
                                                  PW_FILE_RUNTIME,
                                                  root_canonical,
                                                  &root_span);
        if (status != PW_OK)
            goto done;
        status = pw_loader_load(&loader, root_span.bytes, root_span.size,
                                root_canonical);
        if (status != PW_OK)
            goto done;
    }

    /* Bind every loaded module's imports through one resolver. */
    status = pw_export_resolver_init(&resolver, &loader, 4u);
    if (status != PW_OK)
        goto done;
    for (uint32_t index = 0; index < loader.module_count; ++index) {
        PwModule *module = &loader.modules[index];
        PwWineModuleRecord *record = record_for(report, module->name);

        if (record) {
            record->loaded = 1u;
            /* The gate opens every module through PW_FILE_RUNTIME; the root
             * is registered as PW_MODULE_ROOT by the loader, not as a
             * dependency, so its origin is recorded from here. */
            record->runtime =
                (uint8_t)(module->kind == PW_MODULE_RUNTIME ||
                          strcmp(module->name, root_canonical) == 0);
            record->machine = module->machine;
            record->base = (uint32_t)module->mapped.actual_base;
            record->image_bytes = module->mapped.image_bytes;
            record->imports = module->import_symbols;
        }
        if (module->import_symbols == 0u)
            continue;
        if (module->image.machine != PE_MACHINE_I386)
            continue;
        status = pw_import_bind32(&module->image, &module->mapped,
                                  pw_export_import_resolver, &resolver,
                                  &workspace, &bind);
        if (status != PW_OK) {
            report->bind_failures++;
            goto done;
        }
        report->bound_functions += bind.functions;
        report->bound_data += bind.data;
        report->bound_modules++;
        if (record) {
            record->exports_named = 0u;
            record->exports_ordinal = 0u;
        }
    }

    /* TLS is a per-module loader contract; record what the real modules
     * declare instead of assuming every module has a directory. */
    for (uint32_t index = 0; index < loader.module_count; ++index) {
        const PwModule *module = &loader.modules[index];
        PeTlsDirectory tls;
        PwWineModuleRecord *record = record_for(report, module->name);

        if (pe_tls_parse(&tls, &module->image) != PW_OK)
            goto done;
        if (tls.directory_rva != 0u) {
            report->tls_modules++;
            if (record)
                record->tls_present = 1u;
        }
    }

    /* The Unix-call boundary: exported dispatcher slot, then its thunk. */
    {
        const char *dispatcher = config->dispatcher_symbol
            ? config->dispatcher_symbol : "__wine_syscall_dispatcher";
        const char *entry_name = config->entry_symbol
            ? config->entry_symbol : "NtClose";
        const char *entry_machine = config->entry_module
            ? config->entry_module : "ntdll.dll";
        char canonical[PW_MODULE_NAME_MAX + 1];
        int entry_index;

        status = pw_module_name_canonical(canonical, sizeof(canonical),
                                          entry_machine);
        if (status != PW_OK)
            goto done;
        entry_index = pw_loader_find(&loader, canonical);
        if (entry_index < 0) {
            status = entry_index;
            goto done;
        }
        entry_module = pw_loader_module(&loader, (uint32_t)entry_index);
        status = pe_export_parse(&directory, &entry_module->image);
        if (status != PW_OK)
            goto done;
        status = pe_export_find_name(&entry_module->image, &directory,
                                     dispatcher, &symbol);
        if (status != PW_OK)
            goto done;
        report->boundary_slot_rva = symbol.rva;
        report->boundary_slot_va =
            (uint32_t)pw_map_exec_address(&entry_module->mapped, symbol.rva);
        report->boundary_count =
            find_dispatcher_thunks(entry_module, report->boundary_slot_va,
                                   thunks, PW_WINE_GATE_MAX_BOUNDARIES);
        if (report->boundary_count == 0u) {
            status = PW_ERR_NOT_FOUND;
            goto done;
        }
        report->boundary_thunk_rva = thunks[0];
        report->boundary_thunk_va =
            (uint32_t)entry_module->mapped.actual_base + thunks[0];
        report->entry_pe_rva = entry_module->mapped.entry_point;

        status = pe_export_find_name(&entry_module->image, &directory,
                                     entry_name, &symbol);
        if (status != PW_OK)
            goto done;
        if (symbol.is_forwarder || symbol.is_code == 0u) {
            status = PW_ERR_UNSUPPORTED;
            goto done;
        }
        report->entry_rva = symbol.rva;
        report->entry_eip =
            (uint32_t)pw_map_exec_address(&entry_module->mapped, symbol.rva);
        report->stub_syscall_id =
            decode_stub_syscall(entry_module, symbol.rva);
    }

    /* Guest stack for the one stdcall frame the gate enters. */
    {
        uint32_t base = config->stack_base != 0u ? config->stack_base
                                                 : 0x0f000000u;
        int reserved = PW_ERR_VM;

        if ((low.base.capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u)
            reserved = low.base.reserve_at(low.base.context, base,
                                           PW_WINE_GATE_STACK_BYTES,
                                           low.base.page_bytes, &stack);
        if (reserved != PW_OK)
            reserved = config->backend->reserve(config->backend->context,
                                               PW_WINE_GATE_STACK_BYTES,
                                               config->backend->page_bytes,
                                               &stack);
        if (reserved != PW_OK) {
            status = reserved;
            goto done;
        }
        have_stack = 1;
        report->stack_base = (uint32_t)(uintptr_t)stack.exec_base;
        report->stack_bytes = (uint32_t)stack.bytes;
        if ((uint64_t)stack.exec_base + stack.bytes > 0x100000000ull) {
            status = PW_ERR_UNSUPPORTED;
            goto done;
        }
        status = config->backend->commit(config->backend->context, &stack, 0u,
                                         PW_WINE_GATE_STACK_BYTES,
                                         PW_PROT_READ | PW_PROT_WRITE);
        if (status != PW_OK)
            goto done;
    }

    /* Minimal guest thread and process blocks. They are deliberately small:
     * enough for ntdll's first initialization instructions to read a TEB
     * through FS and a PEB through its argument, not a Windows process
     * environment. The offsets are the documented NT TEB fields. */
    {
        uint32_t stack_high =
            report->stack_base + report->stack_bytes;

        status = allocate_guest_page(config, &low, 0x0e000000u, &teb,
                                     &report->teb_base);
        if (status != PW_OK)
            goto done;
        have_teb = 1;
        report->teb_bytes = (uint32_t)teb.bytes;
        status = allocate_guest_page(config, &low, 0x0d000000u, &peb,
                                     &report->peb_base);
        if (status != PW_OK)
            goto done;
        have_peb = 1;
        status = allocate_guest_page(config, &low, 0x0c000000u, &parameters,
                                     &report->parameters_base);
        if (status != PW_OK)
            goto done;
        status = populate_process_parameters(parameters.write_base,
                                             (uint32_t)parameters.bytes,
                                             root_canonical,
                                             &report->parameters_length);
        if (status != PW_OK)
            goto done;
        /*
         * The parameters block stands in for the memory a parent hands a new
         * process, and ntdll's init_user_process_params replaces it with its
         * own copy and releases the original with NtFreeVirtualMemory. The
         * block is therefore registered as one of this run's guest regions
         * (owned = 0, because the guest never allocated it and it is not
         * counted against its live bytes), so that release finds it instead
         * of being told the address was never allocated.
         */
        if (calls.region_count >= PW_WINE_GATE_MAX_CALL_REGIONS) {
            status = PW_ERR_LIMIT;
            goto done;
        }
        calls.regions[calls.region_count] = parameters;
        calls.region_owned[calls.region_count] = 0u;
        calls.region_count++;
        report->call_regions = calls.region_count;
        {
            uint8_t *peb_block = peb.write_base;
            const PwModule *root_module_loaded =
                pw_loader_module(&loader, 0u);

            /* PEB->ProcessParameters (0x10) and PEB->ImageBaseAddress
             * (0x08): ntdll reads both during loader initialisation. */
            memcpy(peb_block + 0x10, &report->parameters_base, 4u);
            if (root_module_loaded) {
                const uint32_t image_base =
                    (uint32_t)root_module_loaded->mapped.actual_base;

                memcpy(peb_block + 0x08, &image_base, 4u);
            }
        }
        {
            uint8_t *block = teb.write_base;

            memcpy(block + 0x04, &stack_high, 4u);   /* StackBase */
            memcpy(block + 0x08, &report->stack_base, 4u); /* StackLimit */
            memcpy(block + 0x18, &report->teb_base, 4u);   /* Self */
            /* TEB->ProcessEnvironmentBlock: ntdll's first server-side reads
             * go through this pointer, so the gate links the two blocks. */
            memcpy(block + 0x30, &report->peb_base, 4u);
            /* ThreadLocalStoragePointer stays zero: no module of this
             * distribution declares a TLS directory, and a zeroed slot is
             * the honest value until the TLS owner publishes an index. */
        }
    }

    memset(&state, 0, sizeof(state));
    state.gpr[4] = (report->stack_base + report->stack_bytes - 16u) & ~15u;
    state.eip = report->entry_eip;
    state.fs_base = report->teb_base;
    state.fs_bytes = report->teb_bytes;
    status = declare_guest_memory(&state, &loader, report->stack_base,
                                  report->stack_bytes, &teb, &peb,
                                  &parameters);
    if (status != PW_OK)
        goto done;
    report->guest_regions = state.memory_count;
    {
        const uint32_t token = 0u;

        memcpy((void *)(uintptr_t)state.gpr[4], &token, 4u);
    }

    status = pw_x86_engine_init(&engine, &low.base, cache,
                                PW_WINE_GATE_CACHE_ENTRIES,
                                PW_WINE_GATE_ARENA_BYTES, 1u,
                                gate_source_view, &loader);
    if (status != PW_OK)
        goto done;
    have_engine = 1;
    report->files_configured = config->files != NULL;
    calls.low = &low;
    calls.config = config;
    calls.report = report;
    calls.heap_cursor = PW_WINE_GATE_HEAP_BASE;
    calls.limit = config->allocation_limit != 0u ? config->allocation_limit
                                                 : PW_WINE_GATE_DEFAULT_ALLOCATION_LIMIT;
    /* Mode toggles exist so the same real code can be run with chaining,
     * register residency and lazy flags on and off and compared. */
    if (config->modes_set) {
        status = pw_x86_engine_set_chaining(&engine, config->chaining);
        if (status == PW_OK)
            status = pw_x86_engine_set_residency(&engine, config->residency);
        if (status == PW_OK)
            status = pw_x86_engine_set_lazy_flags(&engine, config->lazy_flags);
        if (status != PW_OK)
            goto done;
    }
    report->chaining = engine.chaining_enabled;
    report->residency = engine.residency_enabled;
    report->lazy_flags = engine.lazy_flags_enabled;
    status = pw_guest_call_begin(&call, &state, PW_GUEST_STDCALL, 4u, 0);
    if (status != PW_OK)
        goto done;
    /* ntdll's initialization entry takes the PEB as its first argument. */
    memcpy((void *)(uintptr_t)(state.gpr[4] + 4u), &report->peb_base, 4u);

    report->first_eip = state.eip;
    report->stop = PW_WINE_STOP_STEP_BUDGET;
    for (uint32_t step = 0; step < budget; ++step) {
        PwX86StepReport progress;

        if (config->trace)
            config->trace(config->trace_context, &state);
        if (state.eip == report->boundary_thunk_va) {
            /* Stopped before executing the dispatcher jump: no unvalidated
             * guest pointer is dereferenced to reach it. */
            report->observed_syscall_id = state.gpr[0];
            if (config->bridge_calls) {
                const uint32_t budget = config->call_budget != 0u
                    ? config->call_budget : PW_WINE_GATE_DEFAULT_CALLS;
                PwWineStop serviced;

                report->stop_address = state.eip;
                if (report->calls_serviced >= budget) {
                    report->stop = PW_WINE_STOP_STEP_BUDGET;
                    break;
                }
                serviced = service_unix_call(&calls, &state, report);
                if (serviced == PW_WINE_STOP_NONE)
                    continue;
                report->stop = serviced;
                report->stop_address = state.eip;
                break;
            }
            report->stop = PW_WINE_STOP_UNIX_CALL_BOUNDARY;
            report->stop_address = state.eip;
            break;
        }
        if (state.eip == 0u || state.eip == call.return_pc) {
            report->stop = PW_WINE_STOP_RETURNED_TO_CALLER;
            report->stop_address = state.eip;
            break;
        }
        status = pw_x86_engine_step(&engine, &state, &progress);
        report->dispatches++;
        report->retired += progress.retired;
        if (status != PW_OK) {
            report->stop = classify(status);
            report->stop_address = state.eip;
            break;
        }
    }
    report->last_eip = state.eip;
    report->fault_address = state.fault_address;
    report->fault_width = state.fault_width;
    report->fault_write = state.fault_write;
    /*
     * Independent identification of the call that reached the boundary. The
     * stub calls the dispatcher, so the guest return address on top of the
     * stack points into that stub; its own "mov eax, id" must name the
     * syscall we observed in EAX. This binds the number to the image instead
     * of trusting the register alone.
     */
    /* Any stop that happened at the thunk leaves the same two-level frame on
     * the guest stack, including the ones a bridged run stops with. */
    if (report->stop_address == report->boundary_thunk_va &&
        report->boundary_thunk_va != 0u && entry_module &&
        state.gpr[4] >= state.stack_low &&
        (uint64_t)state.gpr[4] + 4u <= state.stack_high) {
        uint32_t return_eip = 0u;
        const uint64_t base = entry_module->mapped.actual_base;
        const uint64_t end = base + entry_module->mapped.image_bytes;

        memcpy(&return_eip, (const void *)(uintptr_t)state.gpr[4], 4u);
        report->boundary_return_eip = return_eip;
        if ((uint64_t)return_eip >= base && (uint64_t)return_eip < end) {
            const uint32_t rva = (uint32_t)((uint64_t)return_eip - base);
            const uint8_t *image = entry_module->mapped.region.write_base;

            report->boundary_return_in_module = 1u;
            for (uint32_t back = 0; back <= 16u && back <= rva; back++) {
                const uint32_t here = rva - back;
                uint32_t operand = 0u;

                /* "mov edx, <dispatcher thunk>" then, five bytes earlier,
                 * "mov eax, <syscall id>". */
                if (here + 6u > entry_module->mapped.image_bytes ||
                    image[here] != 0xbau)
                    continue;
                memcpy(&operand, image + here + 1u, 4u);
                if (operand != report->boundary_thunk_va)
                    continue;
                if (here < 5u || image[here - 5u] != 0xb8u)
                    continue;
                memcpy(&report->caller_stub_id, image + here - 4u, 4u);
                report->caller_stub_rva = here - 5u;
                break;
            }
        }
    }
    report->translated_blocks = engine.cache.publishes;
    report->translated_bytes = engine.cache.cursor;
    /* No host Wine entry point is ever called: the gate only translates and
     * executes guest bytes it mapped itself. */
    report->host_calls = 0u;

done:
    report->status = status;
    for (uint32_t index = 0; index < PW_WINE_GATE_MAX_HANDLES; ++index) {
        if (calls.handles[index].used)
            (void)file_handle_release(&calls, file_handle_value(index));
    }
    if (have_engine) {
        if (pw_x86_engine_destroy(&engine) == PW_OK)
            report->cleanup_translations++;
    }
    if (have_stack) {
        if (config->backend->release(config->backend->context, &stack) == PW_OK)
            report->cleanup_mappings++;
    }
    if (have_teb &&
        config->backend->release(config->backend->context, &teb) == PW_OK)
        report->cleanup_mappings++;
    if (have_peb &&
        config->backend->release(config->backend->context, &peb) == PW_OK)
        report->cleanup_mappings++;
    /* The parameters page is registered among the call regions (it is the
     * block ntdll replaces and releases), so it is released below with them
     * and only once, whether or not the guest already gave it back. */
    for (uint32_t index = 0; index < calls.region_count; ++index) {
        if (calls.low->base.release(calls.low->base.context,
                                    &calls.regions[index]) == PW_OK)
            report->cleanup_mappings++;
    }
    if (have_loader) {
        report->cleanup_modules = loader.module_count;
        report->cleanup_mappings += loader.module_count;
        (void)pw_loader_release(&loader);
    }
    if (root_span.bytes && config->provider->close)
        config->provider->close(config->provider->context, &root_span);
    if (status == PW_OK)
        status = pw_wine_stop_is_acceptance(report->stop) ? PW_OK
                                                          : PW_ERR_UNSUPPORTED;
    report->status = status;
    return status;
}

const char *pw_wine_stop_name(PwWineStop stop)
{
    switch (stop) {
    case PW_WINE_STOP_NONE: return "none";
    case PW_WINE_STOP_UNIX_CALL_BOUNDARY: return "wine-unix-call-boundary";
    case PW_WINE_STOP_UNSUPPORTED_INSTRUCTION: return "unsupported-instruction";
    case PW_WINE_STOP_MEMORY_BOUNDS: return "memory-bounds";
    case PW_WINE_STOP_CACHE_LIMIT: return "cache-limit";
    case PW_WINE_STOP_NON_CODE: return "non-code";
    case PW_WINE_STOP_DECODE_FAILURE: return "decode-failure";
    case PW_WINE_STOP_X87_TRAP: return "x87-trap";
    case PW_WINE_STOP_STEP_BUDGET: return "step-budget";
    case PW_WINE_STOP_RETURNED_TO_CALLER: return "returned-to-caller";
    case PW_WINE_STOP_GATE_ERROR: return "gate-error";
    case PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED: return "unix-call-unimplemented";
    case PW_WINE_STOP_UNIX_CALL_UNKNOWN: return "unix-call-unknown";
    case PW_WINE_STOP_UNIX_CALL_REJECTED: return "unix-call-rejected";
    default: return "unknown";
    }
}

int pw_wine_stop_is_acceptance(PwWineStop stop)
{
    return stop == PW_WINE_STOP_UNIX_CALL_BOUNDARY;
}
