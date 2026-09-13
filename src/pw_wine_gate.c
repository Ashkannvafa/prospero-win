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
                                const PwVmRegion *process_block)
{
    uint32_t used = 0u;

    if (loader->module_count * 2u + 3u > PW_X86_MEMORY_REGIONS)
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
                                  report->stack_bytes, &teb, &peb);
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
    /*
     * Independent identification of the call that reached the boundary. The
     * stub calls the dispatcher, so the guest return address on top of the
     * stack points into that stub; its own "mov eax, id" must name the
     * syscall we observed in EAX. This binds the number to the image instead
     * of trusting the register alone.
     */
    if (report->stop == PW_WINE_STOP_UNIX_CALL_BOUNDARY && entry_module &&
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
    default: return "unknown";
    }
}

int pw_wine_stop_is_acceptance(PwWineStop stop)
{
    return stop == PW_WINE_STOP_UNIX_CALL_BOUNDARY;
}
