/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_loader.h"

#include "pw_module_name.h"

#include <string.h>

enum {
    VISIT_NEW = 0,
    VISIT_ACTIVE = 1,
    VISIT_DONE = 2,
};

int pw_file_provider_valid(const PwFileProvider *provider)
{
    return provider && provider->open && provider->close;
}

const char *pw_module_kind_name(unsigned kind)
{
    switch (kind) {
    case PW_MODULE_ROOT: return "root";
    case PW_MODULE_LOCAL: return "local";
    case PW_MODULE_HOST: return "host";
    default: return "unknown";
    }
}

static void copy_bounded(char *out, size_t out_bytes, const char *value)
{
    size_t length = 0;

    if (!out || out_bytes == 0u)
        return;
    if (value) {
        while (value[length] != '\0' && length + 1u < out_bytes)
            ++length;
        memcpy(out, value, length);
    }
    out[length] = '\0';
}

int pw_loader_init(PwLoader *loader, const PwFileProvider *provider,
                   const PwVmBackend *backend)
{
    if (!loader || !pw_file_provider_valid(provider) ||
        !pw_vm_backend_valid(backend))
        return PW_ERR_PRECONDITION;
    memset(loader, 0, sizeof(*loader));
    loader->provider = provider;
    loader->backend = backend;
    return PW_OK;
}

int pw_loader_find(const PwLoader *loader, const char *name)
{
    if (!loader || !name)
        return PW_ERR_PRECONDITION;
    for (uint32_t index = 0; index < loader->module_count; ++index) {
        if (pw_module_name_equal(loader->modules[index].name, name))
            return (int)index;
    }
    return PW_ERR_NOT_FOUND;
}

const PwModule *pw_loader_module(const PwLoader *loader, uint32_t index)
{
    if (!loader || index >= loader->module_count)
        return NULL;
    return &loader->modules[index];
}

static int add_dependency(PwModule *module, uint16_t target)
{
    for (uint32_t index = 0; index < module->dependency_count; ++index) {
        if (module->dependencies[index] == target)
            return PW_OK;               /* an edge is recorded once */
    }
    if (module->dependency_count >= PW_LOADER_MAX_EDGES)
        return PW_ERR_LIMIT;
    module->dependencies[module->dependency_count++] = target;
    return PW_OK;
}

/* Parses, plans, maps and verifies one image into an already reserved slot. */
static int prepare_module(PwLoader *loader, PwModule *module,
                          const void *bytes, size_t size)
{
    int status = pe_image_parse(&module->image, bytes, size);

    if (status != PW_OK)
        return status;
    module->machine = module->image.machine;
    module->machine_native = (uint8_t)pe_image_machine_is_native(&module->image);
    module->is_dll = (uint8_t)pe_image_is_dll(&module->image);
    if (loader->machine == 0u)
        loader->machine = module->machine;
    else if (loader->machine != module->machine)
        return PW_ERR_UNSUPPORTED;      /* one process, one machine */

    status = pe_layout_plan(&module->layout, &module->image);
    if (status != PW_OK)
        return status;
    status = pw_map_image(&module->mapped, &module->image, &module->layout,
                          loader->backend);
    if (status != PW_OK)
        return status;
    module->mapped_ok = 1u;
    loader->reserved_bytes += module->mapped.region.bytes;

    status = pw_map_verify(&module->mapped, &module->image, &module->layout,
                           &module->verify);
    if (status != PW_OK)
        return status;
    if (!module->verify.headers_present || module->verify.raw_mismatches != 0u ||
        module->verify.zero_tail_violations != 0u ||
        module->verify.alias_mismatches != 0u)
        return PW_ERR_MALFORMED;
    return PW_OK;
}

static int register_host_module(PwLoader *loader, const char *name,
                                uint32_t depth, uint16_t *index_out)
{
    PwModule *module;

    if (loader->module_count >= PW_LOADER_MAX_MODULES)
        return PW_ERR_LIMIT;
    module = &loader->modules[loader->module_count];
    memset(module, 0, sizeof(*module));
    copy_bounded(module->name, sizeof(module->name), name);
    module->kind = PW_MODULE_HOST;
    module->depth = depth;
    *index_out = (uint16_t)loader->module_count;
    ++loader->module_count;
    ++loader->host_count;
    if (depth > loader->max_depth)
        loader->max_depth = depth;
    return PW_OK;
}

static int register_local_module(PwLoader *loader, const char *name,
                                 uint32_t depth, uint16_t *index_out)
{
    PwModule *module;
    PwFileSpan span;
    int status;

    if (loader->module_count >= PW_LOADER_MAX_MODULES)
        return PW_ERR_LIMIT;
    memset(&span, 0, sizeof(span));
    status = loader->provider->open(loader->provider->context, name, &span);
    if (status != PW_OK) {
        copy_bounded(loader->missing, sizeof(loader->missing), name);
        return status == PW_ERR_NOT_FOUND ? PW_ERR_NOT_FOUND : status;
    }
    if (!span.bytes || span.size == 0u) {
        loader->provider->close(loader->provider->context, &span);
        copy_bounded(loader->missing, sizeof(loader->missing), name);
        return PW_ERR_TRUNCATED;
    }

    module = &loader->modules[loader->module_count];
    memset(module, 0, sizeof(*module));
    copy_bounded(module->name, sizeof(module->name), name);
    copy_bounded(module->path, sizeof(module->path), span.path);
    module->kind = PW_MODULE_LOCAL;
    module->depth = depth;
    module->span = span;
    module->owns_span = 1u;
    /* Registered before mapping so a failure still releases the span. */
    *index_out = (uint16_t)loader->module_count;
    ++loader->module_count;
    ++loader->local_count;
    if (depth > loader->max_depth)
        loader->max_depth = depth;

    status = prepare_module(loader, module, span.bytes, span.size);
    if (status != PW_OK)
        return status;
    return PW_OK;
}

/*
 * Resolves one module's imports, appending newly discovered modules to the
 * registry. The registry doubles as the work queue: the caller keeps
 * sweeping until no module is left unresolved, which walks the graph
 * breadth first without recursion.
 */
static int resolve_imports(PwLoader *loader, uint32_t module_index)
{
    PeImportTable table;
    PwModule *module = &loader->modules[module_index];
    const uint32_t depth = module->depth + 1u;
    int status;

    if (module->kind == PW_MODULE_HOST)
        return PW_OK;
    status = pe_import_parse(&table, &module->image);
    if (status != PW_OK)
        return status;
    module->import_symbols = table.symbol_count;
    if (table.module_count != 0u && depth > PW_LOADER_MAX_DEPTH)
        return PW_ERR_LIMIT;

    for (uint32_t index = 0; index < table.module_count; ++index) {
        char canonical[PW_MODULE_NAME_MAX + 1];
        uint16_t target;
        int found;

        status = pw_module_name_canonical(canonical, sizeof(canonical),
                                          table.modules[index].name);
        if (status != PW_OK)
            return status;
        found = pw_loader_find(loader, canonical);
        if (found >= 0) {
            target = (uint16_t)found;
        } else if (pw_module_is_system(canonical)) {
            status = register_host_module(loader, canonical, depth, &target);
            if (status != PW_OK)
                return status;
        } else {
            status = register_local_module(loader, canonical, depth, &target);
            if (status != PW_OK)
                return status;
        }
        /*
         * Refreshed deliberately. The registry is a fixed array today, so
         * the pointer is still valid, but registering a module grew it and
         * a later move to caller-provided storage must not turn this into
         * a stale pointer that only misbehaves under load.
         */
        module = &loader->modules[module_index];
        status = add_dependency(module, target);
        if (status != PW_OK)
            return status;
    }
    return PW_OK;
}

int pw_loader_load(PwLoader *loader, const void *bytes, size_t size,
                   const char *name)
{
    char canonical[PW_MODULE_NAME_MAX + 1];
    PwModule *root;
    uint32_t resolved = 0u;
    int status;

    if (!loader || !loader->provider || !loader->backend || !bytes || !name)
        return PW_ERR_PRECONDITION;
    if (loader->module_count != 0u)
        return PW_ERR_STATE;
    status = pw_module_name_canonical(canonical, sizeof(canonical), name);
    if (status != PW_OK)
        return status;

    root = &loader->modules[0];
    memset(root, 0, sizeof(*root));
    copy_bounded(root->name, sizeof(root->name), canonical);
    root->kind = PW_MODULE_ROOT;
    loader->module_count = 1u;

    status = prepare_module(loader, root, bytes, size);
    if (status != PW_OK) {
        (void)pw_loader_release(loader);
        return status;
    }

    while (resolved < loader->module_count) {
        status = resolve_imports(loader, resolved);
        if (status != PW_OK) {
            (void)pw_loader_release(loader);
            return status;
        }
        ++resolved;
    }
    status = pw_loader_compute_order(loader);
    if (status != PW_OK) {
        (void)pw_loader_release(loader);
        return status;
    }
    return PW_OK;
}

/*
 * Post-order depth-first walk from the root. An edge back to a module still
 * on the stack is a cycle: it is counted and skipped, which is what a PE
 * loader must do, since kernel32 and ntdll import each other by design.
 */
static int visit(PwLoader *loader, uint16_t index, uint32_t depth)
{
    PwModule *module;

    if (depth > PW_LOADER_MAX_MODULES)
        return PW_ERR_LIMIT;
    if (index >= loader->module_count)
        return PW_ERR_PRECONDITION;
    if (loader->visit_state[index] == VISIT_DONE)
        return PW_OK;
    if (loader->visit_state[index] == VISIT_ACTIVE) {
        ++loader->cycle_edges;
        return PW_OK;
    }
    loader->visit_state[index] = VISIT_ACTIVE;
    module = &loader->modules[index];
    for (uint32_t edge = 0; edge < module->dependency_count; ++edge) {
        const int status = visit(loader, module->dependencies[edge], depth + 1u);

        if (status != PW_OK)
            return status;
    }
    loader->visit_state[index] = VISIT_DONE;
    if (loader->order_count >= PW_LOADER_MAX_MODULES)
        return PW_ERR_LIMIT;
    loader->order[loader->order_count++] = index;
    return PW_OK;
}

int pw_loader_compute_order(PwLoader *loader)
{
    if (!loader || loader->module_count == 0u)
        return PW_ERR_PRECONDITION;
    memset(loader->visit_state, 0, sizeof(loader->visit_state));
    loader->order_count = 0u;
    loader->cycle_edges = 0u;

    const int status = visit(loader, 0u, 0u);
    if (status != PW_OK)
        return status;
    /* Modules unreachable from the root would be a registry defect. */
    for (uint16_t index = 0; index < (uint16_t)loader->module_count; ++index) {
        if (loader->visit_state[index] != VISIT_DONE)
            return PW_ERR_STATE;
    }
    return PW_OK;
}

int pw_loader_finalize(PwLoader *loader)
{
    if (!loader || loader->module_count == 0u)
        return PW_ERR_PRECONDITION;
    for (uint32_t index = 0; index < loader->module_count; ++index) {
        PwModule *module = &loader->modules[index];
        int status;

        if (!module->mapped_ok)
            continue;
        status = pw_map_finalize_protections(&module->mapped, &module->layout,
                                             loader->backend);
        if (status != PW_OK)
            return status;
    }
    return PW_OK;
}

int pw_loader_release(PwLoader *loader)
{
    int first_error = PW_OK;

    if (!loader)
        return PW_ERR_PRECONDITION;
    for (uint32_t index = 0; index < loader->module_count; ++index) {
        PwModule *module = &loader->modules[index];

        if (module->mapped_ok) {
            const int status = pw_map_release(&module->mapped,
                                              loader->backend);
            if (status != PW_OK && first_error == PW_OK)
                first_error = status;
            module->mapped_ok = 0u;
        }
        if (module->owns_span && loader->provider) {
            loader->provider->close(loader->provider->context, &module->span);
            module->owns_span = 0u;
        }
    }
    loader->module_count = 0u;
    loader->local_count = 0u;
    loader->host_count = 0u;
    loader->order_count = 0u;
    loader->reserved_bytes = 0u;
    loader->machine = 0u;
    return first_error;
}
