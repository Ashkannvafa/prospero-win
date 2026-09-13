/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_export.h"

#include "pw_map.h"
#include "pw_module_name.h"

#include <string.h>

static int chain_contains(const PwExportResolver *resolver, uint32_t depth,
                          const char *module, const char *symbol,
                          uint32_t ordinal, int by_ordinal)
{
    for (uint32_t index = 0; index < depth; ++index) {
        const PwExportVisit *visit = &resolver->visits[index];

        if (!pw_module_name_equal(visit->module, module))
            continue;
        if (visit->by_ordinal != (uint8_t)(by_ordinal != 0))
            continue;
        if (by_ordinal) {
            if (visit->ordinal == ordinal)
                return 1;
        } else if (strcmp(visit->symbol, symbol) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Records the hop that failed so a caller can report both identities. */
static void record_failure(PwExportResolver *resolver, const char *module,
                           const char *symbol, uint32_t ordinal,
                           int by_ordinal, int status)
{
    const size_t module_length = strlen(module);

    resolver->last_status = status;
    memset(resolver->failed_module, 0, sizeof(resolver->failed_module));
    memset(resolver->failed_symbol, 0, sizeof(resolver->failed_symbol));
    if (module_length <= PW_MODULE_NAME_MAX)
        memcpy(resolver->failed_module, module, module_length);
    if (!by_ordinal && symbol) {
        const size_t symbol_length = strlen(symbol);

        if (symbol_length <= PE_EXPORT_NAME_MAX)
            memcpy(resolver->failed_symbol, symbol, symbol_length);
    }
    resolver->failed_ordinal = by_ordinal ? ordinal : 0u;
}

/*
 * "MODULE.SYMBOL" or "MODULE.#ORDINAL", the two shapes the PE format permits
 * in a forwarder string.
 */
static int parse_forwarder(const char *target, char *module,
                           size_t module_bytes, char *symbol,
                           size_t symbol_bytes, uint32_t *ordinal,
                           int *by_ordinal)
{
    const char *separator = strchr(target, '.');
    size_t module_length;

    if (!separator || separator == target)
        return PW_ERR_MALFORMED;
    module_length = (size_t)(separator - target);
    if (module_length + 1u > module_bytes || separator[1] == '\0')
        return PW_ERR_MALFORMED;
    memcpy(module, target, module_length);
    module[module_length] = '\0';

    if (separator[1] == '#') {
        const char *digits = separator + 2;
        uint32_t value = 0;
        size_t count = 0;

        for (; digits[count] != '\0'; ++count) {
            const char digit = digits[count];

            if (digit < '0' || digit > '9' || count >= 5u)
                return PW_ERR_MALFORMED;
            value = value * 10u + (uint32_t)(digit - '0');
        }
        if (count == 0u || value == 0u || value > 0xffffu)
            return PW_ERR_MALFORMED;
        symbol[0] = '\0';
        *ordinal = value;
        *by_ordinal = 1;
        return PW_OK;
    }
    if (strlen(separator + 1) + 1u > symbol_bytes)
        return PW_ERR_MALFORMED;
    memcpy(symbol, separator + 1, strlen(separator + 1) + 1u);
    *ordinal = 0u;
    *by_ordinal = 0;
    return PW_OK;
}

static int resolve_in_chain(PwExportResolver *resolver, const char *module,
                            const char *name, uint32_t ordinal, int by_ordinal,
                            uint32_t depth, PwExportTarget *out)
{
    char canonical[PW_MODULE_NAME_MAX + 1];
    PeExportDirectory directory;
    PeExportSymbol symbol;
    const PwModule *owner;
    PwExportVisit *visit;
    int status;
    int index;

    if (depth > resolver->max_depth) {
        resolver->depth_exhausted++;
        return PW_ERR_LIMIT;
    }
    status = pw_module_name_canonical(canonical, sizeof(canonical), module);
    if (status != PW_OK)
        return status;
    if (chain_contains(resolver, depth, canonical,
                       by_ordinal ? "" : name, ordinal, by_ordinal)) {
        resolver->cycles++;
        return PW_ERR_MALFORMED;
    }
    visit = &resolver->visits[depth];
    memset(visit, 0, sizeof(*visit));
    memcpy(visit->module, canonical, sizeof(visit->module));
    visit->module[PW_MODULE_NAME_MAX] = '\0';
    if (!by_ordinal) {
        const size_t length = strlen(name);

        if (length > PE_EXPORT_NAME_MAX)
            return PW_ERR_LIMIT;
        memcpy(visit->symbol, name, length + 1u);
    }
    visit->ordinal = ordinal;
    visit->by_ordinal = (uint8_t)(by_ordinal != 0);
    if (depth > resolver->max_observed_depth)
        resolver->max_observed_depth = depth;

    index = pw_loader_find(resolver->loader, canonical);
    if (index < 0) {
        resolver->misses++;
        record_failure(resolver, canonical, name, ordinal, by_ordinal, index);
        return index;
    }
    owner = pw_loader_module(resolver->loader, (uint32_t)index);
    if (!owner || !owner->mapped_ok) {
        record_failure(resolver, canonical, name, ordinal, by_ordinal,
                       PW_ERR_STATE);
        return PW_ERR_STATE;
    }
    status = pe_export_parse(&directory, &owner->image);
    if (status != PW_OK) {
        record_failure(resolver, canonical, name, ordinal, by_ordinal, status);
        return status;
    }
    status = by_ordinal
        ? pe_export_find_ordinal(&owner->image, &directory, ordinal, &symbol)
        : pe_export_find_name(&owner->image, &directory, name, &symbol);
    if (status != PW_OK) {
        if (status == PW_ERR_NOT_FOUND)
            resolver->misses++;
        record_failure(resolver, canonical, name, ordinal, by_ordinal, status);
        return status;
    }

    if (symbol.is_forwarder) {
        char target_module[PW_MODULE_NAME_MAX + 1];
        char target_symbol[PE_EXPORT_NAME_MAX + 1];
        uint32_t target_ordinal = 0u;
        int target_by_ordinal = 0;

        status = parse_forwarder(symbol.target, target_module,
                                 sizeof(target_module), target_symbol,
                                 sizeof(target_symbol), &target_ordinal,
                                 &target_by_ordinal);
        if (status != PW_OK)
            return PW_ERR_MALFORMED;
        resolver->forwarders++;
        status = resolve_in_chain(resolver, target_module,
                                  target_by_ordinal ? NULL : target_symbol,
                                  target_ordinal, target_by_ordinal,
                                  depth + 1u, out);
        if (status != PW_OK)
            return status;
        out->forwarded = 1u;
        out->forwards++;
        return PW_OK;
    }

    {
        const uint64_t address = pw_map_exec_address(&owner->mapped, symbol.rva);

        if (address == 0u || address > 0xffffffffull)
            return PW_ERR_MALFORMED;
        memset(out, 0, sizeof(*out));
        out->address = (uint32_t)address;
        out->rva = symbol.rva;
        out->ordinal = symbol.ordinal;
        out->by_ordinal = symbol.by_ordinal;
        out->is_data = (uint8_t)(symbol.is_code == 0u);
        memcpy(out->module, canonical, sizeof(out->module));
        out->module[PW_MODULE_NAME_MAX] = '\0';
        memcpy(out->symbol, symbol.name, sizeof(out->symbol));
        out->symbol[PE_EXPORT_NAME_MAX] = '\0';
    }
    return PW_OK;
}

int pw_export_resolver_init(PwExportResolver *resolver,
                            const PwLoader *loader, uint32_t max_depth)
{
    if (!resolver || !loader)
        return PW_ERR_PRECONDITION;
    if (max_depth == 0u || max_depth > PW_EXPORT_MAX_DEPTH)
        return PW_ERR_PRECONDITION;
    memset(resolver, 0, sizeof(*resolver));
    resolver->loader = loader;
    resolver->max_depth = max_depth;
    return PW_OK;
}

int pw_export_resolve(PwExportResolver *resolver, const char *module,
                      const char *name, uint32_t ordinal, int by_ordinal,
                      PwExportTarget *out)
{
    if (!resolver || !resolver->loader || !module || !*module || !out)
        return PW_ERR_PRECONDITION;
    if (by_ordinal) {
        if (ordinal == 0u || ordinal > 0xffffu)
            return PW_ERR_PRECONDITION;
    } else if (!name || !*name) {
        return PW_ERR_PRECONDITION;
    }
    memset(out, 0, sizeof(*out));
    resolver->lookups++;
    resolver->last_status = PW_OK;
    memset(resolver->request_module, 0, sizeof(resolver->request_module));
    memset(resolver->request_symbol, 0, sizeof(resolver->request_symbol));
    if (strlen(module) <= PW_MODULE_NAME_MAX)
        memcpy(resolver->request_module, module, strlen(module));
    if (!by_ordinal && name && strlen(name) <= PE_EXPORT_NAME_MAX)
        memcpy(resolver->request_symbol, name, strlen(name));
    resolver->request_ordinal = by_ordinal ? ordinal : 0u;
    resolver->request_by_ordinal = (uint8_t)(by_ordinal != 0);
    return resolve_in_chain(resolver, module, by_ordinal ? "" : name, ordinal,
                            by_ordinal, 0u, out);
}

int pw_export_resolve_request(PwExportResolver *resolver, const char *request,
                              PwExportTarget *out)
{
    char module[PW_MODULE_NAME_MAX + 1];
    char symbol[PE_EXPORT_NAME_MAX + 1];
    uint32_t ordinal = 0u;
    int by_ordinal = 0;
    int status;

    if (!resolver || !request || !out)
        return PW_ERR_PRECONDITION;
    if (strlen(request) >= PW_EXPORT_REQUEST_MAX)
        return PW_ERR_LIMIT;
    status = parse_forwarder(request, module, sizeof(module), symbol,
                             sizeof(symbol), &ordinal, &by_ordinal);
    if (status != PW_OK)
        return status;
    return pw_export_resolve(resolver, module, symbol, ordinal, by_ordinal, out);
}

int pw_export_import_resolver(void *context, const char *module,
                              const PeImportSymbol *symbol,
                              PwImportTarget *out)
{
    PwExportResolver *resolver = context;
    PwExportTarget target;
    int status;

    if (!resolver || !module || !symbol || !out)
        return PW_ERR_PRECONDITION;
    status = pw_export_resolve(resolver, module, symbol->name, symbol->ordinal,
                               symbol->by_ordinal ? 1 : 0, &target);
    if (status != PW_OK)
        return status;
    out->address = target.address;
    out->kind = target.is_data ? PW_IMPORT_DATA : PW_IMPORT_FUNCTION;
    return PW_OK;
}
