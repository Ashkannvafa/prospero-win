/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Module-graph export resolution.
 *
 * The unit of reuse is a Wine module, not an isolated function: a mapped
 * runtime module publishes exports, other mapped modules import them, and
 * Wine's own DLLs forward a large part of the Win32 surface
 * ("KERNEL32.CreateFileA" -> "KERNELBASE.CreateFileA"). This is the single
 * resolver every caller uses, so no module needs a special-case
 * kernel32/ntdll path.
 *
 * Forwarders are followed through the loaded graph with an explicit depth
 * bound and a visited (module, symbol-or-ordinal) chain check, so a
 * self-referential or cyclic export table fails closed instead of recursing.
 * An unresolved export never yields a host pointer: the only address the
 * resolver can return is one the mapper published for a mapped module.
 */
#ifndef PROSPERO_WIN_PW_EXPORT_H
#define PROSPERO_WIN_PW_EXPORT_H

#include "pe_export.h"
#include "pw_import_bind.h"
#include "pw_loader.h"

enum {
    PW_EXPORT_MAX_DEPTH = 8,
    PW_EXPORT_REQUEST_MAX = 128,
};

typedef struct PwExportVisit {
    char module[PW_MODULE_NAME_MAX + 1];
    char symbol[PE_EXPORT_NAME_MAX + 1];
    uint32_t ordinal;
    uint8_t by_ordinal;
} PwExportVisit;

typedef struct PwExportTarget {
    uint32_t address;                       /* guest virtual address, never a host pointer */
    uint32_t rva;
    uint32_t ordinal;
    uint32_t forwards;                      /* forwarder hops followed */
    char module[PW_MODULE_NAME_MAX + 1];    /* module that finally owns the RVA */
    char symbol[PE_EXPORT_NAME_MAX + 1];    /* final name, empty for ordinal-only */
    uint8_t is_data;                        /* exported data, not callable code */
    uint8_t by_ordinal;
    uint8_t forwarded;
} PwExportTarget;

typedef struct PwExportResolver {
    const PwLoader *loader;
    uint32_t max_depth;
    uint64_t lookups, misses, forwarders, cycles, depth_exhausted;
    uint32_t max_observed_depth;
    /* Diagnostics: the identity the caller asked for, and the hop that
     * actually failed. A forwarder chain must never lose either one. */
    char request_module[PW_MODULE_NAME_MAX + 1];
    char request_symbol[PE_EXPORT_NAME_MAX + 1];
    uint32_t request_ordinal;
    uint8_t request_by_ordinal;
    char failed_module[PW_MODULE_NAME_MAX + 1];
    char failed_symbol[PE_EXPORT_NAME_MAX + 1];
    uint32_t failed_ordinal;
    int last_status;
    PwExportVisit visits[PW_EXPORT_MAX_DEPTH + 1];
} PwExportResolver;

int pw_export_resolver_init(PwExportResolver *resolver,
                            const PwLoader *loader, uint32_t max_depth);

/* module is any PE spelling of a canonical name ("KERNEL32.dll"). */
int pw_export_resolve(PwExportResolver *resolver, const char *module,
                      const char *name, uint32_t ordinal, int by_ordinal,
                      PwExportTarget *out);

/* "KERNEL32.CreateFileA" or "NTDLL.#101"; the module part is case-insensitive
 * and may omit the .dll suffix, exactly as a forwarder string is written. */
int pw_export_resolve_request(PwExportResolver *resolver, const char *request,
                              PwExportTarget *out);

/* PwImportResolver adapter: binds an import table against the same graph. */
int pw_export_import_resolver(void *context, const char *module,
                              const PeImportSymbol *symbol,
                              PwImportTarget *out);

#endif
