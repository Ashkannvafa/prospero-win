/*
 * Recursive dependency loader.
 *
 * Walks the import graph from one root image, manually maps every
 * third-party dependency it can resolve locally, and records every Win32
 * module as a host binding to be implemented natively rather than loaded.
 * A DLL chain such as game.exe -> binkw32.dll -> msvcrt.dll therefore ends
 * with two mapped images and one host binding.
 *
 * Cycles are normal in PE and are not errors: a module is registered once,
 * under its canonical name, and a repeat edge only adds a dependency link.
 * Every capacity is compiled in and every overflow fails closed, so a
 * corrupt or hostile import table cannot make the loader allocate or
 * recurse without bound.
 *
 * PwLoader is large by design (it embeds each module's parsed tables). Keep
 * it out of automatic storage: allocate it statically or from the memory
 * backend, which is also the laboratory's measured rule for anything over
 * 256 KiB on this firmware.
 */
#ifndef PROSPERO_WIN_LOADER_H
#define PROSPERO_WIN_LOADER_H

#include "../include/prospero_win_file.h"
#include "pe_import.h"
#include "pw_map.h"

enum {
    PW_LOADER_MAX_MODULES = 32,
    PW_LOADER_MAX_DEPTH = 16,
    PW_LOADER_MAX_EDGES = 32,
};

enum pw_module_kind {
    PW_MODULE_ROOT = 0,    /* the image the loader was asked to load */
    PW_MODULE_LOCAL = 1,   /* third-party code, manually mapped */
    PW_MODULE_HOST = 2,    /* Win32 surface, implemented by prospero-win */
};

typedef struct PwModule {
    char name[PW_MODULE_NAME_MAX + 1];
    char path[PW_PATH_MAX + 1];
    uint8_t kind;
    uint8_t mapped_ok;
    uint8_t is_dll;
    uint8_t machine_native;
    uint16_t machine;
    uint32_t depth;
    uint32_t import_symbols;
    uint32_t dependency_count;
    uint16_t dependencies[PW_LOADER_MAX_EDGES];
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    PwMapVerify verify;
    PwFileSpan span;
    uint8_t owns_span;
} PwModule;

typedef struct PwLoader {
    const PwFileProvider *provider;
    const PwVmBackend *backend;
    uint32_t module_count;
    uint32_t local_count;
    uint32_t host_count;
    uint32_t cycle_edges;
    uint32_t max_depth;
    uint64_t reserved_bytes;
    uint16_t machine;                    /* enforced across the whole graph */
    char missing[PW_MODULE_NAME_MAX + 1];/* first unresolvable dependency */
    PwModule modules[PW_LOADER_MAX_MODULES];
    uint8_t visit_state[PW_LOADER_MAX_MODULES];
    uint16_t order[PW_LOADER_MAX_MODULES];
    uint32_t order_count;
} PwLoader;

int pw_loader_init(PwLoader *loader, const PwFileProvider *provider,
                   const PwVmBackend *backend);

/*
 * Parses, maps and verifies the root, then resolves the whole graph. On any
 * failure every module already mapped is released, so a failed load leaves
 * no reservation behind.
 */
int pw_loader_load(PwLoader *loader, const void *bytes, size_t size,
                   const char *name);

/* Dependencies before dependents; host bindings first. */
int pw_loader_compute_order(PwLoader *loader);

int pw_loader_find(const PwLoader *loader, const char *name);

const PwModule *pw_loader_module(const PwLoader *loader, uint32_t index);

/* Installs final page protections on every mapped module. */
int pw_loader_finalize(PwLoader *loader);

int pw_loader_release(PwLoader *loader);

const char *pw_module_kind_name(unsigned kind);

#endif
