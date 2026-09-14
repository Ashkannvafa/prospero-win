/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The per-run workspace the gate used to keep in function-local statics.
 *
 * `pw_wine_gate_run` had four `static` objects inside it - the import-bind
 * workspace, the loader, the export resolver and the translation cache entries
 * - which made two runs in one host process share mutable state while the code
 * claimed the run owned its own context. The state lives here instead, in an
 * object the *caller* owns: a single-process caller can keep one at file scope,
 * a test can keep two and prove they are independent, and the gate never
 * touches hidden state again.
 *
 * The cache entries are the reason the object is not tiny (PW_WINE_GATE_CACHE_ENTRIES
 * entries of PwX86CacheEntry), so a caller that wants it on the heap or in a
 * static does so deliberately; nothing in this unit allocates.
 */
#ifndef PROSPERO_WIN_PW_WINE_RUNNER_H
#define PROSPERO_WIN_PW_WINE_RUNNER_H

#include "pw_export.h"
#include "pw_import_bind.h"
#include "pw_loader.h"
#include "pw_wine_gate.h"

enum {
    /* Written by init and cleared by release, so a run that is handed an
     * uninitialized or already-released runner fails closed. */
    PW_WINE_RUNNER_READY = 0x57524e52u,     /* 'WRNR' */
};

typedef struct PwWineRunner {
    uint32_t ready;                 /* PW_WINE_RUNNER_READY when initialized */
    PwImportBindWorkspace workspace;
    PwLoader loader;
    PwExportResolver resolver;
    PwX86CacheEntry cache[PW_WINE_GATE_CACHE_ENTRIES];
} PwWineRunner;

/* Zeroes the object and marks it ready. No host allocation, no OS call. */
void pw_wine_runner_init(PwWineRunner *runner);

/* Clears the object and its marker, so a second run needs a fresh init. */
void pw_wine_runner_release(PwWineRunner *runner);

/* True when the runner may be used. */
int pw_wine_runner_ready(const PwWineRunner *runner);

#endif /* PROSPERO_WIN_PW_WINE_RUNNER_H */
