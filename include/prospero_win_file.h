/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Read-only file contract used for recursive dependency loading.
 *
 * The loader core never calls open(), stat() or opendir(). A provider maps
 * a canonical module name ("binkw32.dll") to a read-only byte span. The
 * namespace-aware form keeps application files and the selected Wine/DXVK
 * runtime distribution separate while preserving the same descriptor
 * lifecycle in host tests and on the console.
 */
#ifndef PROSPERO_WIN_FILE_H
#define PROSPERO_WIN_FILE_H

#include "prospero_win.h"

typedef struct PwFileSpan {
    const void *bytes;
    size_t size;
    void *handle;                    /* provider-owned bookkeeping */
    char path[PW_PATH_MAX + 1];      /* provenance, for telemetry only */
} PwFileSpan;

typedef enum PwFileNamespace {
    PW_FILE_APPLICATION = 1, /* executable directory / application override */
    PW_FILE_RUNTIME = 2,     /* Wine/DXVK runtime distribution */
} PwFileNamespace;

typedef struct PwFileProvider {
    void *context;
    /* PW_OK, or PW_ERR_NOT_FOUND when the name is not available locally. */
    int (*open)(void *context, const char *canonical_name, PwFileSpan *out);
    void (*close)(void *context, PwFileSpan *span);
    /* Optional namespace-aware lookup. The loader uses this when present so
     * application DLLs cannot accidentally shadow the selected Wine runtime,
     * or vice versa. A runtime lookup is unsupported when this callback is
     * absent; it never silently falls back to the application directory. */
    int (*open_namespace)(void *context, PwFileNamespace file_namespace,
                          const char *canonical_name, PwFileSpan *out);
} PwFileProvider;

int pw_file_provider_valid(const PwFileProvider *provider);

#endif
