/*
 * Read-only file contract used for recursive dependency loading.
 *
 * The loader core never calls open(), stat() or opendir(). A provider maps
 * a canonical module name ("binkw32.dll") to a read-only byte span, so the
 * same graph resolution runs against an in-memory table in host tests and
 * against sceKernelOpen/sceKernelRead on the console, keeping the whole
 * descriptor lifecycle in one namespace.
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

typedef struct PwFileProvider {
    void *context;
    /* PW_OK, or PW_ERR_NOT_FOUND when the name is not available locally. */
    int (*open)(void *context, const char *canonical_name, PwFileSpan *out);
    void (*close)(void *context, PwFileSpan *span);
} PwFileProvider;

int pw_file_provider_valid(const PwFileProvider *provider);

#endif
