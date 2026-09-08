/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Host file provider: resolves a canonical module name inside one
 * directory, the application directory a Windows loader would search first.
 *
 * Import tables name modules in whatever case the linker recorded, and PE
 * name lookup is case-insensitive, so an exact open is tried first and a
 * case-insensitive directory scan second. On the console neither libc
 * opendir nor getdents is usable on the read-only application image, so the
 * PS5 provider relies on lowercase staging plus a build-time index instead;
 * this backend is for host tools and tests.
 */
#ifndef PROSPERO_WIN_FILE_POSIX_H
#define PROSPERO_WIN_FILE_POSIX_H

#include "../include/prospero_win_file.h"

typedef struct PwFilePosix {
    char directory[PW_PATH_MAX + 1];
    uint32_t opens;
    uint32_t closes;
    uint64_t bytes_read;
} PwFilePosix;

int pw_file_posix_init(PwFilePosix *state, const char *directory);

int pw_file_posix_provider(PwFilePosix *state, PwFileProvider *provider);

/* Reads one whole file; the caller frees span->bytes through the provider. */
int pw_file_posix_read(PwFilePosix *state, const char *path, PwFileSpan *out);

#endif
