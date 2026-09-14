/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Guest-visible names, turned into canonical host-neutral strings.
 *
 * Every service the bridge exposes asks the same question first: what did the
 * guest actually name? Three namespaces reach this file - DOS/NT file paths
 * under the Windows directory, NT registry key paths and NT object-namespace
 * paths - plus value names for registry queries. The rules are the same in all
 * of them: read the guest's UNICODE_STRING or ANSI name through the
 * dispatcher's validated accessor, accept only the documented roots, require
 * single validated components, lower-case the result, and refuse traversal,
 * separators, colons or anything that could name a host path. Nothing here
 * talks to a platform service, which is why it can be reviewed and tested on
 * its own.
 */
#ifndef PROSPERO_WIN_PW_WINE_PATH_H
#define PROSPERO_WIN_PW_WINE_PATH_H

#include "pw_unix_call.h"
#include "../include/prospero_win_file.h"

#include <stddef.h>
#include <stdint.h>

/* The ASCII case fold the namespaces share. */
char pw_wine_path_lower(char value);

/* Case-insensitive prefix match; *used is the prefix length on success. */
int pw_wine_path_prefix(const char *text, const char *prefix, size_t *used);

/* Reads a guest UNICODE_STRING and converts the ASCII part to a C string. */
int pw_wine_path_read_unicode(PwUnixCallAccess guest, void *context,
                              uint32_t address, char *out, size_t out_bytes);

/* True when an already canonical path sits under one of the two roots. */
int pw_wine_path_registry_root(const char *canonical, const char *root);

/* \Registry\Machine or \Registry\User, or relative to a key handle's path. */
int pw_wine_path_registry(const char *path, char *out, size_t out_bytes,
                          uint32_t *status);

/* Reads a registry value name (KEY_VALUE_INFORMATION_CLASS name address). */
int pw_wine_path_value_name(PwUnixCallAccess guest, void *context,
                            uint32_t address, char *out, size_t out_bytes);

/* Lower-cases a value name; the empty name is the default value. */
int pw_wine_path_value(const char *name, char *out, size_t out_bytes,
                       uint32_t *status);

/*
 * A guest DOS/NT path inside the runtime distribution. Only the Windows
 * directory and its system32 subtree are accepted; the result is one
 * lower-case component, or the directory itself when *is_directory is set.
 */
int pw_wine_path_runtime(const char *path, char *out, size_t out_bytes,
                                  PwFileNamespace *file_namespace,
                         int *is_directory, uint32_t *status);

/* An NT object-namespace path: absolute, or relative to the given root. */
int pw_wine_path_object(const char *path, char *out, size_t out_bytes,
                        uint32_t *status);

#endif /* PROSPERO_WIN_PW_WINE_PATH_H */
