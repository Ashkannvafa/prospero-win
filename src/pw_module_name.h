/*
 * Module-name canonicalisation and the local/host split.
 *
 * PE module names are ASCII and case-insensitive. This file implements its
 * own ASCII fold rather than importing strcasecmp or strcasestr: those are
 * locale-dependent by contract, and on this firmware the non-standard one
 * of the pair is routed to an unusable provider (see the porting playbook's
 * strcasestr post-mortem). The loader must not inherit that class of bug.
 *
 * The split decides the whole project's shape. A third-party module such as
 * binkw32.dll is real code that gets manually mapped. A Win32 module such
 * as kernel32.dll is an interface that prospero-win implements natively; it
 * is never loaded from disk, because there is no Windows on the console.
 */
#ifndef PROSPERO_WIN_MODULE_NAME_H
#define PROSPERO_WIN_MODULE_NAME_H

#include "../include/prospero_win.h"

/* Lowercases into out and appends ".dll" when no extension is present. */
int pw_module_name_canonical(char *out, size_t out_bytes, const char *name);

/* ASCII case-insensitive comparison; no locale, no libc. */
int pw_module_name_equal(const char *left, const char *right);

/* Non-zero when the canonical name is part of the Win32 surface. */
int pw_module_is_system(const char *canonical_name);

/* Iteration over the classified surface, for tests and telemetry. */
uint32_t pw_module_system_count(void);
const char *pw_module_system_name(uint32_t index);

#endif
