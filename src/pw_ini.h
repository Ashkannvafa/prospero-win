/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_INI_H
#define PW_INI_H
#include "../include/prospero_win.h"
#include <stddef.h>
#include <stdint.h>

/* Bounded, allocation-free Win32-profile integer lookup. Missing sections,
 * keys and malformed values publish the caller's fallback. */
int pw_ini_get_int(const uint8_t *bytes,size_t length,const char *section,
                   const char *key,uint32_t fallback,uint32_t *value);
#endif
