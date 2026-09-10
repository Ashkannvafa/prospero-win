/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_CRT_FORMAT_H
#define PW_CRT_FORMAT_H
#include "../include/prospero_win.h"

typedef struct PwCrtFormatInput {
    void *opaque;
    int (*u32)(void *opaque,unsigned index,uint32_t *value);
    int (*string)(void *opaque,uint32_t address,char *output,size_t capacity,
                  size_t *length);
} PwCrtFormatInput;

/* Allocation-free MSVCRT-style narrow formatting subset. Output capacity
 * includes the terminator. Failure must be treated as unpublished scratch. */
int pw_crt_format_ascii(char *output,size_t capacity,const char *format,
                        const PwCrtFormatInput *,uint32_t *length);
#endif
