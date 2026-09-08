/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_GUEST_ARGS_H
#define PW_GUEST_ARGS_H
#include <stddef.h>
#include <stdint.h>
enum { PW_ARGS_LIMIT=128, PW_ARGS_BYTES=4096 };
typedef struct PwGuestArgs { uint32_t argc,argv,envp; size_t bytes; } PwGuestArgs;
/* Build guest-relative 32-bit pointers in caller storage, without host
 * environment inheritance. Inputs are narrow command-line/environment bytes.
 * No wildcard expansion. On failure output/report are unchanged. */
int pw_guest_args_build(const char *line,const char *const *env,unsigned env_count,
                        uint32_t base,void *output,size_t capacity,PwGuestArgs *report);
#endif
